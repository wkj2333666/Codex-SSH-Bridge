#![allow(
    clippy::result_large_err,
    reason = "the shared BridgeResult intentionally stores BridgeError inline"
)]

use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command as TokioCommand;
use tokio_util::sync::CancellationToken;

use crate::config::{Config, HostLimitOverrides, HostProfile, ResolvedHost};
use crate::error::{BridgeError, BridgeResult};
use crate::output::OutputStore;
use crate::path::RemotePath;
use crate::quote::shell_word;
use crate::remote::{RemoteBridge, RemoteRunRequest, RemoteRunResult, RunShell, StatRequest};
use crate::ssh::{
    RuntimePaths, SshRunner, ValidatedMountpoint, build_ssh_g_argv, build_sshfs_argv,
};

mod install;
pub use install::{InstallLayout, InstallReport, install_user, uninstall_user};

#[derive(Debug, Parser)]
#[command(
    name = "codex-ssh-bridge",
    about = "Operate allowlisted SSH servers from the local machine",
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the local stdio MCP server.
    Mcp,
    /// Manage exact allowlisted OpenSSH aliases.
    Hosts(HostsArgs),
    /// Diagnose configuration, SSH resolution, and remote capabilities.
    Doctor(DoctorArgs),
    /// Run an argv-style command on an allowlisted remote host.
    Run(RunArgs),
    /// Mount a remote path explicitly with SSHFS (human use only).
    Mount(MountArgs),
    /// Unmount an explicit local SSHFS mountpoint.
    Unmount(MountpointArgs),
    /// Report whether a local path is an SSHFS mountpoint.
    MountStatus(MountpointArgs),
    /// Install the local MCP entry and Skill; dry-run unless --apply is supplied.
    Install(InstallArgs),
    /// Uninstall only an identity-matching local installation; dry-run unless --apply is supplied.
    Uninstall(InstallArgs),
}

#[derive(Debug, Args)]
pub struct HostsArgs {
    #[command(subcommand)]
    pub command: HostsCommand,
}

#[derive(Debug, Subcommand)]
pub enum HostsCommand {
    List,
    Show(HostName),
    Add(AddHostArgs),
    Remove(HostName),
}

#[derive(Debug, Args)]
pub struct HostName {
    #[arg(allow_hyphen_values = true)]
    pub alias: String,
}

#[derive(Debug, Args)]
pub struct AddHostArgs {
    #[arg(allow_hyphen_values = true)]
    pub alias: String,
    #[arg(long)]
    pub root: String,
    #[arg(long)]
    pub description: Option<String>,
    #[arg(long)]
    pub read_only: bool,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    pub host: Option<String>,
    #[arg(long)]
    pub verbose_ssh: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ShellArg {
    Bash,
    Sh,
    Login,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    pub host: String,
    #[arg(long, default_value = ".")]
    pub cwd: String,
    #[arg(long, value_enum, default_value = "bash")]
    pub shell: ShellArg,
    #[arg(long)]
    pub timeout_ms: Option<u64>,
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub argv: Vec<String>,
}

#[derive(Debug, Args)]
pub struct MountArgs {
    pub host: String,
    pub mountpoint: PathBuf,
    #[arg(long, default_value = ".")]
    pub remote_path: String,
    #[arg(long)]
    pub allow_nonempty: bool,
}

#[derive(Debug, Args)]
pub struct MountpointArgs {
    pub mountpoint: PathBuf,
}

#[derive(Debug, Args)]
pub struct InstallArgs {
    #[arg(long, required = true)]
    pub user: bool,
    #[arg(long)]
    pub apply: bool,
}

pub fn known_human_mode(value: &std::ffi::OsStr) -> bool {
    matches!(
        value.to_str(),
        Some(
            "--help"
                | "-h"
                | "hosts"
                | "doctor"
                | "run"
                | "mount"
                | "unmount"
                | "mount-status"
                | "install"
                | "uninstall"
        )
    )
}

pub fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(std::iter::once(OsString::from("codex-ssh-bridge")).chain(arguments))
}

pub async fn run(cli: Cli) -> BridgeResult<()> {
    match cli.command {
        Command::Hosts(arguments) => run_hosts(config_path()?, arguments),
        Command::Mcp => Err(BridgeError::invalid_argument(
            "mcp mode is dispatched by the binary entry point",
        )),
        Command::Doctor(arguments) => run_doctor(config_path()?, arguments).await,
        Command::Run(arguments) => run_remote_command(config_path()?, arguments).await,
        Command::Mount(arguments) => run_mount(config_path()?, arguments).await,
        Command::Unmount(arguments) => run_unmount(arguments).await,
        Command::MountStatus(arguments) => run_mount_status(arguments),
        Command::Install(arguments) => run_install(arguments).await,
        Command::Uninstall(arguments) => run_uninstall_installation(arguments).await,
    }
}

pub async fn doctor_host(bridge: &RemoteBridge, host: &str) -> BridgeResult<serde_json::Value> {
    let result = bridge
        .stat(
            StatRequest {
                host: host.to_owned(),
                paths: vec![".".to_owned()],
            },
            CancellationToken::new(),
        )
        .await?;
    serde_json::to_value(result)
        .map_err(|error| BridgeError::io(format!("cannot render doctor result: {error}")))
}

pub fn redact_ssh_diagnostics(bytes: &[u8]) -> String {
    const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;
    const SENSITIVE_MARKERS: &[&str] = &[
        "identity file",
        "identityfile",
        "identity agent",
        "identityagent",
        "ssh_auth_sock",
        "agent socket",
        "sending command",
        "proxycommand",
        "password",
        "passwd",
        "token",
        "secret",
        "authorization",
        "cookie",
        "private key",
        "access_key",
        "client_secret",
        ".ssh/",
    ];
    let bounded = &bytes[..bytes.len().min(MAX_DIAGNOSTIC_BYTES)];
    let decoded = String::from_utf8_lossy(bounded);
    let mut rendered = String::with_capacity(decoded.len().min(MAX_DIAGNOSTIC_BYTES));
    for line in decoded.lines() {
        let lowered = line.to_ascii_lowercase();
        if SENSITIVE_MARKERS
            .iter()
            .any(|marker| lowered.contains(marker))
        {
            rendered.push_str("[REDACTED]\n");
            continue;
        }
        for character in line.chars() {
            if rendered.len() >= MAX_DIAGNOSTIC_BYTES.saturating_sub(2) {
                break;
            }
            if character.is_control() {
                rendered.push('?');
            } else {
                rendered.push(character);
            }
        }
        rendered.push('\n');
        if rendered.len() >= MAX_DIAGNOSTIC_BYTES {
            break;
        }
    }
    rendered
}

pub async fn run_remote_argv(
    bridge: &RemoteBridge,
    arguments: RunArgs,
) -> BridgeResult<RemoteRunResult> {
    if arguments.argv.is_empty() {
        return Err(BridgeError::invalid_argument(
            "direct run requires a program after --",
        ));
    }
    let command = arguments
        .argv
        .iter()
        .map(|argument| shell_word(argument))
        .collect::<BridgeResult<Vec<_>>>()?
        .join(" ");
    bridge
        .run(
            RemoteRunRequest {
                host: arguments.host,
                command,
                cwd: Some(arguments.cwd),
                shell: match arguments.shell {
                    ShellArg::Bash => RunShell::Bash,
                    ShellArg::Sh => RunShell::Sh,
                    ShellArg::Login => RunShell::Login,
                },
                timeout_ms: arguments.timeout_ms,
                stdin: None,
            },
            CancellationToken::new(),
        )
        .await
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MountStatus {
    pub mountpoint: PathBuf,
    pub mounted: bool,
    pub sshfs: bool,
    pub mount_id: Option<u64>,
    pub filesystem_type: Option<String>,
}

pub fn parse_sshfs_mount_status(bytes: &[u8], mountpoint: &Path) -> BridgeResult<MountStatus> {
    parse_sshfs_mount_status_matching(bytes, mountpoint, None)
}

fn parse_sshfs_mount_status_for_id(
    bytes: &[u8],
    mountpoint: &Path,
    expected_mount_id: u64,
) -> BridgeResult<MountStatus> {
    parse_sshfs_mount_status_matching(bytes, mountpoint, Some(expected_mount_id))
}

fn parse_sshfs_mount_status_matching(
    bytes: &[u8],
    mountpoint: &Path,
    expected_mount_id: Option<u64>,
) -> BridgeResult<MountStatus> {
    if !mountpoint.is_absolute() {
        return Err(BridgeError::invalid_argument(
            "mount-status requires an absolute local path",
        ));
    }
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;
    #[cfg(unix)]
    let expected = mountpoint.as_os_str().as_bytes();
    #[cfg(not(unix))]
    let expected = mountpoint.as_os_str().to_string_lossy().as_bytes();

    for line in bytes.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let separator = line
            .windows(3)
            .position(|window| window == b" - ")
            .ok_or_else(|| BridgeError::invalid_argument("mountinfo line is malformed"))?;
        let before = &line[..separator];
        let after = &line[separator + 3..];
        let encoded_mountpoint = before
            .split(|byte| *byte == b' ')
            .nth(4)
            .ok_or_else(|| BridgeError::invalid_argument("mountinfo mountpoint is missing"))?;
        if decode_mountinfo_field(encoded_mountpoint)? != expected {
            continue;
        }
        let mount_id = before
            .split(|byte| *byte == b' ')
            .next()
            .ok_or_else(|| BridgeError::invalid_argument("mountinfo mount ID is missing"))?;
        let mount_id = std::str::from_utf8(mount_id)
            .map_err(|_| BridgeError::invalid_argument("mountinfo mount ID is not UTF-8"))?
            .parse::<u64>()
            .map_err(|_| BridgeError::invalid_argument("mountinfo mount ID is invalid"))?;
        if expected_mount_id.is_some_and(|expected| mount_id != expected) {
            continue;
        }
        let filesystem = after
            .split(|byte| *byte == b' ')
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| BridgeError::invalid_argument("mountinfo filesystem is missing"))?;
        let filesystem = std::str::from_utf8(filesystem)
            .map_err(|_| BridgeError::invalid_argument("mountinfo filesystem is not UTF-8"))?
            .to_owned();
        return Ok(MountStatus {
            mountpoint: mountpoint.to_owned(),
            mounted: true,
            sshfs: filesystem == "fuse.sshfs",
            mount_id: Some(mount_id),
            filesystem_type: Some(filesystem),
        });
    }
    Ok(MountStatus {
        mountpoint: mountpoint.to_owned(),
        mounted: false,
        sshfs: false,
        mount_id: None,
        filesystem_type: None,
    })
}

fn decode_mountinfo_field(encoded: &[u8]) -> BridgeResult<Vec<u8>> {
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut index = 0;
    while index < encoded.len() {
        if encoded[index] != b'\\' {
            decoded.push(encoded[index]);
            index += 1;
            continue;
        }
        let digits = encoded
            .get(index + 1..index + 4)
            .ok_or_else(|| BridgeError::invalid_argument("mountinfo escape is truncated"))?;
        if !digits.iter().all(|digit| matches!(digit, b'0'..=b'7')) {
            return Err(BridgeError::invalid_argument(
                "mountinfo escape is not octal",
            ));
        }
        let value = (digits[0] - b'0') * 64 + (digits[1] - b'0') * 8 + (digits[2] - b'0');
        decoded.push(value);
        index += 4;
    }
    Ok(decoded)
}

pub async fn mount_sshfs_with_executable(
    runner: &SshRunner,
    executable: PathBuf,
    arguments: MountArgs,
) -> BridgeResult<serde_json::Value> {
    let host = runner.config().host(&arguments.host)?;
    let remote = RemotePath::resolve(&host.profile.root, &arguments.remote_path)?;
    let mountpoint = ValidatedMountpoint::open(&arguments.mountpoint, arguments.allow_nonempty)?;
    let timeout_ms = host.limits.connect_timeout_ms;
    let cancel = CancellationToken::new();
    let (policy, capability) = runner.prepare_host(host.alias, &cancel).await?;
    let host = runner.config().host(&arguments.host)?;
    // Keep the helper operand as the real path. libfuse resolves only its
    // parent before applying final-component checks, and fusermount3 uses
    // UMOUNT_NOFOLLOW. A reproducible compatibility probe is:
    // `exec 9<"$mountpoint"; fusermount3 -u /proc/self/fd/9`.
    // Thus a procfd is useful for our own checks but is not a portable helper
    // operand; the retained fd plus this last-moment rebind check is the
    // strongest compatible boundary.
    let argv = build_sshfs_argv(
        &policy,
        host,
        remote.absolute(),
        mountpoint.path(),
        arguments.allow_nonempty,
    )?;
    let timeout = Duration::from_millis(timeout_ms)
        .checked_add(Duration::from_secs(5))
        .ok_or_else(|| BridgeError::invalid_argument("SSHFS timeout is too large"))?;
    mountpoint.ensure_path_binding()?;
    let output = run_local_command(LocalCommandSpec {
        executable,
        arguments: argv,
        timeout,
        max_output_bytes: 64 * 1024,
    })
    .await?;
    if output.status != 0 {
        return Err(BridgeError::new(
            crate::ErrorCode::RemoteExit,
            "SSHFS exited unsuccessfully",
            false,
        ));
    }
    Ok(json!({
        "remote": true,
        "host": arguments.host,
        "configured_remote_path": remote.absolute(),
        "physical_root": capability.physical_root,
        "mountpoint": mountpoint.path(),
        "read_only": host.profile.read_only,
        "warning": "Files remain remote; this FUSE mount is not an Agent workspace. Run builds, tests, Git, and services through remote_run or this CLI run command.",
    }))
}

pub async fn unmount_sshfs_with_executable(
    executable: PathBuf,
    mountpoint: &Path,
) -> BridgeResult<serde_json::Value> {
    unmount_sshfs_with_mountinfo_reader(executable, mountpoint, || {
        read_bounded_local_file(Path::new("/proc/self/mountinfo"), 1024 * 1024)
    })
    .await
}

// Test seam for supplying mountinfo. Kept private so production callers cannot
// bypass the fresh /proc/self/mountinfo read in unmount_sshfs_with_executable.
async fn unmount_sshfs_with_mountinfo_reader<F>(
    executable: PathBuf,
    mountpoint: &Path,
    read_mountinfo: F,
) -> BridgeResult<serde_json::Value>
where
    F: FnOnce() -> BridgeResult<Vec<u8>>,
{
    let mountpoint = ValidatedMountpoint::open(mountpoint, true)?;
    let opened_mount_id = mountpoint.mount_id()?;
    let mountinfo = read_mountinfo()?;
    mountpoint.ensure_path_binding()?;
    let status = parse_sshfs_mount_status_for_id(&mountinfo, mountpoint.path(), opened_mount_id)?;
    if !status.sshfs {
        return Err(BridgeError::invalid_argument(
            "refusing to unmount a path that is not currently an SSHFS mount",
        ));
    }
    if status.mount_id != Some(opened_mount_id) {
        return Err(BridgeError::invalid_argument(
            "refusing to unmount because mount identity changed during validation",
        ));
    }
    // A same-UID process can still race after this check, but it can also call
    // fusermount3 directly. The bridge's local trust boundary is the UID; the
    // retained fd, mount ID, and rebind check prevent accidental/stale targets.
    mountpoint.ensure_path_binding()?;
    let output = run_local_command(LocalCommandSpec {
        executable,
        arguments: vec![
            OsString::from("-u"),
            mountpoint.path().as_os_str().to_owned(),
        ],
        timeout: Duration::from_secs(30),
        max_output_bytes: 64 * 1024,
    })
    .await?;
    if output.status != 0 {
        return Err(BridgeError::new(
            crate::ErrorCode::Io,
            "SSHFS unmount helper exited unsuccessfully",
            false,
        ));
    }
    Ok(json!({ "unmounted": mountpoint.path() }))
}

#[derive(Debug)]
pub struct LocalCommandSpec {
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCommandOutput {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub async fn run_local_command(spec: LocalCommandSpec) -> BridgeResult<LocalCommandOutput> {
    if !spec.executable.is_absolute() {
        return Err(BridgeError::invalid_argument(
            "local executable must be an absolute path",
        ));
    }
    if spec.timeout.is_zero() || spec.max_output_bytes == 0 {
        return Err(BridgeError::invalid_argument(
            "local command timeout and output limit must be positive",
        ));
    }
    let mut command = TokioCommand::new(&spec.executable);
    command
        .args(&spec.arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // SAFETY: pre_exec runs after fork and calls only async-signal-safe setpgid.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let mut child = command.spawn().map_err(BridgeError::io)?;
    let process_group = child
        .id()
        .ok_or_else(|| BridgeError::io("local child has no process id"))?
        as i32;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| BridgeError::io("local child stdout is missing"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| BridgeError::io("local child stderr is missing"))?;
    let total = Arc::new(AtomicUsize::new(0));
    let mut stdout_task = tokio::spawn(capture_local_stream(
        stdout,
        Arc::clone(&total),
        spec.max_output_bytes,
    ));
    let mut stderr_task = tokio::spawn(capture_local_stream(stderr, total, spec.max_output_bytes));
    let mut wait_task = tokio::spawn(async move { child.wait().await });
    let deadline = tokio::time::sleep(spec.timeout);
    tokio::pin!(deadline);
    let mut status = None;
    let mut stdout = None;
    let mut stderr = None;
    let mut wait_done = false;
    let mut stdout_done = false;
    let mut stderr_done = false;
    let stop = loop {
        tokio::select! {
            biased;
            joined = &mut wait_task, if !wait_done => {
                wait_done = true;
                match joined {
                    Ok(Ok(value)) => status = Some(value),
                    Ok(Err(error)) => break LocalStop::Error(Box::new(BridgeError::io(error))),
                    Err(error) => break LocalStop::Error(Box::new(BridgeError::io(format!("local wait task failed: {error}")))),
                }
            }
            joined = &mut stdout_task, if !stdout_done => {
                stdout_done = true;
                match joined {
                    Ok(Ok(value)) => stdout = Some(value),
                    Ok(Err(error)) => break LocalStop::Error(Box::new(error)),
                    Err(error) => break LocalStop::Error(Box::new(BridgeError::io(format!("local stdout task failed: {error}")))),
                }
            }
            joined = &mut stderr_task, if !stderr_done => {
                stderr_done = true;
                match joined {
                    Ok(Ok(value)) => stderr = Some(value),
                    Ok(Err(error)) => break LocalStop::Error(Box::new(error)),
                    Err(error) => break LocalStop::Error(Box::new(BridgeError::io(format!("local stderr task failed: {error}")))),
                }
            }
            () = &mut deadline => break LocalStop::Timeout,
        }
        if wait_done && stdout_done && stderr_done {
            break LocalStop::Completed;
        }
    };
    match stop {
        LocalStop::Completed => {}
        LocalStop::Timeout => {
            terminate_local_process_group(process_group).await;
            drain_local_tasks(
                &mut wait_task,
                &mut stdout_task,
                &mut stderr_task,
                wait_done,
                stdout_done,
                stderr_done,
            )
            .await;
            return Err(BridgeError::new(
                crate::ErrorCode::CommandTimeout,
                "local subprocess timed out",
                false,
            ));
        }
        LocalStop::Error(error) => {
            terminate_local_process_group(process_group).await;
            drain_local_tasks(
                &mut wait_task,
                &mut stdout_task,
                &mut stderr_task,
                wait_done,
                stdout_done,
                stderr_done,
            )
            .await;
            return Err(*error);
        }
    }
    Ok(LocalCommandOutput {
        status: status.expect("completed local status").code().unwrap_or(-1),
        stdout: stdout.expect("completed local stdout"),
        stderr: stderr.expect("completed local stderr"),
    })
}

enum LocalStop {
    Completed,
    Timeout,
    Error(Box<BridgeError>),
}

async fn capture_local_stream<R: AsyncRead + Unpin>(
    mut reader: R,
    total: Arc<AtomicUsize>,
    maximum: usize,
) -> BridgeResult<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 8 * 1024];
    loop {
        let count = reader.read(&mut buffer).await.map_err(BridgeError::io)?;
        if count == 0 {
            return Ok(output);
        }
        if !reserve_local_output(&total, count, maximum) {
            return Err(BridgeError::new(
                crate::ErrorCode::OutputLimit,
                "local subprocess output exceeded its limit",
                false,
            ));
        }
        output.extend_from_slice(&buffer[..count]);
    }
}

async fn drain_local_tasks(
    wait_task: &mut tokio::task::JoinHandle<std::io::Result<std::process::ExitStatus>>,
    stdout_task: &mut tokio::task::JoinHandle<BridgeResult<Vec<u8>>>,
    stderr_task: &mut tokio::task::JoinHandle<BridgeResult<Vec<u8>>>,
    wait_done: bool,
    stdout_done: bool,
    stderr_done: bool,
) {
    let drained = tokio::time::timeout(Duration::from_millis(250), async {
        if !wait_done {
            let _ = (&mut *wait_task).await;
        }
        if !stdout_done {
            let _ = (&mut *stdout_task).await;
        }
        if !stderr_done {
            let _ = (&mut *stderr_task).await;
        }
    })
    .await;
    if drained.is_err() {
        if !wait_done {
            wait_task.abort();
        }
        if !stdout_done {
            stdout_task.abort();
        }
        if !stderr_done {
            stderr_task.abort();
        }
    }
}

fn reserve_local_output(total: &AtomicUsize, count: usize, maximum: usize) -> bool {
    let mut current = total.load(Ordering::Acquire);
    loop {
        let Some(next) = current.checked_add(count) else {
            return false;
        };
        if next > maximum {
            return false;
        }
        match total.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

async fn terminate_local_process_group(process_group: i32) {
    signal_local_process_group(process_group, libc::SIGTERM);
    tokio::time::sleep(Duration::from_millis(125)).await;
    signal_local_process_group(process_group, libc::SIGKILL);
}

fn signal_local_process_group(process_group: i32, signal: i32) {
    // SAFETY: a negative pid targets only the already-created child process
    // group; kill retains no pointers and errors are intentionally best-effort.
    unsafe {
        libc::kill(-process_group, signal);
    }
}

async fn run_doctor(path: PathBuf, arguments: DoctorArgs) -> BridgeResult<()> {
    let (runner, bridge) = build_remote_bridge(&path)?;
    let mut value = match arguments.host.as_deref() {
        Some(host) => doctor_host(&bridge, host).await?,
        None => serde_json::to_value(bridge.hosts().await?)
            .map_err(|error| BridgeError::io(format!("cannot render doctor result: {error}")))?,
    };
    if arguments.verbose_ssh {
        let host = arguments.host.as_deref().ok_or_else(|| {
            BridgeError::invalid_argument("--verbose-ssh requires an explicit host alias")
        })?;
        let diagnostic = run_verbose_ssh_diagnostic(runner.config().host(host)?).await?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| BridgeError::io("doctor result is not an object"))?;
        object.insert(
            "ssh_diagnostic".to_owned(),
            serde_json::Value::String(diagnostic),
        );
    }
    print_json(&value)
}

pub fn build_verbose_ssh_diagnostic_argv(host: ResolvedHost<'_>) -> Vec<OsString> {
    let mut arguments = build_ssh_g_argv(host.alias, host.limits.connect_timeout_ms);
    arguments.insert(0, OsString::from("-vvv"));
    arguments
}

async fn run_verbose_ssh_diagnostic(host: ResolvedHost<'_>) -> BridgeResult<String> {
    let arguments = build_verbose_ssh_diagnostic_argv(host);
    let output = run_local_command(LocalCommandSpec {
        executable: PathBuf::from("/usr/bin/ssh"),
        arguments,
        timeout: Duration::from_secs(10),
        max_output_bytes: 64 * 1024,
    })
    .await?;
    if output.status != 0 {
        return Err(BridgeError::new(
            crate::ErrorCode::Io,
            "verbose SSH diagnostic exited unsuccessfully",
            false,
        ));
    }
    let mut combined = output.stdout;
    combined.push(b'\n');
    combined.extend_from_slice(&output.stderr);
    Ok(redact_ssh_diagnostics(&combined))
}

async fn run_remote_command(path: PathBuf, arguments: RunArgs) -> BridgeResult<()> {
    let (_runner, bridge) = build_remote_bridge(&path)?;
    let result = run_remote_argv(&bridge, arguments).await?;
    let value = serde_json::to_value(result)
        .map_err(|error| BridgeError::io(format!("cannot render run result: {error}")))?;
    print_json(&value)
}

fn build_remote_bridge(path: &Path) -> BridgeResult<(Arc<SshRunner>, Arc<RemoteBridge>)> {
    let config = Config::load_with_discovery(path)?;
    let spool_quota = config.limits.global_spool_quota_bytes;
    let retention_jobs = config.limits.retention_serialization_jobs;
    let runtime = RuntimePaths::discover()?;
    let store = Arc::new(OutputStore::with_limits(
        &runtime,
        spool_quota,
        retention_jobs,
    )?);
    let runner = Arc::new(SshRunner::new(Arc::new(config), runtime, store)?);
    let bridge = Arc::new(RemoteBridge::new(Arc::clone(&runner)));
    Ok((runner, bridge))
}

async fn run_mount(path: PathBuf, arguments: MountArgs) -> BridgeResult<()> {
    let (runner, _bridge) = build_remote_bridge(&path)?;
    let value =
        mount_sshfs_with_executable(&runner, PathBuf::from("/usr/bin/sshfs"), arguments).await?;
    print_json(&value)
}

fn run_mount_status(arguments: MountpointArgs) -> BridgeResult<()> {
    let bytes = read_bounded_local_file(Path::new("/proc/self/mountinfo"), 1024 * 1024)?;
    let status = parse_sshfs_mount_status(&bytes, &arguments.mountpoint)?;
    let value = serde_json::to_value(status)
        .map_err(|error| BridgeError::io(format!("cannot render mount status: {error}")))?;
    print_json(&value)
}

async fn run_unmount(arguments: MountpointArgs) -> BridgeResult<()> {
    let value =
        unmount_sshfs_with_executable(PathBuf::from("/usr/bin/fusermount3"), &arguments.mountpoint)
            .await?;
    print_json(&value)
}

async fn run_install(arguments: InstallArgs) -> BridgeResult<()> {
    debug_assert!(arguments.user, "Clap requires --user");
    let report = install_user(InstallLayout::discover()?, arguments.apply).await?;
    let value = serde_json::to_value(report)
        .map_err(|error| BridgeError::io(format!("cannot render install plan: {error}")))?;
    print_json(&value)
}

async fn run_uninstall_installation(arguments: InstallArgs) -> BridgeResult<()> {
    debug_assert!(arguments.user, "Clap requires --user");
    let report = uninstall_user(InstallLayout::discover()?, arguments.apply).await?;
    let value = serde_json::to_value(report)
        .map_err(|error| BridgeError::io(format!("cannot render uninstall plan: {error}")))?;
    print_json(&value)
}

fn read_bounded_local_file(path: &Path, maximum: u64) -> BridgeResult<Vec<u8>> {
    let file = fs::File::open(path).map_err(BridgeError::io)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(BridgeError::io)?;
    if bytes.len() as u64 > maximum {
        return Err(BridgeError::new(
            crate::ErrorCode::OutputLimit,
            "local status file exceeded its limit",
            false,
        ));
    }
    Ok(bytes)
}

fn config_path() -> BridgeResult<PathBuf> {
    if let Some(path) = std::env::var_os("CODEX_SSH_BRIDGE_CONFIG") {
        if path.is_empty() {
            return Err(BridgeError::invalid_config(
                "CODEX_SSH_BRIDGE_CONFIG cannot be empty",
            ));
        }
        return Ok(PathBuf::from(path));
    }
    Config::default_path()
}

fn run_hosts(path: PathBuf, arguments: HostsArgs) -> BridgeResult<()> {
    match arguments.command {
        HostsCommand::Add(arguments) => add_host(&path, arguments),
        HostsCommand::Remove(arguments) => remove_host(&path, &arguments.alias),
        HostsCommand::List => {
            let config = Config::load_with_discovery(&path)?;
            let hosts: Vec<_> = config
                .hosts
                .iter()
                .map(|(alias, profile)| host_json(alias, profile))
                .collect();
            print_json(&json!({ "hosts": hosts }))
        }
        HostsCommand::Show(arguments) => {
            let config = Config::load_with_discovery(&path)?;
            let host = config.host(&arguments.alias)?;
            print_json(&host_json(host.alias, host.profile))
        }
    }
}

fn add_host(path: &Path, arguments: AddHostArgs) -> BridgeResult<()> {
    let mut config = load_for_add(path)?;
    if config.hosts.contains_key(&arguments.alias) {
        return Err(BridgeError::invalid_argument("host alias already exists"));
    }
    config.hosts.insert(
        arguments.alias.clone(),
        HostProfile {
            root: arguments.root,
            description: arguments.description,
            read_only: arguments.read_only,
            limits: HostLimitOverrides::default(),
        },
    );
    ensure_config_parent(path)?;
    config.save_atomic(path)?;
    let profile = config
        .hosts
        .get(&arguments.alias)
        .expect("inserted host profile");
    print_json(&host_json(&arguments.alias, profile))
}

fn remove_host(path: &Path, alias: &str) -> BridgeResult<()> {
    let mut config = Config::load(path)?;
    let profile = config
        .hosts
        .remove(alias)
        .ok_or_else(|| BridgeError::invalid_argument("host alias is not configured"))?;
    config.save_atomic(path)?;
    print_json(&json!({ "removed": host_json(alias, &profile) }))
}

fn load_for_add(path: &Path) -> BridgeResult<Config> {
    match fs::symlink_metadata(path) {
        Ok(_) => Config::load(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(error) => Err(BridgeError::io(error)),
    }
}

fn ensure_config_parent(path: &Path) -> BridgeResult<()> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    if !parent.is_absolute() {
        return Err(BridgeError::invalid_config(
            "configuration parent must be an absolute local path",
        ));
    }
    #[cfg(unix)]
    ensure_secure_absolute_directory(parent)?;
    #[cfg(not(unix))]
    fs::create_dir_all(parent).map_err(BridgeError::io)?;
    Ok(())
}

#[cfg(unix)]
pub(super) fn ensure_secure_absolute_directory(path: &Path) -> BridgeResult<Vec<PathBuf>> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    use std::path::Component;

    // SAFETY: credential getters have no preconditions and retain no pointers.
    let current_uid = unsafe { libc::geteuid() };
    let root_uid = fs::symlink_metadata("/").map_err(BridgeError::io)?.uid();
    let mut resolved = PathBuf::from("/");
    let mut created = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => continue,
            Component::CurDir => continue,
            Component::Normal(name) => resolved.push(name),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(BridgeError::invalid_config(
                    "configuration parent must be a normalized absolute path",
                ));
            }
        }
        let metadata = match fs::symlink_metadata(&resolved) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700);
                match builder.create(&resolved) {
                    Ok(()) => created.push(resolved.clone()),
                    Err(create_error)
                        if create_error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(create_error) => return Err(BridgeError::io(create_error)),
                }
                fs::symlink_metadata(&resolved).map_err(BridgeError::io)?
            }
            Err(error) => return Err(BridgeError::io(error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(BridgeError::invalid_config(
                "configuration path ancestors must be real directories",
            ));
        }
        if metadata.uid() != root_uid && metadata.uid() != current_uid {
            return Err(BridgeError::invalid_config(
                "configuration path ancestors must be owned by root or the current user",
            ));
        }
        let writable = metadata.mode() & 0o022 != 0;
        let trusted_tmp = resolved == Path::new("/tmp")
            && metadata.uid() == root_uid
            && metadata.mode() & 0o1000 != 0;
        if writable && !trusted_tmp {
            return Err(BridgeError::invalid_config(
                "configuration path ancestors must not be writable by group or other users",
            ));
        }
    }
    Ok(created)
}

fn host_json(alias: &str, profile: &HostProfile) -> serde_json::Value {
    json!({
        "remote": true,
        "host": alias,
        "configured_root": profile.root,
        "description": profile.description,
        "read_only": profile.read_only,
        "limits": profile.limits,
    })
}

fn print_json(value: &serde_json::Value) -> BridgeResult<()> {
    let rendered = serde_json::to_string_pretty(value)
        .map_err(|error| BridgeError::io(format!("cannot render CLI output: {error}")))?;
    println!("{rendered}");
    Ok(())
}

#[cfg(test)]
mod sshfs_identity_tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn executable_script(directory: &Path, name: &str, source: &str) -> PathBuf {
        let path = directory.join(name);
        fs::write(&path, source).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn mountinfo(mountpoint: &Path, mount_id: u64, filesystem: &str) -> Vec<u8> {
        format!(
            "{mount_id} 25 0:32 / {} rw,nosuid - {filesystem} dev:/srv rw\n",
            mountpoint.display()
        )
        .into_bytes()
    }

    fn mount_id(mountpoint: &Path) -> u64 {
        ValidatedMountpoint::open(mountpoint, true)
            .unwrap()
            .mount_id()
            .unwrap()
    }

    #[tokio::test]
    async fn unmount_uses_fresh_mountinfo_and_the_revalidated_real_path() {
        let private = tempfile::TempDir::new().unwrap();
        let mountpoint = private.path().join("mountpoint");
        let log = private.path().join("unmount.log");
        fs::create_dir(&mountpoint).unwrap();
        let source = format!("#!/bin/sh\nprintf '%s\\n' \"$@\" >'{}'\n", log.display());
        let helper = executable_script(private.path(), "fusermount3", &source);
        let current_mount_id = mount_id(&mountpoint);
        let bytes = mountinfo(&mountpoint, current_mount_id, "fuse.sshfs");

        let result = unmount_sshfs_with_mountinfo_reader(helper.clone(), &mountpoint, || Ok(bytes))
            .await
            .unwrap();

        assert_eq!(result["unmounted"], mountpoint.to_str().unwrap());
        let logged = fs::read_to_string(&log).unwrap();
        assert_eq!(
            logged.lines().collect::<Vec<_>>(),
            ["-u", mountpoint.to_str().unwrap()]
        );

        fs::remove_file(&log).unwrap();
        let other = mountinfo(&mountpoint, current_mount_id, "fuse.other");
        assert!(
            unmount_sshfs_with_mountinfo_reader(helper, &mountpoint, || Ok(other))
                .await
                .is_err()
        );
        assert!(!log.exists());
    }

    #[tokio::test]
    async fn unmount_rejects_a_path_replaced_while_fresh_mountinfo_is_read() {
        let private = tempfile::TempDir::new().unwrap();
        let mountpoint = private.path().join("mountpoint");
        let moved = private.path().join("validated-directory");
        let helper_log = private.path().join("helper.log");
        fs::create_dir(&mountpoint).unwrap();
        let current_mount_id = mount_id(&mountpoint);
        let bytes = mountinfo(&mountpoint, current_mount_id, "fuse.sshfs");
        let source = format!("#!/bin/sh\nprintf called >'{}'\n", helper_log.display());
        let helper = executable_script(private.path(), "fusermount3-swap", &source);

        let result = unmount_sshfs_with_mountinfo_reader(helper, &mountpoint, || {
            fs::rename(&mountpoint, &moved).unwrap();
            fs::create_dir(&mountpoint).unwrap();
            Ok(bytes)
        })
        .await;

        assert!(result.is_err());
        assert!(!helper_log.exists());
    }

    #[tokio::test]
    async fn unmount_rejects_mountinfo_for_a_different_mount_id() {
        let private = tempfile::TempDir::new().unwrap();
        let mountpoint = private.path().join("mountpoint");
        let helper_log = private.path().join("helper.log");
        fs::create_dir(&mountpoint).unwrap();
        let different_mount_id = mount_id(&mountpoint).checked_add(1).unwrap();
        let bytes = mountinfo(&mountpoint, different_mount_id, "fuse.sshfs");
        let source = format!("#!/bin/sh\nprintf called >'{}'\n", helper_log.display());
        let helper = executable_script(private.path(), "fusermount3-wrong-mount", &source);

        let result = unmount_sshfs_with_mountinfo_reader(helper, &mountpoint, || Ok(bytes)).await;

        assert!(result.is_err());
        assert!(!helper_log.exists());
    }

    #[test]
    fn stacked_mountinfo_selects_the_record_for_the_opened_mount_id() {
        let mountpoint = Path::new("/mnt/stacked");
        let bytes = b"40 25 0:31 / /mnt/stacked rw - fuse.other old rw\n\
                      41 25 0:32 / /mnt/stacked rw - fuse.sshfs current rw\n";

        let status = parse_sshfs_mount_status_for_id(bytes, mountpoint, 41).unwrap();

        assert!(status.sshfs);
        assert_eq!(status.mount_id, Some(41));
    }
}
