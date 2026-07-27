#![cfg(unix)]

use std::collections::BTreeMap;
use std::ffi::{CStr, OsString};
use std::fs;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use codex_ssh_bridge::config::{Config, HostLimitOverrides, HostProfile};
use codex_ssh_bridge::output::OutputStore;
use codex_ssh_bridge::remote::{
    ApplyPatchRequest, EncodedValue, ListRequest, ReadEntry, ReadRequest, RemoteBridge,
    RemoteFileKind, RemoteRunRequest, RunShell, SearchRequest, ShellName, StatEntry, StatRequest,
    ValueEncoding, WriteEncoding, WriteMode, WriteOperation, WriteRequest,
};
use codex_ssh_bridge::ssh::{RuntimePaths, SshRunner};
use codex_ssh_bridge::{ErrorCode, quote};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

const BASH_HOST: &str = "real-bash";
const SH_ONLY_HOST: &str = "real-sh-only";
const WRONG_KEY_HOST: &str = "real-wrong-key";

struct RealSshFixture {
    _tree: TempDir,
    root: PathBuf,
    client_config: PathBuf,
    ssh_wrapper: PathBuf,
    daemon: Option<Child>,
    daemon_pid: u32,
}

fn fixture_or_skip<T>(setup: Result<T, String>, required: bool) -> Option<T> {
    match setup {
        Ok(fixture) => Some(fixture),
        Err(reason) if required => {
            panic!("required real SSH integration unavailable: {reason}")
        }
        Err(_) => None,
    }
}

#[test]
fn required_mode_skips_unavailable_setup_only_when_not_required() {
    let reason = "fixture bind was denied";
    assert_eq!(fixture_or_skip::<()>(Err(reason.to_owned()), false), None);
}

#[test]
#[should_panic(expected = "required real SSH integration unavailable: fixture bind was denied")]
fn required_mode_panics_with_original_setup_reason_when_required() {
    let _ = fixture_or_skip::<()>(Err("fixture bind was denied".to_owned()), true);
}

impl RealSshFixture {
    fn start() -> Result<Self, String> {
        for executable in ["/usr/sbin/sshd", "/usr/bin/ssh", "/usr/bin/ssh-keygen"] {
            if !Path::new(executable).is_file() {
                return Err(format!("required executable is unavailable: {executable}"));
            }
        }
        if !Path::new("/run/sshd").is_dir() {
            return Err("sshd privilege-separation directory /run/sshd is unavailable".to_owned());
        }

        let tree = tempfile::Builder::new()
            .prefix("codex-real-ssh-")
            .tempdir()
            .map_err(|error| format!("cannot create fixture directory: {error}"))?;
        set_mode(tree.path(), 0o700)?;
        let root = tree.path().join("remote-root");
        fs::create_dir(&root).map_err(display_io("cannot create remote root"))?;
        set_mode(&root, 0o700)?;
        fs::create_dir(root.join("cwd space'quote"))
            .map_err(display_io("cannot create quoting fixture directory"))?;
        fs::write(root.join("seed.txt"), b"alpha needle omega\nsecond line\n")
            .map_err(display_io("cannot write seed file"))?;

        let host_key = tree.path().join("host_ed25519");
        let wrong_host_key = tree.path().join("wrong_host_ed25519");
        let client_key = tree.path().join("client_ed25519");
        generate_ed25519_key(&host_key)?;
        generate_ed25519_key(&wrong_host_key)?;
        generate_ed25519_key(&client_key)?;

        let authorized_keys = tree.path().join("authorized_keys");
        fs::copy(client_key.with_extension("pub"), &authorized_keys)
            .map_err(display_io("cannot create authorized_keys"))?;
        set_mode(&authorized_keys, 0o600)?;

        let no_bash_bin = tree.path().join("no-bash-bin");
        fs::create_dir(&no_bash_bin).map_err(display_io("cannot create no-Bash PATH"))?;
        populate_path_without_bash(&no_bash_bin)?;

        let dispatcher = tree.path().join("forced-command.sh");
        fs::write(
            &dispatcher,
            format!(
                "#!/bin/sh\nset -eu\nif [ \"${{CODEX_TEST_NO_BASH:-0}}\" = 1 ]; then\n    PATH={}\n    export PATH\nfi\nexec /bin/sh -c \"${{SSH_ORIGINAL_COMMAND:?missing SSH_ORIGINAL_COMMAND}}\"\n",
                quote::shell_word(
                    no_bash_bin
                        .to_str()
                        .ok_or_else(|| "fixture path is not UTF-8".to_owned())?
                )
                .map_err(|error| format!("cannot quote no-Bash PATH: {error:?}"))?,
            ),
        )
        .map_err(display_io("cannot write forced-command dispatcher"))?;
        set_mode(&dispatcher, 0o700)?;

        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .map_err(|error| format!("cannot reserve a localhost port: {error}"))?;
        let port = listener
            .local_addr()
            .map_err(|error| format!("cannot inspect reserved localhost port: {error}"))?
            .port();
        if port < 1024 {
            return Err(format!(
                "OS selected an unexpectedly privileged port: {port}"
            ));
        }
        drop(listener);

        let username = current_username()?;
        let pid_file = tree.path().join("sshd.pid");
        let daemon_config = tree.path().join("sshd_config");
        fs::write(
            &daemon_config,
            format!(
                concat!(
                    "Port {port}\n",
                    "ListenAddress 127.0.0.1\n",
                    "AddressFamily inet\n",
                    "HostKey {host_key}\n",
                    "PidFile {pid_file}\n",
                    "AuthorizedKeysFile {authorized_keys}\n",
                    "StrictModes no\n",
                    "PubkeyAuthentication yes\n",
                    "AuthenticationMethods publickey\n",
                    "PasswordAuthentication no\n",
                    "KbdInteractiveAuthentication no\n",
                    "UsePAM no\n",
                    "PermitRootLogin no\n",
                    "AllowUsers {username}\n",
                    "AllowAgentForwarding no\n",
                    "AllowTcpForwarding no\n",
                    "X11Forwarding no\n",
                    "PermitTunnel no\n",
                    "PermitTTY no\n",
                    "GatewayPorts no\n",
                    "PermitUserEnvironment no\n",
                    "AcceptEnv CODEX_TEST_NO_BASH\n",
                    "ForceCommand {dispatcher}\n",
                    "UseDNS no\n",
                    "PrintMotd no\n",
                    "LogLevel VERBOSE\n",
                    "LoginGraceTime 5\n",
                    "MaxAuthTries 2\n",
                    "MaxSessions 16\n",
                ),
                port = port,
                host_key = config_path(&host_key)?,
                pid_file = config_path(&pid_file)?,
                authorized_keys = config_path(&authorized_keys)?,
                username = username,
                dispatcher = config_path(&dispatcher)?,
            ),
        )
        .map_err(display_io("cannot write sshd configuration"))?;
        set_mode(&daemon_config, 0o600)?;

        let known_hosts = tree.path().join("known_hosts");
        let wrong_known_hosts = tree.path().join("wrong_known_hosts");
        write_known_hosts(&known_hosts, port, &host_key.with_extension("pub"))?;
        write_known_hosts(
            &wrong_known_hosts,
            port,
            &wrong_host_key.with_extension("pub"),
        )?;

        let client_config = tree.path().join("ssh_config");
        fs::write(
            &client_config,
            format!(
                concat!(
                    "Host {bash_host}\n",
                    "    UserKnownHostsFile {known_hosts}\n",
                    "    SetEnv CODEX_TEST_NO_BASH=0\n",
                    "Host {sh_host}\n",
                    "    UserKnownHostsFile {known_hosts}\n",
                    "    SetEnv CODEX_TEST_NO_BASH=1\n",
                    "Host {wrong_host}\n",
                    "    UserKnownHostsFile {wrong_known_hosts}\n",
                    "    SetEnv CODEX_TEST_NO_BASH=0\n",
                    "Host *\n",
                    "    HostName 127.0.0.1\n",
                    "    Port {port}\n",
                    "    User {username}\n",
                    "    IdentityFile {client_key}\n",
                    "    IdentitiesOnly yes\n",
                    "    GlobalKnownHostsFile /dev/null\n",
                    "    PasswordAuthentication no\n",
                    "    KbdInteractiveAuthentication no\n",
                    "    PreferredAuthentications publickey\n",
                    "    CanonicalizeHostname no\n",
                    "    ConnectionAttempts 1\n",
                    "    ConnectTimeout 3\n",
                    "    LogLevel ERROR\n",
                ),
                bash_host = BASH_HOST,
                sh_host = SH_ONLY_HOST,
                wrong_host = WRONG_KEY_HOST,
                known_hosts = config_path(&known_hosts)?,
                wrong_known_hosts = config_path(&wrong_known_hosts)?,
                port = port,
                username = username,
                client_key = config_path(&client_key)?,
            ),
        )
        .map_err(display_io("cannot write SSH client configuration"))?;
        set_mode(&client_config, 0o600)?;

        let ssh_wrapper = tree.path().join("ssh-with-fixture-config");
        fs::write(
            &ssh_wrapper,
            format!(
                "#!/bin/sh\nexec /usr/bin/ssh -F {} \"$@\"\n",
                quote::shell_word(config_path(&client_config)?)
                    .map_err(|error| format!("cannot quote client configuration: {error:?}"))?,
            ),
        )
        .map_err(display_io("cannot write SSH wrapper"))?;
        set_mode(&ssh_wrapper, 0o700)?;

        validate_sshd_config(&daemon_config)?;
        let log = tree.path().join("sshd.log");
        let mut command = Command::new("/usr/sbin/sshd");
        command
            .args(["-D", "-e", "-f"])
            .arg(&daemon_config)
            .arg("-E")
            .arg(&log)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: the child-side closure only invokes async-signal-safe setpgid.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            });
        }
        let mut daemon = command
            .spawn()
            .map_err(|error| format!("cannot start unprivileged sshd: {error}"))?;
        let daemon_pid = daemon.id();
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        let ready_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = daemon
                .try_wait()
                .map_err(|error| format!("cannot poll sshd: {error}"))?
            {
                return Err(format!(
                    "unprivileged sshd exited during startup ({status}): {}",
                    read_diagnostic(&log)
                ));
            }
            if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
                break;
            }
            if Instant::now() >= ready_deadline {
                terminate_process_group(&mut daemon, daemon_pid);
                return Err(format!(
                    "unprivileged sshd did not listen within 5 seconds: {}",
                    read_diagnostic(&log)
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        let mut fixture = Self {
            _tree: tree,
            root,
            client_config,
            ssh_wrapper,
            daemon: Some(daemon),
            daemon_pid,
        };
        if let Err(error) = fixture.probe_login() {
            fixture.stop_daemon();
            return Err(format!(
                "localhost public-key login is unavailable: {error}; sshd log: {}",
                read_diagnostic(&log)
            ));
        }
        Ok(fixture)
    }

    fn probe_login(&self) -> Result<(), String> {
        let output = Command::new("/usr/bin/ssh")
            .arg("-F")
            .arg(&self.client_config)
            .args([
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ControlMaster=no",
                "--",
                BASH_HOST,
                "true",
            ])
            .output()
            .map_err(|error| format!("cannot execute SSH login probe: {error}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "SSH login probe exited {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }

    fn bridge(&self) -> Result<(TempDir, RuntimePaths, Arc<SshRunner>, RemoteBridge), String> {
        let mut config = Config::default();
        config.limits.connect_timeout_ms = 5_000;
        config.limits.command_timeout_ms = 15_000;
        for alias in [BASH_HOST, SH_ONLY_HOST, WRONG_KEY_HOST] {
            config.hosts.insert(
                alias.to_owned(),
                HostProfile {
                    root: config_path(&self.root)?.to_owned(),
                    description: None,
                    read_only: false,
                    limits: HostLimitOverrides::default(),
                },
            );
        }
        let runtime_base = tempfile::Builder::new()
            .prefix("codex-real-ssh-runtime-")
            .tempdir()
            .map_err(|error| format!("cannot create runtime base: {error}"))?;
        set_mode(runtime_base.path(), 0o700)?;
        let runtime = RuntimePaths::ensure_from_base(runtime_base.path())
            .map_err(|error| format!("cannot create bridge runtime: {error:?}"))?;
        let store = Arc::new(
            OutputStore::new(&runtime)
                .map_err(|error| format!("cannot create output store: {error:?}"))?,
        );
        let runner = Arc::new(
            SshRunner::with_executable(
                Arc::new(config),
                runtime.clone(),
                store,
                self.ssh_wrapper.clone(),
                BTreeMap::<OsString, OsString>::new(),
            )
            .map_err(|error| format!("cannot create SSH runner: {error:?}"))?,
        );
        let bridge = RemoteBridge::new(Arc::clone(&runner));
        Ok((runtime_base, runtime, runner, bridge))
    }

    fn close_control_masters(&self, runtime: &RuntimePaths) -> Result<(), String> {
        let sockets = control_sockets(runtime)?;
        for socket in &sockets {
            let mut closed = false;
            for alias in [BASH_HOST, SH_ONLY_HOST, WRONG_KEY_HOST] {
                let status = Command::new("/usr/bin/ssh")
                    .arg("-F")
                    .arg(&self.client_config)
                    .arg("-S")
                    .arg(socket)
                    .args(["-O", "exit", "--", alias])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map_err(|error| format!("cannot stop ControlMaster: {error}"))?;
                if status.success() {
                    closed = true;
                    break;
                }
            }
            if !closed {
                return Err(format!(
                    "no localhost alias could close ControlMaster {}",
                    socket.display()
                ));
            }
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while !control_sockets(runtime)?.is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let remaining = control_sockets(runtime)?;
        if remaining.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "ControlMaster sockets survived cleanup: {remaining:?}"
            ))
        }
    }

    fn stop_daemon(&mut self) {
        if let Some(mut daemon) = self.daemon.take() {
            terminate_process_group(&mut daemon, self.daemon_pid);
        }
    }

    fn shutdown(mut self) -> Result<(), String> {
        self.stop_daemon();
        if process_exists(self.daemon_pid) || process_group_exists(self.daemon_pid) {
            Err(format!(
                "sshd process group {} survived fixture cleanup",
                self.daemon_pid
            ))
        } else {
            Ok(())
        }
    }
}

impl Drop for RealSshFixture {
    fn drop(&mut self) {
        self.stop_daemon();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_localhost_sshd_covers_transport_shell_files_mutation_and_cancellation() {
    let required = std::env::var("CODEX_SSH_BRIDGE_REQUIRE_REAL_SSH").as_deref() == Ok("1");
    let setup = RealSshFixture::start();
    if !required && let Err(reason) = &setup {
        eprintln!("SKIP real SSH integration: {reason}");
    }
    let fixture = match fixture_or_skip(setup, required) {
        Some(fixture) => fixture,
        None => return,
    };
    let (runtime_base, runtime, runner, bridge) = fixture.bridge().expect("build real SSH bridge");
    let root = config_path(&fixture.root).unwrap().to_owned();
    let seed_path = format!("{root}/seed.txt");
    let generated_path = format!("{root}/generated.txt");

    let direct_wrong_key = Command::new("/usr/bin/ssh")
        .arg("-F")
        .arg(&fixture.client_config)
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ControlMaster=no",
            "--",
            WRONG_KEY_HOST,
            "true",
        ])
        .output()
        .expect("run direct wrong-key control probe");
    assert_eq!(direct_wrong_key.status.code(), Some(255));
    let wrong_key_diagnostic = String::from_utf8_lossy(&direct_wrong_key.stderr);
    assert!(
        wrong_key_diagnostic.contains("Host key verification failed")
            || wrong_key_diagnostic.contains("REMOTE HOST IDENTIFICATION HAS CHANGED"),
        "unexpected wrong-key diagnostic: {wrong_key_diagnostic}"
    );
    let host_key_error = bridge
        .stat(
            StatRequest {
                host: WRONG_KEY_HOST.to_owned(),
                paths: vec![seed_path.clone()],
            },
            CancellationToken::new(),
        )
        .await
        .expect_err("changed host key must be rejected");
    assert_eq!(host_key_error.code, ErrorCode::HostKeyUnknown);
    assert_eq!(host_key_error.details.exit_status, Some(255));
    assert!(control_sockets(&runtime).unwrap().is_empty());

    let listed = bridge
        .list(
            ListRequest {
                host: BASH_HOST.to_owned(),
                path: Some(root.clone()),
                depth: Some(2),
                include_hidden: Some(false),
                max_entries: Some(100),
            },
            CancellationToken::new(),
        )
        .await
        .expect("list through real sshd");
    assert!(listed.entries.iter().any(|entry| {
        utf8(&entry.relative_path) == "seed.txt" && entry.metadata.kind == RemoteFileKind::File
    }));
    let sockets = control_sockets(&runtime).unwrap();
    assert_eq!(sockets.len(), 1, "one host must create one ControlMaster");
    let master_inode = fs::metadata(&sockets[0]).unwrap().ino();

    let stated = bridge
        .stat(
            StatRequest {
                host: BASH_HOST.to_owned(),
                paths: vec![seed_path.clone()],
            },
            CancellationToken::new(),
        )
        .await
        .expect("stat through reused ControlMaster");
    assert!(matches!(
        &stated.entries[0],
        StatEntry::Success { metadata, .. } if metadata.kind == RemoteFileKind::File
    ));
    let reused = control_sockets(&runtime).unwrap();
    assert_eq!(reused.len(), 1);
    assert_eq!(fs::metadata(&reused[0]).unwrap().ino(), master_inode);

    let read = bridge
        .read(
            ReadRequest {
                host: BASH_HOST.to_owned(),
                paths: vec![seed_path.clone()],
                start_line: Some(1),
                max_lines: Some(10),
                max_bytes: Some(4096),
            },
            CancellationToken::new(),
        )
        .await
        .expect("read through real sshd");
    assert!(matches!(
        &read.files[0],
        ReadEntry::Success { content, .. }
            if utf8(content) == "alpha needle omega\nsecond line\n"
    ));

    let search = bridge
        .search(
            SearchRequest {
                host: BASH_HOST.to_owned(),
                query: "needle".to_owned(),
                path: Some(root.clone()),
                globs: vec!["*.txt".to_owned()],
                max_results: Some(10),
                binary: Some(false),
            },
            CancellationToken::new(),
        )
        .await
        .expect("search through real sshd");
    assert_eq!(search.matches.len(), 1);
    assert_eq!(utf8(&search.matches[0].relative_path), "seed.txt");
    assert_eq!(search.matches[0].line, 1);

    let bash = bridge
        .run(
            RemoteRunRequest {
                host: BASH_HOST.to_owned(),
                command: "printf '%s' \"$BASH_VERSION\"".to_owned(),
                cwd: Some(root.clone()),
                shell: RunShell::Bash,
                timeout_ms: Some(2_000),
                stdin: None,
            },
            CancellationToken::new(),
        )
        .await
        .expect("explicit Bash through real sshd");
    assert_eq!(bash.context.shell.kind, ShellName::Bash);
    assert!(!bash.context.shell.fallback);
    assert_eq!(
        bash.context.shell.version.as_deref(),
        Some(utf8(&bash.stdout.head))
    );

    let quoted = bridge
        .run(
            RemoteRunRequest {
                host: BASH_HOST.to_owned(),
                command:
                    "printf '<%s>\\n' \"space value\" \"single'quote\" 'dollar $HOME' 'semi;colon'"
                        .to_owned(),
                cwd: Some(format!("{root}/cwd space'quote")),
                shell: RunShell::Sh,
                timeout_ms: Some(2_000),
                stdin: None,
            },
            CancellationToken::new(),
        )
        .await
        .expect("raw command quoting through real sshd");
    assert_eq!(quoted.context.shell.kind, ShellName::Sh);
    assert!(!quoted.context.shell.fallback);
    assert_eq!(
        utf8(&quoted.stdout.head),
        "<space value>\n<single'quote>\n<dollar $HOME>\n<semi;colon>\n"
    );

    let explicit_sh = bridge
        .run(
            RemoteRunRequest {
                host: SH_ONLY_HOST.to_owned(),
                command: "printf sh".to_owned(),
                cwd: Some(root.clone()),
                shell: RunShell::Sh,
                timeout_ms: Some(2_000),
                stdin: None,
            },
            CancellationToken::new(),
        )
        .await
        .expect("explicit sh on no-Bash fixture");
    assert_eq!(explicit_sh.context.shell.kind, ShellName::Sh);
    assert!(!explicit_sh.context.shell.fallback);
    assert_eq!(utf8(&explicit_sh.stdout.head), "sh");
    let bash_error = bridge
        .run(
            RemoteRunRequest {
                host: SH_ONLY_HOST.to_owned(),
                command: "printf bash".to_owned(),
                cwd: Some(root.clone()),
                shell: RunShell::Bash,
                timeout_ms: Some(2_000),
                stdin: None,
            },
            CancellationToken::new(),
        )
        .await
        .expect_err("Bash request must fail on no-Bash fixture");
    assert_eq!(bash_error.code, ErrorCode::RemoteCapabilityMissing);

    let write = bridge
        .write(
            WriteRequest {
                host: BASH_HOST.to_owned(),
                path: generated_path.clone(),
                content: "old\n".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .expect("safe write through real sshd");
    assert_eq!(write.operation, WriteOperation::Create);
    assert!(
        !fixture.root.join("generated.txt").exists(),
        "successful write must remain buffered before a barrier"
    );
    let cached_write = bridge
        .read(
            ReadRequest {
                host: BASH_HOST.to_owned(),
                paths: vec![generated_path.clone()],
                start_line: Some(1),
                max_lines: Some(10),
                max_bytes: Some(4096),
            },
            CancellationToken::new(),
        )
        .await
        .expect("read buffered create through real sshd");
    assert!(matches!(
        &cached_write.files[0],
        ReadEntry::Success { content, .. } if utf8(content) == "old\n"
    ));
    let patch = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: BASH_HOST.to_owned(),
                patch: format!(
                    "--- a/{generated_path}\n+++ b/{generated_path}\n@@ -1 +1 @@\n-old\n+new\n"
                ),
            },
            CancellationToken::new(),
        )
        .await
        .expect("patch through real sshd");
    assert_eq!(
        patch.changed_paths.as_slice(),
        std::slice::from_ref(&generated_path)
    );
    let cached_patch = bridge
        .read(
            ReadRequest {
                host: BASH_HOST.to_owned(),
                paths: vec![generated_path.clone()],
                start_line: Some(1),
                max_lines: Some(10),
                max_bytes: Some(4096),
            },
            CancellationToken::new(),
        )
        .await
        .expect("read buffered patch through real sshd");
    assert!(matches!(
        &cached_patch.files[0],
        ReadEntry::Success { content, .. } if utf8(content) == "new\n"
    ));
    assert!(!fixture.root.join("generated.txt").exists());
    bridge
        .run(
            RemoteRunRequest {
                host: BASH_HOST.to_owned(),
                command: ":".to_owned(),
                cwd: Some(root.clone()),
                shell: RunShell::Sh,
                timeout_ms: Some(2_000),
                stdin: None,
            },
            CancellationToken::new(),
        )
        .await
        .expect("command barrier must synchronize buffered real-SSH edits");
    assert_eq!(
        fs::read(fixture.root.join("generated.txt")).unwrap(),
        b"new\n"
    );

    let timeout_started = Instant::now();
    let timeout_error = bridge
        .run(
            RemoteRunRequest {
                host: BASH_HOST.to_owned(),
                command: "printf '%s' \"$$\" > timeout.pid; exec sleep 10".to_owned(),
                cwd: Some(root.clone()),
                shell: RunShell::Sh,
                timeout_ms: Some(100),
                stdin: None,
            },
            CancellationToken::new(),
        )
        .await
        .expect_err("remote timeout must stop the command");
    assert_eq!(timeout_error.code, ErrorCode::CommandTimeout);
    assert!(timeout_started.elapsed() < Duration::from_secs(2));
    let timeout_pid = read_pid(&fixture.root.join("timeout.pid"));
    wait_process_absent(timeout_pid, Duration::from_secs(2))
        .expect("timed-out remote process survived");

    let cancelled_remote_pid;
    {
        let cancel = CancellationToken::new();
        let cancel_for_task = cancel.clone();
        let cancel_future = bridge.run(
            RemoteRunRequest {
                host: BASH_HOST.to_owned(),
                command: concat!(
                    "child=\n",
                    "cleanup() { [ -z \"$child\" ] || kill \"$child\" 2>/dev/null || :; exit 0; }\n",
                    "trap cleanup HUP TERM INT\n",
                    "printf '%s' \"$$\" > cancel.pid\n",
                    "while :; do sleep 1 & child=$!; wait \"$child\" || :; child=; done",
                )
                .to_owned(),
                cwd: Some(root.clone()),
                shell: RunShell::Sh,
                timeout_ms: Some(10_000),
                stdin: None,
            },
            cancel_for_task,
        );
        tokio::pin!(cancel_future);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                tokio::select! {
                    result = &mut cancel_future => panic!("cancellable command ended early: {result:?}"),
                    () = tokio::time::sleep(Duration::from_millis(10)) => {
                        if fixture.root.join("cancel.pid").exists() {
                            break;
                        }
                    }
                }
            }
        })
        .await
        .expect("remote cancellable command did not start");
        cancelled_remote_pid = read_owned_process(&fixture.root.join("cancel.pid"));
        let cancel_started = Instant::now();
        cancel.cancel();
        let cancel_error = tokio::time::timeout(Duration::from_secs(2), &mut cancel_future)
            .await
            .expect("cancelled SSH operation did not return")
            .expect_err("cancelled SSH operation unexpectedly succeeded");
        assert_eq!(cancel_error.code, ErrorCode::Cancelled);
        assert_eq!(
            cancel_error.details.remote_process_may_continue,
            Some(false)
        );
        assert!(!same_process_exists(cancelled_remote_pid));
        assert!(cancel_started.elapsed() < Duration::from_millis(500));
    }

    drop(bridge);
    drop(runner);
    fixture
        .close_control_masters(&runtime)
        .expect("close all ControlMaster processes");
    terminate_owned_process(cancelled_remote_pid)
        .expect("clean up the truthfully reported possibly-running remote process");
    drop(runtime);
    drop(runtime_base);
    fixture.shutdown().expect("stop isolated sshd");
    assert!(!same_process_exists(cancelled_remote_pid));
}

fn utf8(value: &EncodedValue) -> &str {
    assert_eq!(value.encoding, ValueEncoding::Utf8);
    &value.value
}

fn generate_ed25519_key(path: &Path) -> Result<(), String> {
    let output = Command::new("/usr/bin/ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(path)
        .output()
        .map_err(|error| format!("cannot execute ssh-keygen: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "ssh-keygen exited {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn populate_path_without_bash(destination: &Path) -> Result<(), String> {
    for entry in fs::read_dir("/usr/bin").map_err(display_io("cannot inspect /usr/bin"))? {
        let entry = entry.map_err(display_io("cannot inspect /usr/bin entry"))?;
        if entry.file_name() == "bash" {
            continue;
        }
        symlink(entry.path(), destination.join(entry.file_name()))
            .map_err(display_io("cannot populate no-Bash PATH"))?;
    }
    if !destination.join("sh").exists() {
        symlink("/bin/sh", destination.join("sh"))
            .map_err(display_io("cannot add POSIX sh to no-Bash PATH"))?;
    }
    Ok(())
}

fn write_known_hosts(path: &Path, port: u16, public_key: &Path) -> Result<(), String> {
    let line = fs::read_to_string(public_key).map_err(display_io("cannot read host public key"))?;
    let mut fields = line.split_whitespace();
    let key_type = fields
        .next()
        .ok_or_else(|| "host public key has no type".to_owned())?;
    let key = fields
        .next()
        .ok_or_else(|| "host public key has no body".to_owned())?;
    fs::write(path, format!("[127.0.0.1]:{port} {key_type} {key}\n"))
        .map_err(display_io("cannot write known_hosts"))?;
    set_mode(path, 0o600)
}

fn validate_sshd_config(path: &Path) -> Result<(), String> {
    let output = Command::new("/usr/sbin/sshd")
        .args(["-t", "-f"])
        .arg(path)
        .output()
        .map_err(|error| format!("cannot validate sshd configuration: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "sshd rejected fixture configuration: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn current_username() -> Result<String, String> {
    // SAFETY: getpwuid returns either null or a process-global passwd record;
    // pw_name is NUL-terminated and is copied before another passwd call.
    unsafe {
        let passwd = libc::getpwuid(libc::geteuid());
        if passwd.is_null() || (*passwd).pw_name.is_null() {
            return Err("current uid has no passwd entry".to_owned());
        }
        CStr::from_ptr((*passwd).pw_name)
            .to_str()
            .map(str::to_owned)
            .map_err(|_| "current username is not UTF-8".to_owned())
    }
}

fn config_path(path: &Path) -> Result<&str, String> {
    let value = path
        .to_str()
        .ok_or_else(|| format!("fixture path is not UTF-8: {}", path.display()))?;
    if value.contains(['\n', '\r', ' ', '\t']) {
        return Err(format!(
            "fixture path is unsafe for OpenSSH configuration: {value:?}"
        ));
    }
    Ok(value)
}

fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("cannot chmod {} to {mode:o}: {error}", path.display()))
}

fn display_io(context: &'static str) -> impl FnOnce(io::Error) -> String {
    move |error| format!("{context}: {error}")
}

fn read_diagnostic(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| format!("cannot read {}: {error}", path.display()))
        .trim()
        .to_owned()
}

fn control_sockets(runtime: &RuntimePaths) -> Result<Vec<PathBuf>, String> {
    let mut sockets = Vec::new();
    for entry in fs::read_dir(runtime.directory())
        .map_err(|error| format!("cannot inspect runtime directory: {error}"))?
    {
        let entry = entry.map_err(|error| format!("cannot inspect runtime entry: {error}"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("cannot inspect runtime entry type: {error}"))?;
        if metadata.file_type().is_socket() {
            sockets.push(entry.path());
        }
    }
    sockets.sort();
    Ok(sockets)
}

fn terminate_process_group(child: &mut Child, pid: u32) {
    // SAFETY: a negative pid targets only the isolated sshd process group.
    unsafe {
        libc::kill(-(pid as i32), libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut reaped = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => reaped = true,
            Ok(None) => {}
            Err(_) => break,
        }
        if !process_group_exists(pid) || Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if process_group_exists(pid) {
        // SAFETY: the same isolated process group is forcibly stopped after grace.
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
    if !reaped {
        let _ = child.wait();
    }
}

fn process_exists(pid: u32) -> bool {
    // SAFETY: signal 0 performs a read-only existence/permission check.
    let status = unsafe { libc::kill(pid as i32, 0) };
    status == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn process_group_exists(pid: u32) -> bool {
    // SAFETY: signal 0 performs a read-only existence/permission check for the
    // fixture-owned process group whose leader pid was retained at spawn.
    let status = unsafe { libc::kill(-(pid as i32), 0) };
    status == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn read_pid(path: &Path) -> u32 {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
        .parse()
        .unwrap_or_else(|error| panic!("invalid pid in {}: {error}", path.display()))
}

#[derive(Clone, Copy)]
struct OwnedProcess {
    pid: u32,
    start_ticks: u64,
}

fn read_owned_process(path: &Path) -> OwnedProcess {
    let pid = read_pid(path);
    let proc_path = PathBuf::from(format!("/proc/{pid}"));
    let metadata = fs::metadata(&proc_path)
        .unwrap_or_else(|error| panic!("cannot inspect owned process {pid}: {error}"));
    // SAFETY: geteuid has no preconditions and only reads process credentials.
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    OwnedProcess {
        pid,
        start_ticks: process_start_ticks(pid)
            .unwrap_or_else(|error| panic!("cannot identify owned process {pid}: {error}")),
    }
}

fn process_start_ticks(pid: u32) -> Result<u64, String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|error| format!("cannot read process stat: {error}"))?;
    let (_, fields) = stat
        .rsplit_once(") ")
        .ok_or_else(|| "process stat has no command delimiter".to_owned())?;
    fields
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| "process stat has no start time".to_owned())?
        .parse()
        .map_err(|error| format!("process start time is invalid: {error}"))
}

fn same_process_exists(process: OwnedProcess) -> bool {
    process_start_ticks(process.pid).is_ok_and(|start_ticks| start_ticks == process.start_ticks)
}

fn terminate_owned_process(process: OwnedProcess) -> Result<(), String> {
    if !same_process_exists(process) {
        return Ok(());
    }
    // SAFETY: the pid and start time were emitted by this fixture's command,
    // and ownership was checked against the current effective uid.
    unsafe {
        libc::kill(process.pid as i32, libc::SIGTERM);
    }
    let term_deadline = Instant::now() + Duration::from_millis(500);
    while same_process_exists(process) && Instant::now() < term_deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if same_process_exists(process) {
        // SAFETY: identity is checked again immediately before forced cleanup.
        unsafe {
            libc::kill(process.pid as i32, libc::SIGKILL);
        }
    }
    let kill_deadline = Instant::now() + Duration::from_secs(2);
    while same_process_exists(process) && Instant::now() < kill_deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if same_process_exists(process) {
        Err(format!(
            "owned process {} survived TERM and KILL",
            process.pid
        ))
    } else {
        Ok(())
    }
}

fn wait_process_absent(pid: u32, maximum: Duration) -> Result<(), String> {
    let deadline = Instant::now() + maximum;
    while process_exists(pid) {
        if Instant::now() >= deadline {
            return Err(format!("process {pid} still exists after {maximum:?}"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}
