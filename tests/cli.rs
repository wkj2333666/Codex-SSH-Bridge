#![deny(unsafe_code)]

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::sync::Arc;
use std::time::{Duration, Instant};

use assert_cmd::Command;
use codex_ssh_bridge::cli::{
    LocalCommandSpec, RunArgs, ShellArg, build_verbose_ssh_diagnostic_argv, doctor_host,
    mount_sshfs_with_executable, parse_sshfs_mount_status, redact_ssh_diagnostics,
    run_local_command, run_remote_argv,
};
use codex_ssh_bridge::config::{Config, HostLimitOverrides, HostProfile};
use codex_ssh_bridge::output::OutputStore;
use codex_ssh_bridge::remote::RemoteBridge;
use codex_ssh_bridge::ssh::SshRunner;
use codex_ssh_bridge::ssh::{RuntimePaths, SshPolicy, build_sshfs_argv, validate_sshfs_mountpoint};
use predicates::prelude::*;

fn bridge_command(config: &std::path::Path, runtime: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_codex-ssh-bridge"));
    command
        .env("CODEX_SSH_BRIDGE_CONFIG", config)
        .env("XDG_RUNTIME_DIR", runtime);
    command
}

#[test]
fn task9_help_lists_human_commands_while_mcp_remains_an_entry_mode() {
    Command::new(env!("CARGO_BIN_EXE_codex-ssh-bridge"))
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("mcp"))
        .stdout(predicate::str::contains("hosts"))
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("run"))
        .stdout(predicate::str::contains("mount"))
        .stdout(predicate::str::contains("unmount"))
        .stdout(predicate::str::contains("mount-status"));
}

#[test]
fn hosts_list_discovers_every_concrete_alias_without_policy_fields() {
    let private = tempfile::TempDir::new().unwrap();
    let config = private.path().join("config.toml");
    Config::default().save_atomic(&config).unwrap();
    let home = private.path().join("home");
    let ssh = home.join(".ssh");
    fs::create_dir_all(&ssh).unwrap();
    let mut ssh_config = String::from("Host *\n  ServerAliveInterval 30\n");
    for index in (0..257).rev() {
        ssh_config.push_str(&format!("Host server-{index:03}\n  HostName 192.0.2.1\n"));
    }
    fs::write(ssh.join("config"), ssh_config).unwrap();

    let output = bridge_command(&config, private.path())
        .env("HOME", &home)
        .args(["hosts", "list"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let aliases = value["hosts"].as_array().unwrap();
    assert_eq!(aliases.len(), 257);
    assert_eq!(aliases.first().unwrap(), "server-000");
    assert_eq!(aliases.last().unwrap(), "server-256");
    let rendered = String::from_utf8(output.stdout).unwrap();
    for forbidden in ["configured_root", "description", "read_only", "limits"] {
        assert!(!rendered.contains(forbidden), "{forbidden}");
    }
}

#[test]
fn hosts_cli_is_discovery_only() {
    Command::new(env!("CARGO_BIN_EXE_codex-ssh-bridge"))
        .args(["hosts", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("add").not())
        .stdout(predicate::str::contains("show").not())
        .stdout(predicate::str::contains("remove").not());

    Command::new(env!("CARGO_BIN_EXE_codex-ssh-bridge"))
        .args(["hosts", "add", "dev", "--root", "/srv/dev"])
        .assert()
        .failure();
}

#[test]
fn task9_mcp_source_tree_contains_no_sshfs_or_mount_tool() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for file in [
        "src/mcp/mod.rs",
        "src/mcp/protocol.rs",
        "src/mcp/render.rs",
        "src/mcp/stdio.rs",
        "src/mcp/tools.rs",
    ] {
        let source = fs::read_to_string(manifest.join(file)).unwrap();
        let lowered = source.to_ascii_lowercase();
        assert!(!lowered.contains("sshfs"), "{file}");
        assert!(!lowered.contains("remote_mount"), "{file}");
    }
}

fn sshfs_policy(private: &tempfile::TempDir, read_only: bool) -> (Config, RuntimePaths) {
    let mut config = Config::default();
    config.hosts.insert(
        "future-box".to_owned(),
        HostProfile {
            root: "/srv/project".to_owned(),
            description: None,
            read_only,
            limits: HostLimitOverrides::default(),
        },
    );
    let runtime = RuntimePaths::ensure_from_base(private.path()).unwrap();
    (config, runtime)
}

fn option_is_distinct(argv: &[std::ffi::OsString], expected: &str) -> bool {
    argv.windows(2)
        .any(|pair| pair[0] == "-o" && pair[1] == expected)
}

fn option_count(argv: &[std::ffi::OsString], expected: &str) -> usize {
    argv.windows(2)
        .filter(|pair| pair[0] == "-o" && pair[1] == expected)
        .count()
}

#[test]
fn task9_sshfs_argv_has_exact_hardening_without_bridge_owned_read_only_policy() {
    let private = tempfile::TempDir::new().unwrap();
    let (config, runtime) = sshfs_policy(&private, true);
    let policy =
        SshPolicy::for_host("future-box", config.limits(), &runtime, "resolved identity").unwrap();
    let argv = build_sshfs_argv(
        &policy,
        "future-box",
        "/srv/project/path with spaces",
        std::path::Path::new("/mnt/remote project"),
        true,
    )
    .unwrap();

    for option in [
        "ssh_command=/usr/bin/ssh",
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=no",
        "RequestTTY=no",
        "ConnectTimeout=10",
        "ServerAliveInterval=15",
        "ServerAliveCountMax=3",
        "ControlMaster=auto",
        "ControlPersist=300",
        "reconnect",
        "nonempty",
    ] {
        assert!(
            option_is_distinct(&argv, option),
            "missing {option:?}: {argv:?}"
        );
    }
    assert!(!option_is_distinct(&argv, "ro"));
    for option in ["ServerAliveInterval=15", "ServerAliveCountMax=3"] {
        assert_eq!(
            option_count(&argv, option),
            1,
            "option={option:?}, argv={argv:?}"
        );
    }
    assert!(!argv.iter().any(|argument| argument == "allow_other"));
    assert!(
        argv.iter()
            .any(|argument| argument == "future-box:/srv/project/path with spaces")
    );
    assert!(
        argv.iter()
            .any(|argument| argument == "/mnt/remote project")
    );
}

#[test]
fn task9_sshfs_argv_does_not_add_ro_or_nonempty_for_normal_read_write_mount() {
    let private = tempfile::TempDir::new().unwrap();
    let (config, runtime) = sshfs_policy(&private, false);
    let policy =
        SshPolicy::for_host("future-box", config.limits(), &runtime, "resolved identity").unwrap();
    let argv = build_sshfs_argv(
        &policy,
        "future-box",
        "/srv/project",
        std::path::Path::new("/mnt/project"),
        false,
    )
    .unwrap();
    assert!(!option_is_distinct(&argv, "ro"));
    assert!(!option_is_distinct(&argv, "nonempty"));
}

#[test]
fn task9_mountpoint_must_be_absolute_real_owned_directory_and_empty_by_default() {
    let private = tempfile::TempDir::new().unwrap();
    let empty = private.path().join("empty");
    let nonempty = private.path().join("nonempty");
    let target = private.path().join("target");
    let link = private.path().join("link");
    fs::create_dir(&empty).unwrap();
    fs::create_dir(&nonempty).unwrap();
    fs::create_dir(&target).unwrap();
    fs::write(nonempty.join("sentinel"), b"keep").unwrap();
    symlink(&target, &link).unwrap();

    assert_eq!(validate_sshfs_mountpoint(&empty, false).unwrap(), empty);
    assert!(validate_sshfs_mountpoint(std::path::Path::new("relative"), false).is_err());
    assert!(validate_sshfs_mountpoint(&nonempty, false).is_err());
    assert!(validate_sshfs_mountpoint(&link, true).is_err());
    assert_eq!(
        validate_sshfs_mountpoint(&nonempty, true).unwrap(),
        nonempty
    );
}

fn executable_script(directory: &std::path::Path, name: &str, source: &str) -> std::path::PathBuf {
    let path = directory.join(name);
    fs::write(&path, source).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn remote_bridge(root: &std::path::Path, private: &tempfile::TempDir) -> Arc<RemoteBridge> {
    let mut config = Config::default();
    config.hosts.insert(
        "dev".to_owned(),
        HostProfile {
            root: root.to_str().unwrap().to_owned(),
            description: None,
            read_only: false,
            limits: HostLimitOverrides::default(),
        },
    );
    let runtime = RuntimePaths::ensure_from_base(private.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let runner = Arc::new(
        SshRunner::with_executable(
            Arc::new(config),
            runtime,
            store,
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-ssh.sh"),
            [
                (
                    OsString::from("FAKE_SSH_MODE"),
                    OsString::from("local-fixed"),
                ),
                (OsString::from("FAKE_SSH_SHELL"), OsString::from("bash")),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap(),
    );
    Arc::new(RemoteBridge::new(runner))
}

fn remote_runner(
    root: &std::path::Path,
    private: &tempfile::TempDir,
    read_only: bool,
) -> Arc<SshRunner> {
    let mut config = Config::default();
    config.hosts.insert(
        "dev".to_owned(),
        HostProfile {
            root: root.to_str().unwrap().to_owned(),
            description: None,
            read_only,
            limits: HostLimitOverrides::default(),
        },
    );
    let runtime = RuntimePaths::ensure_from_base(private.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    Arc::new(
        SshRunner::with_executable(
            Arc::new(config),
            runtime,
            store,
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-ssh.sh"),
            [(
                OsString::from("FAKE_SSH_MODE"),
                OsString::from("local-fixed"),
            )]
            .into_iter()
            .collect(),
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn task9_doctor_uses_shared_probe_and_reports_remote_root_and_actual_shell() {
    let private = tempfile::TempDir::new().unwrap();
    let remote = tempfile::TempDir::new().unwrap();
    let bridge = remote_bridge(remote.path(), &private);
    let result = doctor_host(&bridge, "dev").await.unwrap();
    assert_eq!(result["remote"], true);
    assert_eq!(result["host"], "dev");
    assert_eq!(result["physical_root"], remote.path().to_str().unwrap());
    assert_eq!(result["shell"]["kind"], "sh");
    assert_eq!(result["shell"]["version"], serde_json::Value::Null);
    assert_eq!(result["shell"]["fallback"], false);
}

#[tokio::test]
async fn task9_direct_run_quotes_each_argv_word_and_reports_shell() {
    let private = tempfile::TempDir::new().unwrap();
    let remote = tempfile::TempDir::new().unwrap();
    let bridge = remote_bridge(remote.path(), &private);
    let hostile = "space '$HOME' $(touch should-not-exist) * newline\nend";
    let result = run_remote_argv(
        &bridge,
        RunArgs {
            host: "dev".to_owned(),
            cwd: ".".to_owned(),
            shell: ShellArg::Bash,
            timeout_ms: Some(5_000),
            argv: vec!["printf".to_owned(), "%s".to_owned(), hostile.to_owned()],
        },
    )
    .await
    .unwrap();
    let value = serde_json::to_value(result).unwrap();
    assert_eq!(value["shell"]["kind"], "bash");
    assert_eq!(value["shell"]["fallback"], false);
    assert_eq!(value["warnings"], serde_json::json!([]));
    assert_eq!(value["stdout"]["head"]["encoding"], "utf8");
    assert_eq!(value["stdout"]["head"]["value"], hostile);
    assert!(!remote.path().join("should-not-exist").exists());
}

#[tokio::test]
async fn task9_bash_run_fails_when_bash_is_unavailable() {
    let private = tempfile::TempDir::new().unwrap();
    let remote = tempfile::TempDir::new().unwrap();
    let mut config = Config::default();
    config.hosts.insert(
        "dev".to_owned(),
        HostProfile {
            root: remote.path().to_str().unwrap().to_owned(),
            description: None,
            read_only: false,
            limits: HostLimitOverrides::default(),
        },
    );
    let runtime = RuntimePaths::ensure_from_base(private.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let runner = Arc::new(
        SshRunner::with_executable(
            Arc::new(config),
            runtime,
            store,
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-ssh.sh"),
            [
                (
                    OsString::from("FAKE_SSH_MODE"),
                    OsString::from("echo-command"),
                ),
                (OsString::from("FAKE_SSH_SHELL"), OsString::from("sh")),
                (
                    OsString::from("FAKE_SSH_ROOT"),
                    remote.path().as_os_str().to_owned(),
                ),
            ]
            .into_iter()
            .collect(),
        )
        .unwrap(),
    );
    let bridge = RemoteBridge::new(runner);
    let error = run_remote_argv(
        &bridge,
        RunArgs {
            host: "dev".to_owned(),
            cwd: ".".to_owned(),
            shell: ShellArg::Bash,
            timeout_ms: Some(5_000),
            argv: vec!["printf".to_owned(), "%s".to_owned(), "ok".to_owned()],
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.code,
        codex_ssh_bridge::error::ErrorCode::RemoteCapabilityMissing
    );
}

#[tokio::test]
async fn task9_local_executor_preserves_argv_and_bounded_output_without_a_shell() {
    let private = tempfile::TempDir::new().unwrap();
    let executable = executable_script(
        private.path(),
        "fixture",
        "#!/bin/sh\nprintf '%s' \"$1\"\nprintf '%s' \"$2\" >&2\nexit 7\n",
    );
    let output = run_local_command(LocalCommandSpec {
        executable,
        arguments: vec![
            OsString::from("literal;$(false)"),
            OsString::from("diagnostic"),
        ],
        timeout: Duration::from_secs(2),
        max_output_bytes: 1024,
    })
    .await
    .unwrap();
    assert_eq!(output.status, 7);
    assert_eq!(output.stdout, b"literal;$(false)");
    assert_eq!(output.stderr, b"diagnostic");
}

#[tokio::test]
async fn task9_local_executor_timeout_kills_the_process_group_promptly() {
    let private = tempfile::TempDir::new().unwrap();
    let pid_file = private.path().join("child.pid");
    let executable = executable_script(
        private.path(),
        "hang",
        "#!/bin/sh\ntrap '' TERM\nsleep 30 &\nprintf '%s\\n' \"$!\" >\"$1\"\nwait\n",
    );
    let started = Instant::now();
    let error = run_local_command(LocalCommandSpec {
        executable,
        arguments: vec![pid_file.as_os_str().to_owned()],
        timeout: Duration::from_millis(100),
        max_output_bytes: 1024,
    })
    .await
    .unwrap_err();
    assert_eq!(error.code, codex_ssh_bridge::ErrorCode::CommandTimeout);
    assert!(started.elapsed() < Duration::from_secs(1));
    let child: i32 = fs::read_to_string(pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let child_proc = std::path::PathBuf::from(format!("/proc/{child}"));
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        if !child_proc.exists() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "local grandchild survived timeout"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn task9_local_executor_output_limit_wins_and_kills_a_term_ignoring_group() {
    let private = tempfile::TempDir::new().unwrap();
    let executable = executable_script(
        private.path(),
        "overflow",
        "#!/bin/sh\ntrap '' TERM\ndd if=/dev/zero bs=2048 count=1 2>/dev/null\nsleep 30\n",
    );
    let started = Instant::now();
    let error = run_local_command(LocalCommandSpec {
        executable,
        arguments: Vec::new(),
        timeout: Duration::from_secs(2),
        max_output_bytes: 1024,
    })
    .await
    .unwrap_err();
    assert_eq!(error.code, codex_ssh_bridge::ErrorCode::OutputLimit);
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn task9_verbose_doctor_redacts_paths_commands_credentials_and_controls() {
    let diagnostic = b"debug1: safe negotiated algorithm ssh-ed25519\n\
debug1: identity file /home/alice/.ssh/id_ed25519 type 3\n\
debug1: identity agent /run/user/1000/ssh-agent.socket\n\
debug1: Sending command: deploy --token=DOCTOR_TOKEN_SECRET\n\
Authorization: Bearer DOCTOR_BEARER_SECRET\n\
password=DOCTOR_PASSWORD_SECRET\n\
safe-control:\x1b[31m\n";
    let rendered = redact_ssh_diagnostics(diagnostic);
    assert!(rendered.contains("safe negotiated algorithm ssh-ed25519"));
    assert!(rendered.contains("[REDACTED]"));
    for secret in [
        "/home/alice/.ssh/id_ed25519",
        "/run/user/1000/ssh-agent.socket",
        "deploy --token",
        "DOCTOR_TOKEN_SECRET",
        "DOCTOR_BEARER_SECRET",
        "DOCTOR_PASSWORD_SECRET",
        "\u{1b}",
    ] {
        assert!(
            !rendered.contains(secret),
            "leaked {secret:?}: {rendered:?}"
        );
    }
}

#[test]
fn verbose_doctor_ssh_g_argv_uses_effective_timeout_and_exact_hardening_once() {
    let mut config = Config::default();
    config.limits.connect_timeout_ms = 2_501;
    let argv = build_verbose_ssh_diagnostic_argv("dev", config.limits().connect_timeout_ms);

    assert_eq!(argv.first(), Some(&OsString::from("-vvv")));
    assert_eq!(argv.iter().filter(|argument| *argument == "-G").count(), 1);
    for option in [
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=no",
        "RequestTTY=no",
        "ControlPersist=300",
        "ServerAliveInterval=15",
        "ServerAliveCountMax=3",
        "ConnectTimeout=3",
    ] {
        assert_eq!(
            option_count(&argv, option),
            1,
            "option={option:?}, argv={argv:?}"
        );
    }
    assert_eq!(
        argv.iter()
            .filter(|argument| {
                argument
                    .to_str()
                    .is_some_and(|argument| argument.starts_with("ConnectTimeout="))
            })
            .count(),
        1,
        "argv={argv:?}"
    );
    let separator = argv.iter().position(|argument| argument == "--").unwrap();
    assert_eq!(argv.get(separator + 1), Some(&OsString::from("dev")));
}

#[test]
fn task9_mount_status_parser_decodes_mountinfo_and_distinguishes_other_fuse() {
    let sshfs = b"36 25 0:32 / /mnt/remote\\040project rw,nosuid - fuse.sshfs dev:/srv rw\n";
    let status =
        parse_sshfs_mount_status(sshfs, std::path::Path::new("/mnt/remote project")).unwrap();
    assert!(status.mounted);
    assert!(status.sshfs);
    assert_eq!(status.mount_id, Some(36));
    assert_eq!(status.filesystem_type.as_deref(), Some("fuse.sshfs"));

    let other = b"36 25 0:32 / /mnt/remote\\040project rw,nosuid - fuse.other x rw\n";
    let status =
        parse_sshfs_mount_status(other, std::path::Path::new("/mnt/remote project")).unwrap();
    assert!(status.mounted);
    assert!(!status.sshfs);
}

#[tokio::test]
async fn task9_mount_executes_hardened_sshfs_and_forces_profile_read_only() {
    let private = tempfile::TempDir::new().unwrap();
    let remote = tempfile::TempDir::new().unwrap();
    let mountpoint = private.path().join("mountpoint");
    let log = private.path().join("sshfs.log");
    fs::create_dir(&mountpoint).unwrap();
    let source = format!("#!/bin/sh\nprintf '%s\\n' \"$@\" >'{}'\n", log.display());
    let sshfs = executable_script(private.path(), "sshfs", &source);
    let runner = remote_runner(remote.path(), &private, true);
    let result = mount_sshfs_with_executable(
        &runner,
        sshfs,
        codex_ssh_bridge::cli::MountArgs {
            host: "dev".to_owned(),
            mountpoint: mountpoint.clone(),
            remote_path: ".".to_owned(),
            allow_nonempty: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(result["remote"], true);
    assert_eq!(result["host"], "dev");
    assert!(
        result["warning"]
            .as_str()
            .unwrap()
            .contains("not an Agent workspace")
    );
    let logged = fs::read_to_string(log).unwrap();
    for option in [
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "ForwardAgent=no",
        "ClearAllForwardings=yes",
        "reconnect",
        "ro",
    ] {
        assert!(logged.lines().any(|line| line == option), "{logged}");
    }
    assert_eq!(logged.lines().nth(1), mountpoint.to_str());
}

#[test]
fn task9_existing_config_load_and_save_reject_unsafe_ancestors() {
    let private = tempfile::TempDir::new().unwrap();
    let real = private.path().join("real");
    fs::create_dir(&real).unwrap();
    let path = real.join("config.toml");
    Config::default().save_atomic(&path).unwrap();
    let original = fs::read(&path).unwrap();

    fs::set_permissions(&real, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(Config::load(&path).is_err());
    assert!(Config::default().save_atomic(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);

    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    let through = private.path().join("through");
    symlink(&real, &through).unwrap();
    assert!(Config::load(&through.join("config.toml")).is_err());
}
