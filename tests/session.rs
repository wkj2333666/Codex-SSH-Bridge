#![deny(unsafe_code)]

mod support;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

use codex_ssh_bridge::ErrorCode;
use codex_ssh_bridge::capability::ShellRequest;
use codex_ssh_bridge::output::OutputStore;
use codex_ssh_bridge::ssh::{RunRequest, RuntimePaths, SshRunner};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use support::config_with_host;

static PERSISTENT_HELPER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn session_runner(base: &TempDir, log: &std::path::Path) -> Arc<SshRunner> {
    let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (OsString::from("FAKE_SSH_ROOT"), OsString::from("/tmp")),
        (OsString::from("FAKE_SSH_SHELL"), OsString::from("sh")),
        (OsString::from("FAKE_SSH_LOG"), log.as_os_str().to_owned()),
    ]);
    Arc::new(
        SshRunner::with_executable(
            Arc::new(config_with_host("dev", "/tmp")),
            runtime,
            store,
            support::fake_ssh_path(),
            environment,
        )
        .unwrap(),
    )
}

fn persistent_session_runner(
    base: &TempDir,
    log: &std::path::Path,
    install_log: &std::path::Path,
    machine_arch: &str,
    persistent_fail: bool,
) -> Arc<SshRunner> {
    let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let remote_home = base.path().join("remote-home");
    fs::create_dir_all(&remote_home).unwrap();
    let environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (OsString::from("FAKE_SSH_ROOT"), OsString::from("/tmp")),
        (OsString::from("FAKE_SSH_SHELL"), OsString::from("sh")),
        (
            OsString::from("FAKE_SSH_KERNEL_NAME"),
            OsString::from("Linux"),
        ),
        (
            OsString::from("FAKE_SSH_MACHINE_ARCH"),
            OsString::from(machine_arch),
        ),
        (OsString::from("HOME"), remote_home.into_os_string()),
        (OsString::from("FAKE_SSH_LOG"), log.as_os_str().to_owned()),
        (
            OsString::from("FAKE_SSH_INSTALL_LOG"),
            install_log.as_os_str().to_owned(),
        ),
        (
            OsString::from("FAKE_SSH_PERSISTENT_FAIL"),
            OsString::from(if persistent_fail { "1" } else { "0" }),
        ),
    ]);
    Arc::new(
        SshRunner::with_executable(
            Arc::new(config_with_host("dev", "/tmp")),
            runtime,
            store,
            support::fake_ssh_path(),
            environment,
        )
        .unwrap(),
    )
}

fn request(command: &str) -> RunRequest {
    RunRequest {
        host: "dev".to_owned(),
        command: command.to_owned(),
        cwd: "/tmp".to_owned(),
        shell: ShellRequest::Sh,
        stdin: None,
        timeout: Duration::from_secs(5),
    }
}

#[tokio::test]
async fn one_host_reuses_one_persistent_ssh_dispatcher() {
    let base = TempDir::new().unwrap();
    let log = base.path().join("ssh.log");
    let runner = session_runner(&base, &log);
    let first = runner
        .execute(request("printf first"), CancellationToken::new())
        .await
        .unwrap();
    let second = runner
        .execute(request("printf second"), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(first.status, 0);
    assert_eq!(second.status, 0);
    assert_eq!(String::from_utf8_lossy(&first.output.stdout.head), "first");
    assert_eq!(
        String::from_utf8_lossy(&second.output.stdout.head),
        "second"
    );
    let log = fs::read_to_string(log).unwrap();
    assert_eq!(log.lines().filter(|line| *line == "S").count(), 1, "{log}");
}

#[tokio::test]
async fn persistent_helper_installs_once_and_reuses_after_bridge_restart() {
    if std::env::var("CODEX_SSH_BRIDGE_PERSISTENT_HELPER_INTEGRATION").as_deref() != Ok("1") {
        eprintln!(
            "persistent helper integration is opt-in; set CODEX_SSH_BRIDGE_PERSISTENT_HELPER_INTEGRATION=1"
        );
        return;
    }
    let _test_lock = PERSISTENT_HELPER_TEST_LOCK.lock().unwrap();
    let helper_source = std::env::var("CARGO_BIN_EXE_codex-ssh-bridge-helper")
        .or_else(|_| std::env::var("CARGO_BIN_EXE_codex_ssh_bridge_helper"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target/debug/codex-ssh-bridge-helper")
        });
    if !helper_source.is_file() {
        eprintln!("persistent helper fixture is unavailable; skipping");
        return;
    }
    let (machine_arch, helper_target) = match std::env::consts::ARCH {
        "x86_64" => ("x86_64", "x86_64-unknown-linux-musl"),
        "aarch64" => ("aarch64", "aarch64-unknown-linux-musl"),
        _ => {
            eprintln!("persistent helper fixture is unavailable on this architecture; skipping");
            return;
        }
    };
    let helper_parent = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    let helper_directory = helper_parent.join("remote-helpers");
    fs::create_dir_all(&helper_directory).unwrap();
    let helper_path = helper_directory.join(helper_target);
    fs::copy(&helper_source, &helper_path).unwrap();
    fs::set_permissions(&helper_path, fs::Permissions::from_mode(0o700)).unwrap();

    let base = TempDir::new().unwrap();
    let log = base.path().join("ssh.log");
    let install_log = base.path().join("install.log");
    let runner = persistent_session_runner(&base, &log, &install_log, machine_arch, false);
    let mut first_request = request("printf persistent-first");
    first_request.timeout = Duration::from_secs(30);
    let mut concurrent_request = request("printf persistent-concurrent");
    concurrent_request.timeout = Duration::from_secs(30);
    let (first, concurrent) = tokio::join!(
        runner.execute(first_request, CancellationToken::new()),
        runner.execute(concurrent_request, CancellationToken::new()),
    );
    let first = first.unwrap();
    let concurrent = concurrent.unwrap();
    assert_eq!(
        String::from_utf8_lossy(&first.output.stdout.head),
        "persistent-first"
    );
    assert_eq!(
        String::from_utf8_lossy(&concurrent.output.stdout.head),
        "persistent-concurrent"
    );
    assert_eq!(
        first.helper_mode,
        codex_ssh_bridge::ssh::HelperMode::Persistent
    );
    assert_eq!(
        concurrent.helper_mode,
        codex_ssh_bridge::ssh::HelperMode::Persistent
    );

    let mut timed_request = request("sleep 30");
    timed_request.timeout = Duration::from_millis(80);
    let timed_out = runner
        .execute(timed_request, CancellationToken::new())
        .await
        .expect_err("the persistent helper must report its watchdog timeout");
    assert_eq!(timed_out.code, ErrorCode::CommandTimeout);
    assert_eq!(
        timed_out.details.remote_process_may_continue,
        Some(false),
        "{timed_out:?}"
    );

    let after_timeout = runner
        .execute(
            request("printf persistent-after-timeout"),
            CancellationToken::new(),
        )
        .await
        .expect("a timed-out request must not poison the shared session");
    assert_eq!(
        String::from_utf8_lossy(&after_timeout.output.stdout.head),
        "persistent-after-timeout"
    );
    assert_eq!(
        after_timeout.helper_mode,
        codex_ssh_bridge::ssh::HelperMode::Persistent
    );
    drop(runner);

    let restart_log = base.path().join("restart-ssh.log");
    let restart_install_log = base.path().join("restart-install.log");
    let restarted = persistent_session_runner(
        &base,
        &restart_log,
        &restart_install_log,
        machine_arch,
        false,
    );
    let mut second_request = request("printf persistent-second");
    second_request.timeout = Duration::from_secs(30);
    let second = restarted
        .execute(second_request, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&second.output.stdout.head),
        "persistent-second"
    );
    assert_eq!(fs::read_to_string(&install_log).unwrap(), "NEED\n");
    assert_eq!(fs::read_to_string(&restart_install_log).unwrap(), "HIT\n");

    let installed = base
        .path()
        .join("remote-home/.local/share/codex-ssh-bridge/helpers")
        .join(env!("CARGO_PKG_VERSION"))
        .join(format!("{helper_target}/helper"));
    assert_eq!(
        fs::metadata(installed).unwrap().permissions().mode() & 0o777,
        0o700
    );

    drop(restarted);
    let _ = fs::remove_file(helper_path);
    let _ = fs::remove_dir(&helper_directory);
}

#[tokio::test]
async fn persistent_startup_failure_falls_back_to_temporary_helper() {
    if std::env::var("CODEX_SSH_BRIDGE_PERSISTENT_HELPER_INTEGRATION").as_deref() != Ok("1") {
        eprintln!(
            "persistent helper integration is opt-in; set CODEX_SSH_BRIDGE_PERSISTENT_HELPER_INTEGRATION=1"
        );
        return;
    }
    let _test_lock = PERSISTENT_HELPER_TEST_LOCK.lock().unwrap();
    let helper_source = std::env::var("CARGO_BIN_EXE_codex-ssh-bridge-helper")
        .or_else(|_| std::env::var("CARGO_BIN_EXE_codex_ssh_bridge_helper"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target/debug/codex-ssh-bridge-helper")
        });
    if !helper_source.is_file() {
        eprintln!("persistent helper fixture is unavailable; skipping");
        return;
    }
    let (machine_arch, helper_target) = match std::env::consts::ARCH {
        "x86_64" => ("x86_64", "x86_64-unknown-linux-musl"),
        "aarch64" => ("aarch64", "aarch64-unknown-linux-musl"),
        _ => {
            eprintln!("persistent helper fixture is unavailable on this architecture; skipping");
            return;
        }
    };
    let helper_directory = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join("remote-helpers");
    fs::create_dir_all(&helper_directory).unwrap();
    let helper_path = helper_directory.join(helper_target);
    fs::copy(&helper_source, &helper_path).unwrap();
    fs::set_permissions(&helper_path, fs::Permissions::from_mode(0o700)).unwrap();

    let base = TempDir::new().unwrap();
    let log = base.path().join("ssh.log");
    let install_log = base.path().join("install.log");
    let runner = persistent_session_runner(&base, &log, &install_log, machine_arch, true);
    let mut run = request("printf temporary-fallback");
    run.timeout = Duration::from_secs(30);
    let result = runner.execute(run, CancellationToken::new()).await.unwrap();
    assert_eq!(
        result.helper_mode,
        codex_ssh_bridge::ssh::HelperMode::Temporary
    );
    assert_eq!(
        String::from_utf8_lossy(&result.output.stdout.head),
        "temporary-fallback"
    );
    let log_text = fs::read_to_string(log).unwrap();
    assert_eq!(
        log_text.lines().filter(|line| *line == "S").count(),
        2,
        "{log_text}"
    );
    drop(runner);
    let _ = fs::remove_file(helper_path);
    let _ = fs::remove_dir(&helper_directory);
}

#[tokio::test]
async fn unsupported_helper_architecture_uses_shell_mode() {
    let base = TempDir::new().unwrap();
    let log = base.path().join("ssh.log");
    let install_log = base.path().join("install.log");
    let runner = persistent_session_runner(&base, &log, &install_log, "mips64", false);
    let result = runner
        .execute(request("printf shell-only"), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(result.helper_mode, codex_ssh_bridge::ssh::HelperMode::Shell);
    assert_eq!(
        String::from_utf8_lossy(&result.output.stdout.head),
        "shell-only"
    );
    let log_text = fs::read_to_string(log).unwrap();
    assert_eq!(
        log_text.lines().filter(|line| *line == "S").count(),
        1,
        "{log_text}"
    );
}

#[tokio::test]
async fn independent_session_requests_complete_concurrently() {
    let base = TempDir::new().unwrap();
    let log = base.path().join("ssh.log");
    let runner = session_runner(&base, &log);
    let slow = {
        let runner = Arc::clone(&runner);
        tokio::spawn(async move {
            runner
                .execute(request("sleep 0.2; printf slow"), CancellationToken::new())
                .await
                .unwrap()
        })
    };
    let fast = {
        let runner = Arc::clone(&runner);
        tokio::spawn(async move {
            runner
                .execute(request("printf fast"), CancellationToken::new())
                .await
                .unwrap()
        })
    };
    let fast = fast.await.unwrap();
    let slow = slow.await.unwrap();
    assert_eq!(String::from_utf8_lossy(&fast.output.stdout.head), "fast");
    assert_eq!(String::from_utf8_lossy(&slow.output.stdout.head), "slow");
}

#[tokio::test]
async fn session_preserves_large_binary_stdin_across_pipe_short_reads() {
    let base = TempDir::new().unwrap();
    let log = base.path().join("ssh.log");
    let runner = session_runner(&base, &log);
    let stdin = vec![0xA5; 512 * 1024 + 123];
    let mut request = request("wc -c");
    request.stdin = Some(stdin.clone());
    let result = runner
        .execute(request, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(result.status, 0);
    assert_eq!(
        String::from_utf8_lossy(&result.output.stdout.head),
        format!("{}\n", stdin.len())
    );
}

#[tokio::test]
async fn supported_linux_architecture_uses_uploaded_helper_once_per_session() {
    if std::env::var("CODEX_SSH_BRIDGE_HELPER_INTEGRATION").as_deref() != Ok("1") {
        eprintln!("helper integration is opt-in; set CODEX_SSH_BRIDGE_HELPER_INTEGRATION=1");
        return;
    }
    let helper_source = std::env::var("CARGO_BIN_EXE_codex-ssh-bridge-helper")
        .or_else(|_| std::env::var("CARGO_BIN_EXE_codex_ssh_bridge_helper"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target/debug/codex-ssh-bridge-helper")
        });
    if !helper_source.is_file() {
        eprintln!("helper integration binary is not available; skipping");
        return;
    }
    let target = match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-musl",
        "aarch64" => "aarch64-unknown-linux-musl",
        "arm" => "armv7-unknown-linux-musleabihf",
        _ => {
            eprintln!("unsupported test architecture; skipping");
            return;
        }
    };
    let test_binary_parent = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    let helper_directory = test_binary_parent.join("remote-helpers");
    fs::create_dir_all(&helper_directory).unwrap();
    let helper_path = helper_directory.join(target);
    fs::copy(&helper_source, &helper_path).unwrap();
    fs::set_permissions(&helper_path, fs::Permissions::from_mode(0o700)).unwrap();

    let base = TempDir::new().unwrap();
    let log = base.path().join("ssh.log");
    let runner = session_runner(&base, &log);
    let mut helper_request = request("printf helper-first");
    helper_request.timeout = Duration::from_secs(30);
    let first = runner
        .execute(helper_request, CancellationToken::new())
        .await
        .unwrap();
    let second = runner
        .execute(request("printf helper-second"), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&first.output.stdout.head),
        "helper-first"
    );
    assert_eq!(
        String::from_utf8_lossy(&second.output.stdout.head),
        "helper-second"
    );
    let log_text = fs::read_to_string(log).unwrap();
    assert_eq!(
        log_text.lines().filter(|line| *line == "S").count(),
        1,
        "{log_text}"
    );
    drop(runner);

    fs::copy("/bin/false", &helper_path).unwrap();
    fs::set_permissions(&helper_path, fs::Permissions::from_mode(0o700)).unwrap();
    let fallback_base = TempDir::new().unwrap();
    let fallback_log = fallback_base.path().join("ssh.log");
    let fallback_runner = session_runner(&fallback_base, &fallback_log);
    let fallback = fallback_runner
        .execute(request("printf shell-fallback"), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&fallback.output.stdout.head),
        "shell-fallback"
    );
    let fallback_log_text = fs::read_to_string(fallback_log).unwrap();
    assert_eq!(
        fallback_log_text
            .lines()
            .filter(|line| *line == "S")
            .count(),
        2,
        "{fallback_log_text}"
    );
    drop(fallback_runner);
    let _ = fs::remove_file(helper_path);
    let _ = fs::remove_dir(&helper_directory);
}
