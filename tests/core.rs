#![deny(unsafe_code)]

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use codex_ssh_bridge::config::{
    Config, DEFAULT_GLOBAL_SPOOL_QUOTA_BYTES, DEFAULT_RETENTION_SERIALIZATION_JOBS,
    HostLimitOverrides, HostProfile, Limits, MAX_GLOBAL_SPOOL_QUOTA_BYTES,
    MAX_RETENTION_SERIALIZATION_JOBS, MIN_GLOBAL_SPOOL_QUOTA_BYTES, migrate_v1_text,
};
use codex_ssh_bridge::error::{BridgeError, ErrorCode};
use codex_ssh_bridge::path::RemotePath;
use codex_ssh_bridge::quote::{fixed_command, shell_word};
use codex_ssh_bridge::{MAX_FRAME_BYTES, MAX_OUTPUT_BYTES, MAX_READ_BYTES, MAX_WRITE_BYTES};
use proptest::prelude::*;
use tempfile::{NamedTempFile, TempDir};

const LOAD_DEFAULT_CHILD_SENTINEL: &str = "CODEX_SSH_BRIDGE_TEST_LOAD_DEFAULT_CHILD";
#[cfg(unix)]
const FIFO_CHILD_SENTINEL: &str = "CODEX_SSH_BRIDGE_TEST_FIFO_CHILD_PATH";

fn load_default_child(case: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "config_load_default_in_isolated_child_process",
            "--nocapture",
        ])
        .env(LOAD_DEFAULT_CHILD_SENTINEL, case);
    command
}

fn assert_child_passes(mut command: Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "child failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write_config(contents: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    file.as_file().sync_all().unwrap();
    file
}

#[test]
fn v2_config_contains_only_global_non_admission_limits() {
    let config: Config = toml::from_str(
        r#"
version = 2
[limits]
connect_timeout_ms = 10000
command_timeout_ms = 300000
max_frame_bytes = 8388608
read_chunk_bytes = 262144
max_read_bytes = 1048576
max_write_bytes = 4194304
preview_bytes = 262144
max_output_bytes = 67108864
global_spool_quota_bytes = 536870912
retention_serialization_jobs = 2
"#,
    )
    .unwrap();
    let rendered = toml::to_string(&config).unwrap();
    for forbidden in [
        "[hosts",
        "root",
        "description",
        "read_only",
        "global_concurrency",
        "per_host_concurrency",
    ] {
        assert!(!rendered.contains(forbidden), "{forbidden}");
    }
}

#[test]
fn v1_migration_preserves_limits_and_returns_explicit_aliases() {
    const V1: &str = r#"
version = 1
[limits]
command_timeout_ms = 300000
retention_serialization_jobs = 2
global_concurrency = 8
per_host_concurrency = 2
[hosts.nkai]
root = "/home/wkj"
[hosts.weibo]
root = "/"
"#;
    let migrated = migrate_v1_text(V1).unwrap();
    assert_eq!(migrated.config.version, 2);
    assert_eq!(migrated.explicit_aliases, ["nkai", "weibo"]);
    assert_eq!(migrated.config.limits.command_timeout_ms, 300_000);
    assert_eq!(migrated.config.limits.retention_serialization_jobs, 2);
}

fn valid_config(root: &Path) -> String {
    format!(
        r#"
version = 1

[hosts.devbox]
root = {root:?}
description = "development box"

[hosts.devbox.limits]
connect_timeout_ms = 2500
max_read_bytes = 524288
per_host_concurrency = 1
"#,
        root = root.display().to_string()
    )
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn shell_word_round_trips(value in "[^\\x00]{0,256}") {
        let encoded = shell_word(&value).unwrap();
        let script = format!("printf '%s' {}", encoded);
        let output = Command::new("/bin/sh")
            .args(["-c", &script])
            .output().unwrap();
        prop_assert!(output.status.success());
        prop_assert_eq!(output.stdout, value.as_bytes());
    }
}

#[test]
fn shell_word_round_trips_one_hundred_thousand_generated_values_in_one_shell() {
    const CASES: usize = 100_000;
    const ALPHABET: &[char] = &[
        'a', 'Z', '0', ' ', '\t', '\n', '\'', '"', '$', '`', '(', ')', '*', '?', '[', ']', '-',
        '\\', ';', '&', '|', '<', '>', 'é', '中', '🙂',
    ];

    let special = [
        "",
        "'",
        "line one\nline two",
        "你好🙂",
        "$HOME",
        "`uname`",
        "$(uname)",
        "*.txt?[a]",
        "--leading-option",
    ];
    let mut values: Vec<String> = special.iter().map(|value| (*value).to_owned()).collect();
    let mut state = 0x4d59_5df4_d0f3_3173_u64;
    while values.len() < CASES {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let length = ((state >> 58) as usize).min(48);
        let mut value = String::new();
        for _ in 0..length {
            state = state
                .wrapping_mul(2_862_933_555_777_941_757)
                .wrapping_add(3_037_000_493);
            value.push(ALPHABET[(state as usize) % ALPHABET.len()]);
        }
        values.push(value);
    }

    let mut script = NamedTempFile::new().unwrap();
    for value in &values {
        writeln!(script, "printf '%s\\0' {}", shell_word(value).unwrap()).unwrap();
    }
    script.as_file().sync_all().unwrap();

    let output = Command::new("/bin/sh").arg(script.path()).output().unwrap();
    assert!(
        output.status.success(),
        "shell failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout.last(), Some(&0));
    let actual: Vec<&[u8]> = output.stdout[..output.stdout.len() - 1]
        .split(|byte| *byte == 0)
        .collect();
    assert_eq!(actual.len(), CASES);
    for (index, (actual, expected)) in actual.iter().zip(&values).enumerate() {
        assert_eq!(*actual, expected.as_bytes(), "mismatch at case {index}");
    }
}

#[test]
fn quote_rejects_nul_in_words_and_fixed_scripts() {
    let word_error = shell_word("before\0after").unwrap_err();
    assert_eq!(word_error.code, ErrorCode::InvalidArgument);
    assert!(word_error.message.contains("NUL"));

    let argument_error = fixed_command("printf '%s'", &["before\0after"]).unwrap_err();
    assert_eq!(argument_error.code, ErrorCode::InvalidArgument);

    let script_error = fixed_command("printf\0 '%s'", &["safe"]).unwrap_err();
    assert_eq!(script_error.code, ErrorCode::InvalidArgument);
}

#[test]
fn fixed_command_quotes_only_its_arguments() {
    let command = fixed_command("printf '%s\\0%s\\0'", &["$(uname)", "a'b"]).unwrap();
    let output = Command::new("/bin/sh")
        .args(["-c", &command])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"$(uname)\0a'b\0");
}

#[test]
fn remote_paths_normalize_without_escaping_the_root() {
    let path = RemotePath::resolve("/srv/./bridge/root", "projects/demo/../src//main.rs").unwrap();
    assert_eq!(path.absolute(), "/srv/bridge/root/projects/src/main.rs");
    assert_eq!(path.relative(), "projects/src/main.rs");

    let root = RemotePath::resolve("/srv/bridge/root/", ".").unwrap();
    assert_eq!(root.absolute(), "/srv/bridge/root");
    assert_eq!(root.relative(), "");
}

#[test]
fn remote_paths_accept_only_absolute_paths_within_the_root_boundary() {
    let inside = RemotePath::resolve("/srv/bridge/root", "/srv/bridge/root/a/../b").unwrap();
    assert_eq!(inside.absolute(), "/srv/bridge/root/b");
    assert_eq!(inside.relative(), "b");

    for requested in [
        "../escape",
        "child/../../escape",
        "/srv/bridge/rooted/file",
        "/srv/bridge/root/../../escape",
    ] {
        let error = RemotePath::resolve("/srv/bridge/root", requested).unwrap_err();
        assert_eq!(error.code, ErrorCode::PathOutsideRoot, "{requested}");
    }
}

#[test]
fn remote_paths_reject_nul_and_non_absolute_roots() {
    for (root, requested) in [
        ("relative/root", "file"),
        ("/safe\0root", "file"),
        ("/safe/root", "bad\0file"),
    ] {
        let error = RemotePath::resolve(root, requested).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }
}

#[test]
fn config_loads_defaults_and_resolves_exact_aliases_with_overrides() {
    let root = TempDir::new().unwrap();
    let file = write_config(&valid_config(root.path()));
    let config = Config::load(file.path()).unwrap();

    assert_eq!(config.version, 1);
    assert_eq!(config.limits, Limits::default());
    let host = config.host("devbox").unwrap();
    assert_eq!(host.alias, "devbox");
    assert_eq!(host.profile.root, root.path().display().to_string());
    assert_eq!(host.profile.description.as_deref(), Some("development box"));
    assert!(!host.profile.read_only);
    assert_eq!(host.limits.connect_timeout_ms, 2_500);
    assert_eq!(host.limits.command_timeout_ms, 300_000);
    assert_eq!(host.limits.max_read_bytes, 512 * 1024);
    assert_eq!(host.limits.max_write_bytes, MAX_WRITE_BYTES);
    assert_eq!(host.limits.per_host_concurrency, 1);

    assert!(config.host("DevBox").is_err());
    assert!(config.host("devbox.example").is_err());
}

#[test]
fn config_rejects_unsupported_version_when_loading_and_saving() {
    for version in [0, 2] {
        let file = write_config(&format!("version = {version}\n[hosts]\n"));
        let load_error = Config::load(file.path()).unwrap_err();
        assert_eq!(
            load_error.code,
            ErrorCode::InvalidConfig,
            "load version={version}"
        );

        let config = Config {
            version,
            ..Config::default()
        };
        let directory = TempDir::new().unwrap();
        let destination = directory.path().join("config.toml");
        let save_error = config.save_atomic(&destination).unwrap_err();
        assert_eq!(
            save_error.code,
            ErrorCode::InvalidConfig,
            "save version={version}"
        );
        assert!(!destination.exists(), "save version={version}");
    }
}

#[test]
fn config_defaults_match_compiled_limits() {
    let limits = Limits::default();
    assert_eq!(limits.connect_timeout_ms, 10_000);
    assert_eq!(limits.command_timeout_ms, 300_000);
    assert_eq!(limits.max_frame_bytes, MAX_FRAME_BYTES);
    assert_eq!(limits.read_chunk_bytes, 256 * 1024);
    assert_eq!(limits.max_read_bytes, MAX_READ_BYTES);
    assert_eq!(limits.max_write_bytes, MAX_WRITE_BYTES);
    assert_eq!(limits.preview_bytes, 256 * 1024);
    assert_eq!(limits.max_output_bytes, MAX_OUTPUT_BYTES);
    assert_eq!(limits.global_concurrency, 8);
    assert_eq!(limits.per_host_concurrency, 2);
}

#[test]
fn task8_spool_limit_config_defaults_and_exact_bounds_are_frozen() {
    let limits = Limits::default();
    assert_eq!(
        limits.global_spool_quota_bytes,
        DEFAULT_GLOBAL_SPOOL_QUOTA_BYTES
    );
    assert_eq!(
        limits.retention_serialization_jobs,
        DEFAULT_RETENTION_SERIALIZATION_JOBS
    );
    assert_eq!(DEFAULT_GLOBAL_SPOOL_QUOTA_BYTES, 512 * 1024 * 1024);
    assert_eq!(MIN_GLOBAL_SPOOL_QUOTA_BYTES, 64 * 1024 * 1024);
    assert_eq!(MAX_GLOBAL_SPOOL_QUOTA_BYTES, 512 * 1024 * 1024);
    assert_eq!(DEFAULT_RETENTION_SERIALIZATION_JOBS, 2);
    assert_eq!(MAX_RETENTION_SERIALIZATION_JOBS, 4);

    for quota in [MIN_GLOBAL_SPOOL_QUOTA_BYTES, MAX_GLOBAL_SPOOL_QUOTA_BYTES] {
        let file = write_config(&format!(
            "[limits]\nglobal_spool_quota_bytes = {quota}\nretention_serialization_jobs = 1\n[hosts]\n"
        ));
        assert!(Config::load(file.path()).is_ok(), "quota={quota}");
    }
}

#[test]
fn task8_spool_limit_config_rejects_quota_and_job_count_outside_bounds() {
    for limit in [
        format!(
            "global_spool_quota_bytes = {}",
            MIN_GLOBAL_SPOOL_QUOTA_BYTES - 1
        ),
        format!(
            "global_spool_quota_bytes = {}",
            MAX_GLOBAL_SPOOL_QUOTA_BYTES + 1
        ),
        "retention_serialization_jobs = 0".to_owned(),
        format!(
            "retention_serialization_jobs = {}",
            MAX_RETENTION_SERIALIZATION_JOBS + 1
        ),
    ] {
        let file = write_config(&format!("[limits]\n{limit}\n[hosts]\n"));
        let error = Config::load(file.path()).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidConfig, "{limit}");
    }
}

fn config_with_root(root: String) -> Config {
    Config {
        version: 1,
        limits: Limits::default(),
        hosts: std::collections::BTreeMap::from([(
            "dev".to_owned(),
            HostProfile {
                root,
                description: None,
                read_only: false,
                limits: HostLimitOverrides::default(),
            },
        )]),
    }
}

#[test]
fn task78_configured_root_byte_bound_ascii_is_enforced_after_normalization() {
    let exact = format!("/{}", "a".repeat(65_535));
    assert_eq!(exact.len(), 65_536);
    assert!(config_with_root(exact.clone()).host("dev").is_ok());

    let error = config_with_root(format!("{exact}a"))
        .host("dev")
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidConfig);
}

#[test]
fn task78_configured_root_byte_bound_utf8_is_enforced_by_bytes() {
    let exact = format!("/{}a", "é".repeat(32_767));
    assert_eq!(exact.len(), 65_536);
    assert!(exact.chars().count() < 65_536);
    assert!(config_with_root(exact.clone()).host("dev").is_ok());

    let error = config_with_root(format!("{exact}a"))
        .host("dev")
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidConfig);
}

#[test]
fn config_rejects_unknown_fields_at_every_toml_layer() {
    let cases = [
        "unknown = true\n[hosts]\n",
        "[limits]\nunknown = 1\n[hosts]\n",
        "[hosts.dev]\nroot = \"/srv/dev\"\nunknown = true\n",
        "[hosts.dev]\nroot = \"/srv/dev\"\n[hosts.dev.limits]\nunknown = 1\n",
    ];

    for contents in cases {
        let file = write_config(contents);
        let error = Config::load(file.path()).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidConfig, "{contents}");
    }
}

#[test]
fn config_rejects_invalid_aliases_and_roots() {
    let cases = [
        "[hosts.\"-bad\"]\nroot = \"/srv/dev\"\n",
        "[hosts.\"bad alias\"]\nroot = \"/srv/dev\"\n",
        "[hosts.dev]\nroot = \"relative/path\"\n",
    ];

    for contents in cases {
        let file = write_config(contents);
        let error = Config::load(file.path()).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidConfig, "{contents}");
    }

    let too_long = "a".repeat(129);
    let file = write_config(&format!("[hosts.{too_long}]\nroot = \"/srv/dev\"\n"));
    assert_eq!(
        Config::load(file.path()).unwrap_err().code,
        ErrorCode::InvalidConfig
    );
}

#[test]
fn config_rejects_zero_and_over_ceiling_global_limits() {
    let cases = [
        "connect_timeout_ms = 120001",
        "command_timeout_ms = 3600001",
        "max_frame_bytes = 8388609",
        "read_chunk_bytes = 1048577",
        "max_read_bytes = 1048577",
        "max_write_bytes = 4194305",
        "preview_bytes = 1048577",
        "max_output_bytes = 67108865",
        "global_concurrency = 33",
        "per_host_concurrency = 9",
        "max_read_bytes = 0",
        "global_concurrency = 0",
        "global_concurrency = 1\nper_host_concurrency = 2",
    ];

    for limit in cases {
        let file = write_config(&format!("[limits]\n{limit}\n[hosts]\n"));
        let error = Config::load(file.path()).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidConfig, "{limit}");
    }
}

#[test]
fn config_rejects_zero_over_ceiling_and_over_global_host_overrides() {
    let cases = [
        "connect_timeout_ms = 120001",
        "command_timeout_ms = 3600001",
        "max_read_bytes = 1048577",
        "max_write_bytes = 4194305",
        "preview_bytes = 1048577",
        "max_output_bytes = 67108865",
        "per_host_concurrency = 9",
        "max_read_bytes = 0",
        "per_host_concurrency = 0",
        "per_host_concurrency = 3",
    ];

    for limit in cases {
        let file = write_config(&format!(
            "[limits]\nglobal_concurrency = 2\n[hosts.dev]\nroot = \"/srv/dev\"\n[hosts.dev.limits]\n{limit}\n"
        ));
        let error = Config::load(file.path()).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidConfig, "{limit}");
    }
}

#[cfg(unix)]
#[test]
fn config_rejects_unsafe_modes_non_regular_files_and_symlinks() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let directory = TempDir::new().unwrap();
    let unsafe_path = directory.path().join("unsafe.toml");
    fs::write(&unsafe_path, "[hosts]\n").unwrap();
    fs::set_permissions(&unsafe_path, fs::Permissions::from_mode(0o620)).unwrap();
    let mode_error = Config::load(&unsafe_path).unwrap_err();
    assert_eq!(mode_error.code, ErrorCode::InvalidConfig);

    fs::set_permissions(&unsafe_path, fs::Permissions::from_mode(0o602)).unwrap();
    let other_write_error = Config::load(&unsafe_path).unwrap_err();
    assert_eq!(other_write_error.code, ErrorCode::InvalidConfig);

    let non_regular = directory.path().join("directory.toml");
    fs::create_dir(&non_regular).unwrap();
    let file_type_error = Config::load(&non_regular).unwrap_err();
    assert_eq!(file_type_error.code, ErrorCode::InvalidConfig);

    let target = directory.path().join("target.toml");
    fs::write(&target, "[hosts]\n").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    let link = directory.path().join("link.toml");
    symlink(&target, &link).unwrap();
    let link_error = Config::load(&link).unwrap_err();
    assert_eq!(link_error.code, ErrorCode::InvalidConfig);
}

#[cfg(unix)]
#[test]
fn config_load_fifo_in_isolated_child_process() {
    let Some(fifo) = std::env::var_os(FIFO_CHILD_SENTINEL) else {
        return;
    };

    let error = Config::load(Path::new(&fifo)).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidConfig);
}

#[cfg(unix)]
#[test]
#[allow(unsafe_code)]
fn config_load_rejects_fifo_before_the_deadline() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let directory = TempDir::new().unwrap();
    let fifo = directory.path().join("config.fifo");
    let fifo_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: fifo_path is a live NUL-terminated string and mode has the
    // expected mode_t representation.
    let result = unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) };
    assert_eq!(
        result,
        0,
        "mkfifo failed: {}",
        std::io::Error::last_os_error()
    );

    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "config_load_fifo_in_isolated_child_process",
            "--nocapture",
        ])
        .env(FIFO_CHILD_SENTINEL, &fifo)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);

    loop {
        match child.try_wait().unwrap() {
            Some(_) => {
                let output = child.wait_with_output().unwrap();
                assert!(
                    output.status.success(),
                    "FIFO child failed\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                break;
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "FIFO child exceeded its one-second deadline\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}

#[test]
fn missing_config_is_a_typed_error_and_is_not_created() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("missing.toml");
    let error = Config::load(&path).unwrap_err();
    assert!(matches!(
        error.code,
        ErrorCode::Io | ErrorCode::InvalidConfig
    ));
    assert!(!path.exists());
}

#[cfg(target_os = "linux")]
#[test]
#[allow(unsafe_code)]
fn config_load_never_reads_a_different_inode_after_security_validation() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier};

    fn exchange(left: &Path, right: &Path) {
        let left = CString::new(left.as_os_str().as_bytes()).unwrap();
        let right = CString::new(right.as_os_str().as_bytes()).unwrap();
        // SAFETY: both C strings are NUL-terminated and remain alive for the
        // syscall; AT_FDCWD makes their absolute paths self-contained.
        let result = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                left.as_ptr(),
                libc::AT_FDCWD,
                right.as_ptr(),
                libc::RENAME_EXCHANGE,
            )
        };
        assert_eq!(
            result,
            0,
            "renameat2 failed: {}",
            std::io::Error::last_os_error()
        );
    }

    let directory = TempDir::new().unwrap();
    let config_path = directory.path().join("config.toml");
    let alternate_path = directory.path().join("alternate");
    let untrusted_path = directory.path().join("untrusted.toml");
    fs::write(&config_path, "[hosts.safe]\nroot = \"/srv/safe\"\n").unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(
        &untrusted_path,
        "[hosts.untrusted]\nroot = \"/srv/untrusted\"\n",
    )
    .unwrap();
    fs::set_permissions(&untrusted_path, fs::Permissions::from_mode(0o666)).unwrap();
    symlink(&untrusted_path, &alternate_path).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(2));
    let swap_stop = Arc::clone(&stop);
    let swap_barrier = Arc::clone(&barrier);
    let swap_config_path = config_path.clone();
    let swap_alternate_path = alternate_path.clone();
    let swapper = std::thread::spawn(move || {
        swap_barrier.wait();
        while !swap_stop.load(Ordering::Relaxed) {
            exchange(&swap_config_path, &swap_alternate_path);
        }
    });

    barrier.wait();
    let mut accepted_untrusted_inode = false;
    for _ in 0..50_000 {
        if let Ok(config) = Config::load(&config_path)
            && config.hosts.contains_key("untrusted")
        {
            accepted_untrusted_inode = true;
            break;
        }
    }
    stop.store(true, Ordering::Relaxed);
    swapper.join().unwrap();

    assert!(
        !accepted_untrusted_inode,
        "Config::load read an inode other than the one whose metadata it validated"
    );
}

#[test]
fn config_load_default_in_isolated_child_process() {
    let Ok(case) = std::env::var(LOAD_DEFAULT_CHILD_SENTINEL) else {
        return;
    };

    let loaded = Config::load_default().unwrap();
    match case.as_str() {
        "override" => {
            let expected = std::env::var_os("CODEX_SSH_BRIDGE_CONFIG").unwrap();
            assert_eq!(loaded.source.path, Path::new(&expected));
            assert!(loaded.source.from_environment);
            assert!(
                loaded
                    .source
                    .warning
                    .as_deref()
                    .unwrap()
                    .contains("CODEX_SSH_BRIDGE_CONFIG is trusted execution-authority input")
            );
            assert!(loaded.config.hosts.is_empty());
        }
        "xdg" => {
            let expected = Path::new(&std::env::var_os("XDG_CONFIG_HOME").unwrap())
                .join("codex-ssh-bridge/config.toml");
            assert_eq!(loaded.source.path, expected);
            assert!(!loaded.source.from_environment);
            assert_eq!(loaded.source.warning, None);
            assert!(loaded.config.host("xdg").is_ok());
        }
        "home" => {
            let expected = Path::new(&std::env::var_os("HOME").unwrap())
                .join(".config/codex-ssh-bridge/config.toml");
            assert_eq!(loaded.source.path, expected);
            assert!(!loaded.source.from_environment);
            assert_eq!(loaded.source.warning, None);
            assert!(loaded.config.host("home").is_ok());
        }
        unexpected => panic!("unexpected child case: {unexpected}"),
    }
}

#[test]
fn environment_config_path_is_marked_as_trusted_execution_authority_input() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("config.toml");
    fs::write(&path, "[hosts]\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut child = load_default_child("override");
    child
        .env("CODEX_SSH_BRIDGE_CONFIG", &path)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME");
    assert_child_passes(child);
}

#[test]
fn default_config_path_prefers_xdg_then_falls_back_to_home() {
    let directory = TempDir::new().unwrap();
    let xdg = directory.path().join("xdg");
    let home = directory.path().join("home");
    let xdg_config = xdg.join("codex-ssh-bridge/config.toml");
    let home_config = home.join(".config/codex-ssh-bridge/config.toml");
    fs::create_dir_all(xdg_config.parent().unwrap()).unwrap();
    fs::create_dir_all(home_config.parent().unwrap()).unwrap();
    fs::write(&xdg_config, "[hosts.xdg]\nroot = \"/srv/xdg\"\n").unwrap();
    fs::write(&home_config, "[hosts.home]\nroot = \"/srv/home\"\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&xdg_config, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&home_config, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut xdg_child = load_default_child("xdg");
    xdg_child
        .env_remove("CODEX_SSH_BRIDGE_CONFIG")
        .env("XDG_CONFIG_HOME", &xdg)
        .env("HOME", &home);
    assert_child_passes(xdg_child);

    let mut home_child = load_default_child("home");
    home_child
        .env_remove("CODEX_SSH_BRIDGE_CONFIG")
        .env_remove("XDG_CONFIG_HOME")
        .env("HOME", &home);
    assert_child_passes(home_child);
}

#[cfg(unix)]
#[test]
fn atomic_save_writes_mode_0600_and_round_trips() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let root = TempDir::new().unwrap();
    let source = write_config(&valid_config(root.path()));
    let config = Config::load(source.path()).unwrap();
    let directory = TempDir::new().unwrap();
    let destination = directory.path().join("saved.toml");
    let witness = directory.path().join("old-inode-witness");
    fs::write(&destination, b"original destination bytes").unwrap();
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&destination, &witness).unwrap();
    let old_inode = fs::metadata(&witness).unwrap().ino();

    config.save_atomic(&destination).unwrap();

    assert_eq!(fs::read(&witness).unwrap(), b"original destination bytes");
    assert_eq!(fs::metadata(&witness).unwrap().ino(), old_inode);
    assert_ne!(fs::metadata(&destination).unwrap().ino(), old_inode);
    assert_eq!(
        fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let loaded = Config::load(&destination).unwrap();
    assert_eq!(loaded, config);
    let mut entries: Vec<_> = fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    entries.sort();
    assert_eq!(entries, ["old-inode-witness", "saved.toml"]);
}

#[test]
fn failed_atomic_save_preserves_destination_and_leaves_no_temporary_file() {
    let root = TempDir::new().unwrap();
    let source = write_config(&valid_config(root.path()));
    let config = Config::load(source.path()).unwrap();
    let directory = TempDir::new().unwrap();
    let destination = directory.path().join("existing-directory");
    let marker = destination.join("marker");
    fs::create_dir(&destination).unwrap();
    fs::write(&marker, b"must survive").unwrap();

    assert!(config.save_atomic(&destination).is_err());

    assert!(destination.is_dir());
    assert_eq!(fs::read(&marker).unwrap(), b"must survive");
    let entries: Vec<_> = fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries, ["existing-directory"]);
}

#[test]
fn bridge_errors_serialize_codes_and_omit_empty_details() {
    let error = shell_word("bad\0word").unwrap_err();
    assert!(!error.retryable);
    let value = serde_json::to_value(error).unwrap();
    assert_eq!(value["code"], "INVALID_ARGUMENT");
    assert_eq!(value["details"], serde_json::json!({}));
}

#[test]
fn command_timeout_and_forced_termination_details_serialize_stably() {
    let mut error = BridgeError::new(ErrorCode::CommandTimeout, "command timed out", false);
    error.details.remote_process_may_continue = Some(true);
    error.details.bytes_seen = Some(65_537);

    let value = serde_json::to_value(error).unwrap();
    assert_eq!(value["code"], "COMMAND_TIMEOUT");
    assert_eq!(value["details"]["remote_process_may_continue"], true);
    assert_eq!(value["details"]["bytes_seen"], 65_537);
}
