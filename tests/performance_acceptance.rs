use std::collections::BTreeMap;
use std::ffi::OsString;
use std::hint::black_box;
use std::io::{BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use codex_ssh_bridge::config::{Config, HostLimitOverrides, HostProfile};
use codex_ssh_bridge::mcp::stdio::{exact_tools_list_response_bytes, required_mcp_frame_bytes};
use codex_ssh_bridge::mcp::tools::{RemoteMcpTools, tool_definitions};
use codex_ssh_bridge::mcp::{
    McpServer, RequestId, ToolCallContext, ToolService, WireBudget,
    maximum_compact_fallback_result_bytes, parse_strict_json,
};
use codex_ssh_bridge::output::OutputStore;
use codex_ssh_bridge::remote::RemoteBridge;
use codex_ssh_bridge::remote_helper_protocol::{Frame, FrameKind, read_frame, write_frame};
use codex_ssh_bridge::ssh::{RuntimePaths, SshRunner};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

#[allow(dead_code)]
mod support;

const DISPATCH_WARM_CALLS: usize = 16;
const DISPATCH_MEASURED_CALLS: usize = 200;
const SSH_WARM_CALLS: usize = 16;
const SSH_MEASURED_CALLS: usize = 120;
const DISPATCH_P95_CEILING: Duration = Duration::from_millis(2);
// A persistent SSH transport removes handshake and setup probes from warm
// requests. The fake transport's p95 therefore measures the complete framed
// request path, including the remote process and output capture.
const SSH_P95_CEILING: Duration = Duration::from_millis(250);
const FIVE_HOST_CEILING: Duration = Duration::from_millis(1_500);
const CANCELLATION_CEILING: Duration = Duration::from_millis(250);
const OUTPUT_RSS_CEILING_KIB: u64 = 32 * 1024;
const WIDE_JSON_RSS_CEILING_KIB: u64 = 48 * 1024;

struct FakeFixture {
    _runtime_base: TempDir,
    tools: RemoteMcpTools,
    log: std::path::PathBuf,
    install_log: PathBuf,
    helper_bytes_log: PathBuf,
}

fn fake_fixture(hosts: &[&str], environment: &[(&str, OsString)]) -> FakeFixture {
    let runtime_base = TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let config = Config {
        hosts: hosts
            .iter()
            .map(|host| {
                (
                    (*host).to_owned(),
                    HostProfile {
                        root: "/srv/project".to_owned(),
                        description: None,
                        read_only: false,
                        limits: HostLimitOverrides::default(),
                    },
                )
            })
            .collect(),
        ..Config::default()
    };
    let log = runtime_base.path().join("ssh.log");
    let mut fixed_environment =
        BTreeMap::from([(OsString::from("FAKE_SSH_LOG"), log.as_os_str().to_owned())]);
    for (key, value) in environment {
        fixed_environment.insert(OsString::from(key), value.clone());
    }
    let runner = Arc::new(
        SshRunner::with_executable(
            Arc::new(config),
            runtime,
            store,
            support::fake_ssh_path(),
            fixed_environment,
        )
        .unwrap(),
    );
    let bridge = Arc::new(RemoteBridge::new(runner));
    let install_log = runtime_base.path().join("install.log");
    let helper_bytes_log = runtime_base.path().join("helper-bytes.log");
    FakeFixture {
        _runtime_base: runtime_base,
        tools: RemoteMcpTools::new(bridge),
        log,
        install_log,
        helper_bytes_log,
    }
}

fn persistent_fake_fixture(remote_home: &Path) -> FakeFixture {
    let runtime_base = TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let mut config = Config::default();
    config.hosts.insert(
        "dev".to_owned(),
        codex_ssh_bridge::config::HostProfile {
            root: "/tmp".to_owned(),
            description: None,
            read_only: false,
            limits: HostLimitOverrides::default(),
        },
    );
    let log = runtime_base.path().join("ssh.log");
    let install_log = runtime_base.path().join("install.log");
    let helper_bytes_log = runtime_base.path().join("helper-bytes.log");
    let fixed_environment = BTreeMap::from([
        (OsString::from("FAKE_SSH_LOG"), log.as_os_str().to_owned()),
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (OsString::from("FAKE_SSH_ROOT"), OsString::from("/tmp")),
        (OsString::from("FAKE_SSH_SHELL"), OsString::from("sh")),
        (
            OsString::from("FAKE_SSH_INSTALL_LOG"),
            install_log.as_os_str().to_owned(),
        ),
        (
            OsString::from("FAKE_SSH_HELPER_BYTES_LOG"),
            helper_bytes_log.as_os_str().to_owned(),
        ),
        (OsString::from("HOME"), remote_home.as_os_str().to_owned()),
    ]);
    let runner = Arc::new(
        SshRunner::with_executable(
            Arc::new(config),
            runtime,
            store,
            support::fake_ssh_path(),
            fixed_environment,
        )
        .unwrap(),
    );
    FakeFixture {
        _runtime_base: runtime_base,
        tools: RemoteMcpTools::new(Arc::new(RemoteBridge::new(runner))),
        log,
        install_log,
        helper_bytes_log,
    }
}

fn roomy_context() -> ToolCallContext {
    ToolCallContext {
        cancel: CancellationToken::new(),
        wire_budget: WireBudget {
            result_bytes: codex_ssh_bridge::MAX_FRAME_BYTES,
            compact_fallback_bytes: maximum_compact_fallback_result_bytes(),
        },
    }
}

async fn call_json(tools: &RemoteMcpTools, name: &str, arguments: Value) -> Value {
    serde_json::to_value(
        tools
            .call(name.to_owned(), arguments, roomy_context())
            .await,
    )
    .unwrap()
}

fn duration_percentiles(samples: &mut [Duration]) -> (Duration, Duration, Duration) {
    assert!(
        samples.len() >= 100,
        "latency acceptance requires >=100 samples"
    );
    samples.sort_unstable();
    let percentile = |percent: usize| samples[(samples.len() * percent).div_ceil(100) - 1];
    (percentile(50), percentile(95), *samples.last().unwrap())
}

fn short_duration_percentiles(samples: &mut [Duration]) -> (Duration, Duration, Duration) {
    assert!(!samples.is_empty());
    samples.sort_unstable();
    let p95 = samples[(samples.len() * 95).div_ceil(100) - 1];
    (samples[samples.len() / 2], p95, *samples.last().unwrap())
}

fn report_latency(label: &str, samples: &mut [Duration]) -> (Duration, Duration, Duration) {
    let (p50, p95, maximum) = duration_percentiles(samples);
    eprintln!(
        "Task11 {label}: samples={} p50={p50:?} p95={p95:?} max={maximum:?}",
        samples.len()
    );
    (p50, p95, maximum)
}

#[tokio::test(flavor = "current_thread")]
async fn task11_release_cold_and_warm_ssh_profile() {
    if cfg!(debug_assertions) {
        eprintln!("Task11 cold/warm profile acceptance is release-only");
        return;
    }

    const COLD_MEASURED_CALLS: usize = 100;
    let mut cold_samples = Vec::with_capacity(COLD_MEASURED_CALLS);
    for _ in 0..COLD_MEASURED_CALLS {
        let fixture = fake_fixture(
            &["dev"],
            &[
                ("FAKE_SSH_MODE", OsString::from("streams")),
                ("FAKE_SSH_STDOUT", OsString::from("cold")),
                ("FAKE_SSH_STDERR", OsString::new()),
            ],
        );
        let started = Instant::now();
        let result = call_json(
            &fixture.tools,
            "remote_run",
            json!({"host":"dev","command":":","shell":"sh"}),
        )
        .await;
        cold_samples.push(started.elapsed());
        assert_eq!(result["isError"], Value::Null, "{result}");
    }
    let (_, cold_p95, _) = report_latency("cold complete fake-SSH call", &mut cold_samples);

    let warm = fake_fixture(
        &["dev"],
        &[
            ("FAKE_SSH_MODE", OsString::from("streams")),
            ("FAKE_SSH_STDOUT", OsString::from("warm")),
            ("FAKE_SSH_STDERR", OsString::new()),
        ],
    );
    let arguments = json!({"host":"dev","command":":","shell":"sh"});
    for _ in 0..SSH_WARM_CALLS {
        let result = call_json(&warm.tools, "remote_run", arguments.clone()).await;
        assert_eq!(result["isError"], Value::Null, "{result}");
    }
    let mut warm_samples = Vec::with_capacity(SSH_MEASURED_CALLS);
    for _ in 0..SSH_MEASURED_CALLS {
        let started = Instant::now();
        let result = call_json(&warm.tools, "remote_run", arguments.clone()).await;
        warm_samples.push(started.elapsed());
        assert_eq!(result["isError"], Value::Null, "{result}");
    }
    let (_, warm_p95, _) = report_latency("warm complete fake-SSH call", &mut warm_samples);
    assert!(
        warm_p95 < SSH_P95_CEILING,
        "warm complete fake-SSH p95={warm_p95:?} exceeded broad regression ceiling"
    );
    eprintln!("Task11 cold/warm separation: cold_p95={cold_p95:?} warm_p95={warm_p95:?}");
    let warm_kinds = transport_call_kinds(&warm.log);
    assert_eq!(warm_kinds.iter().filter(|kind| **kind == "G").count(), 1);
    assert_eq!(warm_kinds.iter().filter(|kind| **kind == "P").count(), 1);
    assert_eq!(warm_kinds.iter().filter(|kind| **kind == "R").count(), 0);
    assert_eq!(
        warm_kinds.iter().filter(|kind| **kind == "C").count(),
        SSH_WARM_CALLS + SSH_MEASURED_CALLS
    );
}

fn helper_release_path() -> std::path::PathBuf {
    std::env::var("CARGO_BIN_EXE_codex-ssh-bridge-helper")
        .or_else(|_| std::env::var("CARGO_BIN_EXE_codex_ssh_bridge_helper"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target/release/codex-ssh-bridge-helper")
        })
}

fn send_profile_request(writer: &mut impl Write, request_id: u64) {
    let metadata = b"shell=sh\ncwd_length=4\ncommand_length=1\nstdin_length=0\ntimeout_ms=1000\nstdout_limit=1024\nstderr_limit=1024\n";
    for frame in [
        Frame {
            kind: FrameKind::Open,
            request_id,
            payload: metadata.to_vec(),
        },
        Frame {
            kind: FrameKind::Data,
            request_id,
            payload: b"/tmp".to_vec(),
        },
        Frame {
            kind: FrameKind::Data,
            request_id,
            payload: b":".to_vec(),
        },
    ] {
        write_frame(writer, &frame, 64 * 1024).unwrap();
    }
    writer.flush().unwrap();
}

fn wait_profile_exit(reader: &mut BufReader<impl std::io::Read>, request_id: u64) {
    loop {
        let frame = read_frame(reader, 64 * 1024)
            .unwrap()
            .expect("profile transport closed before EXIT");
        assert_eq!(frame.request_id, request_id);
        if frame.kind == FrameKind::Exit {
            return;
        }
    }
}

fn install_release_helper_fixture() -> Option<PathBuf> {
    let source = helper_release_path();
    if !source.is_file() {
        return None;
    }
    let target_name = match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-musl",
        "aarch64" => "aarch64-unknown-linux-musl",
        "arm" => "armv7-unknown-linux-musleabihf",
        _ => return None,
    };
    let directory = std::env::current_exe()
        .ok()?
        .parent()?
        .join("remote-helpers");
    std::fs::create_dir_all(&directory).ok()?;
    let target = directory.join(target_name);
    std::fs::copy(source, &target).ok()?;
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).ok()?;
    Some(target)
}

fn recorded_lines(path: &Path) -> Vec<u64> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.parse().ok())
        .collect()
}

#[tokio::test(flavor = "current_thread")]
async fn task12_release_persistent_helper_cold_reuse_warm_profile() {
    if cfg!(debug_assertions) {
        eprintln!("Task12 persistent helper profile is release-only");
        return;
    }
    let Some(helper_path) = install_release_helper_fixture() else {
        eprintln!("Task12 persistent helper profile skipped: release helper unavailable");
        return;
    };

    let mut install_samples = Vec::new();
    for _ in 0..3 {
        let remote_home = TempDir::new().unwrap();
        let fixture = persistent_fake_fixture(remote_home.path());
        let started = Instant::now();
        let result = call_json(
            &fixture.tools,
            "remote_run",
            json!({"host":"dev","command":"printf install","shell":"sh"}),
        )
        .await;
        assert_eq!(result["isError"], Value::Null, "{result}");
        install_samples.push(started.elapsed());
        assert!(
            recorded_lines(&fixture.helper_bytes_log)
                .first()
                .is_some_and(|n| *n > 0)
        );
    }

    let remote_home = TempDir::new().unwrap();
    let first = persistent_fake_fixture(remote_home.path());
    let started = Instant::now();
    let result = call_json(
        &first.tools,
        "remote_run",
        json!({"host":"dev","command":"printf first","shell":"sh"}),
    )
    .await;
    assert_eq!(result["isError"], Value::Null, "{result}");
    let install_cold = started.elapsed();
    drop(first);

    let reuse = persistent_fake_fixture(remote_home.path());
    let started = Instant::now();
    let result = call_json(
        &reuse.tools,
        "remote_run",
        json!({"host":"dev","command":"printf reuse","shell":"sh"}),
    )
    .await;
    assert_eq!(result["isError"], Value::Null, "{result}");
    let reuse_cold = started.elapsed();
    assert_eq!(
        std::fs::read_to_string(&reuse.install_log).unwrap(),
        "HIT\n"
    );
    assert_eq!(recorded_lines(&reuse.helper_bytes_log), vec![0]);

    let mut persistent_warm = Vec::new();
    for _ in 0..32 {
        let started = Instant::now();
        let result = call_json(
            &reuse.tools,
            "remote_run",
            json!({"host":"dev","command":"printf warm","shell":"sh"}),
        )
        .await;
        assert_eq!(result["isError"], Value::Null, "{result}");
        persistent_warm.push(started.elapsed());
    }
    assert_eq!(recorded_lines(&reuse.helper_bytes_log), vec![0]);

    let shell = fake_fixture(
        &["dev"],
        &[
            ("FAKE_SSH_MODE", OsString::from("streams")),
            ("FAKE_SSH_STDOUT", OsString::from("shell-warm")),
            ("FAKE_SSH_STDERR", OsString::new()),
        ],
    );
    let mut shell_warm = Vec::new();
    for _ in 0..32 {
        let started = Instant::now();
        let result = call_json(
            &shell.tools,
            "remote_run",
            json!({"host":"dev","command":":","shell":"sh"}),
        )
        .await;
        assert_eq!(result["isError"], Value::Null, "{result}");
        shell_warm.push(started.elapsed());
    }
    let (install_p50, install_p95, _) = short_duration_percentiles(&mut install_samples);
    let mut reuse_samples = [reuse_cold];
    let (reuse_p50, reuse_p95, _) = short_duration_percentiles(&mut reuse_samples);
    let (persistent_p50, persistent_p95, _) = short_duration_percentiles(&mut persistent_warm);
    let (shell_p50, shell_p95, _) = short_duration_percentiles(&mut shell_warm);
    eprintln!(
        "Task12 persistent profile: persistent_install_cold={install_p50:?}/{install_p95:?} first_install={install_cold:?} persistent_reuse_cold={reuse_p50:?}/{reuse_p95:?} persistent_warm={persistent_p50:?}/{persistent_p95:?} shell_warm={shell_p50:?}/{shell_p95:?} warm_persistent_upload_bytes=0"
    );
    let _ = std::fs::remove_file(helper_path);
}

fn close_profile_child(mut child: std::process::Child, mut writer: impl Write) {
    write_frame(
        &mut writer,
        &Frame {
            kind: FrameKind::Close,
            request_id: 0,
            payload: Vec::new(),
        },
        64 * 1024,
    )
    .unwrap();
    writer.flush().unwrap();
    drop(writer);
    assert!(child.wait().unwrap().success());
}

#[test]
fn task12_release_helper_and_shell_cold_warm_profile() {
    if cfg!(debug_assertions) {
        eprintln!("Task12 helper profile is release-only");
        return;
    }
    let helper_path = helper_release_path();
    if !helper_path.is_file() {
        eprintln!("Task12 helper profile skipped: release helper binary is unavailable");
        return;
    }
    let dispatcher = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/ssh/dispatcher.sh"),
    )
    .unwrap();
    let mut helper_cold = Vec::new();
    let mut shell_cold = Vec::new();
    for _ in 0..8 {
        let started = Instant::now();
        let mut child = Command::new(&helper_path)
            .args(["--max-frame", "65536"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let writer = child.stdin.take().unwrap();
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        assert_eq!(
            read_frame(&mut reader, 65536).unwrap().unwrap().kind,
            FrameKind::HelloAck
        );
        helper_cold.push(started.elapsed());
        close_profile_child(child, writer);

        let started = Instant::now();
        let mut child = Command::new("/bin/sh")
            .args(["-c", &dispatcher, "--", "codex-ssh-dispatcher-1", "65536"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let writer = child.stdin.take().unwrap();
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        assert_eq!(
            read_frame(&mut reader, 65536).unwrap().unwrap().kind,
            FrameKind::HelloAck
        );
        shell_cold.push(started.elapsed());
        close_profile_child(child, writer);
    }

    let mut shell = Command::new("/bin/sh")
        .args(["-c", &dispatcher, "--", "codex-ssh-dispatcher-1", "65536"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut shell_writer = shell.stdin.take().unwrap();
    let mut shell_reader = BufReader::new(shell.stdout.take().unwrap());
    assert_eq!(
        read_frame(&mut shell_reader, 65536).unwrap().unwrap().kind,
        FrameKind::HelloAck
    );
    let mut shell_warm = Vec::new();
    for request_id in 1..=32 {
        let started = Instant::now();
        send_profile_request(&mut shell_writer, request_id);
        wait_profile_exit(&mut shell_reader, request_id);
        shell_warm.push(started.elapsed());
    }
    close_profile_child(shell, shell_writer);

    let mut helper = Command::new(&helper_path)
        .args(["--max-frame", "65536"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut helper_writer = helper.stdin.take().unwrap();
    let mut helper_reader = BufReader::new(helper.stdout.take().unwrap());
    let _ = read_frame(&mut helper_reader, 65536).unwrap();
    let mut helper_warm = Vec::new();
    for request_id in 1..=32 {
        let started = Instant::now();
        send_profile_request(&mut helper_writer, request_id);
        wait_profile_exit(&mut helper_reader, request_id);
        helper_warm.push(started.elapsed());
    }
    close_profile_child(helper, helper_writer);

    let (helper_cold_p50, helper_cold_p95, _) = short_duration_percentiles(&mut helper_cold);
    let (shell_cold_p50, shell_cold_p95, _) = short_duration_percentiles(&mut shell_cold);
    let (shell_warm_p50, shell_warm_p95, _) = short_duration_percentiles(&mut shell_warm);
    let (helper_warm_p50, helper_warm_p95, _) = short_duration_percentiles(&mut helper_warm);
    eprintln!(
        "Task12 helper/shell cold/warm: helper_cold={helper_cold_p50:?}/{helper_cold_p95:?}, shell_cold={shell_cold_p50:?}/{shell_cold_p95:?}, helper_warm={helper_warm_p50:?}/{helper_warm_p95:?}, shell_warm={shell_warm_p50:?}/{shell_warm_p95:?}"
    );
}

fn transport_call_kinds(log: &std::path::Path) -> Vec<&'static str> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| match line {
            "G" => Some("G"),
            "P" => Some("P"),
            "R" => Some("R"),
            "C" => Some("C"),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "current_thread")]
async fn task11_release_latency_concurrency_cancellation_and_wire_acceptance() {
    if cfg!(debug_assertions) {
        eprintln!("Task11 timing acceptance is release-only");
        return;
    }

    let dispatch = fake_fixture(&["dev"], &[]);
    for _ in 0..DISPATCH_WARM_CALLS {
        black_box(call_json(&dispatch.tools, "remote_hosts", json!({})).await);
    }
    let mut dispatch_samples = Vec::with_capacity(DISPATCH_MEASURED_CALLS);
    for _ in 0..DISPATCH_MEASURED_CALLS {
        let started = Instant::now();
        let result = call_json(&dispatch.tools, "remote_hosts", json!({})).await;
        dispatch_samples.push(started.elapsed());
        assert_eq!(result["isError"], Value::Null, "{result}");
        black_box(result);
    }
    let (_, dispatch_p95, _) = report_latency("bridge dispatch", &mut dispatch_samples);
    assert!(
        dispatch_p95 < DISPATCH_P95_CEILING,
        "bridge dispatch p95={dispatch_p95:?}, samples={dispatch_samples:?}"
    );

    let complete = fake_fixture(
        &["dev"],
        &[
            ("FAKE_SSH_MODE", OsString::from("streams")),
            ("FAKE_SSH_STDOUT", OsString::from("acceptance")),
            ("FAKE_SSH_STDERR", OsString::new()),
        ],
    );
    let run_arguments = json!({"host":"dev","command":":","shell":"sh"});
    for _ in 0..SSH_WARM_CALLS {
        let result = call_json(&complete.tools, "remote_run", run_arguments.clone()).await;
        assert_eq!(result["isError"], Value::Null, "{result}");
    }
    let mut ssh_samples = Vec::with_capacity(SSH_MEASURED_CALLS);
    for _ in 0..SSH_MEASURED_CALLS {
        let started = Instant::now();
        let result = call_json(&complete.tools, "remote_run", run_arguments.clone()).await;
        ssh_samples.push(started.elapsed());
        assert_eq!(result["isError"], Value::Null, "{result}");
        black_box(result);
    }
    let (_, ssh_p95, _) = report_latency("complete fake-SSH MCP call", &mut ssh_samples);
    assert!(
        ssh_p95 < SSH_P95_CEILING,
        "complete fake-SSH call p95={ssh_p95:?}, samples={ssh_samples:?}"
    );
    let complete_kinds = transport_call_kinds(&complete.log);
    assert_eq!(
        complete_kinds.iter().filter(|kind| **kind == "G").count(),
        1
    );
    assert_eq!(
        complete_kinds.iter().filter(|kind| **kind == "P").count(),
        1
    );
    assert_eq!(
        complete_kinds.iter().filter(|kind| **kind == "R").count(),
        0
    );
    assert_eq!(
        complete_kinds.iter().filter(|kind| **kind == "C").count(),
        SSH_WARM_CALLS + SSH_MEASURED_CALLS
    );

    five_hosts_finish_in_parallel().await;
    cancellation_kills_the_entire_process_group().await;
    report_maximum_mcp_wire();
}

async fn five_hosts_finish_in_parallel() {
    let hosts = ["one", "two", "three", "four", "five"];
    let fixture = fake_fixture(
        &hosts,
        &[
            ("FAKE_SSH_MODE", OsString::from("sleep")),
            ("FAKE_SSH_SLEEP_SECONDS", OsString::from("1")),
        ],
    );
    let started = Instant::now();
    let mut operations = JoinSet::new();
    for host in hosts {
        let tools = fixture.tools.clone();
        operations.spawn(async move {
            call_json(
                &tools,
                "remote_run",
                json!({"host":host,"command":":","shell":"sh"}),
            )
            .await
        });
    }
    while let Some(operation) = operations.join_next().await {
        let result = operation.unwrap();
        assert_eq!(result["isError"], Value::Null, "{result}");
    }
    let elapsed = started.elapsed();
    let kinds = transport_call_kinds(&fixture.log);
    eprintln!(
        "Task11 five-host fake-SSH concurrency: hosts=5 remote_sleep=1s elapsed={elapsed:?} calls={kinds:?}"
    );
    assert!(
        elapsed < FIVE_HOST_CEILING,
        "five one-second hosts took {elapsed:?}"
    );
    for kind in ["G", "P", "C"] {
        assert_eq!(
            kinds.iter().filter(|observed| **observed == kind).count(),
            5,
            "each host must perform exactly one {kind} call: {kinds:?}"
        );
    }
    assert_eq!(kinds.iter().filter(|observed| **observed == "R").count(), 0);
}

async fn cancellation_kills_the_entire_process_group() {
    let files = TempDir::new().unwrap();
    let pid_file = files.path().join("child.pid");
    let fixture = fake_fixture(
        &["dev"],
        &[
            ("FAKE_SSH_MODE", OsString::from("sleep")),
            ("FAKE_SSH_SLEEP_SECONDS", OsString::from("10")),
            ("FAKE_SSH_IGNORE_TERM", OsString::from("1")),
            ("FAKE_SSH_CHILD_PID_FILE", pid_file.as_os_str().to_owned()),
        ],
    );
    let cancel = CancellationToken::new();
    let call_cancel = cancel.clone();
    let tools = fixture.tools.clone();
    let operation = tokio::spawn(async move {
        tools
            .call(
                "remote_run".to_owned(),
                json!({"host":"dev","command":":","shell":"sh"}),
                ToolCallContext {
                    cancel: call_cancel,
                    wire_budget: roomy_context().wire_budget,
                },
            )
            .await
    });
    wait_for_file(&pid_file, Duration::from_secs(2)).await;
    let pid = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse::<u32>()
        .unwrap();
    let process_group = process_group_id(pid);
    let started = Instant::now();
    cancel.cancel();
    let result = tokio::time::timeout(CANCELLATION_CEILING, operation)
        .await
        .expect("cancelled MCP call exceeded 250 ms")
        .unwrap();
    let wire = serde_json::to_value(result).unwrap();
    assert_eq!(wire["isError"], true, "{wire}");
    assert_eq!(
        wire["structuredContent"]["error"]["code"], "CANCELLED",
        "{wire}"
    );
    let remaining = CANCELLATION_CEILING
        .checked_sub(started.elapsed())
        .unwrap_or(Duration::ZERO);
    wait_for_process_group_exit(process_group, remaining).await;
    let elapsed = started.elapsed();
    eprintln!(
        "Task11 process-group cancellation: pid={pid} pgid={process_group} elapsed={elapsed:?} ceiling={CANCELLATION_CEILING:?}"
    );
    assert!(elapsed < CANCELLATION_CEILING);
}

fn report_maximum_mcp_wire() {
    let id = RequestId::synthetic_max_wire();
    let definitions = tool_definitions();
    let tools_list_bytes = exact_tools_list_response_bytes(definitions, &id).unwrap();
    let required_bytes =
        required_mcp_frame_bytes(definitions, maximum_compact_fallback_result_bytes(), &id)
            .unwrap();
    let fixture = fake_fixture(&["dev"], &[]);
    let service = Arc::new(fixture.tools);
    McpServer::new(service, codex_ssh_bridge::MAX_FRAME_BYTES).unwrap();
    eprintln!(
        "Task11 maximum MCP wire: frame_payload_bytes={} line_bytes_with_newline={} exact_tools_list_bytes={tools_list_bytes} required_server_bytes={required_bytes}",
        codex_ssh_bridge::MAX_FRAME_BYTES,
        codex_ssh_bridge::MAX_FRAME_BYTES + 1
    );
    assert_eq!(codex_ssh_bridge::MAX_FRAME_BYTES, 8 * 1024 * 1024);
    assert!(tools_list_bytes <= codex_ssh_bridge::MAX_FRAME_BYTES);
    assert!(required_bytes <= codex_ssh_bridge::MAX_FRAME_BYTES);
}

async fn wait_for_file(path: &std::path::Path, maximum: Duration) {
    tokio::time::timeout(maximum, async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {}", path.display()));
}

fn process_group_id(pid: u32) -> i32 {
    // SAFETY: getpgid only reads kernel metadata for an existing process ID.
    let group = unsafe { libc::getpgid(pid as libc::pid_t) };
    assert!(group > 0, "failed to resolve process group for PID {pid}");
    group
}

fn process_group_exists(group: i32) -> bool {
    // SAFETY: signal zero only checks existence/permission and sends no signal.
    let status = unsafe { libc::kill(-group, 0) };
    status == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

async fn wait_for_process_group_exit(group: i32, maximum: Duration) {
    tokio::time::timeout(maximum, async {
        while process_group_exists(group) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("process group {group} survived for {maximum:?}"));
}

#[test]
fn task11_release_bounded_session_output_rss_fresh_child() {
    const CHILD_ENV: &str = "CODEX_SSH_BRIDGE_TASK11_OUTPUT_RSS_CHILD";
    const TEST_NAME: &str = "task11_release_bounded_session_output_rss_fresh_child";
    if cfg!(debug_assertions) {
        eprintln!("Task11 bounded session output RSS acceptance is release-only");
        return;
    }
    if std::env::var_os(CHILD_ENV).is_some() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(output_rss_child());
        return;
    }
    run_fresh_child(CHILD_ENV, TEST_NAME, "Task11 bounded session output RSS:");
}

async fn output_rss_child() {
    // The persistent session intentionally keeps one bounded request result in
    // memory before handing it to the file-backed output store. Exercise that
    // bounded path here; the full 64 MiB quota is covered by the output-store
    // and remote-operation suites without turning this acceptance test into a
    // resident-buffer benchmark.
    const SESSION_OUTPUT_BYTES: u64 = 8 * 1024 * 1024;
    let fixture = fake_fixture(
        &["dev"],
        &[
            ("FAKE_SSH_MODE", OsString::from("bytes")),
            (
                "FAKE_SSH_STDOUT_BYTES",
                OsString::from(SESSION_OUTPUT_BYTES.to_string()),
            ),
            ("FAKE_SSH_STDERR_BYTES", OsString::from("0")),
        ],
    );
    let baseline = resident_kib();
    let tools = fixture.tools;
    let worker = tokio::spawn(async move {
        call_json(
            &tools,
            "remote_run",
            json!({"host":"dev","command":":","shell":"sh"}),
        )
        .await
    });
    let mut peak = baseline;
    while !worker.is_finished() {
        peak = peak.max(resident_kib());
        tokio::time::sleep(Duration::from_micros(250)).await;
    }
    let result = worker.await.unwrap();
    assert_eq!(result["isError"], Value::Null, "{result}");
    assert_eq!(result["structuredContent"]["exit_code"], 0);
    assert_eq!(result["structuredContent"]["truncated"], true);
    assert!(result["structuredContent"]["output_ref"].is_string());
    black_box(&result);
    for _ in 0..20 {
        peak = peak.max(resident_kib());
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let delta = peak.saturating_sub(baseline);
    eprintln!(
        "Task11 bounded session output RSS: baseline={baseline} KiB peak={peak} KiB delta={delta} KiB ceiling={OUTPUT_RSS_CEILING_KIB} KiB"
    );
    assert!(
        delta < OUTPUT_RSS_CEILING_KIB,
        "bounded session output RSS delta={delta} KiB"
    );
}

#[test]
fn task11_release_max_wide_array_rss_fresh_child() {
    run_wide_json_rss_fresh_child(
        "CODEX_SSH_BRIDGE_TASK11_WIDE_ARRAY_RSS_CHILD",
        "task11_release_max_wide_array_rss_fresh_child",
        WideJsonShape::Array,
    );
}

#[test]
fn task11_release_max_wide_object_rss_fresh_child() {
    run_wide_json_rss_fresh_child(
        "CODEX_SSH_BRIDGE_TASK11_WIDE_OBJECT_RSS_CHILD",
        "task11_release_max_wide_object_rss_fresh_child",
        WideJsonShape::Object,
    );
}

#[derive(Clone, Copy, Debug)]
enum WideJsonShape {
    Array,
    Object,
}

fn run_wide_json_rss_fresh_child(child_env: &str, test_name: &str, shape: WideJsonShape) {
    if cfg!(debug_assertions) {
        eprintln!("Task11 maximum wide {shape:?} RSS acceptance is release-only");
        return;
    }
    let marker = format!("Task11 maximum wide JSON {shape:?} RSS:");
    if std::env::var_os(child_env).is_some() {
        wide_json_rss_child(shape);
        return;
    }
    run_fresh_child(child_env, test_name, &marker);
}

fn run_fresh_child(child_env: &str, test_name: &str, marker: &str) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test_name, "--nocapture"])
        .env(child_env, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprint!("{stdout}");
    eprint!("{stderr}");
    assert!(
        output.status.success(),
        "fresh child {test_name} failed: {stderr}"
    );
    assert!(
        stdout.contains(marker) || stderr.contains(marker),
        "fresh child {test_name} did not emit {marker:?}"
    );
}

fn wide_json_rss_child(shape: WideJsonShape) {
    use std::sync::Barrier;

    const ROUNDS: usize = 4;
    let input = Arc::new(match shape {
        WideJsonShape::Array => maximum_wide_array(),
        WideJsonShape::Object => maximum_wide_object(),
    });
    black_box(
        input
            .iter()
            .step_by(4096)
            .fold(0_u8, |sum, byte| sum.wrapping_add(*byte)),
    );
    assert!(parse_strict_json(b"null").is_ok());

    let start = Arc::new(Barrier::new(2));
    let finish = Arc::new(Barrier::new(2));
    let completed = Arc::new(AtomicBool::new(false));
    let worker = {
        let input = Arc::clone(&input);
        let start = Arc::clone(&start);
        let finish = Arc::clone(&finish);
        let completed = Arc::clone(&completed);
        std::thread::spawn(move || {
            start.wait();
            for round in 0..ROUNDS {
                let parsed = parse_strict_json(&input).unwrap();
                match (shape, &parsed) {
                    (WideJsonShape::Array, Value::Array(values)) => {
                        assert_eq!(values.len(), 262_143);
                    }
                    (WideJsonShape::Object, Value::Object(values)) => {
                        assert_eq!(values.len(), 131_072);
                    }
                    _ => panic!("wide JSON shape changed"),
                }
                if round + 1 == ROUNDS {
                    completed.store(true, Ordering::Release);
                    finish.wait();
                }
                black_box(&parsed);
            }
        })
    };

    let baseline = resident_kib();
    let mut peak = baseline;
    start.wait();
    while !completed.load(Ordering::Acquire) {
        peak = peak.max(resident_kib());
        std::thread::sleep(Duration::from_micros(250));
    }
    for _ in 0..20 {
        peak = peak.max(resident_kib());
        std::thread::sleep(Duration::from_millis(1));
    }
    finish.wait();
    worker.join().unwrap();
    let delta = peak.saturating_sub(baseline);
    eprintln!(
        "Task11 maximum wide JSON {shape:?} RSS: baseline={baseline} KiB peak={peak} KiB delta={delta} KiB ceiling={WIDE_JSON_RSS_CEILING_KIB} KiB"
    );
    assert!(
        delta < WIDE_JSON_RSS_CEILING_KIB,
        "maximum wide JSON {shape:?} RSS delta={delta} KiB"
    );
}

fn maximum_wide_array() -> Vec<u8> {
    const VALUES: usize = 262_143;
    let mut input = Vec::with_capacity(VALUES * 5 + 2);
    input.push(b'[');
    for index in 0..VALUES {
        if index != 0 {
            input.push(b',');
        }
        input.extend_from_slice(b"null");
    }
    input.push(b']');
    input
}

fn maximum_wide_object() -> Vec<u8> {
    const MEMBERS: usize = 131_072;
    let mut input = Vec::with_capacity(MEMBERS * 16 + 2);
    input.push(b'{');
    for index in 0..MEMBERS {
        if index != 0 {
            input.push(b',');
        }
        use std::io::Write as _;
        write!(input, "\"{index}\":null").unwrap();
    }
    input.push(b'}');
    input
}

fn resident_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse().ok())
        })
        .unwrap()
}

#[test]
fn task11_max_output_constant_matches_64_mib() {
    assert_eq!(codex_ssh_bridge::MAX_OUTPUT_BYTES, 64 * 1024 * 1024);
}
