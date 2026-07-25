use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{BufRead, BufReader as StdBufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use codex_ssh_bridge::config::{Config, HostLimitOverrides, HostProfile};
use codex_ssh_bridge::mcp::stdio::{exact_tools_list_response_bytes, required_mcp_frame_bytes};
use codex_ssh_bridge::mcp::tools::{RemoteMcpTools, tool_definitions};
use codex_ssh_bridge::mcp::{
    CallToolResult, McpServer, RequestId, ToolCallContext, ToolDefinition, ToolFuture, ToolService,
    WireBudget,
};
use codex_ssh_bridge::output::OutputStore;
use codex_ssh_bridge::remote::{RemoteBridge, RemoteRunRequest, RunShell};
use codex_ssh_bridge::ssh::{RuntimePaths, SshRunner};
use serde_json::{Value, json};
use tokio::io::{
    AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader, DuplexStream, ReadHalf, WriteHalf,
};
use tokio_util::sync::CancellationToken;

mod support;

fn remote_tools_fixture() -> (tempfile::TempDir, Arc<RemoteBridge>, RemoteMcpTools) {
    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let config = Arc::new(support::config_with_host("dev", "/srv/remote"));
    let runner = Arc::new(SshRunner::new(config, runtime, store).unwrap());
    let bridge = Arc::new(RemoteBridge::new(runner));
    (
        runtime_base,
        Arc::clone(&bridge),
        RemoteMcpTools::new(bridge),
    )
}

fn roomy_context() -> ToolCallContext {
    ToolCallContext {
        cancel: CancellationToken::new(),
        wire_budget: WireBudget {
            result_bytes: 2 * 1024 * 1024,
            compact_fallback_bytes: codex_ssh_bridge::mcp::maximum_compact_fallback_result_bytes(),
        },
    }
}

fn fake_remote_tools_fixture(
    root: &std::path::Path,
) -> (tempfile::TempDir, std::path::PathBuf, RemoteMcpTools) {
    fake_remote_tools_with_options(root, false, &[])
}

fn fake_remote_tools_with_options(
    root: &std::path::Path,
    read_only: bool,
    extra: &[(&str, OsString)],
) -> (tempfile::TempDir, std::path::PathBuf, RemoteMcpTools) {
    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let mut config = support::config_with_host("dev", root.to_str().unwrap());
    config.hosts.get_mut("dev").unwrap().read_only = read_only;
    if read_only {
        config.hosts.get_mut("dev").unwrap().description = Some("D".repeat(2 * 1024 * 1024));
    }
    let log = runtime_base.path().join("ssh.log");
    let mut environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (OsString::from("FAKE_SSH_ROOT"), root.as_os_str().to_owned()),
        (OsString::from("FAKE_SSH_LOG"), log.as_os_str().to_owned()),
    ]);
    for (key, value) in extra {
        environment.insert(OsString::from(key), value.clone());
    }
    let runner = Arc::new(
        SshRunner::with_executable(
            Arc::new(config),
            runtime,
            store,
            support::fake_ssh_path(),
            environment,
        )
        .unwrap(),
    );
    let bridge = Arc::new(RemoteBridge::new(runner));
    (runtime_base, log, RemoteMcpTools::new(bridge))
}

async fn call_json(tools: &RemoteMcpTools, name: &str, arguments: Value) -> Value {
    serde_json::to_value(
        tools
            .call(name.to_owned(), arguments, roomy_context())
            .await,
    )
    .unwrap()
}

#[tokio::test]
async fn remote_run_nonzero_exit_is_a_failed_result_not_an_mcp_error() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, _log, tools) = fake_remote_tools_fixture(remote.path());

    for exit_status in [1, 2, 127] {
        let rendered = call_json(
            &tools,
            "remote_run",
            json!({
                "host":"dev",
                "command":format!("printf stdout-{exit_status}; printf stderr-{exit_status} >&2; exit {exit_status}"),
                "shell":"sh"
            }),
        )
        .await;

        assert!(
            rendered.get("isError").is_none() || rendered["isError"] == false,
            "completed command failure must not be an MCP protocol/tool error: {rendered}"
        );
        assert_eq!(
            rendered["structuredContent"],
            json!({"exit_code":exit_status})
        );
        let text = text_content(&rendered);
        assert!(text.contains(&format!("stdout-{exit_status}")), "{text}");
        assert!(text.contains(&format!("stderr-{exit_status}")), "{text}");
        assert!(text.contains("POSIX sh"), "{text}");
    }

    let rendered = call_json(
        &tools,
        "remote_run",
        json!({
            "host":"dev",
            "command":"printf applied > review-side-effect; dd if=/dev/zero bs=1024 count=300 >&2 2>/dev/null; exit 2",
            "shell":"sh"
        }),
    )
    .await;
    assert_eq!(rendered["structuredContent"]["exit_code"], 2);
    assert_eq!(rendered["structuredContent"]["truncated"], true);
    assert_eq!(
        std::fs::read_to_string(remote.path().join("review-side-effect")).unwrap(),
        "applied"
    );
    let output_ref = rendered["structuredContent"]["output_ref"]
        .as_str()
        .expect("failed command's large stderr must publish an output reference");
    let page = call_json(
        &tools,
        "remote_output_read",
        json!({
            "output_ref":output_ref,
            "stream":"stderr",
            "offset":256 * 1024,
            "max_bytes":4096
        }),
    )
    .await;
    assert!(page.get("isError").is_none() || page["isError"] == false);
    let page_text = text_content(&page)
        .strip_prefix("base64:")
        .expect("binary page must be explicitly marked");
    assert_eq!(
        page_text,
        base64::engine::general_purpose::STANDARD.encode(vec![0; 4096])
    );
    assert_eq!(page["structuredContent"]["next_offset"], 260 * 1024);
    assert_eq!(page["structuredContent"]["eof"], false);
}

fn text_content(result: &Value) -> &str {
    result["content"][0]["text"].as_str().unwrap()
}

fn assert_no_diagnostic_success_fields(result: &Value) {
    const FORBIDDEN: &[&str] = &[
        "remote",
        "host",
        "physical_root",
        "helper_mode",
        "shell",
        "elapsed_ms",
        "entry_count",
        "match_count",
        "raw_bytes",
        "aggregate_bytes",
        "detail_retained",
        "action",
        "suggested_action",
    ];
    fn visit(value: &Value) {
        match value {
            Value::Array(values) => values.iter().for_each(visit),
            Value::Object(object) => {
                for key in FORBIDDEN {
                    assert!(
                        !object.contains_key(*key),
                        "normal success leaked diagnostic field {key}: {value}"
                    );
                }
                object.values().for_each(visit);
            }
            _ => {}
        }
    }
    visit(&result["structuredContent"]);
}

fn command_calls(log: &std::path::Path) -> usize {
    transport_call_kinds(log)
        .into_iter()
        .filter(|kind| *kind == "C")
        .count()
}

fn transport_call_kinds(log: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|kind| matches!(*kind, "G" | "P" | "C"))
        .map(str::to_owned)
        .collect()
}

fn write_binary_config(directory: &std::path::Path, contents: &str) -> std::path::PathBuf {
    let path = directory.join("config.toml");
    std::fs::write(&path, contents).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn binary_command(config: &std::path::Path, runtime: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_codex-ssh-bridge"));
    command
        .env("CODEX_SSH_BRIDGE_CONFIG", config)
        .env("XDG_RUNTIME_DIR", runtime);
    command
}

fn wait_for_child_bounded(
    mut child: std::process::Child,
    timeout: Duration,
) -> (std::process::Output, bool) {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().unwrap().is_some() {
            return (child.wait_with_output().unwrap(), false);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return (child.wait_with_output().unwrap(), true);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn task8_binary_lifecycle_smoke_exposes_exact_surface_without_leaks() {
    let private = tempfile::TempDir::new().unwrap();
    std::fs::set_permissions(private.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let host_root = "/srv/BINARY_HOST_PATH_SENTINEL";
    let secret = "CONFIG_CONTENT_SENTINEL";
    let config = write_binary_config(
        private.path(),
        &format!(
            "version = 2\n# {secret}\n[limits]\nmax_frame_bytes = 8388608\nglobal_spool_quota_bytes = 67108864\nretention_serialization_jobs = 1\n"
        ),
    );
    std::fs::create_dir(private.path().join(".ssh")).unwrap();
    std::fs::write(
        private.path().join(".ssh/config"),
        format!("Host dev\n    HostName {host_root}\n"),
    )
    .unwrap();
    let caller_frame = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"remote_hosts","arguments":{}}}
"#;
    let ssh_log = private.path().join("unexpected-ssh.log");
    std::os::unix::fs::symlink(support::fake_ssh_path(), private.path().join("ssh")).unwrap();
    let mut child = binary_command(&config, private.path())
        .arg("mcp")
        .env("HOME", private.path())
        .env("PATH", private.path())
        .env("FAKE_SSH_LOG", &ssh_log)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(caller_frame.as_bytes()).unwrap();
    stdin.flush().unwrap();
    let child_stdout = child.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in StdBufReader::new(child_stdout).lines() {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let mut response_lines = Vec::new();
    for _ in 0..3 {
        match receiver.recv_timeout(Duration::from_secs(3)) {
            Ok(Ok(line)) => response_lines.push(line),
            other => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("timed out or failed reading MCP response: {other:?}");
            }
        }
    }
    drop(stdin);
    let (output, eof_timed_out) = wait_for_child_bounded(child, Duration::from_secs(5));
    reader.join().unwrap();
    for line in receiver.try_iter() {
        response_lines.push(line.unwrap());
    }
    assert!(
        !eof_timed_out,
        "binary did not terminate after stdin EOF; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines = response_lines
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 3, "responses={lines:#?}");
    assert_eq!(
        lines.iter().map(|line| &line["id"]).collect::<Vec<_>>(),
        [&json!(1), &json!(2), &json!(3)]
    );
    assert_eq!(lines[0]["result"]["protocolVersion"], "2025-11-25");
    let names = lines[1]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|definition| definition["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        tool_definitions()
            .iter()
            .map(|definition| definition.name.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(lines[2]["result"]["isError"], Value::Null);
    assert_eq!(lines[2]["result"]["structuredContent"], json!({}));
    assert_eq!(text_content(&lines[2]["result"]), "dev");
    assert_eq!(std::fs::read(&ssh_log).unwrap_or_default(), b"");
    let stderr = String::from_utf8(output.stderr).unwrap();
    for forbidden in [
        secret,
        host_root,
        config.to_str().unwrap(),
        "ControlPath",
        caller_frame.trim(),
    ] {
        assert!(
            !stderr.contains(forbidden),
            "stderr leaked {forbidden:?}: {stderr}"
        );
    }
}

struct ProtocolSession {
    input: WriteHalf<DuplexStream>,
    output: TokioBufReader<ReadHalf<DuplexStream>>,
    server: tokio::task::JoinHandle<codex_ssh_bridge::BridgeResult<()>>,
    next_id: u64,
}

impl ProtocolSession {
    async fn start(tools: RemoteMcpTools) -> Self {
        Self::start_with_frame(tools, codex_ssh_bridge::MAX_FRAME_BYTES).await
    }

    async fn start_with_frame(tools: RemoteMcpTools, max_frame_bytes: usize) -> Self {
        Self::start_with_limits(tools, max_frame_bytes, 4).await
    }

    async fn start_with_limits(
        tools: RemoteMcpTools,
        max_frame_bytes: usize,
        _concurrency: usize,
    ) -> Self {
        let (client, server_io) = tokio::io::duplex(16 * 1024 * 1024);
        let (client_output, client_input) = tokio::io::split(client);
        let (server_input, server_output) = tokio::io::split(server_io);
        let server = McpServer::new(Arc::new(tools), max_frame_bytes).unwrap();
        let server = tokio::spawn(server.serve(server_input, server_output));
        let mut session = Self {
            input: client_input,
            output: TokioBufReader::new(client_output),
            server,
            next_id: 1,
        };
        let initialized = session
            .request(json!({
                "jsonrpc":"2.0",
                "id":1,
                "method":"initialize",
                "params":{
                    "protocolVersion":"2025-11-25",
                    "capabilities":{},
                    "clientInfo":{"name":"task8","version":"1"}
                }
            }))
            .await;
        assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
        session
            .send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await;
        session
    }

    async fn send(&mut self, frame: Value) {
        self.input
            .write_all(format!("{}\n", serde_json::to_string(&frame).unwrap()).as_bytes())
            .await
            .unwrap();
        self.input.flush().await.unwrap();
    }

    async fn request(&mut self, frame: Value) -> Value {
        self.send(frame).await;
        self.read_response(Duration::from_secs(5)).await
    }

    async fn read_response(&mut self, timeout: Duration) -> Value {
        let mut line = String::new();
        tokio::time::timeout(timeout, self.output.read_line(&mut line))
            .await
            .expect("MCP response timed out")
            .unwrap();
        assert!(!line.is_empty(), "MCP output reached EOF before a response");
        serde_json::from_str(&line).unwrap()
    }

    async fn call(&mut self, name: &str, arguments: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let response = self
            .request(json!({
                "jsonrpc":"2.0",
                "id":id,
                "method":"tools/call",
                "params":{"name":name,"arguments":arguments}
            }))
            .await;
        assert_eq!(response["id"], id);
        response["result"].clone()
    }

    async fn close(mut self) {
        self.input.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), self.server)
            .await
            .expect("MCP server close timed out")
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn task8_complete_surface_all_nine_tools_are_real_json_rpc_calls() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(
        remote
            .path()
            .join("hostile $(touch SHOULD_NOT_EXIST)\nname.txt"),
        b"hostile name marker\n",
    )
    .unwrap();
    std::fs::write(
        remote.path().join("utf8.txt"),
        b"literal $(touch SHOULD_NOT_EXIST)\nUTF8_SURFACE\n",
    )
    .unwrap();
    std::fs::write(remote.path().join("binary.bin"), [0xff, 0x00, 0x7f]).unwrap();
    let (_runtime, _log, tools) = fake_remote_tools_fixture(remote.path());
    let mut session = ProtocolSession::start(tools).await;

    let hosts = session.call("remote_hosts", json!({})).await;
    assert_no_diagnostic_success_fields(&hosts);
    assert_eq!(hosts["structuredContent"], json!({}));
    assert_eq!(text_content(&hosts), "dev");

    let listed = session
        .call(
            "remote_list",
            json!({"host":"dev","path":".","max_entries":32}),
        )
        .await;
    assert_no_diagnostic_success_fields(&listed);
    assert_eq!(listed["structuredContent"], json!({}));
    assert!(text_content(&listed).contains("hostile $(touch SHOULD_NOT_EXIST)\nname.txt"));

    let stated = session
        .call(
            "remote_stat",
            json!({"host":"dev","paths":["binary.bin","missing.txt"]}),
        )
        .await;
    assert_no_diagnostic_success_fields(&stated);
    assert_eq!(stated["structuredContent"], json!({}));
    let stat_lines = text_content(&stated).lines().collect::<Vec<_>>();
    assert_eq!(stat_lines.len(), 2);
    assert!(text_content(&stated).contains("missing.txt"));

    let searched = session
        .call(
            "remote_search",
            json!({"host":"dev","query":"$(touch SHOULD_NOT_EXIST)","path":"."}),
        )
        .await;
    assert_no_diagnostic_success_fields(&searched);
    assert_eq!(searched["structuredContent"], json!({}));
    assert!(text_content(&searched).contains("$(touch SHOULD_NOT_EXIST)"));

    let read = session
        .call(
            "remote_read",
            json!({"host":"dev","paths":["utf8.txt","binary.bin"],"max_bytes":4096}),
        )
        .await;
    assert_no_diagnostic_success_fields(&read);
    assert_eq!(read["structuredContent"], json!({}));
    let read_text = text_content(&read);
    assert!(read_text.contains("UTF8_SURFACE"), "read={read_text}");
    assert!(read_text.contains("/wB/"));

    let run = session
        .call(
            "remote_run",
            json!({"host":"dev","cwd":"/","command":"printf RUN_SURFACE; dd if=/dev/zero bs=1024 count=300 2>/dev/null","shell":"sh"}),
        )
        .await;
    assert_no_diagnostic_success_fields(&run);
    assert_eq!(run["structuredContent"]["exit_code"], 0);
    let output_ref = run["structuredContent"]["output_ref"]
        .as_str()
        .expect("run must publish a pageable output reference")
        .to_owned();

    let output = session
        .call(
            "remote_output_read",
            json!({"output_ref":output_ref,"stream":"stdout","offset":0,"max_bytes":11}),
        )
        .await;
    assert_no_diagnostic_success_fields(&output);
    assert!(text_content(&output).contains("RUN_SURFACE"));
    assert_eq!(output["structuredContent"]["next_offset"], 11);

    let written = session
        .call(
            "remote_write",
            json!({
                "host":"dev","path":"created.txt","content":"WRITE_SURFACE\n",
                "encoding":"utf8","mode":{"kind":"create"}
            }),
        )
        .await;
    assert_no_diagnostic_success_fields(&written);
    assert_eq!(written["structuredContent"], json!({}));
    assert!(text_content(&written).starts_with("Wrote "));

    let patched = session
        .call(
            "remote_apply_patch",
            json!({
                "host":"dev",
                "patch":"--- a/created.txt\n+++ b/created.txt\n@@ -1 +1 @@\n-WRITE_SURFACE\n+PATCH_SURFACE\n"
            }),
        )
        .await;
    assert_no_diagnostic_success_fields(&patched);
    assert_eq!(patched["structuredContent"], json!({}));
    assert_eq!(text_content(&patched), "Done!");
    assert_eq!(
        std::fs::read(remote.path().join("created.txt")).unwrap(),
        b"PATCH_SURFACE\n"
    );
    assert!(!remote.path().join("SHOULD_NOT_EXIST").exists());
    assert!(!std::path::Path::new("SHOULD_NOT_EXIST").exists());
    session.close().await;
}

#[tokio::test]
async fn task8_shell_surface_reports_bash_default_and_explicit_sh() {
    let remote = tempfile::TempDir::new().unwrap();
    let bash_extra = [
        ("FAKE_SSH_MODE", OsString::from("echo-command")),
        ("FAKE_SSH_SHELL", OsString::from("bash")),
        ("FAKE_SSH_BASH_VERSION", OsString::from("5.2.15")),
    ];
    let extra = bash_extra
        .iter()
        .map(|(key, value)| (*key, value.clone()))
        .collect::<Vec<_>>();
    let (_runtime, _log, tools) = fake_remote_tools_with_options(remote.path(), false, &extra);
    let mut session = ProtocolSession::start(tools).await;
    let default_bash = session
        .call(
            "remote_run",
            json!({"host":"dev","cwd":"/","command":"printf safe"}),
        )
        .await;
    assert_eq!(default_bash["isError"], Value::Null, "{default_bash}");
    assert_eq!(default_bash["structuredContent"], json!({"exit_code":0}));
    assert!(!default_bash.to_string().contains("5.2.15"));
    session.close().await;

    let (_runtime, _log, tools) = fake_remote_tools_with_options(remote.path(), false, &extra);
    let mut session = ProtocolSession::start(tools).await;
    let explicit_sh = session
        .call(
            "remote_run",
            json!({"host":"dev","cwd":"/","command":"printf safe","shell":"sh"}),
        )
        .await;
    assert_eq!(explicit_sh["isError"], Value::Null, "{explicit_sh}");
    assert_eq!(explicit_sh["structuredContent"], json!({"exit_code":0}));
    assert!(text_content(&explicit_sh).contains("POSIX sh"));
    session.close().await;
}

#[tokio::test]
async fn task8_shell_surface_missing_bash_rejects_before_command_child() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, log, tools) = fake_remote_tools_with_options(
        remote.path(),
        false,
        &[
            ("FAKE_SSH_MODE", OsString::from("echo-command")),
            ("FAKE_SSH_SHELL", OsString::from("sh")),
        ],
    );
    let mut session = ProtocolSession::start(tools).await;
    let run = session
        .call(
            "remote_run",
            json!({"host":"dev","cwd":"/","command":"printf must-not-run","shell":"bash"}),
        )
        .await;
    assert_eq!(run["isError"], true);
    assert_eq!(
        run["structuredContent"]["error"]["code"],
        "REMOTE_CAPABILITY_MISSING"
    );
    assert_eq!(run["structuredContent"]["requested_shell"], "bash");
    assert_eq!(run["structuredContent"]["available_shells"], json!(["sh"]));
    assert!(!run.to_string().contains("action"));
    assert_eq!(command_calls(&log), 0);
    session.close().await;
}

#[tokio::test]
async fn task8_shell_surface_login_metadata_and_local_timeout_are_explicit() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, _log, tools) = fake_remote_tools_with_options(
        remote.path(),
        false,
        &[("FAKE_SSH_MODE", OsString::from("echo-command"))],
    );
    let mut session = ProtocolSession::start(tools).await;
    let run = session
        .call(
            "remote_run",
            json!({"host":"dev","cwd":"/","command":"printf safe","shell":"login"}),
        )
        .await;
    assert_eq!(run["structuredContent"], json!({"exit_code":0}));
    session.close().await;

    let (_runtime, _log, tools) = fake_remote_tools_with_options(
        remote.path(),
        false,
        &[
            ("FAKE_SSH_MODE", OsString::from("sleep")),
            ("FAKE_SSH_SLEEP_SECONDS", OsString::from("5")),
        ],
    );
    let mut session = ProtocolSession::start(tools).await;
    let timed_out = session
        .call(
            "remote_run",
            json!({"host":"dev","cwd":"/","command":"printf never","shell":"login","timeout_ms":50}),
        )
        .await;
    assert_eq!(timed_out["isError"], true);
    assert_eq!(
        timed_out["structuredContent"]["error"]["code"],
        "COMMAND_TIMEOUT"
    );
    assert!(timed_out["structuredContent"].get("shell").is_none());
    session.close().await;
}

#[tokio::test]
async fn task8_shell_surface_read_only_is_enforced_server_side_for_every_mutation() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("read.txt"), b"READ_ONLY_SENTINEL\n").unwrap();
    let (_runtime, log, tools) = fake_remote_tools_with_options(remote.path(), true, &[]);
    let id = RequestId::synthetic_max_wire();
    let minimum_frame = required_mcp_frame_bytes(
        tool_definitions(),
        codex_ssh_bridge::mcp::maximum_compact_fallback_result_bytes(),
        &id,
    )
    .unwrap();
    let mut session = ProtocolSession::start_with_frame(tools, minimum_frame).await;
    let hosts = session.call("remote_hosts", json!({})).await;
    assert_eq!(hosts["structuredContent"], json!({}));
    assert_eq!(text_content(&hosts), "dev");

    for (name, arguments) in [
        (
            "remote_list",
            json!({"host":"dev","path":".","max_entries":1}),
        ),
        ("remote_stat", json!({"host":"dev","paths":["read.txt"]})),
        (
            "remote_search",
            json!({"host":"dev","query":"READ_ONLY_SENTINEL","path":"."}),
        ),
        ("remote_read", json!({"host":"dev","paths":["read.txt"]})),
    ] {
        let result = session.call(name, arguments).await;
        assert_ne!(result["isError"], true, "{name}: {result}");
        assert!(
            result["structuredContent"].get("remote").is_none(),
            "{name}: {result}"
        );
    }

    std::fs::write(&log, b"").unwrap();
    for (name, arguments) in [
        (
            "remote_write",
            json!({"host":"dev","path":"new.txt","content":"x","encoding":"utf8","mode":{"kind":"create"}}),
        ),
        (
            "remote_apply_patch",
            json!({"host":"dev","patch":"--- a/read.txt\n+++ b/read.txt\n@@ -1 +1 @@\n-READ_ONLY_SENTINEL\n+changed\n"}),
        ),
        (
            "remote_run",
            json!({"host":"dev","cwd":"/","command":"printf must-not-run","shell":"sh"}),
        ),
    ] {
        let result = session.call(name, arguments).await;
        assert_eq!(result["isError"], true, "{name}: {result}");
        assert_eq!(
            result["structuredContent"]["error"]["code"], "READ_ONLY_HOST",
            "{name}"
        );
    }
    assert_eq!(
        command_calls(&log),
        0,
        "read-only mutations must launch no command child"
    );
    assert!(!remote.path().join("new.txt").exists());
    assert_eq!(
        std::fs::read(remote.path().join("read.txt")).unwrap(),
        b"READ_ONLY_SENTINEL\n"
    );
    session.close().await;
}

#[test]
fn task8_binary_unknown_and_missing_modes_have_fixed_usage_and_exit_two() {
    let private = tempfile::TempDir::new().unwrap();
    let config = private.path().join("absent-config-is-not-consulted");
    let expected = "usage: codex-ssh-bridge mcp\n";
    for arguments in [Vec::<&str>::new(), vec!["unknown"], vec!["mcp", "extra"]] {
        let output = binary_command(&config, private.path())
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(String::from_utf8(output.stderr).unwrap(), expected);
    }
}

#[test]
fn task8_binary_fatal_error_is_only_fixed_prefix_and_stable_code() {
    let private = tempfile::TempDir::new().unwrap();
    let secret = "FATAL_CONFIG_SECRET";
    let config = write_binary_config(private.path(), secret);
    let output = binary_command(&config, private.path())
        .arg("mcp")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "codex-ssh-bridge fatal: INVALID_CONFIG\n"
    );
    assert!(
        !output
            .stderr
            .windows(secret.len())
            .any(|window| window == secret.as_bytes())
    );
    assert!(
        !output
            .stderr
            .windows(config.as_os_str().len())
            .any(|window| window == config.as_os_str().as_encoded_bytes())
    );
}

#[test]
fn task8_binary_bootstrap_preserves_exact_limits_and_ownership_chain() {
    let source = include_str!("../src/main.rs");
    for required in [
        "Config::load_default()",
        "loaded.config.limits.max_frame_bytes",
        "loaded.config.limits.global_spool_quota_bytes",
        "loaded.config.limits.retention_serialization_jobs",
        "OutputStore::with_limits(",
        "global_spool_quota_bytes,",
        "retention_serialization_jobs,",
        "Arc::new(loaded.config)",
        "SshRunner::new(Arc::clone(&config), runtime, output_store)",
        "RemoteBridge::new(runner)",
        "RemoteMcpTools::new(bridge)",
        "McpServer::new(tools, max_frame_bytes)",
    ] {
        assert!(
            source.contains(required),
            "bootstrap lost required ownership/limit source: {required}"
        );
    }
    assert!(!source.contains("OutputStore::new("));
    assert!(
        !source
            .lines()
            .any(|line| line.trim_start().starts_with("println!("))
    );

    for quota in [64_u64, 127, 255, 511].map(|mebibytes| mebibytes * 1024 * 1024) {
        for jobs in 1..=4 {
            let runtime_base = tempfile::TempDir::new().unwrap();
            let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
            OutputStore::with_limits(&runtime, quota, jobs).unwrap();
        }
    }
}

#[tokio::test]
async fn task8_binary_remote_tools_constructor_accepts_exact_minimum_only() {
    let (_runtime, _bridge, tools) = remote_tools_fixture();
    let id = RequestId::synthetic_max_wire();
    let exact_tools = exact_tools_list_response_bytes(tool_definitions(), &id).unwrap();
    let fallback = codex_ssh_bridge::mcp::maximum_compact_fallback_result_bytes();
    let required = required_mcp_frame_bytes(tool_definitions(), fallback, &id).unwrap();
    assert_eq!(required, 1_048_576.max(exact_tools));
    assert!(McpServer::new(Arc::new(tools.clone()), required - 1).is_err());

    let mut session = ProtocolSession::start_with_frame(tools, required).await;
    let maximum_id = "x".repeat(254);
    let listed = session
        .request(json!({
            "jsonrpc":"2.0",
            "id":maximum_id,
            "method":"tools/list",
            "params":{}
        }))
        .await;
    assert_eq!(listed["id"], maximum_id);
    let names = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|definition| definition["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        tool_definitions()
            .iter()
            .map(|definition| definition.name.as_str())
            .collect::<Vec<_>>()
    );
    session.close().await;
}

fn property<'a>(tool: &'a ToolDefinition, name: &str) -> &'a Value {
    &tool.input_schema["properties"][name]
}

fn tool(name: &str) -> &'static ToolDefinition {
    tool_definitions()
        .iter()
        .find(|tool| tool.name == name)
        .unwrap_or_else(|| panic!("missing tool {name}"))
}

fn assert_closed_objects(value: &Value) {
    match value {
        Value::Object(object) => {
            if object.get("type") == Some(&Value::String("object".to_owned())) {
                assert_eq!(
                    object.get("additionalProperties"),
                    Some(&Value::Bool(false)),
                    "object schema was not closed: {value}"
                );
            }
            for child in object.values() {
                assert_closed_objects(child);
            }
        }
        Value::Array(array) => array.iter().for_each(assert_closed_objects),
        _ => {}
    }
}

#[test]
fn task8_registry_contains_exactly_the_nine_high_level_remote_tools() {
    let tools = tool_definitions();
    let names = tools
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "remote_hosts",
            "remote_list",
            "remote_stat",
            "remote_search",
            "remote_read",
            "remote_output_read",
            "remote_apply_patch",
            "remote_write",
            "remote_run",
        ]
    );
    let serialized = serde_json::to_string(tools).unwrap();
    for forbidden in ["sshfs", "guarded_delete", "probe", "shell_word", "raw_ssh"] {
        assert!(!serialized.contains(forbidden));
    }
    for tool in tools {
        assert_closed_objects(&tool.input_schema);
        assert!(
            serde_json::to_value(tool)
                .unwrap()
                .get("outputSchema")
                .is_none(),
            "{} unexpectedly advertises an output schema",
            tool.name
        );
    }
}

struct RegistryService;

impl ToolService for RegistryService {
    fn definitions(&self) -> &[ToolDefinition] {
        tool_definitions()
    }

    fn call(&self, _: String, _: Value, _: ToolCallContext) -> ToolFuture {
        Box::pin(async { CallToolResult::text("unused") })
    }
}

#[test]
fn task8_registry_full_tools_list_is_an_undegradable_service_minimum() {
    let id = RequestId::synthetic_max_wire();
    let exact = exact_tools_list_response_bytes(tool_definitions(), &id).unwrap();
    let fallback = codex_ssh_bridge::mcp::maximum_compact_fallback_result_bytes();
    let required = required_mcp_frame_bytes(tool_definitions(), fallback, &id).unwrap();
    assert_eq!(required, 1_048_576.max(exact));
    assert!(exact <= required);
    assert!(
        exact_tools_list_response_bytes(&tool_definitions()[..8], &id).unwrap() < exact,
        "the test must prove that silently dropping a tool would shrink the frame"
    );
    assert!(McpServer::new(Arc::new(RegistryService), required).is_ok());
    // Construction uses the complete immutable registry. It must reject a
    // smaller frame instead of silently degrading the advertised surface.
    assert!(McpServer::new(Arc::new(RegistryService), required - 1).is_err());
}

fn assert_string_bounds(schema: &Value, maximum: u64) {
    assert_eq!(schema["type"], "string");
    assert_eq!(schema["minLength"], 1);
    assert_eq!(schema["maxLength"], maximum);
}

fn assert_host(schema: &Value) {
    assert_string_bounds(schema, 128);
    assert_eq!(schema["pattern"], "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$");
}

fn assert_integer_range(schema: &Value, minimum: u64, maximum: u64) {
    assert_eq!(schema["type"], "integer");
    assert_eq!(schema["minimum"], minimum);
    assert_eq!(schema["maximum"], maximum);
}

#[test]
fn task8_schema_has_exact_required_fields_and_advisory_bounds() {
    let expected_required = [
        ("remote_hosts", json!([])),
        ("remote_list", json!(["host", "path"])),
        ("remote_stat", json!(["host", "paths"])),
        ("remote_search", json!(["host", "query", "path"])),
        ("remote_read", json!(["host", "paths"])),
        ("remote_output_read", json!(["output_ref", "stream"])),
        ("remote_apply_patch", json!(["host", "patch"])),
        (
            "remote_write",
            json!(["host", "path", "content", "encoding", "mode"]),
        ),
        ("remote_run", json!(["host", "command", "cwd"])),
    ];
    for (name, required) in expected_required {
        assert_eq!(tool(name).input_schema["required"], required, "{name}");
    }
    assert_eq!(tool("remote_hosts").input_schema["properties"], json!({}));

    for name in [
        "remote_list",
        "remote_stat",
        "remote_search",
        "remote_read",
        "remote_apply_patch",
        "remote_write",
        "remote_run",
    ] {
        assert_host(property(tool(name), "host"));
    }
    for (name, field) in [
        ("remote_list", "path"),
        ("remote_search", "path"),
        ("remote_write", "path"),
        ("remote_run", "cwd"),
    ] {
        assert_string_bounds(property(tool(name), field), 65_536);
        assert_eq!(property(tool(name), field)["pattern"], "^/");
    }
    for name in ["remote_stat", "remote_read"] {
        assert_string_bounds(&property(tool(name), "paths")["items"], 65_536);
        assert_eq!(property(tool(name), "paths")["items"]["pattern"], "^/");
    }

    assert_integer_range(property(tool("remote_list"), "depth"), 1, 32);
    assert_integer_range(property(tool("remote_list"), "max_entries"), 1, 10_000);
    assert_eq!(property(tool("remote_stat"), "paths")["minItems"], 1);
    assert_eq!(property(tool("remote_stat"), "paths")["maxItems"], 256);

    assert_string_bounds(property(tool("remote_search"), "query"), 65_536);
    assert_eq!(property(tool("remote_search"), "globs")["maxItems"], 128);
    assert_string_bounds(&property(tool("remote_search"), "globs")["items"], 4_096);
    assert_integer_range(property(tool("remote_search"), "max_results"), 1, 10_000);

    assert_eq!(property(tool("remote_read"), "paths")["minItems"], 1);
    assert_eq!(property(tool("remote_read"), "paths")["maxItems"], 32);
    assert_eq!(property(tool("remote_read"), "start_line")["minimum"], 1);
    assert_integer_range(property(tool("remote_read"), "max_lines"), 1, 100_000);
    assert_integer_range(property(tool("remote_read"), "max_bytes"), 1, 1_048_576);

    assert_eq!(
        property(tool("remote_output_read"), "output_ref")["pattern"],
        "^[0-9a-f]{32}$"
    );
    assert_eq!(
        property(tool("remote_output_read"), "stream")["enum"],
        json!(["stdout", "stderr"])
    );
    assert_integer_range(
        property(tool("remote_output_read"), "max_bytes"),
        1,
        1_048_576,
    );

    assert_string_bounds(property(tool("remote_apply_patch"), "patch"), 4_194_304);
    assert_eq!(property(tool("remote_write"), "content")["type"], "string");
    assert_eq!(
        property(tool("remote_write"), "content")["maxLength"],
        5_592_408
    );
    assert_eq!(
        property(tool("remote_write"), "encoding")["enum"],
        json!(["utf8", "base64"])
    );

    assert_string_bounds(property(tool("remote_run"), "command"), 8_388_608);
    assert_eq!(
        property(tool("remote_run"), "shell")["enum"],
        json!(["bash", "sh", "login"])
    );
    assert_integer_range(property(tool("remote_run"), "timeout_ms"), 1, 3_600_000);
    let stdin = property(tool("remote_run"), "stdin");
    assert_eq!(stdin["required"], json!(["encoding", "value"]));
    assert_eq!(stdin["properties"]["value"]["maxLength"], 5_592_408);
}

#[test]
fn task8_schema_defaults_and_closed_write_mode_are_exact() {
    assert_eq!(property(tool("remote_list"), "depth")["default"], 1);
    assert_eq!(
        property(tool("remote_list"), "include_hidden")["default"],
        false
    );
    assert_eq!(
        property(tool("remote_list"), "max_entries")["default"],
        1_000
    );
    assert_eq!(
        property(tool("remote_search"), "globs")["default"],
        json!([])
    );
    assert_eq!(
        property(tool("remote_search"), "max_results")["default"],
        100
    );
    assert_eq!(property(tool("remote_search"), "binary")["default"], false);
    assert_eq!(property(tool("remote_read"), "start_line")["default"], 1);
    assert_eq!(property(tool("remote_read"), "max_lines")["default"], 2_000);
    assert_eq!(property(tool("remote_output_read"), "offset")["default"], 0);
    assert_eq!(
        property(tool("remote_output_read"), "max_bytes")["default"],
        262_144
    );
    assert_eq!(property(tool("remote_run"), "shell")["default"], "bash");

    let alternatives = property(tool("remote_write"), "mode")["oneOf"]
        .as_array()
        .unwrap();
    assert_eq!(alternatives.len(), 2);
    for alternative in alternatives {
        assert_closed_objects(alternative);
    }
    assert_eq!(alternatives[0]["required"], json!(["kind"]));
    assert_eq!(alternatives[0]["properties"]["kind"]["const"], "create");
    assert_eq!(
        alternatives[1]["required"],
        json!(["kind"]),
        "the replace hash is deliberately optional"
    );
    assert_eq!(alternatives[1]["properties"]["kind"]["const"], "replace");
    let hash = &alternatives[1]["properties"]["expected_sha256"];
    assert_eq!(hash["minLength"], 64);
    assert_eq!(hash["maxLength"], 64);
    assert_eq!(hash["pattern"], "^[0-9a-f]{64}$");
}

#[test]
fn task8_schema_annotations_match_remote_side_effects() {
    for name in ["remote_hosts", "remote_output_read"] {
        let annotations = serde_json::to_value(tool(name).annotations).unwrap();
        assert_eq!(
            annotations,
            json!({
                "readOnlyHint": true,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": false
            }),
            "{name}"
        );
    }
    for name in ["remote_list", "remote_stat", "remote_search", "remote_read"] {
        let annotations = serde_json::to_value(tool(name).annotations).unwrap();
        assert_eq!(
            annotations,
            json!({
                "readOnlyHint": true,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": true
            }),
            "{name}"
        );
    }
    for name in ["remote_apply_patch", "remote_write", "remote_run"] {
        let annotations = serde_json::to_value(tool(name).annotations).unwrap();
        assert_eq!(
            annotations,
            json!({
                "readOnlyHint": false,
                "destructiveHint": true,
                "idempotentHint": false,
                "openWorldHint": true
            }),
            "{name}"
        );
    }
}

#[test]
fn task8_dispatch_architecture_is_bridge_only() {
    let source = include_str!("../src/mcp/tools.rs");
    for forbidden in [
        "std::process",
        "tokio::process",
        "Command::new",
        "SshRunner",
        "OutputStore",
        "sshfs",
    ] {
        assert!(
            !source.contains(forbidden),
            "MCP dispatch must use RemoteBridge, found {forbidden}"
        );
    }
    assert!(source.contains("RemoteBridge"));
}

#[tokio::test]
async fn task8_dispatch_rejects_known_tool_arguments_before_bridge_work() {
    let (_runtime, _bridge, tools) = remote_tools_fixture();
    let result = tools
        .call(
            "remote_list".to_owned(),
            json!({"host":"dev", "unknown":true}),
            roomy_context(),
        )
        .await;
    let rendered = serde_json::to_value(result).unwrap();
    assert_eq!(rendered["isError"], true);
    assert_eq!(rendered["content"].as_array().unwrap().len(), 1);
    assert_eq!(
        rendered["structuredContent"]["error"]["code"],
        "INVALID_ARGUMENT"
    );
}

#[tokio::test]
async fn task8_single_copy_hosts_payload_is_only_in_text_content() {
    let (_runtime, _bridge, tools) = remote_tools_fixture();
    let result = tools
        .call("remote_hosts".to_owned(), json!({}), roomy_context())
        .await;
    let rendered = serde_json::to_value(result).unwrap();
    assert_eq!(rendered["content"].as_array().unwrap().len(), 1);
    assert_eq!(text_content(&rendered), "dev");
    assert_eq!(rendered["structuredContent"], json!({}));
}

#[tokio::test]
async fn task8_dispatch_fake_ssh_maps_read_search_run_write_and_patch_presentations() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("utf8.txt"), b"UTF8_SENTINEL\nsecond\n").unwrap();
    std::fs::write(remote.path().join("binary.bin"), [0xff, 0x00, 0x7f]).unwrap();
    let (_runtime, log, tools) = fake_remote_tools_fixture(remote.path());

    let listed = call_json(
        &tools,
        "remote_list",
        json!({"host":"dev", "path":".", "max_entries":32}),
    )
    .await;
    assert!(text_content(&listed).contains("utf8.txt"));
    assert!(listed["structuredContent"].get("entries").is_none());

    std::fs::write(&log, b"").unwrap();
    let stated = call_json(
        &tools,
        "remote_stat",
        json!({"host":"dev", "paths":["utf8.txt", "binary.bin"]}),
    )
    .await;
    assert_eq!(text_content(&stated).lines().count(), 2);
    assert_eq!(
        command_calls(&log),
        1,
        "cached stat must not implicitly retry"
    );

    let read = call_json(
        &tools,
        "remote_read",
        json!({"host":"dev", "paths":["utf8.txt", "binary.bin"], "max_bytes":4096}),
    )
    .await;
    let read_text = text_content(&read);
    assert!(read_text.contains("UTF8_SENTINEL"));
    assert!(read_text.contains("/wB/"), "binary content must be base64");
    assert!(
        !read["structuredContent"]
            .to_string()
            .contains("UTF8_SENTINEL")
    );

    let searched = call_json(
        &tools,
        "remote_search",
        json!({"host":"dev", "query":"UTF8_SENTINEL", "path":"."}),
    )
    .await;
    assert!(text_content(&searched).contains("UTF8_SENTINEL"));

    let run = call_json(
        &tools,
        "remote_run",
        json!({"host":"dev", "cwd":"/", "command":"printf RUN_SENTINEL", "shell":"sh"}),
    )
    .await;
    let run_text = text_content(&run);
    assert!(run_text.contains("RUN_SENTINEL"));
    assert!(run_text.contains("POSIX sh"));
    assert_eq!(run["structuredContent"]["exit_code"], 0);

    let written = call_json(
        &tools,
        "remote_write",
        json!({
            "host":"dev",
            "path":"created.txt",
            "content":"WRITE_SENTINEL\n",
            "encoding":"utf8",
            "mode":{"kind":"create"}
        }),
    )
    .await;
    assert_eq!(written["structuredContent"], json!({}));
    assert!(text_content(&written).starts_with("Wrote "));
    assert_eq!(
        std::fs::read(remote.path().join("created.txt")).unwrap(),
        b"WRITE_SENTINEL\n"
    );

    let patched = call_json(
        &tools,
        "remote_apply_patch",
        json!({
            "host":"dev",
            "patch":"--- a/created.txt\n+++ b/created.txt\n@@ -1 +1 @@\n-WRITE_SENTINEL\n+PATCH_SENTINEL\n"
        }),
    )
    .await;
    assert_eq!(patched["structuredContent"], json!({}));
    assert_eq!(text_content(&patched), "Done!");
    assert_eq!(
        std::fs::read(remote.path().join("created.txt")).unwrap(),
        b"PATCH_SENTINEL\n"
    );

    let patch_error = call_json(
        &tools,
        "remote_apply_patch",
        json!({"host":"dev", "patch":"GIT binary patch\n"}),
    )
    .await;
    assert_eq!(patch_error["isError"], true);
    assert_eq!(
        patch_error["structuredContent"]["error"]["code"],
        "INVALID_ARGUMENT"
    );
}

#[tokio::test]
async fn task8_dispatch_pre_cancelled_call_launches_no_ssh_process() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, log, tools) = fake_remote_tools_fixture(remote.path());
    let cancel = CancellationToken::new();
    cancel.cancel();
    let result = tools
        .call(
            "remote_list".to_owned(),
            json!({"host":"dev"}),
            ToolCallContext {
                cancel,
                wire_budget: roomy_context().wire_budget,
            },
        )
        .await;
    let rendered = serde_json::to_value(result).unwrap();
    assert_eq!(rendered["structuredContent"]["error"]["code"], "CANCELLED");
    assert!(transport_call_kinds(&log).is_empty());
}

#[tokio::test]
async fn task8_error_rendering_is_direct_bounded_and_does_not_serialize_bridge_error() {
    let (_runtime, _bridge, tools) = remote_tools_fixture();
    let result = tools
        .call(
            "remote_list".to_owned(),
            json!({"host":"not-configured"}),
            roomy_context(),
        )
        .await;
    let rendered = serde_json::to_value(result).unwrap();
    assert_eq!(rendered["isError"], true);
    assert_eq!(rendered["content"].as_array().unwrap().len(), 1);
    assert_eq!(
        rendered["structuredContent"]["error"]["code"],
        "INVALID_CONFIG"
    );
    assert!(
        rendered["structuredContent"]["error"]["message"]
            .as_str()
            .unwrap()
            .len()
            <= 1_024
    );
    assert!(rendered["structuredContent"].get("host").is_none());
    assert!(
        rendered["structuredContent"]["error"]
            .get("details")
            .is_none()
    );
}

#[tokio::test]
async fn host_descriptions_are_not_exposed_or_retained_in_model_output() {
    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let hosts = (0..7)
        .map(|index| {
            (
                format!("host-{index}"),
                HostProfile {
                    root: format!("/srv/remote/{index}"),
                    description: Some(format!("DETAIL-{index}-{}", "x".repeat(256 * 1024))),
                    read_only: true,
                    limits: HostLimitOverrides::default(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let runner = Arc::new(
        SshRunner::new(
            Arc::new(Config {
                hosts,
                ..Config::default()
            }),
            runtime,
            store,
        )
        .unwrap(),
    );
    let bridge = Arc::new(RemoteBridge::new(runner));
    let tools = RemoteMcpTools::new(bridge);
    let id = RequestId::synthetic_max_wire();
    let minimum_frame = required_mcp_frame_bytes(
        tool_definitions(),
        codex_ssh_bridge::mcp::maximum_compact_fallback_result_bytes(),
        &id,
    )
    .unwrap();
    let mut session = ProtocolSession::start_with_frame(tools, minimum_frame).await;
    let rendered = session.call("remote_hosts", json!({})).await;
    assert_eq!(rendered["structuredContent"], json!({}));
    assert_eq!(text_content(&rendered).lines().count(), 7);
    assert!(!rendered.to_string().contains("DETAIL-"));
    session.close().await;
}

#[test]
fn task8_error_rendering_real_compact_fallback_is_nonzero_and_fits_minimum() {
    let fallback = codex_ssh_bridge::mcp::maximum_compact_fallback_result_bytes();
    assert!(fallback > 0);
    let id = RequestId::synthetic_max_wire();
    let required = required_mcp_frame_bytes(tool_definitions(), fallback, &id).unwrap();
    assert!(fallback <= required);
    assert!(required <= codex_ssh_bridge::MAX_FRAME_BYTES);
}

fn task8_hostile_values(include_nul: bool) -> Vec<&'static str> {
    let mut values = vec![
        "spaces value",
        "'",
        "\"",
        "line\nbreak",
        "-leading-hyphen",
        "*",
        "$HOME",
        "$(touch SHOULD_NOT_EXIST)",
        "`touch SHOULD_NOT_EXIST`",
        "Unicode-雪",
    ];
    if include_nul {
        values.push("nul\0value");
    }
    values
}

fn command_records(log: &std::path::Path) -> Vec<(String, String)> {
    let contents = std::fs::read_to_string(log).unwrap();
    let records = contents
        .split("END\n")
        .filter(|record| record.starts_with("C\n"))
        .collect::<Vec<_>>();
    records
        .into_iter()
        .map(|record| {
            let (argv_prefix, command) = record
                .rsplit_once("\narg=")
                .expect("command record has a final remote-command argument");
            (
                argv_prefix.to_owned(),
                command.trim_end_matches('\n').to_owned(),
            )
        })
        .collect()
}

fn only_command_record(log: &std::path::Path) -> (String, String) {
    let records = command_records(log);
    assert_eq!(records.len(), 1, "unexpected fake SSH command count");
    records.into_iter().next().unwrap()
}

fn fixed_command_shapes(log: &std::path::Path) -> Vec<(String, String)> {
    command_records(log)
        .into_iter()
        .map(|(argv, command)| (argv, fixed_script_prefix(&command, " codex-ssh-bridge-op ")))
        .collect()
}

fn fixed_script_prefix(command: &str, marker: &str) -> String {
    command
        .split_once(marker)
        .unwrap_or_else(|| panic!("remote command lacks {marker:?}: {command}"))
        .0
        .to_owned()
}

fn normalized_remote_run_shape(log: &std::path::Path) -> (String, String) {
    // The payload is carried in DATA frames; a hostile stdin value must not
    // alter the static direct-rendered remote command at all. The final shell
    // word is the remaining request deadline, so normalize only that dynamic
    // value before comparing repeated calls.
    let (argv, command) = only_command_record(log);
    let (prefix, timeout) = command
        .rsplit_once(' ')
        .expect("remote_run command has a timeout argument");
    let seconds = timeout
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix("s'"))
        .expect("remote_run timeout is a quoted seconds value");
    let seconds = seconds
        .parse::<f64>()
        .expect("remote_run timeout contains a finite number");
    assert!(seconds.is_finite(), "remote_run timeout must be finite");
    (argv, format!("{prefix} '<timeout>'"))
}

fn assert_hostile_marker_absent(remote: &std::path::Path) {
    assert!(!remote.join("SHOULD_NOT_EXIST").exists());
    assert!(!std::path::Path::new("SHOULD_NOT_EXIST").exists());
}

#[tokio::test]
async fn task8_hostile_path_and_cwd_are_data_only_and_nul_is_prelaunch() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, log, tools) = fake_remote_tools_fixture(remote.path());

    call_json(
        &tools,
        "remote_list",
        json!({"host":"dev","path":".","max_entries":1}),
    )
    .await;
    let mut list_shape = None;
    for value in task8_hostile_values(true) {
        std::fs::write(&log, b"").unwrap();
        let result = call_json(
            &tools,
            "remote_list",
            json!({"host":"dev","path":value,"max_entries":1}),
        )
        .await;
        if value.contains('\0') {
            assert_eq!(result["isError"], true, "value={value:?}: {result}");
            assert!(
                transport_call_kinds(&log).is_empty(),
                "rejected value launched transport: {value:?}"
            );
        } else {
            let (argv, command) = only_command_record(&log);
            let shape = (argv, fixed_script_prefix(&command, " codex-ssh-bridge-op "));
            if let Some(expected) = &list_shape {
                assert_eq!(&shape, expected, "path altered argv/script: {value:?}");
            } else {
                list_shape = Some(shape);
            }
        }
        assert_hostile_marker_absent(remote.path());
    }

    call_json(
        &tools,
        "remote_run",
        json!({"host":"dev","command":"printf safe","cwd":".","shell":"sh"}),
    )
    .await;
    let mut run_shape = None;
    for value in task8_hostile_values(true) {
        std::fs::write(&log, b"").unwrap();
        let result = call_json(
            &tools,
            "remote_run",
            json!({"host":"dev","command":"printf safe","cwd":value,"shell":"sh"}),
        )
        .await;
        if value.contains('\0') {
            assert_eq!(result["isError"], true, "value={value:?}: {result}");
            assert!(
                transport_call_kinds(&log).is_empty(),
                "rejected value launched transport: {value:?}"
            );
        } else {
            let (argv, command) = only_command_record(&log);
            let shape = (
                argv,
                fixed_script_prefix(&command, " codex-ssh-bridge-run "),
            );
            if let Some(expected) = &run_shape {
                assert_eq!(&shape, expected, "cwd altered argv/wrapper: {value:?}");
            } else {
                run_shape = Some(shape);
            }
        }
        assert_hostile_marker_absent(remote.path());
    }
}

#[tokio::test]
async fn task8_hostile_query_and_glob_are_data_only_with_closed_rejections() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("needle.txt"), b"needle\n").unwrap();
    let (_runtime, log, tools) = fake_remote_tools_fixture(remote.path());
    call_json(
        &tools,
        "remote_search",
        json!({"host":"dev","query":"needle","path":"."}),
    )
    .await;

    let mut query_shape = None;
    for value in task8_hostile_values(true) {
        std::fs::write(&log, b"").unwrap();
        let result = call_json(
            &tools,
            "remote_search",
            json!({"host":"dev","query":value,"path":"."}),
        )
        .await;
        if value.contains(['\0', '\n']) {
            assert_eq!(result["isError"], true, "value={value:?}: {result}");
            assert!(
                transport_call_kinds(&log).is_empty(),
                "rejected value launched transport: {value:?}"
            );
        } else {
            let shape = fixed_command_shapes(&log);
            assert_eq!(shape.len(), 2, "query must use the closed two-step search");
            if let Some(expected) = &query_shape {
                assert_eq!(&shape, expected, "query altered argv/script: {value:?}");
            } else {
                query_shape = Some(shape);
            }
        }
        assert_hostile_marker_absent(remote.path());
    }

    let allowed_search_shapes = query_shape.expect("at least one valid query");
    for value in task8_hostile_values(true) {
        std::fs::write(&log, b"").unwrap();
        let result = call_json(
            &tools,
            "remote_search",
            json!({"host":"dev","query":"needle","path":".","globs":[value]}),
        )
        .await;
        if value.contains('\0') {
            assert_eq!(result["isError"], true, "value={value:?}: {result}");
            assert!(
                transport_call_kinds(&log).is_empty(),
                "rejected value launched transport: {value:?}"
            );
        } else {
            let shape = fixed_command_shapes(&log);
            assert!(!shape.is_empty(), "glob must launch candidate collection");
            for operation in &shape {
                assert!(
                    allowed_search_shapes.contains(operation),
                    "glob altered argv/script: {value:?}: {operation:?}"
                );
            }
        }
        assert_hostile_marker_absent(remote.path());
    }
}

#[tokio::test]
async fn task8_hostile_content_and_command_output_remain_single_response_data() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, log, tools) = fake_remote_tools_fixture(remote.path());
    call_json(
        &tools,
        "remote_write",
        json!({
            "host":"dev","path":"warm","content":"warm","encoding":"utf8",
            "mode":{"kind":"create"}
        }),
    )
    .await;
    let mut write_shape = None;
    for (index, value) in task8_hostile_values(true).into_iter().enumerate() {
        std::fs::write(&log, b"").unwrap();
        let path = format!("content-{index}");
        let result = call_json(
            &tools,
            "remote_write",
            json!({
                "host":"dev","path":path,"content":value,"encoding":"utf8",
                "mode":{"kind":"create"}
            }),
        )
        .await;
        assert_eq!(result["isError"], Value::Null, "value={value:?}: {result}");
        assert_eq!(
            std::fs::read(remote.path().join(&path)).unwrap(),
            value.as_bytes()
        );
        let (argv, command) = only_command_record(&log);
        let shape = (argv, fixed_script_prefix(&command, " codex-ssh-bridge-op "));
        if let Some(expected) = &write_shape {
            assert_eq!(&shape, expected, "content altered argv/script: {value:?}");
        } else {
            write_shape = Some(shape);
        }
        assert_hostile_marker_absent(remote.path());
    }

    let mut session = ProtocolSession::start(tools).await;
    let mut output_shape = None;
    let mut output_values = task8_hostile_values(true);
    output_values.push(
        "{\"jsonrpc\":\"2.0\",\"id\":999,\"result\":{}}\n{\"jsonrpc\":\"2.0\",\"method\":\"evil\"}",
    );
    for value in output_values {
        std::fs::write(&log, b"").unwrap();
        let result = session
            .call(
                "remote_run",
                json!({
                    "host":"dev","command":"cat","shell":"sh",
                    "stdin":{"encoding":"utf8","value":value}
                }),
            )
            .await;
        assert_eq!(result["isError"], Value::Null, "value={value:?}: {result}");
        let text = text_content(&result);
        if value.contains('\0') {
            let encoded = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
            assert!(
                text.contains(&format!("base64:{encoded}")),
                "binary command output was not preserved reversibly: {text}"
            );
        } else {
            assert!(
                text.contains(value),
                "command output was not preserved exactly: {text}"
            );
        }
        let shape = normalized_remote_run_shape(&log);
        if let Some(expected) = &output_shape {
            assert_eq!(
                &shape, expected,
                "stdin/output altered argv/source: {value:?}"
            );
        } else {
            output_shape = Some(shape);
        }
        assert_hostile_marker_absent(remote.path());
    }
    let ping = session
        .request(json!({"jsonrpc":"2.0","id":9001,"method":"ping"}))
        .await;
    assert_eq!(ping["id"], 9001);
    session.close().await;
}

fn five_host_tools_fixture(
    roots: &[(String, std::path::PathBuf)],
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    Arc<RemoteBridge>,
    RemoteMcpTools,
) {
    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let hosts = roots
        .iter()
        .map(|(host, root)| {
            (
                host.clone(),
                HostProfile {
                    root: root.to_string_lossy().into_owned(),
                    description: None,
                    read_only: false,
                    limits: HostLimitOverrides::default(),
                },
            )
        })
        .collect();
    let config = Config {
        limits: codex_ssh_bridge::config::Limits::default(),
        hosts,
        ..Config::default()
    };
    let log = runtime_base.path().join("ssh.log");
    let environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (OsString::from("FAKE_SSH_LOG"), log.as_os_str().to_owned()),
    ]);
    let runner = Arc::new(
        SshRunner::with_executable(
            Arc::new(config),
            runtime,
            store,
            support::fake_ssh_path(),
            environment,
        )
        .unwrap(),
    );
    let bridge = Arc::new(RemoteBridge::new(runner));
    let tools = RemoteMcpTools::new(Arc::clone(&bridge));
    (runtime_base, log, bridge, tools)
}

#[tokio::test]
async fn task8_five_hosts_pipeline_in_parallel_with_exact_context_and_no_sixth_call() {
    let roots = (0..5)
        .map(|index| {
            let root = tempfile::TempDir::new().unwrap();
            (format!("host-{index}"), root)
        })
        .collect::<Vec<_>>();
    let root_paths = roots
        .iter()
        .map(|(host, root)| (host.clone(), root.path().to_owned()))
        .collect::<Vec<_>>();
    let (_runtime, log, _bridge, tools) = five_host_tools_fixture(&root_paths);

    for (host, _) in &root_paths {
        let warm = call_json(
            &tools,
            "remote_run",
            json!({"host":host,"cwd":"/","command":":","shell":"sh"}),
        )
        .await;
        assert_eq!(warm["isError"], Value::Null, "warm host={host}: {warm}");
    }
    std::fs::write(&log, b"").unwrap();

    let mut session =
        ProtocolSession::start_with_limits(tools, codex_ssh_bridge::MAX_FRAME_BYTES, 8).await;
    let started = Instant::now();
    for (index, (host, _)) in root_paths.iter().enumerate() {
        let id = 100 + index as u64;
        session
            .send(json!({
                "jsonrpc":"2.0","id":id,"method":"tools/call",
                "params":{"name":"remote_run","arguments":{
                    "host":host,
                    "command":format!("sleep 1; printf HOST-{index}"),
                    "shell":"sh"
                }}
            }))
            .await;
    }
    let mut responses = BTreeMap::new();
    for _ in 0..5 {
        let response = session.read_response(Duration::from_secs(3)).await;
        let id = response["id"].as_u64().unwrap();
        assert!(responses.insert(id, response).is_none());
    }
    let elapsed = started.elapsed();
    if !cfg!(debug_assertions) {
        assert!(
            elapsed < Duration::from_millis(1_500),
            "five-host release elapsed={elapsed:?}"
        );
    }
    for (index, (host, _root)) in root_paths.iter().enumerate() {
        let id = 100 + index as u64;
        let result = &responses[&id]["result"];
        assert_eq!(result["isError"], Value::Null, "host={host}: {result}");
        assert_eq!(result["structuredContent"]["exit_code"], 0);
        assert!(result["structuredContent"].get("host").is_none());
        let text = text_content(result);
        assert!(
            text.contains(&format!("HOST-{index}")),
            "host output was interleaved or lost: {text}"
        );
    }
    let mut call_kinds = transport_call_kinds(&log);
    call_kinds.sort_unstable();
    assert_eq!(
        call_kinds,
        vec!["C"; 5],
        "each warm operation must perform exactly one command"
    );
    eprintln!("five-host MCP release sample: elapsed={elapsed:?}");
    session.close().await;
    drop(roots);
}

async fn wait_for_file(path: &std::path::Path, timeout: Duration) {
    tokio::time::timeout(timeout, async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {}", path.display()));
}

fn process_group_id(pid: u32) -> i32 {
    // SAFETY: getpgid only inspects kernel process metadata for the supplied PID.
    let group = unsafe { libc::getpgid(pid as libc::pid_t) };
    assert!(group > 0, "failed to resolve process group for PID {pid}");
    group
}

fn process_group_exists(group: i32) -> bool {
    // SAFETY: signal zero performs an existence/permission check and sends no signal.
    let status = unsafe { libc::kill(-group, 0) };
    status == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

async fn wait_for_process_group_exit(group: i32, timeout: Duration) -> Duration {
    let started = Instant::now();
    tokio::time::timeout(timeout, async {
        while process_group_exists(group) {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("process group {group} survived cancellation for {timeout:?}"));
    started.elapsed()
}

fn regular_file_count(directory: &std::path::Path) -> usize {
    std::fs::read_dir(directory)
        .into_iter()
        .flatten()
        .map(|entry| entry.unwrap())
        .map(|entry| {
            if entry.file_type().unwrap().is_dir() {
                regular_file_count(&entry.path())
            } else if entry.file_type().unwrap().is_file() {
                1
            } else {
                0
            }
        })
        .sum()
}

fn cancellation_tools_fixture() -> (
    tempfile::TempDir,
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    Arc<RemoteBridge>,
    RemoteMcpTools,
) {
    let remote = tempfile::TempDir::new().unwrap();
    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let log = runtime_base.path().join("ssh.log");
    let pid_file = runtime_base.path().join("command-child.pid");
    let environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (
            OsString::from("FAKE_SSH_FIXED_SLEEP_SECONDS"),
            OsString::from("10"),
        ),
        (OsString::from("FAKE_SSH_IGNORE_TERM"), OsString::from("1")),
        (OsString::from("FAKE_SSH_LOG"), log.as_os_str().to_owned()),
        (
            OsString::from("FAKE_SSH_CHILD_PID_FILE"),
            pid_file.as_os_str().to_owned(),
        ),
    ]);
    let runner = Arc::new(
        SshRunner::with_executable(
            Arc::new(support::config_with_host(
                "dev",
                remote.path().to_str().unwrap(),
            )),
            runtime,
            store,
            support::fake_ssh_path(),
            environment,
        )
        .unwrap(),
    );
    let bridge = Arc::new(RemoteBridge::new(runner));
    let tools = RemoteMcpTools::new(Arc::clone(&bridge));
    (runtime_base, remote, log, pid_file, bridge, tools)
}

#[tokio::test]
async fn task8_cancel_process_mcp_reaches_group_under_250ms_and_service_recovers() {
    let (runtime, remote, log, pid_file, bridge, tools) = cancellation_tools_fixture();
    let mut session = ProtocolSession::start(tools).await;
    let cancelled_id = 41;
    session
        .send(json!({
            "jsonrpc":"2.0","id":cancelled_id,"method":"tools/call",
            "params":{"name":"remote_run","arguments":{
                "host":"dev","command":"printf NEVER","shell":"sh"
            }}
        }))
        .await;
    wait_for_file(&pid_file, Duration::from_secs(2)).await;
    let pid = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse::<u32>()
        .unwrap();
    let process_group = process_group_id(pid);
    let started = Instant::now();
    session
        .send(json!({
            "jsonrpc":"2.0","method":"notifications/cancelled",
            "params":{"requestId":cancelled_id,"reason":"hostile\n$(touch SHOULD_NOT_EXIST)\0雪"}
        }))
        .await;
    session
        .send(json!({"jsonrpc":"2.0","id":42,"method":"ping"}))
        .await;
    let process_elapsed =
        wait_for_process_group_exit(process_group, Duration::from_millis(250)).await;
    let cancel_elapsed = started.elapsed();
    assert!(
        cancel_elapsed < Duration::from_millis(250),
        "cancel-to-process-exit={cancel_elapsed:?}, process-poll={process_elapsed:?}"
    );
    let ping = session.read_response(Duration::from_secs(1)).await;
    assert_eq!(
        ping["id"], 42,
        "cancelled request leaked a response: {ping}"
    );
    session
        .send(json!({
            "jsonrpc":"2.0","id":43,"method":"tools/call",
            "params":{"name":"remote_hosts","arguments":{}}
        }))
        .await;
    let hosts = session.read_response(Duration::from_secs(1)).await;
    assert_eq!(hosts["id"], 43);
    assert_eq!(hosts["result"]["structuredContent"], json!({}));
    assert_eq!(text_content(&hosts["result"]), "dev");
    assert!(
        tokio::time::timeout(Duration::from_millis(500), session.output.fill_buf())
            .await
            .is_err(),
        "cancelled request emitted a late MCP response"
    );
    assert_hostile_marker_absent(remote.path());
    assert_eq!(
        regular_file_count(runtime.path().join("codex-ssh-bridge").as_path()),
        0,
        "cancelled MCP call left a spool file"
    );

    let direct_cancel = CancellationToken::new();
    let direct_bridge = Arc::clone(&bridge);
    let task_cancel = direct_cancel.clone();
    let prior_calls = command_calls(&log);
    let direct = tokio::spawn(async move {
        direct_bridge
            .run(
                RemoteRunRequest {
                    host: "dev".to_owned(),
                    command: "printf NEVER".to_owned(),
                    cwd: None,
                    shell: RunShell::Sh,
                    timeout_ms: None,
                    stdin: None,
                },
                task_cancel,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while command_calls(&log) == prior_calls {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("direct bridge command did not start");
    direct_cancel.cancel();
    let error = direct.await.unwrap().unwrap_err();
    assert_eq!(
        error.details.remote_process_may_continue,
        Some(true),
        "forced cancellation must preserve unknown remote-process state"
    );
    eprintln!(
        "MCP cancellation release sample: total={cancel_elapsed:?} process_poll={process_elapsed:?}"
    );
    session.close().await;
}

#[tokio::test]
async fn task8_hostile_cancellation_reason_matrix_is_local_data_only() {
    let (_runtime, remote, log, pid_file, _bridge, tools) = cancellation_tools_fixture();
    let mut session = ProtocolSession::start(tools).await;
    for (index, reason) in task8_hostile_values(true).into_iter().enumerate() {
        let request_id = 1_000 + index as u64;
        let ping_id = 2_000 + index as u64;
        if pid_file.exists() {
            std::fs::remove_file(&pid_file).unwrap();
        }
        let prior_calls = command_calls(&log);
        session
            .send(json!({
                "jsonrpc":"2.0","id":request_id,"method":"tools/call",
                "params":{"name":"remote_run","arguments":{
                    "host":"dev","command":"printf NEVER","shell":"sh"
                }}
            }))
            .await;
        wait_for_file(&pid_file, Duration::from_secs(2)).await;
        assert_eq!(command_calls(&log), prior_calls + 1);
        session
            .send(json!({
                "jsonrpc":"2.0","method":"notifications/cancelled",
                "params":{"requestId":request_id,"reason":reason}
            }))
            .await;
        session
            .send(json!({"jsonrpc":"2.0","id":ping_id,"method":"ping"}))
            .await;
        let response = session.read_response(Duration::from_secs(1)).await;
        assert_eq!(response["id"], ping_id, "reason={reason:?}: {response}");
        assert_hostile_marker_absent(remote.path());
    }
    session.close().await;
}

fn duration_percentile(samples: &mut [Duration], percentile: usize) -> Duration {
    assert!(!samples.is_empty());
    assert!((1..=100).contains(&percentile));
    samples.sort_unstable();
    let index = (samples.len() * percentile).div_ceil(100) - 1;
    samples[index]
}

fn report_latency_samples(label: &str, samples: &mut [Duration]) -> (Duration, Duration, Duration) {
    let p50 = duration_percentile(samples, 50);
    let p95 = duration_percentile(samples, 95);
    let maximum = *samples.last().unwrap();
    eprintln!(
        "{label}: samples={} p50={p50:?} p95={p95:?} max={maximum:?}",
        samples.len()
    );
    (p50, p95, maximum)
}

#[tokio::test(flavor = "current_thread")]
async fn task78_release_dispatch_p95_is_below_two_milliseconds() {
    const WARM_CALLS: usize = 16;
    const MEASURED_CALLS: usize = 200;
    let (_runtime, _bridge, tools) = remote_tools_fixture();
    for _ in 0..WARM_CALLS {
        let result = tools
            .call("remote_hosts".to_owned(), json!({}), roomy_context())
            .await;
        std::hint::black_box(result);
    }
    let mut samples = Vec::with_capacity(MEASURED_CALLS);
    for _ in 0..MEASURED_CALLS {
        let started = Instant::now();
        let result = tools
            .call("remote_hosts".to_owned(), json!({}), roomy_context())
            .await;
        samples.push(started.elapsed());
        std::hint::black_box(result);
    }
    let (_, p95, _) =
        report_latency_samples("bridge-only MCP dispatch release sample", &mut samples);
    if !cfg!(debug_assertions) {
        assert!(
            p95 < Duration::from_millis(2),
            "bridge-only dispatch p95={p95:?}, raw={samples:?}"
        );
    }
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

fn compact_context() -> ToolCallContext {
    let compact = codex_ssh_bridge::mcp::maximum_compact_fallback_result_bytes();
    ToolCallContext {
        cancel: CancellationToken::new(),
        wire_budget: WireBudget {
            result_bytes: compact,
            compact_fallback_bytes: compact,
        },
    }
}

fn retention_models_fixture(
    base: &std::path::Path,
) -> (tempfile::TempDir, RemoteMcpTools, Value, Value, Value) {
    let mut root = base.to_owned();
    for index in 0..14 {
        root.push(format!("root-{index:02}-{}", "r".repeat(224)));
        std::fs::create_dir(&root).unwrap();
    }
    for index in 0..1_000 {
        let name = format!("list-{index:04}-{}", "l".repeat(180));
        std::fs::write(root.join(name), b"x").unwrap();
    }
    let search_line = format!("needle {}\n", "s".repeat(2_992));
    std::fs::write(root.join("search.txt"), search_line.repeat(500)).unwrap();
    let stat_paths = (0..256)
        .map(|index| format!("missing-{index:03}-{}", "p".repeat(2_000)))
        .collect::<Vec<_>>();

    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let config = Config {
        hosts: BTreeMap::from([(
            "dev".to_owned(),
            HostProfile {
                root: root.to_string_lossy().into_owned(),
                description: Some("h".repeat(2 * 1024 * 1024)),
                read_only: false,
                limits: HostLimitOverrides::default(),
            },
        )]),
        ..Config::default()
    };
    let environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (OsString::from("FAKE_SSH_ROOT"), root.as_os_str().to_owned()),
    ]);
    let runner = Arc::new(
        SshRunner::with_executable(
            Arc::new(config),
            runtime,
            store,
            support::fake_ssh_path(),
            environment,
        )
        .unwrap(),
    );
    let bridge = Arc::new(RemoteBridge::new(runner));
    (
        runtime_base,
        RemoteMcpTools::new(bridge),
        json!({"host":"dev","path":".","max_entries":1_000}),
        json!({"host":"dev","paths":stat_paths}),
        json!({
            "host":"dev","query":"needle","path":".","max_results":500
        }),
    )
}

async fn retain_all_large_models(
    tools: &RemoteMcpTools,
    list_args: Value,
    stat_args: Value,
    search_args: Value,
) -> Vec<Value> {
    let mut retained = Vec::new();
    for (name, arguments) in [
        ("remote_list", list_args),
        ("remote_stat", stat_args),
        ("remote_search", search_args),
    ] {
        let result = serde_json::to_value(
            tools
                .call(name.to_owned(), arguments, compact_context())
                .await,
        )
        .unwrap();
        let serialized_bytes = serde_json::to_vec(&result).unwrap().len();
        assert_eq!(result["isError"], Value::Null, "{name} returned an error");
        assert_eq!(
            result["structuredContent"]["truncated"],
            true,
            "{name}: serialized_bytes={serialized_bytes}, result_budget={}",
            compact_context().wire_budget.result_bytes
        );
        assert!(result["structuredContent"]["output_ref"].is_string());
        retained.push(result);
    }
    retained
}

#[tokio::test(flavor = "current_thread")]
async fn task8_output_rss_large_list_stat_search_models_all_force_retention() {
    let root = tempfile::TempDir::new().unwrap();
    let (_runtime, tools, list_args, stat_args, search_args) =
        retention_models_fixture(root.path());
    let retained = retain_all_large_models(&tools, list_args, stat_args, search_args).await;
    assert_eq!(retained.len(), 3);
}

#[test]
fn task8_output_rss_64_mib_and_retained_models_stay_below_sixteen_mib() {
    const CHILD_ENV: &str = "CODEX_SSH_BRIDGE_MCP_OUTPUT_RSS_CHILD";
    const TEST_NAME: &str = "task8_output_rss_64_mib_and_retained_models_stay_below_sixteen_mib";
    if cfg!(debug_assertions) {
        eprintln!("MCP output RSS assertion is release-only");
        return;
    }
    if std::env::var_os(CHILD_ENV).is_some() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(task8_output_rss_child());
        return;
    }
    for round in 1..=3 {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(CHILD_ENV, round.to_string())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("MCP output RSS fresh-child round {round}/3:");
        eprint!("{stdout}");
        eprint!("{stderr}");
        assert!(
            output.status.success(),
            "fresh MCP output RSS child {round}/3 failed: {output:?}"
        );
        assert!(
            stdout.contains("MCP output release RSS:")
                || stderr.contains("MCP output release RSS:"),
            "fresh MCP output RSS child {round}/3 did not run the requested test"
        );
    }
}

async fn task8_output_rss_child() {
    const RSS_DELTA_CEILING_KIB: u64 = 16 * 1024;
    let model_root = tempfile::TempDir::new().unwrap();
    let (_model_runtime, model_tools, list_args, stat_args, search_args) =
        retention_models_fixture(model_root.path());
    let output_root = tempfile::TempDir::new().unwrap();
    let (_output_runtime, _log, output_tools) = fake_remote_tools_with_options(
        output_root.path(),
        false,
        &[
            ("FAKE_SSH_MODE", OsString::from("bytes")),
            (
                "FAKE_SSH_STDOUT_BYTES",
                OsString::from(codex_ssh_bridge::MAX_OUTPUT_BYTES.to_string()),
            ),
            ("FAKE_SSH_STDERR_BYTES", OsString::from("0")),
        ],
    );

    let baseline = resident_kib();
    let worker = tokio::spawn(async move {
        let retained =
            retain_all_large_models(&model_tools, list_args, stat_args, search_args).await;
        let output = call_json(
            &output_tools,
            "remote_run",
            json!({"host":"dev","cwd":"/","command":":","shell":"sh"}),
        )
        .await;
        assert_eq!(output["isError"], Value::Null, "{output}");
        assert_eq!(output["structuredContent"]["exit_code"], 0);
        assert_eq!(output["structuredContent"]["truncated"], true);
        assert!(output["structuredContent"]["output_ref"].is_string());
        (retained, output)
    });
    let mut peak = baseline;
    while !worker.is_finished() {
        peak = peak.max(resident_kib());
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let values = worker.await.unwrap();
    std::hint::black_box(values);
    for _ in 0..20 {
        peak = peak.max(resident_kib());
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let delta = peak.saturating_sub(baseline);
    eprintln!(
        "MCP output release RSS: baseline={baseline} KiB peak={peak} KiB delta={delta} KiB ceiling={RSS_DELTA_CEILING_KIB} KiB"
    );
    assert!(
        delta < RSS_DELTA_CEILING_KIB,
        "MCP output RSS baseline={baseline} peak={peak} delta={delta}"
    );
}
