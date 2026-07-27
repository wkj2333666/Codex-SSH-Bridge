use std::future::Future;
use std::pin::Pin;

use codex_ssh_bridge::mcp::stdio::{
    CappedJsonBuffer, FrameEvent, FrameReader, MIN_MCP_FRAME_BYTES, SerializeLineError,
    exact_tools_list_response_bytes, required_mcp_frame_bytes, serialize_json_line,
    write_json_line,
};
use codex_ssh_bridge::mcp::{
    CallToolResult, McpServer, ProtocolState, RequestId, SUPPORTED_PROTOCOL_VERSIONS,
    ShutdownFuture, StrictJsonError, ToolAnnotations, ToolCallContext, ToolDefinition, ToolFuture,
    ToolService, WireBudget, duplicate_request_id_response, internal_error_response,
    invalid_params_response, invalid_request_id_response, invalid_request_response,
    maximum_compact_fallback_result_bytes, method_not_found_response, parse_error_response,
    parse_strict_json, request_too_large_response, result_response,
    server_not_initialized_response,
};
use codex_ssh_bridge::{BridgeError, ErrorCode};
use serde::Serialize;
use serde_json::{Value, json};
use std::io;
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{
    AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream,
};
use tokio::sync::{Mutex, Notify, Semaphore};
use tokio::time::{Duration, timeout};

fn nested_arrays(depth: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(depth * 2 + 4);
    input.extend(std::iter::repeat_n(b'[', depth));
    input.extend_from_slice(b"null");
    input.extend(std::iter::repeat_n(b']', depth));
    input
}

fn wide_array(nodes: usize) -> Vec<u8> {
    assert!(nodes >= 1);
    let mut input = Vec::with_capacity(nodes.saturating_mul(5));
    input.push(b'[');
    for index in 1..nodes {
        if index != 1 {
            input.push(b',');
        }
        input.extend_from_slice(b"null");
    }
    input.push(b']');
    input
}

fn wide_object(members: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(members.saturating_mul(16));
    input.push(b'{');
    for index in 0..members {
        if index != 0 {
            input.push(b',');
        }
        input.extend_from_slice(format!(r#""{index}":null"#).as_bytes());
    }
    input.push(b'}');
    input
}

fn object_with_key_bytes(bytes: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(bytes + 9);
    input.extend_from_slice(b"{\"");
    input.extend(std::iter::repeat_n(b'k', bytes));
    input.extend_from_slice(b"\":null}");
    input
}

fn nested_objects_with_members(members: usize) -> Vec<u8> {
    assert!(members >= 1);
    let inner = wide_object(members - 1);
    let mut input = Vec::with_capacity(inner.len() + 10);
    input.extend_from_slice(b"{\"outer\":");
    input.extend_from_slice(&inner);
    input.push(b'}');
    input
}

fn nested_objects_with_key_bytes(key_bytes: usize) -> Vec<u8> {
    const OUTER_KEY_BYTES: usize = "outer".len();
    assert!(key_bytes >= OUTER_KEY_BYTES);
    let inner = object_with_key_bytes(key_bytes - OUTER_KEY_BYTES);
    let mut input = Vec::with_capacity(inner.len() + 10);
    input.extend_from_slice(b"{\"outer\":");
    input.extend_from_slice(&inner);
    input.push(b'}');
    input
}

#[test]
fn task7_strict_json_rejects_duplicate_keys_at_every_depth() {
    for input in [
        br#"{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"ping"}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","name":"y"}}"#,
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"host":"a","host":"b"}}}"#,
    ] {
        assert_eq!(
            parse_strict_json(input),
            Err(StrictJsonError::DuplicateKey)
        );
    }
}

#[test]
fn task7_strict_json_duplicate_marker_wins_before_malformed_duplicate_value() {
    assert_eq!(
        parse_strict_json(br#"{"a":1,"a":}"#),
        Err(StrictJsonError::DuplicateKey)
    );
}

#[test]
fn task7_strict_json_classifies_syntax_and_trailing_data_without_diagnostics() {
    assert_eq!(
        parse_strict_json(br#"{"x":]"#),
        Err(StrictJsonError::Syntax)
    );
    assert_eq!(parse_strict_json(br#"{} {}"#), Err(StrictJsonError::Syntax));
    assert_eq!(StrictJsonError::Syntax.to_string(), "invalid JSON syntax");
}

#[test]
fn task7_adversarial_strict_json_enforces_depth_boundary() {
    assert!(parse_strict_json(&nested_arrays(64)).is_ok());
    assert_eq!(
        parse_strict_json(&nested_arrays(65)),
        Err(StrictJsonError::StructuralBudget)
    );
}

#[test]
fn task7_adversarial_strict_json_enforces_node_boundary_for_wide_arrays() {
    assert!(parse_strict_json(&wide_array(262_144)).is_ok());
    assert_eq!(
        parse_strict_json(&wide_array(262_145)),
        Err(StrictJsonError::StructuralBudget)
    );
}

#[test]
fn task7_adversarial_strict_json_enforces_aggregate_member_boundary_for_wide_objects() {
    assert!(parse_strict_json(&wide_object(131_072)).is_ok());
    assert_eq!(
        parse_strict_json(&wide_object(131_073)),
        Err(StrictJsonError::StructuralBudget)
    );
}

#[test]
fn task7_adversarial_strict_json_member_budget_is_aggregate_across_distinct_nested_maps() {
    assert!(parse_strict_json(&nested_objects_with_members(131_072)).is_ok());
    assert_eq!(
        parse_strict_json(&nested_objects_with_members(131_073)),
        Err(StrictJsonError::StructuralBudget)
    );
}

#[test]
fn task7_adversarial_strict_json_enforces_aggregate_key_byte_boundary() {
    assert!(parse_strict_json(&object_with_key_bytes(1_048_576)).is_ok());
    assert_eq!(
        parse_strict_json(&object_with_key_bytes(1_048_577)),
        Err(StrictJsonError::StructuralBudget)
    );
}

#[test]
fn task7_adversarial_strict_json_key_byte_budget_is_aggregate_across_distinct_nested_maps() {
    assert!(parse_strict_json(&nested_objects_with_key_bytes(1_048_576)).is_ok());
    assert_eq!(
        parse_strict_json(&nested_objects_with_key_bytes(1_048_577)),
        Err(StrictJsonError::StructuralBudget)
    );
}

#[test]
fn task7_strict_json_builds_all_json_value_kinds() {
    let parsed = parse_strict_json(
        br#"{"null":null,"bool":true,"signed":-1,"unsigned":18446744073709551615,"float":1.5,"string":"ok","array":[]}"#,
    )
    .unwrap();
    assert_eq!(
        parsed,
        json!({
            "null": null,
            "bool": true,
            "signed": -1,
            "unsigned": 18_446_744_073_709_551_615_u64,
            "float": 1.5,
            "string": "ok",
            "array": []
        })
    );
}

#[test]
fn task7_adversarial_strict_json_duplicate_detection_uses_destination_map_only() {
    let source = include_str!("../src/mcp/protocol.rs");
    assert!(source.contains("contains_key"));
    assert!(source.contains("next_key_seed"));
    assert!(source.contains("StrictKeySeed"));
    assert!(!source.contains("next_key::<String>"));
    assert!(!source.contains("HashSet"));
    assert!(!source.contains("HashSet<String>"));
    assert!(!source.contains("HashSet::<String>"));
    assert!(!source.contains("key.clone()"));
}

#[test]
fn task7_request_ids_preserve_exact_string_and_integer_identity() {
    assert_ne!(
        RequestId::try_from(json!(1)).unwrap(),
        RequestId::try_from(json!("1")).unwrap()
    );
    for invalid in [Value::Null, json!(true), json!(1.5), json!({}), json!([])] {
        assert!(RequestId::try_from(invalid).is_err());
    }
}

#[test]
fn task7_request_ids_preserve_wire_type_and_enforce_serialized_size() {
    let numeric = RequestId::try_from(json!(42)).unwrap();
    let string = RequestId::try_from(json!("42")).unwrap();
    assert_eq!(serde_json::to_vec(&numeric).unwrap(), b"42");
    assert_eq!(serde_json::to_vec(&string).unwrap(), br#""42""#);

    let exact = RequestId::try_from(json!("x".repeat(254))).unwrap();
    assert_eq!(serde_json::to_vec(&exact).unwrap().len(), 256);
    assert!(RequestId::try_from(json!("x".repeat(255))).is_err());
    assert_eq!(
        serde_json::to_vec(&RequestId::synthetic_max_wire())
            .unwrap()
            .len(),
        256
    );
}

#[test]
fn task7_request_ids_borrow_validate_before_bounded_clone() {
    let exact = json!("x".repeat(254));
    assert_eq!(
        RequestId::try_from_ref(&exact).unwrap(),
        RequestId::try_from(exact).unwrap()
    );
    let oversized = json!("x".repeat(1024 * 1024));
    assert!(RequestId::try_from_ref(&oversized).is_err());
    let source = include_str!("../src/mcp/protocol.rs");
    let method = source
        .split("pub fn try_from_ref")
        .nth(1)
        .unwrap()
        .split("impl Serialize")
        .next()
        .unwrap();
    assert!(method.find("string_wire_len_at_most").unwrap() < method.find("to_owned").unwrap());
}

#[test]
fn task7_request_ids_enforce_escaped_control_wire_boundary() {
    let exact_value = format!("{}\n", "x".repeat(252));
    let oversized_value = format!("{}\n", "x".repeat(253));
    assert_eq!(serde_json::to_vec(&exact_value).unwrap().len(), 256);
    assert_eq!(serde_json::to_vec(&oversized_value).unwrap().len(), 257);
    assert!(RequestId::try_from(json!(exact_value)).is_ok());
    assert!(RequestId::try_from(json!(oversized_value)).is_err());
}

#[test]
fn task7_request_ids_enforce_multibyte_utf8_wire_boundary() {
    let prefix = "界".repeat(84);
    let exact_value = format!("{prefix}ab");
    let oversized_value = format!("{prefix}abc");
    assert_eq!(serde_json::to_vec(&exact_value).unwrap().len(), 256);
    assert_eq!(serde_json::to_vec(&oversized_value).unwrap().len(), 257);
    assert!(RequestId::try_from(json!(exact_value)).is_ok());
    assert!(RequestId::try_from(json!(oversized_value)).is_err());
}

#[test]
fn task7_request_id_wire_counter_uses_its_explicit_bound() {
    let source = include_str!("../src/mcp/protocol.rs");
    assert!(source.contains("fn escaped_json_string_len(value: &str, maximum: usize)"));
    assert!(source.contains("escaped_json_string_len(value, maximum)"));
    assert!(source.contains("if length > maximum"));
    assert!(!source.contains("if length > MAX_REQUEST_ID_WIRE_BYTES"));
}

#[test]
fn task7_protocol_constants_and_state_are_exact() {
    assert_eq!(SUPPORTED_PROTOCOL_VERSIONS, ["2025-11-25", "2025-06-18"]);
    assert_ne!(ProtocolState::AwaitInitialize, ProtocolState::Ready);
    let _ = ProtocolState::AwaitInitialized;
    let _ = ProtocolState::Closing;
}

#[test]
fn task7_protocol_constructors_are_fixed_and_preserve_trusted_ids() {
    assert_eq!(
        parse_error_response(),
        json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}})
    );
    assert_eq!(
        invalid_request_response(),
        json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid Request"}})
    );
    assert_eq!(
        invalid_params_response(RequestId::try_from(json!(7)).unwrap()),
        json!({"jsonrpc":"2.0","id":7,"error":{"code":-32602,"message":"Invalid params"}})
    );
    assert_eq!(
        method_not_found_response(RequestId::try_from(json!(8)).unwrap()),
        json!({"jsonrpc":"2.0","id":8,"error":{"code":-32601,"message":"Method not found"}})
    );
    assert_eq!(
        internal_error_response(RequestId::try_from(json!(9)).unwrap()),
        json!({"jsonrpc":"2.0","id":9,"error":{"code":-32603,"message":"Internal error"}})
    );
    assert_eq!(
        server_not_initialized_response(RequestId::try_from(json!(10)).unwrap()),
        json!({"jsonrpc":"2.0","id":10,"error":{"code":-32002,"message":"Server not initialized"}})
    );
    assert_eq!(
        request_too_large_response(),
        json!({"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"Request too large"}})
    );
    assert_eq!(
        result_response(
            RequestId::try_from(json!("hostile\nmethod")).unwrap(),
            json!({"ok":true})
        ),
        json!({"jsonrpc":"2.0","id":"hostile\nmethod","result":{"ok":true}})
    );

    for response in [
        parse_error_response(),
        invalid_request_response(),
        invalid_params_response(RequestId::try_from(json!(1)).unwrap()),
    ] {
        let message = response["error"]["message"].as_str().unwrap();
        assert!(!message.contains("hostile"));
        assert!(!message.contains("method"));
    }
}

#[test]
fn task7_tool_protocol_models_serialize_exact_shapes() {
    let annotations = ToolAnnotations {
        read_only_hint: true,
        destructive_hint: false,
        idempotent_hint: true,
        open_world_hint: false,
    };
    let definition = ToolDefinition {
        name: "remote_read".into(),
        title: "Read remote file".into(),
        description: "Read a bounded remote file".into(),
        input_schema: json!({"type":"object"}),
        annotations,
    };
    assert_eq!(
        serde_json::to_value(definition).unwrap(),
        json!({
            "name":"remote_read",
            "title":"Read remote file",
            "description":"Read a bounded remote file",
            "inputSchema":{"type":"object"},
            "annotations":{
                "readOnlyHint":true,
                "destructiveHint":false,
                "idempotentHint":true,
                "openWorldHint":false
            }
        })
    );

    assert_eq!(
        serde_json::to_value(CallToolResult::text("ok")).unwrap(),
        json!({
            "content":[{"type":"text","text":"ok"}],
            "structuredContent":{}
        })
    );
    let invalid = CallToolResult::invalid_argument();
    let wire = serde_json::to_value(invalid).unwrap();
    assert_eq!(wire["isError"], true);
    assert_eq!(
        wire["structuredContent"]["error"]["code"],
        "INVALID_ARGUMENT"
    );
    assert_eq!(
        wire["structuredContent"]["error"]["message"],
        "invalid tool arguments"
    );
    assert!(wire["structuredContent"].get("action").is_none());
    let text: Value = serde_json::from_str(wire["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text["error"]["code"], "INVALID_ARGUMENT");
    assert_eq!(text["error"]["message"], "invalid tool arguments");
    assert!(text.get("action").is_none());
}

#[test]
fn invalid_argument_is_fixed_factual_and_contains_no_action() {
    let rendered = serde_json::to_value(CallToolResult::invalid_argument()).unwrap();
    assert_eq!(
        rendered["structuredContent"],
        json!({"error":{"code":"INVALID_ARGUMENT","message":"invalid tool arguments"}})
    );
    assert!(!rendered.to_string().contains("action"));
    let source = include_str!("../src/mcp/protocol.rs");
    assert!(source.contains("pub fn invalid_argument() -> Self"));
}

#[derive(Debug)]
struct NullService {
    definitions: Vec<ToolDefinition>,
}

fn lifecycle_definitions() -> Vec<ToolDefinition> {
    ["block", "echo"]
        .into_iter()
        .map(|name| ToolDefinition {
            name: name.into(),
            title: name.into(),
            description: format!("{name} test tool"),
            input_schema: if name == "echo" {
                json!({"type":"object","properties":{"text":{"type":"string"}},"required":["text"],"additionalProperties":false})
            } else {
                json!({"type":"object","properties":{},"additionalProperties":false})
            },
            annotations: ToolAnnotations {
                read_only_hint: true,
                destructive_hint: false,
                idempotent_hint: true,
                open_world_hint: false,
            },
        })
        .collect()
}

fn control_definitions() -> Vec<ToolDefinition> {
    let mut definitions = lifecycle_definitions();
    definitions.push(ToolDefinition {
        name: "remote_hosts".into(),
        title: "remote_hosts".into(),
        description: "return cached remote host metadata".into(),
        input_schema: json!({"type":"object","properties":{},"additionalProperties":false}),
        annotations: ToolAnnotations {
            read_only_hint: true,
            destructive_hint: false,
            idempotent_hint: true,
            open_world_hint: false,
        },
    });
    definitions
}

#[derive(Clone)]
struct StubTools {
    definitions: Arc<Vec<ToolDefinition>>,
    synchronous_calls: Arc<AtomicUsize>,
    first_polls: Arc<AtomicUsize>,
    bridge_ops: Arc<AtomicUsize>,
    observed_cancel: Arc<AtomicBool>,
    cancel_notify: Arc<Notify>,
    entered: Arc<AtomicBool>,
    entered_notify: Arc<Notify>,
    release: Arc<Semaphore>,
    contexts: Arc<Mutex<Vec<ToolCallContext>>>,
    shutdowns: Arc<AtomicUsize>,
}

impl StubTools {
    fn new() -> Self {
        Self {
            definitions: Arc::new(lifecycle_definitions()),
            synchronous_calls: Arc::new(AtomicUsize::new(0)),
            first_polls: Arc::new(AtomicUsize::new(0)),
            bridge_ops: Arc::new(AtomicUsize::new(0)),
            observed_cancel: Arc::new(AtomicBool::new(false)),
            cancel_notify: Arc::new(Notify::new()),
            entered: Arc::new(AtomicBool::new(false)),
            entered_notify: Arc::new(Notify::new()),
            release: Arc::new(Semaphore::new(0)),
            contexts: Arc::new(Mutex::new(Vec::new())),
            shutdowns: Arc::new(AtomicUsize::new(0)),
        }
    }

    async fn wait_for_polls(&self, count: usize) {
        loop {
            let notified = self.entered_notify.notified();
            if self.first_polls.load(Ordering::Acquire) >= count {
                return;
            }
            timeout(Duration::from_secs(1), notified)
                .await
                .expect("tool must be first-polled");
        }
    }

    async fn wait_for_cancel(&self) {
        loop {
            let notified = self.cancel_notify.notified();
            if self.observed_cancel.load(Ordering::Acquire) {
                return;
            }
            timeout(Duration::from_secs(1), notified)
                .await
                .expect("service must observe cancellation");
        }
    }
}

impl ToolService for StubTools {
    fn definitions(&self) -> &[ToolDefinition] {
        self.definitions.as_slice()
    }

    fn call(&self, name: String, arguments: Value, context: ToolCallContext) -> ToolFuture {
        self.synchronous_calls.fetch_add(1, Ordering::SeqCst);
        let first_polls = Arc::clone(&self.first_polls);
        let bridge_ops = Arc::clone(&self.bridge_ops);
        let observed_cancel = Arc::clone(&self.observed_cancel);
        let cancel_notify = Arc::clone(&self.cancel_notify);
        let entered = Arc::clone(&self.entered);
        let entered_notify = Arc::clone(&self.entered_notify);
        let release = Arc::clone(&self.release);
        let contexts = Arc::clone(&self.contexts);
        Box::pin(async move {
            first_polls.fetch_add(1, Ordering::SeqCst);
            contexts.lock().await.push(context.clone());
            entered.store(true, Ordering::Release);
            entered_notify.notify_waiters();
            if name == "block" {
                bridge_ops.fetch_add(1, Ordering::SeqCst);
                tokio::select! {
                    () = context.cancel.cancelled() => {
                        observed_cancel.store(true, Ordering::SeqCst);
                        cancel_notify.notify_waiters();
                        return CallToolResult::text("cancelled internally");
                    }
                    permit = release.acquire() => {
                        permit.expect("test release semaphore remains open").forget();
                        return CallToolResult::text("released");
                    }
                }
            }
            if name == "echo" {
                return match arguments.get("text").and_then(Value::as_str) {
                    Some(text) => {
                        bridge_ops.fetch_add(1, Ordering::SeqCst);
                        CallToolResult::text(text)
                    }
                    None => CallToolResult::invalid_argument(),
                };
            }
            unreachable!("the lifecycle owner rejects unknown names")
        })
    }

    fn shutdown(&self) -> ShutdownFuture<'_> {
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

struct ControlTools {
    definitions: Arc<Vec<ToolDefinition>>,
    stub: StubTools,
}

impl ControlTools {
    fn new() -> Self {
        Self {
            definitions: Arc::new(control_definitions()),
            stub: StubTools::new(),
        }
    }
}

impl ToolService for ControlTools {
    fn definitions(&self) -> &[ToolDefinition] {
        self.definitions.as_slice()
    }

    fn call(&self, name: String, arguments: Value, context: ToolCallContext) -> ToolFuture {
        if name == "remote_hosts" {
            return Box::pin(async { CallToolResult::text("cached hosts") });
        }
        self.stub.call(name, arguments, context)
    }
}

struct Session {
    input: DuplexStream,
    output: BufReader<DuplexStream>,
    serve: tokio::task::JoinHandle<Result<(), BridgeError>>,
}

impl Session {
    async fn start<S: ToolService>(server: McpServer<S>) -> Self {
        Self::start_with_output_capacity(server, 128 * 1024).await
    }

    async fn start_with_output_capacity<S: ToolService>(
        server: McpServer<S>,
        capacity: usize,
    ) -> Self {
        Self::start_with_capacities(server, 128 * 1024, capacity).await
    }

    async fn start_with_capacities<S: ToolService>(
        server: McpServer<S>,
        input_capacity: usize,
        output_capacity: usize,
    ) -> Self {
        let (input, server_reader) = tokio::io::duplex(input_capacity);
        let (server_writer, output) = tokio::io::duplex(output_capacity);
        let serve = tokio::spawn(server.serve(server_reader, server_writer));
        Self {
            input,
            output: BufReader::new(output),
            serve,
        }
    }

    async fn send(&mut self, value: &Value) {
        let mut frame = serde_json::to_vec(value).unwrap();
        frame.push(b'\n');
        timeout(Duration::from_secs(1), self.input.write_all(&frame))
            .await
            .expect("send must finish")
            .unwrap();
    }

    async fn recv(&mut self) -> Value {
        let mut line = String::new();
        timeout(Duration::from_secs(1), self.output.read_line(&mut line))
            .await
            .expect("response must arrive")
            .unwrap();
        assert!(!line.is_empty(), "response stream closed");
        serde_json::from_str(line.trim_end()).unwrap()
    }

    async fn ready(&mut self) {
        self.send(&initialize(json!(100), "2025-11-25")).await;
        assert_eq!(self.recv().await["id"], 100);
        self.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}))
            .await;
    }

    async fn close(mut self) -> Result<(), BridgeError> {
        self.input.shutdown().await.unwrap();
        timeout(Duration::from_secs(1), self.serve)
            .await
            .expect("serve must stop")
            .expect("serve must not panic")
    }
}

#[test]
fn task7_constructor_enforces_exact_frame_bounds() {
    let service = Arc::new(NullService {
        definitions: lifecycle_definitions(),
    });
    let required =
        required_mcp_frame_bytes(service.definitions(), 0, &RequestId::synthetic_max_wire())
            .unwrap();
    assert!(McpServer::new(Arc::clone(&service), required).is_ok());

    let too_small = McpServer::new(Arc::clone(&service), required - 1).unwrap_err();
    assert_eq!(
        too_small,
        BridgeError::invalid_argument("MCP frame bound is invalid")
    );
    let too_large =
        McpServer::new(Arc::clone(&service), codex_ssh_bridge::MAX_FRAME_BYTES + 1).unwrap_err();
    assert_eq!(
        too_large,
        BridgeError::invalid_argument("MCP frame bound is invalid")
    );
}

#[tokio::test]
async fn task7_constructor_max_id_counts_every_fixed_response_and_live_control_result() {
    timeout(Duration::from_secs(5), async {
        let service = Arc::new(NullService {
            definitions: lifecycle_definitions(),
        });
        let id = RequestId::synthetic_max_wire();
        let id_value = serde_json::to_value(&id).unwrap();
        let required = required_mcp_frame_bytes(service.definitions(), 0, &id).unwrap();
        assert!(McpServer::new(Arc::clone(&service), required).is_ok());
        assert_eq!(
            McpServer::new(Arc::clone(&service), required - 1).unwrap_err(),
            BridgeError::invalid_argument("MCP frame bound is invalid")
        );

        let fixed = [
            parse_error_response(),
            invalid_request_response(),
            invalid_request_id_response(id.clone()),
            duplicate_request_id_response(),
            method_not_found_response(id.clone()),
            invalid_params_response(id.clone()),
            internal_error_response(id.clone()),
            server_not_initialized_response(id.clone()),
            request_too_large_response(),
        ];
        for response in fixed {
            assert!(serde_json::to_vec(&response).unwrap().len() <= required);
            assert!(serialize_json_line(&response, required).is_ok());
        }

        let server = McpServer::new(service, required).unwrap();
        let frames = [
            initialize(id_value.clone(), "2025-11-25"),
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
            json!({"jsonrpc":"2.0","id":id_value.clone(),"method":"ping","params":{}}),
            json!({"jsonrpc":"2.0","id":id_value,"method":"tools/list","params":{}}),
        ];
        let (responses, result) = serve_frames(server, &frames).await;
        assert!(result.is_ok());
        assert_eq!(responses.len(), 3);
        for response in responses {
            assert!(serde_json::to_vec(&response).unwrap().len() <= required);
        }
    })
    .await
    .expect("test must complete");
}

async fn serve_frames<S: ToolService>(
    server: McpServer<S>,
    frames: &[Value],
) -> (Vec<Value>, Result<(), BridgeError>) {
    let mut input = Vec::new();
    for frame in frames {
        input.extend(serde_json::to_vec(frame).unwrap());
        input.push(b'\n');
    }
    serve_raw(server, input).await
}

async fn serve_raw<S: ToolService>(
    server: McpServer<S>,
    input: Vec<u8>,
) -> (Vec<Value>, Result<(), BridgeError>) {
    let (writer, mut reader) = tokio::io::duplex(2 * 1024 * 1024);
    let serve = tokio::spawn(server.serve(std::io::Cursor::new(input), writer));
    let mut output = Vec::new();
    timeout(Duration::from_secs(1), reader.read_to_end(&mut output))
        .await
        .expect("writer must close")
        .unwrap();
    let result = timeout(Duration::from_secs(1), serve)
        .await
        .expect("server must stop")
        .expect("server task must not panic");
    let responses = output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    (responses, result)
}

fn initialize(id: Value, version: &str) -> Value {
    json!({
        "jsonrpc":"2.0",
        "id":id,
        "method":"initialize",
        "params":{
            "protocolVersion":version,
            "capabilities":{},
            "clientInfo":{"name":"test-client","version":"1"}
        }
    })
}

async fn initialize_client_is_accepted(version: &str, client_info: Value) -> bool {
    let service = Arc::new(NullService {
        definitions: lifecycle_definitions(),
    });
    let server = McpServer::new(service, MIN_MCP_FRAME_BYTES).unwrap();
    let request = json!({
        "jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":version,
            "capabilities":{},
            "clientInfo":client_info
        }
    });
    let (responses, result) = serve_frames(server, &[request]).await;
    assert!(result.is_ok());
    responses[0].get("result").is_some()
}

#[tokio::test]
async fn task7_lifecycle_initialize_ready_ping_and_list() {
    timeout(Duration::from_secs(5), async {
        let service = Arc::new(NullService {
            definitions: lifecycle_definitions(),
        });
        let server = McpServer::new(service, MIN_MCP_FRAME_BYTES).unwrap();
        let frames = [
            initialize(json!(1), "2025-11-25"),
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
            json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{}}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}),
        ];
        let (responses, result) = serve_frames(server, &frames).await;
        assert!(result.is_ok());
        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0]["id"], 1);
        assert_eq!(responses[0]["result"]["protocolVersion"], "2025-11-25");
        assert_eq!(responses[1], json!({"jsonrpc":"2.0","id":2,"result":{}}));
        assert_eq!(responses[2]["id"], 3);
        assert_eq!(responses[2]["result"]["tools"].as_array().unwrap().len(), 2);
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_optional_empty_method_params_may_be_absent() {
    timeout(Duration::from_secs(5), async {
        let service = Arc::new(NullService {
            definitions: lifecycle_definitions(),
        });
        let server = McpServer::new(service, MIN_MCP_FRAME_BYTES).unwrap();
        let frames = [
            initialize(json!(1), "2025-11-25"),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"ping"}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}),
        ];
        let (responses, result) = serve_frames(server, &frames).await;
        assert!(result.is_ok());
        assert_eq!(responses.len(), 3);
        assert_eq!(responses[1]["result"], json!({}));
        assert!(responses[2]["result"]["tools"].is_array());
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_request_notification_barrier_and_strict_envelope() {
    timeout(Duration::from_secs(5), async {
        let service = Arc::new(NullService {
            definitions: lifecycle_definitions(),
        });
        let server = McpServer::new(service, MIN_MCP_FRAME_BYTES).unwrap();
        let frames = [
            json!({"jsonrpc":"2.0","method":"initialize","params":{}}),
            json!({"jsonrpc":"2.0","id":null,"method":"ping","params":{}}),
            initialize(json!(1), "2025-11-25"),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
            json!({"jsonrpc":"2.0","id":3,"method":"notifications/initialized","params":{}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
            json!({"jsonrpc":"2.0","method":"ping","params":{}}),
            json!({"jsonrpc":"2.0","id":4,"method":"ping","params":{},"extra":true}),
            json!({"jsonrpc":"2.0","id":5,"method":"ping","params":{"_meta":{}}}),
        ];
        let (responses, result) = serve_frames(server, &frames).await;
        assert!(result.is_ok());
        assert_eq!(
            responses
                .iter()
                .map(|v| v["id"].clone())
                .collect::<Vec<_>>(),
            [
                Value::Null,
                json!(1),
                json!(2),
                json!(3),
                json!(4),
                json!(5)
            ]
        );
        assert_eq!(responses[0], invalid_request_response());
        assert_eq!(responses[2]["error"]["code"], -32002);
        assert_eq!(responses[3]["error"]["code"], -32600);
        assert_eq!(responses[4]["error"]["code"], -32600);
        assert_eq!(responses[5]["result"], json!({}));
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_invalid_id_and_nonobject_envelope_matrix() {
    timeout(Duration::from_secs(5), async {
        let service = Arc::new(NullService {
            definitions: lifecycle_definitions(),
        });
        let server = McpServer::new(service, MIN_MCP_FRAME_BYTES).unwrap();
        let frames = [
            json!(null),
            json!([]),
            json!("scalar"),
            json!({"jsonrpc":"2.0","id":null,"method":"ping"}),
            json!({"jsonrpc":"2.0","id":true,"method":"ping"}),
            json!({"jsonrpc":"2.0","id":1.5,"method":"ping"}),
            json!({"jsonrpc":"2.0","id":{},"method":"ping"}),
            json!({"jsonrpc":"2.0","id":[],"method":"ping"}),
            json!({"jsonrpc":"2.0","id":"x".repeat(255),"method":"ping"}),
            initialize(json!(10), "2025-11-25"),
        ];
        let (responses, result) = serve_frames(server, &frames).await;
        assert!(result.is_ok());
        assert_eq!(responses.len(), 10);
        for response in &responses[..9] {
            assert_eq!(response, &invalid_request_response());
        }
        assert_eq!(responses[9]["id"], 10);
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_june_open_and_november_closed_method_extensions() {
    timeout(Duration::from_secs(5), async {
        let service = Arc::new(NullService { definitions: lifecycle_definitions() });
        let server = McpServer::new(Arc::clone(&service), MIN_MCP_FRAME_BYTES).unwrap();
        let june = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"1"},"extension":{"bounded":true}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{"extension":true}}),
            json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{"extension":true}}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"extension":true}}),
        ];
        let (responses, result) = serve_frames(server, &june).await;
        assert!(result.is_ok());
        assert_eq!(responses.len(), 3);
        assert_eq!(responses[1]["result"], json!({}));
        assert!(responses[2]["result"]["tools"].is_array());

        let server = McpServer::new(service, MIN_MCP_FRAME_BYTES).unwrap();
        let november = [
            initialize(json!(1), "2025-11-25"),
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
            json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{"extension":true}}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"extension":true}}),
        ];
        let (responses, result) = serve_frames(server, &november).await;
        assert!(result.is_ok());
        assert_eq!(responses[1]["error"]["code"], -32602);
        assert_eq!(responses[2]["error"]["code"], -32602);
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_june_initialize_rejects_unnegotiated_task() {
    timeout(Duration::from_secs(5), async {
        let service = Arc::new(NullService {
            definitions: lifecycle_definitions(),
        });
        let server = McpServer::new(service, MIN_MCP_FRAME_BYTES).unwrap();
        let request = json!({
            "jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-06-18",
                "capabilities":{},
                "clientInfo":{"name":"x","version":"1"},
                "task":{"ttl":1}
            }
        });
        let (responses, result) = serve_frames(server, &[request]).await;
        assert!(result.is_ok());
        assert_eq!(
            responses,
            [invalid_params_response(
                RequestId::try_from(json!(1)).unwrap()
            )]
        );
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_official_six_method_versioned_params_matrix() {
    timeout(Duration::from_secs(5), async {
        for version in ["2025-06-18", "2025-11-25"] {
            let june = version == "2025-06-18";
            let tools = Arc::new(StubTools::new());
            let mut session = Session::start(McpServer::new(
                Arc::clone(&tools),
                MIN_MCP_FRAME_BYTES
            ).unwrap()).await;
            let init_extension = if june { json!({"extension":true}) } else { json!({}) };
            session.send(&json!({
                "jsonrpc":"2.0","id":1,"method":"initialize","params":{
                    "protocolVersion":version,"capabilities":{},
                    "clientInfo":{"name":"x","version":"1"},
                    "_meta":{"trace":1},
                    "extension":init_extension.get("extension").cloned().unwrap_or(Value::Null)
                }
            })).await;
            let init_response = session.recv().await;
            if june {
                assert_eq!(init_response["result"]["protocolVersion"], version);
            } else {
                assert_eq!(init_response["error"]["code"], -32602);
                session.send(&json!({"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":version,"capabilities":{},"clientInfo":{"name":"x","version":"1"},"_meta":{"trace":1}}})).await;
                assert_eq!(session.recv().await["result"]["protocolVersion"], version);
            }
            session.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{"_meta":{"trace":1},"extension":true}})).await;
            if !june {
                session.send(&json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}})).await;
                assert_eq!(session.recv().await["error"]["code"], -32002);
                session.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{"_meta":{"trace":1}}})).await;
            }

            for (id, method, mut params) in [
                (10, "ping", json!({"_meta":{"trace":1}})),
                (11, "tools/list", json!({"_meta":{"trace":1}})),
                (12, "tools/call", json!({"name":"echo","arguments":{"text":"ok"},"_meta":{"trace":1}})),
            ] {
                if june { params["extension"] = json!(true); }
                session.send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})).await;
                assert!(session.recv().await.get("result").is_some(), "version={version} method={method}");
            }
            assert_eq!(tools.synchronous_calls.load(Ordering::SeqCst), 1);

            for (id, method, params) in [
                (20, "ping", json!({"task":{}})),
                (21, "tools/list", json!({"task":{}})),
                (22, "tools/call", json!({"name":"echo","arguments":{"text":"bad"},"task":{}})),
            ] {
                session.send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})).await;
                assert_eq!(session.recv().await["error"]["code"], -32602);
            }
            assert_eq!(tools.synchronous_calls.load(Ordering::SeqCst), 1);

            session.send(&json!({"jsonrpc":"2.0","id":"cancel","method":"tools/call","params":{"name":"block","arguments":{}}})).await;
            tools.wait_for_polls(2).await;
            session.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"cancel","_meta":{"trace":1},"extension":true}})).await;
            session.send(&json!({"jsonrpc":"2.0","id":29,"method":"ping","params":{}})).await;
            assert_eq!(session.recv().await["id"], 29);
            assert_eq!(tools.contexts.lock().await[1].cancel.is_cancelled(), june);
            if !june {
                session.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"cancel","task":{}}})).await;
                session.send(&json!({"jsonrpc":"2.0","id":28,"method":"ping","params":{}})).await;
                assert_eq!(session.recv().await["id"], 28);
                assert!(!tools.contexts.lock().await[1].cancel.is_cancelled());
                session.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"cancel","_meta":{"trace":1}}})).await;
            }
            session.send(&json!({"jsonrpc":"2.0","id":30,"method":"ping","params":{"_meta":{}}})).await;
            assert_eq!(session.recv().await["id"], 30);
            assert!(session.close().await.is_ok());
        }
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_duplicate_and_notification_shapes_have_zero_service_effect() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start(McpServer::new(
            Arc::clone(&tools),
            MIN_MCP_FRAME_BYTES
            ).unwrap()).await;
        session.send(&json!({"jsonrpc":"2.0","method":"initialize","params":{}})).await;
        session.send(&initialize(json!(1), "2025-11-25")).await;
        assert_eq!(session.recv().await["id"], 1);
        session.send(&initialize(json!(2), "2025-11-25")).await;
        assert_eq!(session.recv().await["error"]["code"], -32600);
        session.send(&json!({"jsonrpc":"2.0","id":3,"method":"notifications/initialized","params":{}})).await;
        assert_eq!(session.recv().await["error"]["code"], -32600);
        session.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{"task":{}}})).await;
        session.send(&json!({"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}})).await;
        assert_eq!(session.recv().await["error"]["code"], -32002);
        session.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}})).await;
        session.send(&json!({"jsonrpc":"2.0","method":"ping","params":{}})).await;
        session.send(&json!({"jsonrpc":"2.0","method":"tools/list","params":{}})).await;
        session.send(&json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{"text":"ignored"}}})).await;
        assert_eq!(tools.synchronous_calls.load(Ordering::SeqCst), 0);
        assert_eq!(tools.first_polls.load(Ordering::SeqCst), 0);
        assert_eq!(tools.bridge_ops.load(Ordering::SeqCst), 0);
        session.send(&json!({"jsonrpc":"2.0","id":5,"method":"ping","params":{}})).await;
        assert_eq!(session.recv().await["id"], 5);
        assert!(session.close().await.is_ok());
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_complete_validation_and_zero_service_effect_matrix() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let server = McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES).unwrap();
        let frames = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{},"clientInfo":{"name":"x","version":"1"}}}),
            json!({"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"x","version":"1"}}}),
            json!({"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{}}}),
            json!({"jsonrpc":"2.0","id":4,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"x","version":"1"},"_meta":false}}),
            json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"echo","arguments":{"text":"before initialize"}}}),
            json!({"jsonrpc":"2.0","id":6,"method":"unknown/request","params":{}}),
            json!({"jsonrpc":"2.0","method":"unknown/notification","params":{}}),
            initialize(json!(7), "2025-11-25"),
            json!({"jsonrpc":"2.0","id":8,"method":"ping","params":{}}),
            json!({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"echo","arguments":{"text":"before initialized"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{"_meta":false}}),
            json!({"jsonrpc":"2.0","id":10,"method":"tools/list","params":{}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
            json!({"jsonrpc":"2.0","id":11,"method":"ping","params":{"_meta":false}}),
            json!({"jsonrpc":"2.0","id":12,"method":"tools/list","params":{"_meta":false}}),
            json!({"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"echo","arguments":{"text":"bad meta"},"_meta":false}}),
            json!({"jsonrpc":"2.0","id":14,"method":"tools/list"}),
            json!({"jsonrpc":"2.0","id":15,"method":"tools/list","params":{"cursor":""}}),
            json!({"jsonrpc":"2.0","id":16,"method":"tools/list","params":{"cursor":"next"}}),
            json!({"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"missing","arguments":{}}}),
            json!({"jsonrpc":"2.0","id":18,"method":"tools/call","params":{"name":"echo","arguments":{"text":"extra"},"extension":true}}),
            json!({"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"echo","arguments":{"text":"malformed envelope"}},"extra":true}),
            json!({"jsonrpc":"2.0","id":20,"method":"unknown/request","params":{}}),
            json!({"jsonrpc":"2.0","method":"unknown/notification","params":{}}),
            json!({"jsonrpc":"2.0","id":21,"method":"ping","params":{}}),
        ];
        let (responses, result) = serve_frames(server, &frames).await;
        assert!(result.is_ok(), "unexpected server result: {result:?}");
        assert_eq!(
            responses
                .iter()
                .map(|response| response["id"].clone())
                .collect::<Vec<_>>(),
            (1..=21).map(|id| json!(id)).collect::<Vec<_>>()
        );
        for response in &responses[0..4] {
            assert_eq!(response["error"]["code"], -32602);
        }
        assert_eq!(responses[4]["error"]["code"], -32002);
        assert_eq!(responses[5]["error"]["code"], -32601);
        assert_eq!(responses[6]["result"]["protocolVersion"], "2025-11-25");
        assert_eq!(responses[7]["result"], json!({}));
        assert_eq!(responses[8]["error"]["code"], -32002);
        assert_eq!(responses[9]["error"]["code"], -32002);
        for response in &responses[10..13] {
            assert_eq!(response["error"]["code"], -32602);
        }
        for response in &responses[13..15] {
            assert!(response["result"]["tools"].is_array());
            assert!(response["result"].get("nextCursor").is_none());
        }
        for response in &responses[15..18] {
            assert_eq!(response["error"]["code"], -32602);
        }
        assert_eq!(responses[18]["error"]["code"], -32600);
        assert_eq!(responses[19]["error"]["code"], -32601);
        assert_eq!(responses[20]["result"], json!({}));
        assert_eq!(tools.synchronous_calls.load(Ordering::SeqCst), 0);
        assert_eq!(tools.first_polls.load(Ordering::SeqCst), 0);
        assert_eq!(tools.bridge_ops.load(Ordering::SeqCst), 0);
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_june_rejects_task_for_initialized_and_cancelled() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start(
            McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES).unwrap(),
        )
        .await;
        session.send(&initialize(json!(1), "2025-06-18")).await;
        assert_eq!(session.recv().await["id"], 1);
        session
            .send(&json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{"task":{}}}))
            .await;
        session
            .send(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}))
            .await;
        assert_eq!(session.recv().await["error"]["code"], -32002);
        assert_eq!(tools.synchronous_calls.load(Ordering::SeqCst), 0);
        assert_eq!(tools.first_polls.load(Ordering::SeqCst), 0);
        assert_eq!(tools.bridge_ops.load(Ordering::SeqCst), 0);

        session
            .send(&json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}))
            .await;
        session
            .send(&json!({"jsonrpc":"2.0","id":"active","method":"tools/call","params":{"name":"block","arguments":{}}}))
            .await;
        tools.wait_for_polls(1).await;
        let token = tools.contexts.lock().await[0].cancel.clone();
        session
            .send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"active","task":{}}}))
            .await;
        session
            .send(&json!({"jsonrpc":"2.0","id":3,"method":"ping","params":{}}))
            .await;
        assert_eq!(session.recv().await["id"], 3);
        assert!(!token.is_cancelled());
        session
            .send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"active"}}))
            .await;
        tools.wait_for_cancel().await;
        assert!(session.close().await.is_ok());
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_strict_json_errors_are_fixed_and_side_effect_free() {
    timeout(Duration::from_secs(5), async {
        let service = Arc::new(NullService { definitions: lifecycle_definitions() });
        let server = McpServer::new(service, MIN_MCP_FRAME_BYTES).unwrap();
        let input = br#"{"jsonrpc":"2.0","id":1,"method":"ping","method":"initialize"}
{"jsonrpc":"2.0","id":1,"method":]
{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}
"#.to_vec();
        let (responses, result) = serve_raw(server, input).await;
        assert!(result.is_ok());
        assert_eq!(responses[0], invalid_request_response());
        assert_eq!(responses[1], parse_error_response());
        assert_eq!(responses[2]["id"], 2);
        assert_eq!(responses[2]["result"]["protocolVersion"], "2025-11-25");
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_version_shapes_and_absolute_uri_policy() {
    timeout(Duration::from_secs(5), async {
        let june_with_icons = json!({
            "jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-06-18","capabilities":{},
                "clientInfo":{"name":"x","version":"1","icons":[{"src":"data:,ok"}]}
            }
        });
        let invalid_uri = json!({
            "jsonrpc":"2.0","id":2,"method":"initialize","params":{
                "protocolVersion":"2025-11-25","capabilities":{},
                "clientInfo":{"name":"x","version":"1","icons":[{"src":"https://user@example.com/x"}]}
            }
        });
        let valid_latest = json!({
            "jsonrpc":"2.0","id":3,"method":"initialize","params":{
                "protocolVersion":"unsupported","capabilities":{},
                "clientInfo":{"name":"x","version":"1","title":"t","websiteUrl":"HTTPS://example.com:443/a//b?q=?#f","icons":[{"src":"data:,hello","mimeType":"text/plain","sizes":["16x16"],"theme":"dark"}]}
            }
        });
        let numeric_dns = json!({
            "jsonrpc":"2.0","id":4,"method":"initialize","params":{
                "protocolVersion":"2025-11-25","capabilities":{},
                "clientInfo":{"name":"x","version":"1","websiteUrl":"https://123/x"}
            }
        });
        for (request, accepted) in [(june_with_icons, false), (invalid_uri, false), (valid_latest, true), (numeric_dns, true)] {
            let service = Arc::new(NullService { definitions: lifecycle_definitions() });
            let server = McpServer::new(service, MIN_MCP_FRAME_BYTES).unwrap();
            let (responses, result) = serve_frames(server, &[request]).await;
            assert!(result.is_ok());
            assert_eq!(responses.len(), 1);
            if accepted {
                assert_eq!(responses[0]["result"]["protocolVersion"], "2025-11-25");
            } else {
                assert_eq!(responses[0]["error"]["code"], -32602);
            }
        }
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_uri_state_machine_adversarial_matrix() {
    timeout(Duration::from_secs(5), async {
        let cases = [
            ("HTTPS://example.com/x", true),
            ("http://127.0.0.1:65535/a", true),
            ("https://[::1]/a", true),
            ("urn:example:test", true),
            ("data:,hello", true),
            ("x:a//b?q=?#f", true),
            ("", false),
            ("relative/path", false),
            ("http:path", false),
            ("https:///x", false),
            ("https://user@example.com/x", false),
            ("https://example..com/x", false),
            ("https://256.1.1.1/x", false),
            ("https://example.com:/x", false),
            ("https://example.com:65536/x", false),
            ("https://example.com/a[b]", false),
            ("urn:a%2", false),
            ("urn:a%zz", false),
            ("urn:a#b#c", false),
            ("urn:a b", false),
            ("urn:界", false),
        ];
        for (index, (uri, accepted)) in cases.into_iter().enumerate() {
            let request = json!({
                "jsonrpc":"2.0","id":index,"method":"initialize","params":{
                    "protocolVersion":"2025-11-25","capabilities":{},
                    "clientInfo":{"name":"x","version":"1","websiteUrl":uri}
                }
            });
            let service = Arc::new(NullService {
                definitions: lifecycle_definitions(),
            });
            let server = McpServer::new(service, MIN_MCP_FRAME_BYTES).unwrap();
            let (responses, result) = serve_frames(server, &[request]).await;
            assert!(result.is_ok());
            assert_eq!(
                responses[0].get("result").is_some(),
                accepted,
                "URI case {uri:?}"
            );
        }
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_client_info_exact_limits_and_plus_one() {
    timeout(Duration::from_secs(5), async {
        let exact_website = format!("https://e/{}", "a".repeat(2048 - "https://e/".len()));
        let exact_icon = format!("data:,{}", "a".repeat(65_536 - "data:,".len()));
        for (field, value, accepted) in [
            ("name", "x".repeat(256), true),
            ("name", "x".repeat(257), false),
            ("title", "x".repeat(256), true),
            ("title", "x".repeat(257), false),
            ("description", "x".repeat(4096), true),
            ("description", "x".repeat(4097), false),
            ("websiteUrl", exact_website.clone(), true),
            ("websiteUrl", format!("{exact_website}a"), false),
        ] {
            let mut client = json!({"name":"x","version":"1"});
            client.as_object_mut().unwrap().insert(field.into(), Value::String(value));
            let request = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":client}});
            let service = Arc::new(NullService { definitions: lifecycle_definitions() });
            let server = McpServer::new(service, MIN_MCP_FRAME_BYTES).unwrap();
            let (responses, _) = serve_frames(server, &[request]).await;
            assert_eq!(responses[0].get("result").is_some(), accepted, "field {field}");
        }
        for (src, accepted) in [(exact_icon.clone(), true), (format!("{exact_icon}a"), false)] {
            let request = json!({"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"x","version":"1","icons":[{"src":src}]}}});
            let service = Arc::new(NullService { definitions: lifecycle_definitions() });
            let server = McpServer::new(service, MIN_MCP_FRAME_BYTES).unwrap();
            let (responses, _) = serve_frames(server, &[request]).await;
            assert_eq!(responses[0].get("result").is_some(), accepted);
        }
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_lifecycle_client_and_icon_complete_boundary_matrix() {
    timeout(Duration::from_secs(5), async {
        for (field, exact_limit) in [
            ("name", 256),
            ("title", 256),
            ("version", 256),
            ("description", 4096),
        ] {
            for delta in [0, 1] {
                let mut client = json!({"name":"x","version":"1"});
                let bytes = exact_limit + delta;
                let value = format!("{}{}", "界".repeat(bytes / 3), "x".repeat(bytes % 3));
                client
                    .as_object_mut()
                    .unwrap()
                    .insert(field.into(), Value::String(value));
                assert_eq!(client[field].as_str().unwrap().len(), bytes);
                assert_eq!(
                    initialize_client_is_accepted("2025-11-25", client).await,
                    delta == 0,
                    "field={field} delta={delta}"
                );
            }
        }

        let base_icon = json!({"src":"data:,ok"});
        for (icons, accepted) in [
            (vec![base_icon.clone(); 16], true),
            (vec![base_icon.clone(); 17], false),
        ] {
            assert_eq!(
                initialize_client_is_accepted(
                    "2025-11-25",
                    json!({"name":"x","version":"1","icons":icons}),
                )
                .await,
                accepted
            );
        }

        for (icon, accepted) in [
            (json!({"src":"data:,ok","mimeType":"x".repeat(256)}), true),
            (json!({"src":"data:,ok","mimeType":"x".repeat(257)}), false),
            (json!({"src":"data:,ok","sizes":vec!["1"; 16]}), true),
            (json!({"src":"data:,ok","sizes":vec!["1"; 17]}), false),
            (json!({"src":"data:,ok","sizes":["x".repeat(32)]}), true),
            (json!({"src":"data:,ok","sizes":["x".repeat(33)]}), false),
            (json!({"src":"data:,ok","theme":"light"}), true),
            (json!({"src":"data:,ok","theme":"dark"}), true),
            (json!({"src":"data:,ok","theme":"system"}), false),
            (json!({"src":"data:,ok","unknown":true}), false),
            (json!({"mimeType":"text/plain"}), false),
        ] {
            assert_eq!(
                initialize_client_is_accepted(
                    "2025-11-25",
                    json!({"name":"x","version":"1","icons":[icon]}),
                )
                .await,
                accepted
            );
        }
    })
    .await
    .expect("test must complete");
}

#[derive(Clone, Copy)]
enum PanicMode {
    Construct,
    FirstPoll,
    AfterPoll,
}

struct PanicTools {
    definitions: Vec<ToolDefinition>,
    mode: PanicMode,
}

impl PanicTools {
    fn new(mode: PanicMode) -> Self {
        let mut definitions = lifecycle_definitions();
        definitions[0].name = "panic".into();
        Self { definitions, mode }
    }
}

impl ToolService for PanicTools {
    fn definitions(&self) -> &[ToolDefinition] {
        &self.definitions
    }

    fn call(&self, name: String, arguments: Value, _context: ToolCallContext) -> ToolFuture {
        if name == "echo" {
            let text = arguments
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or("ok")
                .to_owned();
            return Box::pin(async move { CallToolResult::text(text) });
        }
        match self.mode {
            PanicMode::Construct => panic!("HOSTILE construction payload"),
            PanicMode::FirstPoll => Box::pin(async { panic!("HOSTILE first-poll payload") }),
            PanicMode::AfterPoll => Box::pin(async {
                tokio::task::yield_now().await;
                panic!("HOSTILE later payload")
            }),
        }
    }
}

#[tokio::test]
async fn task7_panic_is_fixed_per_id_and_owner_continues() {
    timeout(Duration::from_secs(5), async {
        for mode in [PanicMode::Construct, PanicMode::FirstPoll, PanicMode::AfterPoll] {
            let tools = Arc::new(PanicTools::new(mode));
            let mut session = Session::start(McpServer::new(tools, MIN_MCP_FRAME_BYTES).unwrap()).await;
            session.ready().await;
            session.send(&json!({"jsonrpc":"2.0","id":"boom","method":"tools/call","params":{"name":"panic","arguments":{}}})).await;
            let panic_response = session.recv().await;
            assert_eq!(panic_response, json!({"jsonrpc":"2.0","id":"boom","error":{"code":-32603,"message":"Internal error"}}));
            assert!(!serde_json::to_string(&panic_response).unwrap().contains("HOSTILE"));
            session.send(&json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"still alive"}}})).await;
            assert_eq!(session.recv().await["result"]["content"][0]["text"], "still alive");
            assert!(session.close().await.is_ok());
        }
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_dispatch_completes_out_of_order_and_propagates_exact_context() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES).unwrap()).await;
        session.ready().await;
        session.send(&json!({"jsonrpc":"2.0","id":"slow","method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        tools.wait_for_polls(1).await;
        session.send(&json!({"jsonrpc":"2.0","id":"fast","method":"tools/call","params":{"name":"echo","arguments":{"text":"done"}}})).await;
        let fast = session.recv().await;
        assert_eq!(fast["id"], "fast");
        assert_eq!(fast["result"]["content"][0]["text"], "done");
        tools.release.add_permits(1);
        assert_eq!(session.recv().await["id"], "slow");
        let contexts = tools.contexts.lock().await;
        assert_eq!(contexts.len(), 2);
        let compact_fallback_bytes = maximum_compact_fallback_result_bytes();
        let expected_slow = WireBudget::for_response(
            MIN_MCP_FRAME_BYTES,
            &RequestId::try_from(json!("slow")).unwrap(),
            compact_fallback_bytes,
        )
        .unwrap();
        let expected_fast = WireBudget::for_response(
            MIN_MCP_FRAME_BYTES,
            &RequestId::try_from(json!("fast")).unwrap(),
            compact_fallback_bytes,
        )
        .unwrap();
        assert_eq!(contexts[0].wire_budget.result_bytes, expected_slow.result_bytes);
        assert_eq!(contexts[0].wire_budget.compact_fallback_bytes, expected_slow.compact_fallback_bytes);
        assert_eq!(contexts[1].wire_budget.result_bytes, expected_fast.result_bytes);
        assert_eq!(contexts[1].wire_budget.compact_fallback_bytes, expected_fast.compact_fallback_bytes);
        drop(contexts);
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task8_duplicate_validation_precedes_task_queue_admission() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES).unwrap()).await;
        session.ready().await;
        session.send(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        tools.wait_for_polls(1).await;
        session.send(&json!({"jsonrpc":"2.0","id":1,"method":"unknown","params":null})).await;
        assert_eq!(session.recv().await, json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Duplicate request id"}}));
        session.send(&json!({"jsonrpc":"2.0","id":1.0,"method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        assert_eq!(session.recv().await, invalid_request_response());
        session.send(&json!({"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        tools.wait_for_polls(2).await;
        assert_eq!(tools.synchronous_calls.load(Ordering::SeqCst), 2);
        assert_eq!(tools.first_polls.load(Ordering::SeqCst), 2);
        tools.release.add_permits(2);
        let first = session.recv().await["id"].clone();
        let second = session.recv().await["id"].clone();
        assert!(matches!((first, second), (a, b) if (a == json!(1) && b == json!("1")) || (a == json!("1") && b == json!(1))));
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task8_task_registry_releases_before_response_backlog() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start_with_output_capacity(
            McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES).unwrap(),
            1,
        )
        .await;
        session.ready().await;
        session.send(&json!({"jsonrpc":"2.0","id":"reuse","method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        tools.wait_for_polls(1).await;
        tools.release.add_permits(1);
        // One byte proves the first response passed the writer's suppression
        // check and the owner already removed the registry entry. Capacity one
        // keeps the rest durably backlogged without a sleep/yield heuristic.
        let first_byte = timeout(Duration::from_secs(1), session.output.read_u8()).await.expect("first response must start").unwrap();
        session.send(&json!({"jsonrpc":"2.0","id":"reuse","method":"tools/call","params":{"name":"echo","arguments":{"text":"second"}}})).await;
        let mut rest = String::new();
        timeout(Duration::from_secs(1), session.output.read_line(&mut rest)).await.expect("first response must finish").unwrap();
        let mut first_wire = vec![first_byte];
        first_wire.extend_from_slice(rest.as_bytes());
        let first: Value = serde_json::from_slice(&first_wire).unwrap();
        let second = session.recv().await;
        assert_eq!(first["id"], "reuse");
        assert_eq!(second["id"], "reuse");
        assert_eq!(second["result"]["content"][0]["text"], "second");
        assert_eq!(tools.synchronous_calls.load(Ordering::SeqCst), 2);
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task8_runner_contention_is_not_mcp_server_busy() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES).unwrap()).await;
        session.ready().await;
        for id in [1, 2, 3] {
            session.send(&json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        }
        tools.wait_for_polls(3).await;
        assert_eq!(tools.synchronous_calls.load(Ordering::SeqCst), 3);
        assert_eq!(tools.first_polls.load(Ordering::SeqCst), 3);
        tools.release.add_permits(3);
        let mut ids = [session.recv().await["id"].clone(), session.recv().await["id"].clone(), session.recv().await["id"].clone()];
        ids.sort_by_key(Value::to_string);
        assert_eq!(ids, [json!(1), json!(2), json!(3)]);
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task8_mcp_admits_calls_without_an_artificial_task_window() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES).unwrap()).await;
        session.ready().await;
        for id in 1..=9 {
            session.send(&json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        }
        tools.wait_for_polls(9).await;
        session.send(&json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"echo","arguments":{"text":"queue"}}})).await;
        let tenth = session.recv().await;
        assert_eq!(tenth["id"], 10);
        assert_eq!(tenth["result"]["content"][0]["text"], "queue");
        assert_eq!(tools.synchronous_calls.load(Ordering::SeqCst), 10);
        tools.release.add_permits(9);
        for _ in 0..9 {
            assert_eq!(session.recv().await["result"]["content"][0]["text"], "released");
        }
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task8_remote_hosts_control_lane_survives_full_remote_task_window() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(ControlTools::new());
        let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES).unwrap()).await;
        session.ready().await;
        for id in 1..=9 {
            session.send(&json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        }
        tools.stub.wait_for_polls(9).await;
        session.send(&json!({"jsonrpc":"2.0","id":"hosts","method":"tools/call","params":{"name":"remote_hosts","arguments":{}}})).await;
        let hosts = session.recv().await;
        assert_eq!(hosts["id"], "hosts");
        assert_eq!(hosts["result"]["content"][0]["text"], "cached hosts");
        assert_eq!(tools.stub.synchronous_calls.load(Ordering::SeqCst), 9);
        tools.stub.release.add_permits(9);
        for _ in 0..9 {
            assert_eq!(session.recv().await["result"]["content"][0]["text"], "released");
        }
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task8_task_registry_oversized_flood_reaps_one_completion_and_releases_id() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start_with_capacities(
            McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES).unwrap(),
            4 * 1024 * 1024,
            128 * 1024,
        )
        .await;
        session.ready().await;
        session.send(&json!({"jsonrpc":"2.0","id":"reuse","method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        tools.wait_for_polls(1).await;

        let mut flood = Vec::new();
        for _ in 0..3 {
            flood.extend(std::iter::repeat_n(b'x', MIN_MCP_FRAME_BYTES + 1));
            flood.push(b'\n');
        }
        flood.extend(serde_json::to_vec(&json!({"jsonrpc":"2.0","id":"reuse","method":"tools/call","params":{"name":"echo","arguments":{"text":"second"}}})).unwrap());
        flood.push(b'\n');
        session.input.write_all(&flood).await.unwrap();
        tools.release.add_permits(1);

        assert_eq!(session.recv().await, request_too_large_response());
        assert_eq!(session.recv().await["id"], "reuse");
        let mut saw_second = false;
        for _ in 0..3 {
            let response = session.recv().await;
            if response["id"] == "reuse" {
                assert_eq!(response["result"]["content"][0]["text"], "second");
                saw_second = true;
            }
        }
        assert!(saw_second, "the completed ID and task capacity must be reusable");
        assert_eq!(tools.synchronous_calls.load(Ordering::SeqCst), 2);
        assert!(session.close().await.is_ok());
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_dispatch_known_invalid_arguments_are_normal_tool_results() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES).unwrap()).await;
        session.ready().await;
        session.send(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unknown","arguments":{}}})).await;
        assert_eq!(session.recv().await["error"]["code"], -32602);
        session.send(&json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}})).await;
        let invalid = session.recv().await;
        assert_eq!(invalid["id"], 2);
        assert_eq!(invalid["result"]["isError"], true);
        assert_eq!(tools.synchronous_calls.load(Ordering::SeqCst), 1);
        assert_eq!(tools.first_polls.load(Ordering::SeqCst), 1);
        assert_eq!(tools.bridge_ops.load(Ordering::SeqCst), 0);
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_cancellation_cancels_shared_token_and_suppresses_response() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES).unwrap()).await;
        session.ready().await;
        session.send(&json!({"jsonrpc":"2.0","id":"job","method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        tools.wait_for_polls(1).await;
        let token = tools.contexts.lock().await[0].cancel.clone();
        session.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"job","reason":"hostile\nreason"}})).await;
        tools.wait_for_cancel().await;
        assert!(token.is_cancelled());
        session.send(&json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{}})).await;
        assert_eq!(session.recv().await["id"], 2);
        session.send(&json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"slot released"}}})).await;
        let admitted = session.recv().await;
        assert_eq!(admitted["id"], 3);
        assert_eq!(admitted["result"]["content"][0]["text"], "slot released");
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_cancellation_fully_validates_before_touching_token() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES).unwrap()).await;
        session.ready().await;
        session.send(&json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        tools.wait_for_polls(1).await;
        for params in [
            json!({}),
            json!({"requestId":null}),
            json!({"requestId":7.5}),
            json!({"requestId":7,"reason":1}),
            json!({"requestId":7,"reason":"x".repeat(1025)}),
            json!({"requestId":7,"_meta":false}),
            json!({"requestId":7,"task":{}}),
            json!({"requestId":7,"extra":true}),
        ] {
            session.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":params})).await;
        }
        session.send(&json!({"jsonrpc":"2.0","id":6,"method":"ping","params":{}})).await;
        assert_eq!(session.recv().await["id"], 6);
        assert!(!tools.observed_cancel.load(Ordering::Acquire));
        assert!(!tools.contexts.lock().await[0].cancel.is_cancelled());
        session.send(&json!({"jsonrpc":"2.0","id":8,"method":"notifications/cancelled","params":{"requestId":7}})).await;
        assert_eq!(session.recv().await["error"]["code"], -32600);
        assert!(!tools.contexts.lock().await[0].cancel.is_cancelled());
        session.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"_meta":{}}})).await;
        tools.wait_for_cancel().await;
        session.send(&json!({"jsonrpc":"2.0","id":9,"method":"ping","params":{}})).await;
        assert_eq!(session.recv().await["id"], 9);
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_cancellation_shared_token_works_in_service_to_test_direction() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES).unwrap()).await;
        session.ready().await;
        session.send(&json!({"jsonrpc":"2.0","id":"manual","method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        tools.wait_for_polls(1).await;
        tools.contexts.lock().await[0].cancel.cancel();
        assert_eq!(session.recv().await["id"], "manual");
        assert!(tools.observed_cancel.load(Ordering::Acquire));
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

#[test]
fn task7_cancellation_owner_select_has_required_order_and_empty_guard() {
    let source = include_str!("../src/mcp/mod.rs");
    let helper = source
        .split("async fn next_owner_event")
        .nth(1)
        .unwrap()
        .split("async fn writer_loop")
        .next()
        .unwrap();
    assert!(helper.contains("biased;"));
    let writer = helper.find("writer_result = writer_handle").unwrap();
    let input = helper.find("input = frames.next_frame()").unwrap();
    let completion = helper
        .find("completion = join_set.join_next_with_id()")
        .unwrap();
    assert!(writer < input && input < completion);
    assert!(helper.contains("if !join_set.is_empty()"));
    assert!(!helper.contains("loop {"));
}

#[tokio::test]
async fn task7_cancellation_buffered_frame_wins_over_ready_completion() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES).unwrap()).await;
        session.ready().await;
        session.send(&json!({"jsonrpc":"2.0","id":"race","method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        tools.wait_for_polls(1).await;
        // On the current-thread runtime the buffered frame and durable task
        // are both ready before the owner is scheduled again.
        session.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"race"}})).await;
        tools.release.add_permits(1);
        session.send(&json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{}})).await;
        assert_eq!(session.recv().await["id"], 2);
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_cancellation_versioned_extension_policy_unknown_duplicate_and_late() {
    timeout(Duration::from_secs(5), async {
        for (version, extra_cancels) in [("2025-06-18", true), ("2025-11-25", false)] {
            let tools = Arc::new(StubTools::new());
            let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES).unwrap()).await;
            session.send(&initialize(json!(100), version)).await;
            session.recv().await;
            session.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}})).await;
            session.send(&json!({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"block","arguments":{}}})).await;
            tools.wait_for_polls(1).await;
            session.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"unknown","extension":true}})).await;
            session.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":11,"extension":true}})).await;
            session.send(&json!({"jsonrpc":"2.0","id":10,"method":"ping","params":{}})).await;
            assert_eq!(session.recv().await["id"], 10);
            assert_eq!(tools.contexts.lock().await[0].cancel.is_cancelled(), extra_cancels);
            if !extra_cancels {
                session.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":11}})).await;
            }
            // Duplicate and later cancellation are both harmless no-ops.
            session.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":11}})).await;
            session.send(&json!({"jsonrpc":"2.0","id":12,"method":"ping","params":{}})).await;
            assert_eq!(session.recv().await["id"], 12);
            session.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":11}})).await;
            session.send(&json!({"jsonrpc":"2.0","id":13,"method":"ping","params":{}})).await;
            assert_eq!(session.recv().await["id"], 13);
            assert!(session.close().await.is_ok());
        }
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_cancellation_notification_flood_cannot_starve_ready_completion() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES).unwrap()).await;
        session.ready().await;
        session.send(&json!({"jsonrpc":"2.0","id":"done","method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        tools.wait_for_polls(1).await;
        tools.release.add_permits(1);
        let mut flood = Vec::new();
        for _ in 0..64 {
            flood.extend(serde_json::to_vec(&json!({"jsonrpc":"2.0","method":"unknown/notification","params":{}})).unwrap());
            flood.push(b'\n');
        }
        flood.extend(serde_json::to_vec(&json!({"jsonrpc":"2.0","id":"after","method":"ping","params":{}})).unwrap());
        flood.push(b'\n');
        session.input.write_all(&flood).await.unwrap();
        assert_eq!(session.recv().await["id"], "done");
        assert_eq!(session.recv().await["id"], "after");
        assert!(session.close().await.is_ok());
    }).await.expect("test must complete");
}

struct TestWriter {
    bytes: Arc<StdMutex<Vec<u8>>>,
    one_byte: bool,
    pending: bool,
    fail_write: bool,
    fail_shutdown: bool,
}

impl AsyncWrite for TestWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending {
            return Poll::Pending;
        }
        if self.fail_write {
            return Poll::Ready(Err(io::Error::other("HOSTILE writer diagnostic")));
        }
        let count = if self.one_byte {
            buffer.len().min(1)
        } else {
            buffer.len()
        };
        self.bytes
            .lock()
            .unwrap()
            .extend_from_slice(&buffer[..count]);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.fail_shutdown {
            Poll::Ready(Err(io::Error::other("HOSTILE shutdown diagnostic")))
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

fn test_writer(one_byte: bool) -> (TestWriter, Arc<StdMutex<Vec<u8>>>) {
    let bytes = Arc::new(StdMutex::new(Vec::new()));
    (
        TestWriter {
            bytes: Arc::clone(&bytes),
            one_byte,
            pending: false,
            fail_write: false,
            fail_shutdown: false,
        },
        bytes,
    )
}

struct PrefixFailWriter {
    bytes: Arc<StdMutex<Vec<u8>>>,
    fail_at: usize,
}

impl AsyncWrite for PrefixFailWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = self.bytes.lock().unwrap().len();
        if written >= self.fail_at {
            return Poll::Ready(Err(io::Error::other("HOSTILE prefix failure")));
        }
        let count = buffer.len().min(self.fail_at - written);
        self.bytes
            .lock()
            .unwrap()
            .extend_from_slice(&buffer[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct PrefixPendingWriter {
    bytes: Arc<StdMutex<Vec<u8>>>,
    pending_at: usize,
}

struct SwitchWriter {
    bytes: Arc<StdMutex<Vec<u8>>>,
    fail: Arc<AtomicBool>,
    wrote: Arc<Notify>,
}

impl AsyncWrite for SwitchWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.fail.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::Error::other("HOSTILE switched failure")));
        }
        self.bytes.lock().unwrap().extend_from_slice(buffer);
        self.wrote.notify_waiters();
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn wait_for_stored_lines(bytes: &Arc<StdMutex<Vec<u8>>>, wrote: &Arc<Notify>, lines: usize) {
    loop {
        let notified = wrote.notified();
        if bytes
            .lock()
            .unwrap()
            .iter()
            .filter(|byte| **byte == b'\n')
            .count()
            >= lines
        {
            return;
        }
        timeout(Duration::from_secs(1), notified)
            .await
            .expect("writer must store the expected line");
    }
}

impl AsyncWrite for PrefixPendingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = self.bytes.lock().unwrap().len();
        if written >= self.pending_at {
            return Poll::Pending;
        }
        let count = buffer.len().min(self.pending_at - written);
        self.bytes
            .lock()
            .unwrap()
            .extend_from_slice(&buffer[..count]);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

struct PanicWriter;

impl AsyncWrite for PanicWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        panic!("HOSTILE writer panic payload")
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClosingActiveKind {
    Cooperative,
    TokenIgnoringYielding,
    AlreadyReady,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClosingSource {
    PartialEof,
    QueueBackpressure,
    WriterWriteZero,
    WriterPanic,
    ShutdownFailure,
    PendingAfterPrefix,
}

impl ClosingSource {
    fn stalls_writer(self) -> bool {
        matches!(self, Self::QueueBackpressure | Self::PendingAfterPrefix)
    }
}

struct ClosingTaskState {
    entered: AtomicBool,
    entered_notify: Notify,
    cancelled: AtomicBool,
    completed: AtomicBool,
    dropped: AtomicBool,
    live: AtomicUsize,
    token: StdMutex<Option<tokio_util::sync::CancellationToken>>,
    ready_trigger: StdMutex<Option<ReadyClosingTrigger>>,
    gate: Semaphore,
}

impl ClosingTaskState {
    fn new() -> Self {
        Self {
            entered: AtomicBool::new(false),
            entered_notify: Notify::new(),
            cancelled: AtomicBool::new(false),
            completed: AtomicBool::new(false),
            dropped: AtomicBool::new(false),
            live: AtomicUsize::new(0),
            token: StdMutex::new(None),
            ready_trigger: StdMutex::new(None),
            gate: Semaphore::new(0),
        }
    }

    async fn wait_until_entered(&self) {
        loop {
            let notified = self.entered_notify.notified();
            if self.entered.load(Ordering::Acquire) {
                return;
            }
            timeout(Duration::from_secs(1), notified)
                .await
                .expect("Closing matrix task must enter");
        }
    }
}

enum ReadyClosingTrigger {
    Input { input: DuplexStream, partial: bool },
    Writer(Arc<ClosingWriterState>),
}

struct ClosingTaskGuard {
    state: Arc<ClosingTaskState>,
}

impl Drop for ClosingTaskGuard {
    fn drop(&mut self) {
        self.state.live.fetch_sub(1, Ordering::SeqCst);
        self.state.dropped.store(true, Ordering::Release);
    }
}

struct ClosingTools {
    definitions: Vec<ToolDefinition>,
    active_kind: ClosingActiveKind,
    state: Arc<ClosingTaskState>,
}

impl ToolService for ClosingTools {
    fn definitions(&self) -> &[ToolDefinition] {
        &self.definitions
    }

    fn call(&self, _name: String, _arguments: Value, context: ToolCallContext) -> ToolFuture {
        let active_kind = self.active_kind;
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            state.live.fetch_add(1, Ordering::SeqCst);
            let _guard = ClosingTaskGuard {
                state: Arc::clone(&state),
            };
            *state.token.lock().unwrap() = Some(context.cancel.clone());
            state.entered.store(true, Ordering::Release);
            state.entered_notify.notify_waiters();
            match active_kind {
                ClosingActiveKind::Cooperative => {
                    tokio::select! {
                        () = context.cancel.cancelled() => {
                            state.cancelled.store(true, Ordering::Release);
                            CallToolResult::text("cooperatively cancelled")
                        }
                        permit = state.gate.acquire() => {
                            permit.expect("Closing matrix gate stays open").forget();
                            state.completed.store(true, Ordering::Release);
                            CallToolResult::text("released")
                        }
                    }
                }
                ClosingActiveKind::TokenIgnoringYielding => loop {
                    tokio::task::yield_now().await;
                },
                ClosingActiveKind::AlreadyReady => {
                    state
                        .gate
                        .acquire()
                        .await
                        .expect("Closing matrix gate stays open")
                        .forget();
                    let trigger = state.ready_trigger.lock().unwrap().take();
                    match trigger {
                        Some(ReadyClosingTrigger::Input { mut input, partial }) => {
                            if partial {
                                input.write_all(b"{").await.unwrap();
                            }
                            input.shutdown().await.unwrap();
                        }
                        Some(ReadyClosingTrigger::Writer(writer)) => writer.arm_writer(),
                        None => {}
                    }
                    state.completed.store(true, Ordering::Release);
                    CallToolResult::text("already ready")
                }
            }
        })
    }
}

struct ClosingWriterState {
    bytes: StdMutex<Vec<u8>>,
    wrote: Notify,
    blocked: AtomicBool,
    blocked_notify: Notify,
    writer_armed: AtomicBool,
    writer_waker: StdMutex<Option<std::task::Waker>>,
}

impl ClosingWriterState {
    fn new(writer_armed: bool) -> Self {
        Self {
            bytes: StdMutex::new(Vec::new()),
            wrote: Notify::new(),
            blocked: AtomicBool::new(false),
            blocked_notify: Notify::new(),
            writer_armed: AtomicBool::new(writer_armed),
            writer_waker: StdMutex::new(None),
        }
    }

    fn bytes(&self) -> Vec<u8> {
        self.bytes.lock().unwrap().clone()
    }

    async fn wait_for_lines(&self, lines: usize) {
        loop {
            let notified = self.wrote.notified();
            if self
                .bytes
                .lock()
                .unwrap()
                .iter()
                .filter(|byte| **byte == b'\n')
                .count()
                >= lines
            {
                return;
            }
            timeout(Duration::from_secs(1), notified)
                .await
                .expect("Closing matrix writer must store line");
        }
    }

    async fn wait_until_blocked(&self) {
        loop {
            let notified = self.blocked_notify.notified();
            if self.blocked.load(Ordering::Acquire) {
                return;
            }
            timeout(Duration::from_secs(1), notified)
                .await
                .expect("Closing matrix writer must reach its durable block");
        }
    }

    fn mark_blocked(&self) {
        self.blocked.store(true, Ordering::Release);
        self.blocked_notify.notify_waiters();
    }

    fn arm_writer(&self) {
        self.writer_armed.store(true, Ordering::Release);
        if let Some(waker) = self.writer_waker.lock().unwrap().take() {
            waker.wake();
        }
    }
}

struct ClosingWriter {
    source: ClosingSource,
    state: Arc<ClosingWriterState>,
}

impl AsyncWrite for ClosingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut bytes = self.state.bytes.lock().unwrap();
        let first_line_end = bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|index| index + 1);
        if first_line_end.is_none() {
            bytes.extend_from_slice(buffer);
            drop(bytes);
            self.state.wrote.notify_waiters();
            return Poll::Ready(Ok(buffer.len()));
        }
        match self.source {
            ClosingSource::PartialEof | ClosingSource::ShutdownFailure => {
                bytes.extend_from_slice(buffer);
                drop(bytes);
                self.state.wrote.notify_waiters();
                Poll::Ready(Ok(buffer.len()))
            }
            ClosingSource::QueueBackpressure => {
                if !self.state.writer_armed.load(Ordering::Acquire) {
                    *self.state.writer_waker.lock().unwrap() = Some(cx.waker().clone());
                    if !self.state.writer_armed.load(Ordering::Acquire) {
                        drop(bytes);
                        self.state.mark_blocked();
                        return Poll::Pending;
                    }
                }
                bytes.extend_from_slice(buffer);
                drop(bytes);
                self.state.wrote.notify_waiters();
                Poll::Ready(Ok(buffer.len()))
            }
            ClosingSource::WriterWriteZero => {
                if !self.state.writer_armed.load(Ordering::Acquire) {
                    *self.state.writer_waker.lock().unwrap() = Some(cx.waker().clone());
                    if !self.state.writer_armed.load(Ordering::Acquire) {
                        drop(bytes);
                        self.state.mark_blocked();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Ok(0))
            }
            ClosingSource::WriterPanic => {
                if !self.state.writer_armed.load(Ordering::Acquire) {
                    *self.state.writer_waker.lock().unwrap() = Some(cx.waker().clone());
                    if !self.state.writer_armed.load(Ordering::Acquire) {
                        drop(bytes);
                        self.state.mark_blocked();
                        return Poll::Pending;
                    }
                }
                drop(bytes);
                panic!("HOSTILE Closing matrix writer panic")
            }
            ClosingSource::PendingAfterPrefix => {
                const PREFIX_BYTES: usize = 32;
                let second_bytes = bytes.len() - first_line_end.unwrap();
                if second_bytes >= PREFIX_BYTES {
                    drop(bytes);
                    self.state.mark_blocked();
                    return Poll::Pending;
                }
                let count = buffer.len().min(PREFIX_BYTES - second_bytes);
                bytes.extend_from_slice(&buffer[..count]);
                drop(bytes);
                self.state.wrote.notify_waiters();
                Poll::Ready(Ok(count))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.source == ClosingSource::ShutdownFailure {
            Poll::Ready(Err(io::Error::other("HOSTILE Closing shutdown")))
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

async fn send_closing_frame(input: &mut DuplexStream, frame: Value) -> io::Result<()> {
    let mut wire = serde_json::to_vec(&frame).unwrap();
    wire.push(b'\n');
    timeout(Duration::from_secs(1), input.write_all(&wire))
        .await
        .expect("Closing matrix input write must terminate")
}

async fn run_closing_matrix_case(source: ClosingSource, active_kind: ClosingActiveKind) {
    let task_state = Arc::new(ClosingTaskState::new());
    let tools = Arc::new(ClosingTools {
        definitions: vec![lifecycle_definitions().remove(0)],
        active_kind,
        state: Arc::clone(&task_state),
    });
    let writer_starts_armed = active_kind != ClosingActiveKind::AlreadyReady
        || !matches!(
            source,
            ClosingSource::WriterWriteZero | ClosingSource::WriterPanic
        );
    let writer_state = Arc::new(ClosingWriterState::new(writer_starts_armed));
    let writer = ClosingWriter {
        source,
        state: Arc::clone(&writer_state),
    };
    let input_capacity = if source == ClosingSource::QueueBackpressure {
        1
    } else {
        128 * 1024
    };
    let (mut input, server_reader) = tokio::io::duplex(input_capacity);
    let server = McpServer::new(tools, MIN_MCP_FRAME_BYTES).unwrap();
    let serve = tokio::spawn(server.serve(server_reader, writer));

    send_closing_frame(&mut input, initialize(json!(1), "2025-11-25"))
        .await
        .unwrap();
    writer_state.wait_for_lines(1).await;
    send_closing_frame(
        &mut input,
        json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
    )
    .await
    .unwrap();
    send_closing_frame(
        &mut input,
        json!({"jsonrpc":"2.0","id":"active","method":"tools/call","params":{"name":"block","arguments":{}}}),
    )
    .await
    .unwrap();
    task_state.wait_until_entered().await;

    let started = Instant::now();
    match source {
        ClosingSource::PartialEof => {
            if active_kind == ClosingActiveKind::AlreadyReady {
                *task_state.ready_trigger.lock().unwrap() = Some(ReadyClosingTrigger::Input {
                    input,
                    partial: true,
                });
                task_state.gate.add_permits(1);
            } else {
                input.write_all(b"{").await.unwrap();
                input.shutdown().await.unwrap();
            }
        }
        ClosingSource::QueueBackpressure => {
            send_closing_frame(
                &mut input,
                json!({"jsonrpc":"2.0","id":100,"method":"ping","params":{}}),
            )
            .await
            .unwrap();
            writer_state.wait_until_blocked().await;
            for id in 101..=117 {
                send_closing_frame(
                    &mut input,
                    json!({"jsonrpc":"2.0","id":id,"method":"ping","params":{}}),
                )
                .await
                .unwrap();
            }
            send_closing_frame(
                &mut input,
                json!({"jsonrpc":"2.0","method":"unknown/notification","params":{}}),
            )
            .await
            .unwrap();
            let _ = send_closing_frame(
                &mut input,
                json!({"jsonrpc":"2.0","id":118,"method":"ping","params":{}}),
            )
            .await;
            if active_kind == ClosingActiveKind::AlreadyReady {
                task_state.gate.add_permits(1);
            }
        }
        ClosingSource::WriterWriteZero | ClosingSource::WriterPanic => {
            if active_kind == ClosingActiveKind::AlreadyReady {
                *task_state.ready_trigger.lock().unwrap() =
                    Some(ReadyClosingTrigger::Writer(Arc::clone(&writer_state)));
            }
            let _ = send_closing_frame(
                &mut input,
                json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{}}),
            )
            .await;
            if active_kind == ClosingActiveKind::AlreadyReady {
                writer_state.wait_until_blocked().await;
                task_state.gate.add_permits(1);
            }
        }
        ClosingSource::ShutdownFailure => {
            if active_kind == ClosingActiveKind::AlreadyReady {
                *task_state.ready_trigger.lock().unwrap() = Some(ReadyClosingTrigger::Input {
                    input,
                    partial: false,
                });
                task_state.gate.add_permits(1);
            } else {
                input.shutdown().await.unwrap();
            }
        }
        ClosingSource::PendingAfterPrefix => {
            if active_kind == ClosingActiveKind::AlreadyReady {
                task_state.gate.add_permits(1);
            } else {
                send_closing_frame(
                    &mut input,
                    json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{}}),
                )
                .await
                .unwrap();
            }
            writer_state.wait_until_blocked().await;
            input.shutdown().await.unwrap();
        }
    }

    let result = timeout(Duration::from_secs(2), serve)
        .await
        .expect("Closing matrix server must terminate within its bounded graces")
        .expect("Closing matrix server must not panic");
    let elapsed = started.elapsed();
    match source {
        ClosingSource::PartialEof => {
            let error = result.unwrap_err();
            assert_eq!(
                error.code,
                ErrorCode::ProtocolError,
                "{source:?}/{active_kind:?}"
            );
            assert_eq!(error.message, "partial MCP frame at EOF");
        }
        _ => assert_eq!(
            result.unwrap_err(),
            BridgeError::io("MCP transport failed"),
            "{source:?}/{active_kind:?}"
        ),
    }
    if source.stalls_writer() || active_kind == ClosingActiveKind::TokenIgnoringYielding {
        assert!(
            elapsed >= Duration::from_millis(200),
            "bounded grace was not observable for {source:?}/{active_kind:?}: {elapsed:?}"
        );
    }
    assert!(
        elapsed < Duration::from_millis(1_200),
        "Closing exceeded its bounded graces for {source:?}/{active_kind:?}: {elapsed:?}"
    );

    assert_eq!(task_state.live.load(Ordering::Acquire), 0);
    assert!(task_state.dropped.load(Ordering::Acquire));
    match active_kind {
        ClosingActiveKind::Cooperative => {
            assert!(task_state.cancelled.load(Ordering::Acquire));
            assert!(
                task_state
                    .token
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(tokio_util::sync::CancellationToken::is_cancelled)
            );
        }
        ClosingActiveKind::TokenIgnoringYielding => assert!(
            task_state
                .token
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(tokio_util::sync::CancellationToken::is_cancelled)
        ),
        ClosingActiveKind::AlreadyReady => {
            assert!(task_state.completed.load(Ordering::Acquire));
        }
    }

    let bytes = writer_state.bytes();
    let active_id = b"\"id\":\"active\"";
    let complete_line_count = bytes.iter().filter(|byte| **byte == b'\n').count();
    let complete_lines: Vec<&[u8]> = bytes
        .split(|byte| *byte == b'\n')
        .take(complete_line_count)
        .collect();
    assert!(
        complete_lines.iter().all(|line| !line
            .windows(active_id.len())
            .any(|window| window == active_id)),
        "Closing emitted a complete call response for {source:?}/{active_kind:?}"
    );
    if source == ClosingSource::PendingAfterPrefix && active_kind == ClosingActiveKind::AlreadyReady
    {
        assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert!(
            bytes
                .windows(active_id.len())
                .any(|window| window == active_id),
            "the call prefix past the suppression commit is non-retractable"
        );
    } else {
        assert!(
            !bytes
                .windows(active_id.len())
                .any(|window| window == active_id),
            "uncommitted call output must be globally suppressed for {source:?}/{active_kind:?}"
        );
    }
    if source == ClosingSource::PartialEof {
        assert!(complete_lines.iter().any(|line| {
            serde_json::from_slice::<Value>(line).is_ok_and(|value| value == parse_error_response())
        }));
    }
}

#[tokio::test]
async fn task7_closing_source_by_active_call_matrix_is_complete_and_bounded() {
    timeout(Duration::from_secs(15), async {
        for source in [
            ClosingSource::PartialEof,
            ClosingSource::WriterWriteZero,
            ClosingSource::WriterPanic,
            ClosingSource::ShutdownFailure,
            ClosingSource::PendingAfterPrefix,
        ] {
            for active_kind in [
                ClosingActiveKind::Cooperative,
                ClosingActiveKind::TokenIgnoringYielding,
                ClosingActiveKind::AlreadyReady,
            ] {
                run_closing_matrix_case(source, active_kind).await;
            }
        }
    })
    .await
    .expect("complete Closing matrix must remain bounded");
}

#[tokio::test]
async fn task8_writer_queue_applies_backpressure_without_killing_the_server() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(StubTools::new());
        let writer_state = Arc::new(ClosingWriterState::new(false));
        let writer = ClosingWriter {
            source: ClosingSource::QueueBackpressure,
            state: Arc::clone(&writer_state),
        };
        let (mut input, server_reader) = tokio::io::duplex(128 * 1024);
        let server = McpServer::new(tools, MIN_MCP_FRAME_BYTES).unwrap();
        let serve = tokio::spawn(server.serve(server_reader, writer));

        send_closing_frame(&mut input, initialize(json!(1), "2025-11-25"))
            .await
            .unwrap();
        writer_state.wait_for_lines(1).await;
        send_closing_frame(
            &mut input,
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
        )
        .await
        .unwrap();
        for id in 2..=40 {
            send_closing_frame(
                &mut input,
                json!({"jsonrpc":"2.0","id":id,"method":"ping","params":{}}),
            )
            .await
            .unwrap();
        }
        writer_state.wait_until_blocked().await;
        tokio::task::yield_now().await;
        assert!(
            !serve.is_finished(),
            "a full response queue must backpressure instead of closing MCP"
        );

        writer_state.arm_writer();
        writer_state.wait_for_lines(40).await;
        input.shutdown().await.unwrap();
        assert!(
            serve.await.expect("server must not panic").is_ok(),
            "server must recover after the client resumes reading"
        );
    })
    .await
    .expect("backpressure recovery must terminate");
}

#[tokio::test]
async fn task7_writer_one_byte_writes_complete_noninterleaved_lines() {
    timeout(Duration::from_secs(5), async {
        let service = Arc::new(NullService {
            definitions: lifecycle_definitions(),
        });
        let server = McpServer::new(service, MIN_MCP_FRAME_BYTES).unwrap();
        let mut input = Vec::new();
        for frame in [
            initialize(json!(1), "2025-11-25"),
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
            json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{}}),
        ] {
            input.extend(serde_json::to_vec(&frame).unwrap());
            input.push(b'\n');
        }
        let (writer, bytes) = test_writer(true);
        assert!(
            server
                .serve(std::io::Cursor::new(input), writer)
                .await
                .is_ok()
        );
        let bytes = bytes.lock().unwrap().clone();
        let lines: Vec<Value> = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["id"], 1);
        assert_eq!(lines[1]["id"], 2);
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_writer_failure_shutdown_and_backpressure_are_fixed() {
    timeout(Duration::from_secs(5), async {
        for writer in [
            TestWriter {
                bytes: Arc::new(StdMutex::new(Vec::new())),
                one_byte: false,
                pending: false,
                fail_write: true,
                fail_shutdown: false,
            },
            TestWriter {
                bytes: Arc::new(StdMutex::new(Vec::new())),
                one_byte: false,
                pending: false,
                fail_write: false,
                fail_shutdown: true,
            },
        ] {
            let service = Arc::new(NullService {
                definitions: lifecycle_definitions(),
            });
            let server = McpServer::new(service, MIN_MCP_FRAME_BYTES).unwrap();
            let mut input = Vec::new();
            for frame in std::iter::once(initialize(json!(1), "2025-11-25")).chain(
                (0..20).map(|id| json!({"jsonrpc":"2.0","id":id + 10,"method":"ping","params":{}})),
            ) {
                input.extend(serde_json::to_vec(&frame).unwrap());
                input.push(b'\n');
            }
            let error = server
                .serve(std::io::Cursor::new(input), writer)
                .await
                .unwrap_err();
            assert_eq!(error, BridgeError::io("MCP transport failed"));
            assert!(!error.message.contains("HOSTILE"));
        }
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_writer_prefix_error_and_panic_close_without_replacement() {
    timeout(Duration::from_secs(5), async {
        let request = initialize(json!(1), "2025-11-25");
        let mut input = serde_json::to_vec(&request).unwrap();
        input.push(b'\n');
        let bytes = Arc::new(StdMutex::new(Vec::new()));
        let writer = PrefixFailWriter {
            bytes: Arc::clone(&bytes),
            fail_at: 17,
        };
        let service = Arc::new(NullService {
            definitions: lifecycle_definitions(),
        });
        let error = McpServer::new(service, MIN_MCP_FRAME_BYTES)
            .unwrap()
            .serve(std::io::Cursor::new(input.clone()), writer)
            .await
            .unwrap_err();
        assert_eq!(error, BridgeError::io("MCP transport failed"));
        assert_eq!(bytes.lock().unwrap().len(), 17);

        let service = Arc::new(NullService {
            definitions: lifecycle_definitions(),
        });
        let error = McpServer::new(service, MIN_MCP_FRAME_BYTES)
            .unwrap()
            .serve(std::io::Cursor::new(input), PanicWriter)
            .await
            .unwrap_err();
        assert_eq!(error, BridgeError::io("MCP transport failed"));
        assert!(!error.message.contains("HOSTILE"));
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_writer_pending_forever_after_controlled_prefix_is_bounded() {
    timeout(Duration::from_secs(5), async {
        let mut input = serde_json::to_vec(&initialize(json!(1), "2025-11-25")).unwrap();
        input.push(b'\n');
        let bytes = Arc::new(StdMutex::new(Vec::new()));
        let writer = PrefixPendingWriter {
            bytes: Arc::clone(&bytes),
            pending_at: 23,
        };
        let service = Arc::new(NullService {
            definitions: lifecycle_definitions(),
        });
        let started = Instant::now();
        let error = McpServer::new(service, MIN_MCP_FRAME_BYTES)
            .unwrap()
            .serve(std::io::Cursor::new(input), writer)
            .await
            .unwrap_err();
        let elapsed = started.elapsed();
        assert_eq!(error, BridgeError::io("MCP transport failed"));
        assert_eq!(bytes.lock().unwrap().len(), 23);
        assert!(elapsed >= Duration::from_millis(200));
        assert!(elapsed < Duration::from_millis(750));
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_writer_failure_is_monitored_while_input_stays_open() {
    timeout(Duration::from_secs(5), async {
        let service = Arc::new(NullService {
            definitions: lifecycle_definitions(),
        });
        let server = McpServer::new(service, MIN_MCP_FRAME_BYTES).unwrap();
        let (mut input, server_reader) = tokio::io::duplex(4096);
        let writer = TestWriter {
            bytes: Arc::new(StdMutex::new(Vec::new())),
            one_byte: false,
            pending: false,
            fail_write: true,
            fail_shutdown: false,
        };
        let serve = tokio::spawn(server.serve(server_reader, writer));
        let mut request = serde_json::to_vec(&initialize(json!(1), "2025-11-25")).unwrap();
        request.push(b'\n');
        input.write_all(&request).await.unwrap();
        let error = timeout(Duration::from_secs(1), serve)
            .await
            .expect("writer failure must wake owner")
            .expect("owner must not panic")
            .unwrap_err();
        assert_eq!(error, BridgeError::io("MCP transport failed"));
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_writer_failure_closes_cooperative_and_already_ready_calls_without_output() {
    timeout(Duration::from_secs(5), async {
        for make_ready in [false, true] {
            let tools = Arc::new(StubTools::new());
            let server = McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES).unwrap();
            let (mut input, server_reader) = tokio::io::duplex(128 * 1024);
            let bytes = Arc::new(StdMutex::new(Vec::new()));
            let fail = Arc::new(AtomicBool::new(false));
            let wrote = Arc::new(Notify::new());
            let writer = SwitchWriter {
                bytes: Arc::clone(&bytes),
                fail: Arc::clone(&fail),
                wrote: Arc::clone(&wrote),
            };
            let serve = tokio::spawn(server.serve(server_reader, writer));
            for frame in [
                initialize(json!(1), "2025-11-25"),
                json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
                json!({"jsonrpc":"2.0","id":"active","method":"tools/call","params":{"name":"block","arguments":{}}}),
            ] {
                let mut wire = serde_json::to_vec(&frame).unwrap();
                wire.push(b'\n');
                input.write_all(&wire).await.unwrap();
            }
            wait_for_stored_lines(&bytes, &wrote, 1).await;
            tools.wait_for_polls(1).await;
            if make_ready {
                tools.release.add_permits(1);
            }
            fail.store(true, Ordering::Release);
            let mut trigger = serde_json::to_vec(
                &json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{}}),
            )
            .unwrap();
            trigger.push(b'\n');
            input.write_all(&trigger).await.unwrap();
            let error = timeout(Duration::from_secs(1), serve)
                .await
                .expect("writer failure must close")
                .expect("owner must not panic")
                .unwrap_err();
            assert_eq!(error, BridgeError::io("MCP transport failed"));
            let stored = bytes.lock().unwrap().clone();
            assert_eq!(stored.iter().filter(|byte| **byte == b'\n').count(), 1);
            assert!(!String::from_utf8_lossy(&stored).contains("active"));
            if !make_ready {
                assert!(tools.observed_cancel.load(Ordering::Acquire));
            }
        }
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn task7_writer_failure_aborts_token_ignoring_call_within_cleanup_bound() {
    timeout(Duration::from_secs(5), async {
        let entered = Arc::new(Notify::new());
        let tools = Arc::new(IgnoringTools {
            definitions: lifecycle_definitions(),
            entered: Arc::clone(&entered),
        });
        let server = McpServer::new(tools, MIN_MCP_FRAME_BYTES).unwrap();
        let (mut input, server_reader) = tokio::io::duplex(128 * 1024);
        let bytes = Arc::new(StdMutex::new(Vec::new()));
        let fail = Arc::new(AtomicBool::new(false));
        let wrote = Arc::new(Notify::new());
        let writer = SwitchWriter {
            bytes: Arc::clone(&bytes),
            fail: Arc::clone(&fail),
            wrote: Arc::clone(&wrote),
        };
        let serve = tokio::spawn(server.serve(server_reader, writer));
        let entered_wait = entered.notified();
        for frame in [
            initialize(json!(1), "2025-11-25"),
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
            json!({"jsonrpc":"2.0","id":"active","method":"tools/call","params":{"name":"block","arguments":{}}}),
        ] {
            let mut wire = serde_json::to_vec(&frame).unwrap();
            wire.push(b'\n');
            input.write_all(&wire).await.unwrap();
        }
        wait_for_stored_lines(&bytes, &wrote, 1).await;
        timeout(Duration::from_secs(1), entered_wait)
            .await
            .expect("ignoring task must start");
        fail.store(true, Ordering::Release);
        let mut trigger = serde_json::to_vec(
            &json!({"jsonrpc":"2.0","id":2,"method":"ping","params":{}}),
        )
        .unwrap();
        trigger.push(b'\n');
        input.write_all(&trigger).await.unwrap();
        let started = Instant::now();
        let error = timeout(Duration::from_secs(1), serve)
            .await
            .expect("writer failure must close")
            .expect("owner must not panic")
            .unwrap_err();
        let elapsed = started.elapsed();
        assert_eq!(error, BridgeError::io("MCP transport failed"));
        assert!(elapsed >= Duration::from_millis(200));
        assert!(elapsed < Duration::from_millis(750));
        assert_eq!(
            bytes
                .lock()
                .unwrap()
                .iter()
                .filter(|byte| **byte == b'\n')
                .count(),
            1
        );
    })
    .await
    .expect("test must complete");
}

struct HugeTools {
    definitions: Vec<ToolDefinition>,
}

impl ToolService for HugeTools {
    fn definitions(&self) -> &[ToolDefinition] {
        &self.definitions
    }
    fn call(&self, _name: String, _arguments: Value, _context: ToolCallContext) -> ToolFuture {
        Box::pin(async { CallToolResult::text("x".repeat(MIN_MCP_FRAME_BYTES + 1)) })
    }
}

#[tokio::test]
async fn task7_writer_capacity_overflow_writes_zero_bytes_of_that_frame() {
    timeout(Duration::from_secs(5), async {
        let tools = Arc::new(HugeTools { definitions: vec![lifecycle_definitions().remove(1)] });
        let server = McpServer::new(tools, MIN_MCP_FRAME_BYTES).unwrap();
        let (mut input, server_reader) = tokio::io::duplex(128 * 1024);
        let (writer, bytes) = test_writer(false);
        let serve = tokio::spawn(server.serve(server_reader, writer));
        for frame in [
            initialize(json!(1), "2025-11-25"),
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}),
        ] {
            let mut wire = serde_json::to_vec(&frame).unwrap();
            wire.push(b'\n');
            input.write_all(&wire).await.unwrap();
        }
        let error = timeout(Duration::from_secs(1), serve).await.expect("capacity failure must wake owner").expect("owner must not panic").unwrap_err();
        assert_eq!(error, BridgeError::io("MCP transport failed"));
        let bytes = bytes.lock().unwrap().clone();
        let lines: Vec<_> = bytes.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()).collect();
        assert_eq!(lines.len(), 1, "overflowing call frame must contribute zero bytes");
        assert_eq!(serde_json::from_slice::<Value>(lines[0]).unwrap()["id"], 1);
    }).await.expect("test must complete");
}

#[test]
fn task7_writer_call_queue_is_intrinsically_prepared_and_bounded() {
    let source = include_str!("../src/mcp/mod.rs");
    assert!(source.contains("struct PreparedJsonLine"));
    assert!(source.contains("CallResponse(PreparedJsonLine)"));
    assert!(!source.contains("serde_json::to_value(completed.outcome)"));
}

#[tokio::test]
async fn task7_eof_clean_and_partial_have_exact_precedence() {
    timeout(Duration::from_secs(5), async {
        let service = Arc::new(NullService {
            definitions: lifecycle_definitions(),
        });
        let server = McpServer::new(Arc::clone(&service), MIN_MCP_FRAME_BYTES).unwrap();
        let (responses, result) = serve_raw(server, Vec::new()).await;
        assert!(responses.is_empty());
        assert!(result.is_ok());

        let server = McpServer::new(service, MIN_MCP_FRAME_BYTES).unwrap();
        let (responses, result) = serve_raw(server, b"{".to_vec()).await;
        assert_eq!(responses, [parse_error_response()]);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert_eq!(error.message, "partial MCP frame at EOF");
    })
    .await
    .expect("test must complete");
}

#[tokio::test]
async fn clean_eof_runs_service_shutdown_once_but_partial_eof_does_not() {
    let clean = Arc::new(StubTools::new());
    let server = McpServer::new(Arc::clone(&clean), MIN_MCP_FRAME_BYTES).unwrap();
    let (_, result) = serve_raw(server, Vec::new()).await;
    assert!(result.is_ok());
    assert_eq!(clean.shutdowns.load(Ordering::SeqCst), 1);

    let partial = Arc::new(StubTools::new());
    let server = McpServer::new(Arc::clone(&partial), MIN_MCP_FRAME_BYTES).unwrap();
    let (_, result) = serve_raw(server, b"{".to_vec()).await;
    assert_eq!(result.unwrap_err().code, ErrorCode::ProtocolError);
    assert_eq!(partial.shutdowns.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn task7_eof_partial_parse_error_yields_to_later_writer_failure() {
    timeout(Duration::from_secs(5), async {
        for writer in [
            TestWriter {
                bytes: Arc::new(StdMutex::new(Vec::new())),
                one_byte: false,
                pending: false,
                fail_write: true,
                fail_shutdown: false,
            },
            TestWriter {
                bytes: Arc::new(StdMutex::new(Vec::new())),
                one_byte: false,
                pending: false,
                fail_write: false,
                fail_shutdown: true,
            },
        ] {
            let service = Arc::new(NullService {
                definitions: lifecycle_definitions(),
            });
            let error = McpServer::new(service, MIN_MCP_FRAME_BYTES)
                .unwrap()
                .serve(std::io::Cursor::new(b"{".to_vec()), writer)
                .await
                .unwrap_err();
            assert_eq!(error, BridgeError::io("MCP transport failed"));
        }
    })
    .await
    .expect("test must complete");
}

struct IgnoringTools {
    definitions: Vec<ToolDefinition>,
    entered: Arc<Notify>,
}

impl ToolService for IgnoringTools {
    fn definitions(&self) -> &[ToolDefinition] {
        &self.definitions
    }
    fn call(&self, _name: String, _arguments: Value, _context: ToolCallContext) -> ToolFuture {
        let entered = Arc::clone(&self.entered);
        Box::pin(async move {
            entered.notify_waiters();
            loop {
                tokio::task::yield_now().await;
            }
        })
    }
}

#[tokio::test]
async fn task7_eof_aborts_token_ignoring_yielding_task_within_bound() {
    timeout(Duration::from_secs(5), async {
        let entered = Arc::new(Notify::new());
        let tools = Arc::new(IgnoringTools { definitions: lifecycle_definitions(), entered: Arc::clone(&entered) });
        let mut session = Session::start(McpServer::new(tools, MIN_MCP_FRAME_BYTES).unwrap()).await;
        session.ready().await;
        let notified = entered.notified();
        session.send(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"block","arguments":{}}})).await;
        timeout(Duration::from_secs(1), notified).await.expect("task must start");
        let started = Instant::now();
        assert!(session.close().await.is_ok());
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(200));
        assert!(elapsed < Duration::from_millis(750));
    }).await.expect("test must complete");
}

#[tokio::test]
async fn task7_eof_cancels_cooperative_and_suppresses_already_ready_completion() {
    timeout(Duration::from_secs(5), async {
        for make_ready in [false, true] {
            let tools = Arc::new(StubTools::new());
            let mut session = Session::start(McpServer::new(Arc::clone(&tools), MIN_MCP_FRAME_BYTES).unwrap()).await;
            session.ready().await;
            session.send(&json!({"jsonrpc":"2.0","id":"closing","method":"tools/call","params":{"name":"block","arguments":{}}})).await;
            tools.wait_for_polls(1).await;
            if make_ready {
                tools.release.add_permits(1);
            }
            session.input.shutdown().await.unwrap();
            let result = timeout(Duration::from_secs(1), &mut session.serve).await.expect("serve must stop").expect("serve must not panic");
            assert!(result.is_ok());
            let mut trailing = Vec::new();
            timeout(Duration::from_secs(1), session.output.read_to_end(&mut trailing)).await.expect("writer must close").unwrap();
            assert!(trailing.is_empty(), "Closing must suppress tool completion");
            if !make_ready {
                assert!(tools.observed_cancel.load(Ordering::Acquire));
            }
        }
    }).await.expect("test must complete");
}

impl ToolService for NullService {
    fn definitions(&self) -> &[ToolDefinition] {
        &self.definitions
    }

    fn call(&self, _name: String, _arguments: Value, _context: ToolCallContext) -> ToolFuture {
        Box::pin(async { CallToolResult::text("ok") })
    }
}

#[test]
fn task7_tool_service_future_and_context_contract_are_sendable() {
    fn require_send<T: Send>(_: T) {}
    fn require_future<T: Future<Output = CallToolResult> + Send>(_: T) {}

    let context = ToolCallContext {
        cancel: tokio_util::sync::CancellationToken::new(),
        wire_budget: WireBudget {
            result_bytes: 1024,
            compact_fallback_bytes: 256,
        },
    };
    assert_eq!(context.wire_budget.result_bytes, 1024);
    require_send(context);
    require_future(async { CallToolResult::text("ok") });

    let service = NullService {
        definitions: Vec::new(),
    };
    assert!(service.definitions().is_empty());
    let future: Pin<Box<dyn Future<Output = CallToolResult> + Send>> = service.call(
        "ignored".into(),
        json!({}),
        ToolCallContext {
            cancel: tokio_util::sync::CancellationToken::new(),
            wire_budget: WireBudget {
                result_bytes: 1,
                compact_fallback_bytes: 1,
            },
        },
    );
    require_send(future);
}

#[tokio::test]
async fn task7_frame_reader_accepts_exact_limit_and_recovers_after_plus_one() {
    let wire = b"12345678\n123456789\n{}\n";
    let mut reader = FrameReader::new(BufReader::with_capacity(3, wire.as_slice()), 8);
    assert_eq!(
        reader.next_frame().await.unwrap(),
        FrameEvent::Frame(b"12345678".to_vec())
    );
    assert_eq!(reader.next_frame().await.unwrap(), FrameEvent::Oversized);
    assert_eq!(
        reader.next_frame().await.unwrap(),
        FrameEvent::Frame(b"{}".to_vec())
    );
    assert_eq!(reader.next_frame().await.unwrap(), FrameEvent::Eof);
}

#[tokio::test]
async fn task7_frame_reader_handles_buffering_crlf_empty_and_partial_eof() {
    let wire = b"{}\n[]\r\n\n{\"raw\":\xff}\npartial";
    let mut reader = FrameReader::new(BufReader::with_capacity(64, wire.as_slice()), 64);
    for expected in [
        b"{}".as_slice(),
        b"[]\r".as_slice(),
        b"".as_slice(),
        b"{\"raw\":\xff}".as_slice(),
    ] {
        let event = reader.next_frame().await.unwrap();
        assert_eq!(event, FrameEvent::Frame(expected.to_vec()));
        if expected.contains(&0xff) {
            let FrameEvent::Frame(raw) = event else {
                unreachable!();
            };
            assert_eq!(parse_strict_json(&raw), Err(StrictJsonError::Syntax));
        }
    }
    assert_eq!(reader.next_frame().await.unwrap(), FrameEvent::PartialEof);
    assert_eq!(reader.next_frame().await.unwrap(), FrameEvent::Eof);
}

#[tokio::test]
async fn task7_frame_reader_reports_empty_eof_and_oversized_partial_eof() {
    let mut empty = FrameReader::new(BufReader::new(&b""[..]), 4);
    assert_eq!(empty.next_frame().await.unwrap(), FrameEvent::Eof);

    let mut partial = FrameReader::new(BufReader::new(&b"12345"[..]), 4);
    assert_eq!(partial.next_frame().await.unwrap(), FrameEvent::PartialEof);
    assert_eq!(partial.next_frame().await.unwrap(), FrameEvent::Eof);
}

#[test]
fn task7_capped_writer_accepts_exact_limit_and_rejects_first_extra_byte() {
    let mut output = CappedJsonBuffer::new(8);
    assert_eq!(output.write(b"12345678").unwrap(), 8);
    assert!(output.write(b"9").is_err());
    assert_eq!(output.into_inner(), b"12345678");
}

#[tokio::test]
async fn task7_capped_writer_emits_one_injection_safe_json_line() {
    let value = json!({"text":"line\n\0界 {\"jsonrpc\":\"2.0\"}"});
    let expected_without_delimiter = serde_json::to_vec(&value).unwrap();
    let line = serialize_json_line(&value, expected_without_delimiter.len()).unwrap();
    assert_eq!(line.last(), Some(&b'\n'));
    assert!(!line[..line.len() - 1].contains(&b'\n'));
    assert_eq!(
        serde_json::from_slice::<Value>(&line[..line.len() - 1]).unwrap(),
        value
    );
    assert!(matches!(
        serialize_json_line(&value, expected_without_delimiter.len() - 1),
        Err(SerializeLineError::CapacityExceeded)
    ));

    let (mut tx, mut rx) = tokio::io::duplex(line.len() + 8);
    write_json_line(&mut tx, &value, expected_without_delimiter.len())
        .await
        .unwrap();
    drop(tx);
    let mut actual = Vec::new();
    rx.read_to_end(&mut actual).await.unwrap();
    assert_eq!(actual, line);
}

struct HostileSerializer;

impl Serialize for HostileSerializer {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Err(serde::ser::Error::custom(
            "HOSTILE caller-controlled serializer diagnostic",
        ))
    }
}

#[test]
fn task7_capped_writer_errors_are_classified_and_do_not_echo_diagnostics() {
    let error = serialize_json_line(&HostileSerializer, 64).unwrap_err();
    assert!(matches!(error, SerializeLineError::Serialization));
    assert_eq!(error.to_string(), "failed to serialize compact JSON frame");
    assert!(!error.to_string().contains("HOSTILE"));

    let capacity = serialize_json_line(&json!({"value":"too long"}), 1).unwrap_err();
    assert!(matches!(capacity, SerializeLineError::CapacityExceeded));
    assert_eq!(
        capacity.to_string(),
        "compact JSON frame exceeds configured bound"
    );
}

fn stub_definition(description: &str) -> ToolDefinition {
    ToolDefinition {
        name: "remote_read".into(),
        title: "Read remote file".into(),
        description: description.into(),
        input_schema: json!({"type":"object","additionalProperties":false}),
        annotations: ToolAnnotations {
            read_only_hint: true,
            destructive_hint: false,
            idempotent_hint: true,
            open_world_hint: false,
        },
    }
}

#[test]
fn task7_min_frame_counts_complete_tools_list_and_definition_growth() {
    let id = RequestId::synthetic_max_wire();
    let short = vec![stub_definition("bounded")];
    let long = vec![stub_definition(&"x".repeat(4096))];
    let short_count = exact_tools_list_response_bytes(&short, &id).unwrap();
    let long_count = exact_tools_list_response_bytes(&long, &id).unwrap();
    assert!(long_count > short_count);
    assert!(short_count < MIN_MCP_FRAME_BYTES);
    let task5_nominal = required_mcp_frame_bytes(&short, 0, &id).unwrap();
    assert_eq!(task5_nominal, MIN_MCP_FRAME_BYTES);
    assert!(WireBudget::for_response(task5_nominal, &id, 0).is_some());

    let fallback_result_bytes = MIN_MCP_FRAME_BYTES + 17;
    let envelope = serde_json::to_vec(&result_response(id.clone(), Value::Null))
        .unwrap()
        .len()
        - b"null".len();
    assert_eq!(
        required_mcp_frame_bytes(&short, fallback_result_bytes, &id).unwrap(),
        (envelope + fallback_result_bytes).max(short_count)
    );
    let required = required_mcp_frame_bytes(&short, fallback_result_bytes, &id).unwrap();
    assert!(WireBudget::for_response(required, &id, fallback_result_bytes).is_some());
    assert_eq!(
        required_mcp_frame_bytes(&long, 0, &id).unwrap(),
        MIN_MCP_FRAME_BYTES.max(long_count)
    );
}

#[test]
fn compact_fallback_fits_the_compiled_frame_floor() {
    let result = serde_json::to_value(CallToolResult::invalid_argument()).unwrap();
    let response = result_response(RequestId::synthetic_max_wire(), result);
    let exact = serde_json::to_vec(&response).unwrap().len();
    assert!(serialize_json_line(&response, exact).is_ok());
    assert!(matches!(
        serialize_json_line(&response, exact - 1),
        Err(SerializeLineError::CapacityExceeded)
    ));
    let bytes = serialize_json_line(&response, MIN_MCP_FRAME_BYTES).unwrap();
    assert!(bytes.len() - 1 <= MIN_MCP_FRAME_BYTES);
}

fn count_exact_string(value: &Value, needle: &str) -> usize {
    match value {
        Value::String(value) => usize::from(value == needle),
        Value::Array(values) => values
            .iter()
            .map(|value| count_exact_string(value, needle))
            .sum(),
        Value::Object(values) => values
            .values()
            .map(|value| count_exact_string(value, needle))
            .sum(),
        Value::Null | Value::Bool(_) | Value::Number(_) => 0,
    }
}

#[test]
fn task7_min_frame_wire_budget_reserves_envelope_id_and_fallback_only() {
    let id = RequestId::synthetic_max_wire();
    let fallback_bytes = 8192;
    let envelope_bytes = serde_json::to_vec(&result_response(id.clone(), Value::Null))
        .unwrap()
        .len()
        - b"null".len();
    let frame = envelope_bytes + fallback_bytes + 123;
    let budget = WireBudget::for_response(frame, &id, fallback_bytes).unwrap();
    assert_eq!(budget.result_bytes, 123);
    assert_eq!(budget.compact_fallback_bytes, fallback_bytes);
    assert!(
        WireBudget::for_response(envelope_bytes + fallback_bytes - 1, &id, fallback_bytes)
            .is_none()
    );
    assert_eq!(
        serde_json::to_vec(&id).unwrap().len(),
        codex_ssh_bridge::mcp::MAX_REQUEST_ID_WIRE_BYTES
    );

    let manually_constructed_oversized_id = RequestId::String("x".repeat(255));
    assert!(
        serde_json::to_vec(&manually_constructed_oversized_id)
            .unwrap()
            .len()
            > codex_ssh_bridge::mcp::MAX_REQUEST_ID_WIRE_BYTES
    );
    assert!(
        WireBudget::for_response(frame, &manually_constructed_oversized_id, fallback_bytes)
            .is_none()
    );
}

#[tokio::test]
async fn task7_adversarial_exact_eight_mib_and_plus_one_recovery() {
    let exact_request =
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":"exact","method":"ping","params":{}}))
            .unwrap();
    assert!(exact_request.len() < codex_ssh_bridge::MAX_FRAME_BYTES);

    let mut input = Vec::with_capacity(codex_ssh_bridge::MAX_FRAME_BYTES * 2 + 512);
    input.extend_from_slice(&exact_request);
    input.resize(codex_ssh_bridge::MAX_FRAME_BYTES, b' ');
    input.push(b'\n');
    input.extend(std::iter::repeat_n(
        b'x',
        codex_ssh_bridge::MAX_FRAME_BYTES + 1,
    ));
    input.push(b'\n');
    input.extend_from_slice(br#"{"jsonrpc":"2.0","id":"after","method":"ping","params":{}}"#);
    input.push(b'\n');

    let service = Arc::new(NullService {
        definitions: lifecycle_definitions(),
    });
    let server = McpServer::new(service, codex_ssh_bridge::MAX_FRAME_BYTES).unwrap();
    let (responses, result) = serve_raw(server, input).await;

    assert!(result.is_ok());
    assert_eq!(
        responses,
        [
            server_not_initialized_response(RequestId::String("exact".into())),
            request_too_large_response(),
            server_not_initialized_response(RequestId::String("after".into())),
        ]
    );
}

#[tokio::test]
async fn task7_adversarial_nul_utf8_and_non_utf8_are_fixed_parse_errors() {
    const ONE_MIB: usize = 1024 * 1024;
    let nul_utf8 = vec![0_u8; ONE_MIB];
    let non_utf8 = vec![0xff_u8; ONE_MIB];
    assert!(std::str::from_utf8(&nul_utf8).is_ok());
    assert!(std::str::from_utf8(&non_utf8).is_err());
    assert_eq!(parse_strict_json(&nul_utf8), Err(StrictJsonError::Syntax));
    assert_eq!(parse_strict_json(&non_utf8), Err(StrictJsonError::Syntax));

    let mut input = Vec::with_capacity(2 * ONE_MIB + 128);
    input.extend_from_slice(&nul_utf8);
    input.push(b'\n');
    input.extend_from_slice(&non_utf8);
    input.push(b'\n');
    input.extend_from_slice(br#"{"jsonrpc":"2.0","id":7,"method":"ping","params":{}}"#);
    input.push(b'\n');

    let service = Arc::new(NullService {
        definitions: lifecycle_definitions(),
    });
    let server = McpServer::new(service, codex_ssh_bridge::MAX_FRAME_BYTES).unwrap();
    let (responses, result) = serve_raw(server, input).await;
    assert!(result.is_ok());
    assert_eq!(
        responses,
        [
            parse_error_response(),
            parse_error_response(),
            server_not_initialized_response(RequestId::Number(7_u64.into())),
        ]
    );
}

#[test]
fn task7_adversarial_large_nested_arguments_reject_duplicate_key() {
    const UNIQUE_ARGUMENTS: usize = 32 * 1024;
    let mut input = Vec::with_capacity(768 * 1024);
    input.extend_from_slice(br#"{"arguments":{"#);
    for index in 0..UNIQUE_ARGUMENTS {
        if index != 0 {
            input.push(b',');
        }
        write!(input, "\"k{index}\":null").unwrap();
    }
    input.extend_from_slice(br#", "k0":null}}"#);

    assert_eq!(
        parse_strict_json(&input),
        Err(StrictJsonError::DuplicateKey)
    );
}

#[tokio::test]
async fn task7_adversarial_json_rpc_like_output_is_one_line_one_copy_and_atomic() {
    let payload = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":41,\"result\":{}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":42,\"error\":{\"code\":-1}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\"}"
    );
    let response = result_response(
        RequestId::String("hostile-output".into()),
        serde_json::to_value(CallToolResult::text(payload)).unwrap(),
    );
    let exact = serde_json::to_vec(&response).unwrap().len();
    let line = serialize_json_line(&response, exact).unwrap();

    assert_eq!(line.iter().filter(|byte| **byte == b'\n').count(), 1);
    assert_eq!(line.last(), Some(&b'\n'));
    let parsed: Value = serde_json::from_slice(&line[..line.len() - 1]).unwrap();
    assert_eq!(count_exact_string(&parsed, payload), 1);

    let (mut writer, written) = test_writer(false);
    let error = write_json_line(&mut writer, &response, exact - 1)
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "failed to serialize bounded JSON line");
    assert!(written.lock().unwrap().is_empty());
}

#[test]
fn task7_wide_json_rss_array_fresh_child() {
    run_wide_json_rss_fresh_child(
        "CODEX_SSH_BRIDGE_WIDE_ARRAY_RSS_CHILD",
        "task7_wide_json_rss_array_fresh_child",
        WideJsonShape::Array,
    );
}

#[test]
fn task7_wide_json_rss_object_fresh_child() {
    run_wide_json_rss_fresh_child(
        "CODEX_SSH_BRIDGE_WIDE_OBJECT_RSS_CHILD",
        "task7_wide_json_rss_object_fresh_child",
        WideJsonShape::Object,
    );
}

#[derive(Clone, Copy, Debug)]
enum WideJsonShape {
    Array,
    Object,
}

fn run_wide_json_rss_fresh_child(child_environment: &str, test_name: &str, shape: WideJsonShape) {
    if cfg!(debug_assertions) {
        eprintln!("wide JSON RSS assertion is release-only for {shape:?}");
        return;
    }
    if std::env::var_os(child_environment).is_some() {
        wide_json_rss_child(shape);
        return;
    }

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test_name, "--nocapture"])
        .env(child_environment, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprint!("{stdout}");
    eprint!("{stderr}");
    assert!(
        output.status.success(),
        "fresh {shape:?} wide-JSON RSS child failed: {stderr}"
    );
    let marker = format!("wide JSON {shape:?} release RSS:");
    assert!(
        stdout.contains(&marker) || stderr.contains(&marker),
        "fresh {shape:?} wide-JSON RSS child did not run the requested test"
    );
}

fn wide_json_rss_child(shape: WideJsonShape) {
    use std::sync::Barrier;

    const RSS_DELTA_CEILING_KIB: u64 = 48 * 1024;
    const ROUNDS: usize = 4;

    let input = Arc::new(match shape {
        WideJsonShape::Array => wide_array(262_144),
        WideJsonShape::Object => wide_object(131_072),
    });
    let touched = input
        .iter()
        .step_by(4096)
        .fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
    std::hint::black_box(touched);
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
                match (&shape, &parsed) {
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
                std::hint::black_box(&parsed);
            }
        })
    };

    let baseline = resident_kib_for_wide_json_rss();
    let mut peak = baseline;
    start.wait();
    while !completed.load(Ordering::Acquire) {
        peak = peak.max(resident_kib_for_wide_json_rss());
        std::thread::sleep(Duration::from_micros(250));
    }
    for _ in 0..20 {
        peak = peak.max(resident_kib_for_wide_json_rss());
        std::thread::sleep(Duration::from_millis(1));
    }
    finish.wait();
    worker.join().unwrap();

    let delta = peak.saturating_sub(baseline);
    eprintln!(
        "wide JSON {shape:?} release RSS: baseline={baseline} KiB peak={peak} KiB delta={delta} KiB ceiling={RSS_DELTA_CEILING_KIB} KiB"
    );
    assert!(
        delta < RSS_DELTA_CEILING_KIB,
        "wide JSON {shape:?} RSS baseline={baseline} KiB peak={peak} KiB delta={delta} KiB"
    );
}

fn resident_kib_for_wide_json_rss() -> u64 {
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
