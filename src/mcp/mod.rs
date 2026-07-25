mod protocol;
mod render;
pub mod stdio;
pub mod tools;

pub use protocol::*;
pub use render::maximum_compact_fallback_result_bytes;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use self::stdio::{
    FrameEvent, FrameReader, required_mcp_frame_bytes, serialize_json_line, write_json_line,
};
use crate::ErrorCode;
use crate::error::{BridgeError, BridgeResult};
use serde::Serialize;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio::task::{Id, JoinError, JoinHandle, JoinSet};

const MCP_TASK_CLEANUP_GRACE: Duration = Duration::from_millis(250);
const MCP_WRITER_SHUTDOWN_GRACE: Duration = Duration::from_millis(250);
const MCP_ABORT_DRAIN_GRACE: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtocolShape {
    June,
    November,
}

#[derive(Debug)]
enum WriterMessage {
    Control(Value),
    CallResponse(PreparedJsonLine),
}

#[derive(Debug)]
struct PreparedJsonLine {
    bytes: Vec<u8>,
}

impl PreparedJsonLine {
    fn serialize<T: Serialize>(value: &T, max_frame_bytes: usize) -> Result<Self, ()> {
        let bytes = serialize_json_line(value, max_frame_bytes).map_err(|_| ())?;
        debug_assert!(bytes.len() <= max_frame_bytes + 1);
        Ok(Self { bytes })
    }
}

#[derive(Serialize)]
struct BorrowedCallResponse<'a> {
    jsonrpc: &'static str,
    id: &'a RequestId,
    result: &'a CallToolResult,
}

struct InFlight {
    cancel: tokio_util::sync::CancellationToken,
    cancelled_by_client: bool,
}

struct CompletedCall {
    id: RequestId,
    outcome: CallToolResult,
}

enum OwnerEvent {
    Writer(Box<Result<BridgeResult<()>, JoinError>>),
    Input(std::io::Result<FrameEvent>),
    Tool(Option<Result<(Id, CompletedCall), JoinError>>),
}

#[derive(Debug)]
pub struct McpServer<S> {
    service: Arc<S>,
    max_frame_bytes: usize,
    compact_fallback_result_bytes: usize,
}

const MCP_WRITER_CHANNEL_CAPACITY: usize = 16;

impl<S: ToolService> McpServer<S> {
    #[allow(clippy::result_large_err)]
    pub fn new(service: Arc<S>, max_frame_bytes: usize) -> BridgeResult<Self> {
        let compact_fallback_result_bytes = render::maximum_compact_fallback_result_bytes();
        let synthetic_id = RequestId::synthetic_max_wire();
        let required = required_mcp_frame_bytes(
            service.definitions(),
            compact_fallback_result_bytes,
            &synthetic_id,
        )
        .map_err(|_| BridgeError::invalid_argument("MCP response budget is invalid"))?;
        if max_frame_bytes < required || max_frame_bytes > crate::MAX_FRAME_BYTES {
            return Err(BridgeError::invalid_argument("MCP frame bound is invalid"));
        }
        Ok(Self {
            service,
            max_frame_bytes,
            compact_fallback_result_bytes,
        })
    }

    pub async fn serve<R, W>(self, reader: R, writer: W) -> BridgeResult<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (sender, receiver) = mpsc::channel(MCP_WRITER_CHANNEL_CAPACITY);
        let suppress_call_responses = Arc::new(AtomicBool::new(false));
        let writer_suppression = Arc::clone(&suppress_call_responses);
        let max_frame_bytes = self.max_frame_bytes;
        let mut writer_handle = tokio::spawn(async move {
            writer_loop(writer, receiver, writer_suppression, max_frame_bytes).await
        });
        let mut frames = FrameReader::new(BufReader::new(reader), self.max_frame_bytes);
        let mut state = ProtocolState::AwaitInitialize;
        let mut shape = None;
        let mut active = HashMap::<RequestId, InFlight>::new();
        let mut task_ids = HashMap::<Id, RequestId>::new();
        let mut join_set = JoinSet::<CompletedCall>::new();
        let mut partial_eof = false;
        let mut transport_failed = false;
        let mut writer_observed = false;

        loop {
            match next_owner_event(&mut writer_handle, &mut frames, &mut join_set).await {
                OwnerEvent::Writer(_result) => {
                    writer_observed = true;
                    // The sender is still owned by this loop, so even a
                    // nominal writer return is an unexpected transport loss.
                    transport_failed = true;
                    break;
                }
                OwnerEvent::Input(Err(_)) => {
                    transport_failed = true;
                    break;
                }
                OwnerEvent::Input(Ok(FrameEvent::Eof)) => break,
                OwnerEvent::Input(Ok(FrameEvent::PartialEof)) => {
                    partial_eof = true;
                    if sender
                        .try_send(WriterMessage::Control(parse_error_response()))
                        .is_err()
                    {
                        transport_failed = true;
                    }
                    break;
                }
                OwnerEvent::Input(Ok(FrameEvent::Oversized)) => {
                    if sender
                        .try_send(WriterMessage::Control(request_too_large_response()))
                        .is_err()
                    {
                        transport_failed = true;
                        break;
                    }
                    if try_reap_one_completion(
                        &mut join_set,
                        &mut active,
                        &mut task_ids,
                        &sender,
                        self.max_frame_bytes,
                    )
                    .is_err()
                    {
                        transport_failed = true;
                        break;
                    }
                }
                OwnerEvent::Input(Ok(FrameEvent::Frame(frame))) => {
                    let mut initialize_transition = None;
                    if let Some(response) = self.process_control_frame(
                        &frame,
                        &mut state,
                        &mut shape,
                        &mut active,
                        &mut task_ids,
                        &mut join_set,
                        &mut initialize_transition,
                    ) {
                        if sender.try_send(WriterMessage::Control(response)).is_err() {
                            transport_failed = true;
                            break;
                        }
                        if let Some(selected_shape) = initialize_transition {
                            state = ProtocolState::AwaitInitialized;
                            shape = Some(selected_shape);
                        }
                    }
                    if try_reap_one_completion(
                        &mut join_set,
                        &mut active,
                        &mut task_ids,
                        &sender,
                        self.max_frame_bytes,
                    )
                    .is_err()
                    {
                        transport_failed = true;
                        break;
                    }
                }
                OwnerEvent::Tool(Some(completion)) => {
                    if process_completion(
                        completion,
                        &mut active,
                        &mut task_ids,
                        &sender,
                        self.max_frame_bytes,
                    )
                    .is_err()
                    {
                        transport_failed = true;
                        break;
                    }
                }
                OwnerEvent::Tool(None) => {
                    transport_failed = true;
                    break;
                }
            }
        }

        state = ProtocolState::Closing;
        let _ = state;
        suppress_call_responses.store(true, Ordering::Release);
        for inflight in active.values() {
            inflight.cancel.cancel();
        }
        let cleanup = async {
            while !join_set.is_empty() {
                let Some(completion) = join_set.join_next_with_id().await else {
                    break;
                };
                remove_completion(completion, &mut active, &mut task_ids)?;
            }
            Ok::<(), ()>(())
        };
        match tokio::time::timeout(MCP_TASK_CLEANUP_GRACE, cleanup).await {
            Ok(Ok(())) => {}
            Ok(Err(())) => transport_failed = true,
            Err(_) => {
                join_set.abort_all();
                let drain = async {
                    while let Some(completion) = join_set.join_next_with_id().await {
                        remove_completion(completion, &mut active, &mut task_ids)?;
                    }
                    Ok::<(), ()>(())
                };
                if !matches!(
                    tokio::time::timeout(MCP_ABORT_DRAIN_GRACE, drain).await,
                    Ok(Ok(()))
                ) {
                    transport_failed = true;
                }
            }
        }
        active.clear();
        task_ids.clear();
        drop(sender);
        if writer_observed {
            // `next_owner_event` already consumed the writer result.
        } else if !writer_handle.is_finished() {
            match tokio::time::timeout(MCP_WRITER_SHUTDOWN_GRACE, &mut writer_handle).await {
                Ok(Ok(Ok(()))) => {}
                Ok(_) => transport_failed = true,
                Err(_) => {
                    writer_handle.abort();
                    let _ = tokio::time::timeout(MCP_ABORT_DRAIN_GRACE, &mut writer_handle).await;
                    transport_failed = true;
                }
            }
        } else {
            match writer_handle.await {
                Ok(Ok(())) => {}
                _ => transport_failed = true,
            }
        }
        if transport_failed {
            return Err(BridgeError::io("MCP transport failed"));
        }
        if partial_eof {
            return Err(BridgeError::new(
                ErrorCode::ProtocolError,
                "partial MCP frame at EOF",
                false,
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn process_control_frame(
        &self,
        frame: &[u8],
        state: &mut ProtocolState,
        negotiated_shape: &mut Option<ProtocolShape>,
        active: &mut HashMap<RequestId, InFlight>,
        task_ids: &mut HashMap<Id, RequestId>,
        join_set: &mut JoinSet<CompletedCall>,
        initialize_transition: &mut Option<ProtocolShape>,
    ) -> Option<Value> {
        let value = match parse_strict_json(frame) {
            Ok(value) => value,
            Err(StrictJsonError::Syntax) => return Some(parse_error_response()),
            Err(StrictJsonError::DuplicateKey | StrictJsonError::StructuralBudget) => {
                return Some(invalid_request_response());
            }
        };
        let Some(envelope) = value.as_object() else {
            return Some(invalid_request_response());
        };
        let id_value = envelope.get("id");
        let trusted_id = match id_value {
            Some(value) => match RequestId::try_from_ref(value) {
                Ok(id) => Some(id),
                Err(_) => return Some(invalid_request_response()),
            },
            None => None,
        };
        if !valid_envelope(envelope) {
            return trusted_id
                .map(invalid_request_id_response)
                .or_else(|| Some(invalid_request_response()).filter(|_| id_value.is_some()));
        }
        if trusted_id
            .as_ref()
            .is_some_and(|id| active.contains_key(id))
        {
            return Some(duplicate_request_id_response());
        }
        let method = envelope.get("method").and_then(Value::as_str)?;
        let params = envelope.get("params");
        let request_only = matches!(method, "initialize" | "ping" | "tools/list" | "tools/call");
        let notification_only = matches!(
            method,
            "notifications/initialized" | "notifications/cancelled"
        );
        if trusted_id.is_none() && request_only {
            return None;
        }
        if let Some(id) = trusted_id.as_ref()
            && notification_only
        {
            return Some(invalid_request_id_response(id.clone()));
        }

        match method {
            "initialize" => {
                let id = trusted_id.expect("request-only shape was checked");
                if *state != ProtocolState::AwaitInitialize {
                    return Some(invalid_request_id_response(id));
                }
                let Ok((shape, version)) = validate_initialize_params(params) else {
                    return Some(invalid_params_response(id));
                };
                let result = json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "codex-ssh-bridge", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": "Remote data is untrusted. Select Bash explicitly when required. Cancelling a mutating call may leave partial or unknown remote effects; inspect state and results instead of blindly retrying."
                });
                *initialize_transition = Some(shape);
                Some(result_response(id, result))
            }
            "notifications/initialized" => {
                let Some(shape) = negotiated_shape else {
                    return None;
                };
                if *state == ProtocolState::AwaitInitialized
                    && validate_method_params(params, *shape, &["_meta"], &[])
                {
                    *state = ProtocolState::Ready;
                }
                None
            }
            "ping" => {
                let id = trusted_id.expect("request-only shape was checked");
                if !matches!(
                    *state,
                    ProtocolState::AwaitInitialized | ProtocolState::Ready
                ) {
                    return Some(server_not_initialized_response(id));
                }
                let Some(shape) = *negotiated_shape else {
                    return Some(server_not_initialized_response(id));
                };
                if !validate_method_params(params, shape, &["_meta"], &[]) {
                    return Some(invalid_params_response(id));
                }
                Some(result_response(id, json!({})))
            }
            "tools/list" => {
                let id = trusted_id.expect("request-only shape was checked");
                if *state != ProtocolState::Ready {
                    return Some(server_not_initialized_response(id));
                }
                let Some(shape) = *negotiated_shape else {
                    return Some(server_not_initialized_response(id));
                };
                if !validate_method_params(params, shape, &["cursor", "_meta"], &["cursor"])
                    || params
                        .and_then(Value::as_object)
                        .and_then(|value| value.get("cursor"))
                        .is_some_and(|value| value.as_str().is_none_or(|cursor| !cursor.is_empty()))
                {
                    return Some(invalid_params_response(id));
                }
                Some(result_response(
                    id,
                    json!({"tools": self.service.definitions()}),
                ))
            }
            "tools/call" => {
                let id = trusted_id.expect("request-only shape was checked");
                if *state != ProtocolState::Ready {
                    return Some(server_not_initialized_response(id));
                }
                let Some(shape) = *negotiated_shape else {
                    return Some(server_not_initialized_response(id));
                };
                let Ok((name, arguments)) = validate_tool_call_params(params, shape) else {
                    return Some(invalid_params_response(id));
                };
                if !self
                    .service
                    .definitions()
                    .iter()
                    .any(|definition| definition.name == name)
                {
                    return Some(invalid_params_response(id));
                }
                let Some(wire_budget) = WireBudget::for_response(
                    self.max_frame_bytes,
                    &id,
                    self.compact_fallback_result_bytes,
                ) else {
                    return Some(internal_error_response(id));
                };
                let cancel = tokio_util::sync::CancellationToken::new();
                let context = ToolCallContext {
                    cancel: cancel.clone(),
                    wire_budget,
                };
                let _admission_profile =
                    crate::bridge_profile_span!(crate::profile::ProfileEvent {
                        phase: "mcp_admission",
                        host: None,
                        request_id: None,
                        class: None,
                        elapsed_us: 0,
                        bytes: None,
                    });
                active.insert(
                    id.clone(),
                    InFlight {
                        cancel,
                        cancelled_by_client: false,
                    },
                );
                let name = name.to_owned();
                let arguments = arguments.cloned().unwrap_or_else(|| json!({}));
                let service = Arc::clone(&self.service);
                let completed_id = id.clone();
                let handle = join_set.spawn(async move {
                    let _service_profile =
                        crate::bridge_profile_span!(crate::profile::ProfileEvent {
                            phase: "mcp_service",
                            host: None,
                            request_id: None,
                            class: None,
                            elapsed_us: 0,
                            bytes: None,
                        });
                    let outcome = service.call(name, arguments, context).await;
                    CompletedCall {
                        id: completed_id,
                        outcome,
                    }
                });
                task_ids.insert(handle.id(), id);
                None
            }
            "notifications/cancelled" => {
                let shape = (*negotiated_shape)?;
                let Ok(request_id) = validate_cancellation_params(params, shape) else {
                    return None;
                };
                if let Some(inflight) = active.get_mut(&request_id) {
                    inflight.cancelled_by_client = true;
                    inflight.cancel.cancel();
                }
                None
            }
            _ => trusted_id.map(method_not_found_response),
        }
    }
}

async fn next_owner_event<R: tokio::io::AsyncBufRead + Unpin>(
    writer_handle: &mut JoinHandle<BridgeResult<()>>,
    frames: &mut FrameReader<R>,
    join_set: &mut JoinSet<CompletedCall>,
) -> OwnerEvent {
    tokio::select! {
        biased;
        writer_result = writer_handle => OwnerEvent::Writer(Box::new(writer_result)),
        input = frames.next_frame() => OwnerEvent::Input(input),
        completion = join_set.join_next_with_id(), if !join_set.is_empty() => {
            OwnerEvent::Tool(completion)
        }
    }
}

fn process_completion(
    completion: Result<(Id, CompletedCall), JoinError>,
    active: &mut HashMap<RequestId, InFlight>,
    task_ids: &mut HashMap<Id, RequestId>,
    sender: &mpsc::Sender<WriterMessage>,
    max_frame_bytes: usize,
) -> Result<(), ()> {
    match completion {
        Ok((task_id, completed)) => {
            let Some(associated_id) = task_ids.remove(&task_id) else {
                return Err(());
            };
            if associated_id != completed.id {
                return Err(());
            }
            // Removing the registry entry is the task-capacity release point;
            // the writer loop must not control admission.
            let Some(inflight) = active.remove(&completed.id) else {
                return Err(());
            };
            if !inflight.cancelled_by_client {
                let _render_profile = crate::bridge_profile_span!(crate::profile::ProfileEvent {
                    phase: "mcp_render",
                    host: None,
                    request_id: None,
                    class: None,
                    elapsed_us: 0,
                    bytes: None,
                });
                let response = BorrowedCallResponse {
                    jsonrpc: "2.0",
                    id: &completed.id,
                    result: &completed.outcome,
                };
                let prepared = PreparedJsonLine::serialize(&response, max_frame_bytes)?;
                sender
                    .try_send(WriterMessage::CallResponse(prepared))
                    .map_err(|_| ())?;
            }
            Ok(())
        }
        Err(error) => {
            let task_id = error.id();
            let Some(id) = task_ids.remove(&task_id) else {
                return Err(());
            };
            let Some(inflight) = active.remove(&id) else {
                return Err(());
            };
            if !inflight.cancelled_by_client && !error.is_cancelled() {
                let response = internal_error_response(id);
                let prepared = PreparedJsonLine::serialize(&response, max_frame_bytes)?;
                sender
                    .try_send(WriterMessage::CallResponse(prepared))
                    .map_err(|_| ())?;
            }
            Ok(())
        }
    }
}

fn try_reap_one_completion(
    join_set: &mut JoinSet<CompletedCall>,
    active: &mut HashMap<RequestId, InFlight>,
    task_ids: &mut HashMap<Id, RequestId>,
    sender: &mpsc::Sender<WriterMessage>,
    max_frame_bytes: usize,
) -> Result<(), ()> {
    if !join_set.is_empty()
        && let Some(completion) = join_set.try_join_next_with_id()
    {
        process_completion(completion, active, task_ids, sender, max_frame_bytes)?;
    }
    Ok(())
}

fn remove_completion(
    completion: Result<(Id, CompletedCall), JoinError>,
    active: &mut HashMap<RequestId, InFlight>,
    task_ids: &mut HashMap<Id, RequestId>,
) -> Result<(), ()> {
    let (task_id, completed_id) = match completion {
        Ok((task_id, completed)) => (task_id, completed.id),
        Err(error) => {
            let task_id = error.id();
            let Some(id) = task_ids.get(&task_id).cloned() else {
                return Err(());
            };
            (task_id, id)
        }
    };
    let Some(associated_id) = task_ids.remove(&task_id) else {
        return Err(());
    };
    if associated_id != completed_id || active.remove(&completed_id).is_none() {
        return Err(());
    }
    Ok(())
}

async fn writer_loop<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut receiver: mpsc::Receiver<WriterMessage>,
    suppress_call_responses: Arc<AtomicBool>,
    max_frame_bytes: usize,
) -> BridgeResult<()> {
    while let Some(message) = receiver.recv().await {
        match message {
            WriterMessage::CallResponse(_) if suppress_call_responses.load(Ordering::Acquire) => {
                continue;
            }
            WriterMessage::CallResponse(prepared) => writer
                .write_all(&prepared.bytes)
                .await
                .map_err(|_| BridgeError::io("MCP transport failed"))?,
            WriterMessage::Control(value) => write_json_line(&mut writer, &value, max_frame_bytes)
                .await
                .map_err(|_| BridgeError::io("MCP transport failed"))?,
        }
    }
    writer
        .shutdown()
        .await
        .map_err(|_| BridgeError::io("MCP transport failed"))
}

fn valid_envelope(envelope: &Map<String, Value>) -> bool {
    envelope
        .keys()
        .all(|key| matches!(key.as_str(), "jsonrpc" | "id" | "method" | "params"))
        && envelope.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        && envelope.get("method").is_some_and(Value::is_string)
}

fn validate_initialize_params(params: Option<&Value>) -> Result<(ProtocolShape, &'static str), ()> {
    let object = params.and_then(Value::as_object).ok_or(())?;
    if object.contains_key("task") {
        return Err(());
    }
    let requested = object
        .get("protocolVersion")
        .and_then(Value::as_str)
        .ok_or(())?;
    if requested.len() > 256 {
        return Err(());
    }
    let shape = if requested == "2025-06-18" {
        ProtocolShape::June
    } else {
        ProtocolShape::November
    };
    if shape == ProtocolShape::November
        && !object.keys().all(|key| {
            matches!(
                key.as_str(),
                "protocolVersion" | "capabilities" | "clientInfo" | "_meta"
            )
        })
    {
        return Err(());
    }
    if !object.get("capabilities").is_some_and(Value::is_object)
        || !optional_object(object.get("_meta"))
    {
        return Err(());
    }
    validate_client_info(object.get("clientInfo"), shape)?;
    let selected = if requested == "2025-06-18" {
        "2025-06-18"
    } else {
        "2025-11-25"
    };
    Ok((shape, selected))
}

fn validate_client_info(value: Option<&Value>, shape: ProtocolShape) -> Result<(), ()> {
    let object = value.and_then(Value::as_object).ok_or(())?;
    if !object.keys().all(|key| match shape {
        ProtocolShape::June => matches!(key.as_str(), "name" | "version" | "title"),
        ProtocolShape::November => matches!(
            key.as_str(),
            "name" | "version" | "title" | "icons" | "description" | "websiteUrl"
        ),
    }) {
        return Err(());
    }
    for required in ["name", "version"] {
        if !bounded_string(object.get(required), 256) {
            return Err(());
        }
    }
    if object.get("title").is_some() && !bounded_string(object.get("title"), 256) {
        return Err(());
    }
    if object.get("description").is_some() && !bounded_string(object.get("description"), 4096) {
        return Err(());
    }
    if let Some(website) = object.get("websiteUrl") {
        let website = website.as_str().ok_or(())?;
        if website.len() > 2048 || !valid_absolute_uri(website, 2048) {
            return Err(());
        }
    }
    if let Some(icons) = object.get("icons") {
        let icons = icons.as_array().ok_or(())?;
        if icons.len() > 16 {
            return Err(());
        }
        for icon in icons {
            validate_icon(icon)?;
        }
    }
    Ok(())
}

fn validate_icon(value: &Value) -> Result<(), ()> {
    let object = value.as_object().ok_or(())?;
    if !object
        .keys()
        .all(|key| matches!(key.as_str(), "src" | "mimeType" | "sizes" | "theme"))
    {
        return Err(());
    }
    let src = object.get("src").and_then(Value::as_str).ok_or(())?;
    if !valid_absolute_uri(src, 65_536) {
        return Err(());
    }
    if object.get("mimeType").is_some() && !bounded_string(object.get("mimeType"), 256) {
        return Err(());
    }
    if let Some(sizes) = object.get("sizes") {
        let sizes = sizes.as_array().ok_or(())?;
        if sizes.len() > 16
            || sizes
                .iter()
                .any(|size| size.as_str().is_none_or(|s| s.len() > 32))
        {
            return Err(());
        }
    }
    if object
        .get("theme")
        .is_some_and(|theme| !matches!(theme.as_str(), Some("light" | "dark")))
    {
        return Err(());
    }
    Ok(())
}

fn bounded_string(value: Option<&Value>, maximum: usize) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|value| value.len() <= maximum)
}

fn optional_object(value: Option<&Value>) -> bool {
    value.is_none_or(Value::is_object)
}

fn validate_method_params(
    params: Option<&Value>,
    shape: ProtocolShape,
    allowed: &[&str],
    string_fields: &[&str],
) -> bool {
    let Some(params) = params else {
        return true;
    };
    let Some(object) = params.as_object() else {
        return false;
    };
    if !optional_object(object.get("_meta")) || object.contains_key("task") {
        return false;
    }
    if shape == ProtocolShape::November && !object.keys().all(|key| allowed.contains(&key.as_str()))
    {
        return false;
    }
    string_fields
        .iter()
        .all(|field| object.get(*field).is_none_or(Value::is_string))
}

fn validate_tool_call_params(
    params: Option<&Value>,
    shape: ProtocolShape,
) -> Result<(&str, Option<&Value>), ()> {
    let object = params.and_then(Value::as_object).ok_or(())?;
    if !optional_object(object.get("_meta")) || object.contains_key("task") {
        return Err(());
    }
    if shape == ProtocolShape::November
        && !object
            .keys()
            .all(|key| matches!(key.as_str(), "name" | "arguments" | "_meta"))
    {
        return Err(());
    }
    let name = object.get("name").and_then(Value::as_str).ok_or(())?;
    if name.is_empty() || name.len() > 256 {
        return Err(());
    }
    let arguments = object.get("arguments");
    if arguments.is_some_and(|arguments| !arguments.is_object()) {
        return Err(());
    }
    Ok((name, arguments))
}

fn validate_cancellation_params(
    params: Option<&Value>,
    shape: ProtocolShape,
) -> Result<RequestId, ()> {
    let object = params.and_then(Value::as_object).ok_or(())?;
    if !optional_object(object.get("_meta")) || object.contains_key("task") {
        return Err(());
    }
    if shape == ProtocolShape::November
        && !object
            .keys()
            .all(|key| matches!(key.as_str(), "requestId" | "reason" | "_meta"))
    {
        return Err(());
    }
    if object
        .get("reason")
        .is_some_and(|reason| reason.as_str().is_none_or(|value| value.len() > 1024))
    {
        return Err(());
    }
    RequestId::try_from_ref(object.get("requestId").ok_or(())?).map_err(|_| ())
}

fn valid_absolute_uri(value: &str, maximum: usize) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > maximum || !bytes.is_ascii() {
        return false;
    }
    if bytes.iter().any(|byte| {
        byte.is_ascii_control()
            || byte.is_ascii_whitespace()
            || matches!(
                *byte,
                b'\\' | b'"' | b'<' | b'>' | b'^' | b'`' | b'{' | b'|' | b'}'
            )
    }) {
        return false;
    }
    let Some(colon) = bytes.iter().position(|byte| *byte == b':') else {
        return false;
    };
    if colon == 0
        || colon + 1 >= bytes.len()
        || !bytes[0].is_ascii_alphabetic()
        || !bytes[1..colon]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'+' | b'-' | b'.'))
    {
        return false;
    }
    let http =
        value[..colon].eq_ignore_ascii_case("http") || value[..colon].eq_ignore_ascii_case("https");
    let mut index = colon + 1;
    if bytes.get(index..index + 2) == Some(b"//") {
        index += 2;
        let end = bytes[index..]
            .iter()
            .position(|byte| matches!(*byte, b'/' | b'?' | b'#'))
            .map_or(bytes.len(), |offset| index + offset);
        if !valid_authority(&value[index..end]) {
            return false;
        }
        index = end;
    } else if http {
        return false;
    }
    validate_uri_suffix(&bytes[index..])
}

fn valid_authority(authority: &str) -> bool {
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let Some(close) = rest.find(']') else {
            return false;
        };
        if rest[..close].parse::<Ipv6Addr>().is_err() {
            return false;
        }
        let suffix = &rest[close + 1..];
        if suffix.is_empty() {
            return true;
        }
        let Some(port) = suffix.strip_prefix(':') else {
            return false;
        };
        (None, Some(port))
    } else {
        let mut split = authority.rsplitn(2, ':');
        let last = split.next().unwrap_or_default();
        let before = split.next();
        match before {
            Some(host) => (Some(host), Some(last)),
            None => (Some(last), None),
        }
    };
    if let Some(port) = port
        && (port.is_empty()
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || port.parse::<u16>().is_err())
    {
        return false;
    }
    let Some(host) = host else {
        return true;
    };
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.contains('.')
        && host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return host.parse::<Ipv4Addr>().is_ok();
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn validate_uri_suffix(bytes: &[u8]) -> bool {
    #[derive(Clone, Copy)]
    enum Component {
        Path,
        Query,
        Fragment,
    }
    let mut component = Component::Path;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        match (component, byte) {
            (Component::Path, b'?') => component = Component::Query,
            (Component::Path | Component::Query, b'#') => component = Component::Fragment,
            (Component::Fragment, b'#') => return false,
            (_, b'%') => {
                if index + 2 >= bytes.len()
                    || !bytes[index + 1].is_ascii_hexdigit()
                    || !bytes[index + 2].is_ascii_hexdigit()
                {
                    return false;
                }
                index += 2;
            }
            (Component::Path, b'[' | b']') => return false,
            (Component::Path, value) if value == b'/' || is_pchar(value) => {}
            (Component::Query | Component::Fragment, value)
                if value == b'/' || value == b'?' || is_pchar(value) => {}
            _ => return false,
        }
        index += 1;
    }
    true
}

fn is_pchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

#[cfg(test)]
mod lifecycle_tests {
    use super::{
        BorrowedCallResponse, CompletedCall, FrameEvent, FrameReader, OwnerEvent, PreparedJsonLine,
        next_owner_event,
    };
    use crate::error::BridgeResult;
    use crate::mcp::{CallToolResult, RequestId};
    use serde_json::json;
    use std::future;
    use std::time::Duration;
    use tokio::io::{AsyncWriteExt, BufReader};
    use tokio::task::JoinSet;

    #[tokio::test]
    async fn task7_next_owner_event_empty_join_set_stays_pending_then_reads_input() {
        let (mut input, reader) = tokio::io::duplex(64);
        let mut frames = FrameReader::new(BufReader::new(reader), 64);
        let mut joins = JoinSet::<CompletedCall>::new();
        let mut writer = tokio::spawn(future::pending::<BridgeResult<()>>());

        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                next_owner_event(&mut writer, &mut frames, &mut joins),
            )
            .await
            .is_err()
        );

        input.write_all(b"{}\n").await.unwrap();
        let event = tokio::time::timeout(
            Duration::from_secs(1),
            next_owner_event(&mut writer, &mut frames, &mut joins),
        )
        .await
        .unwrap();
        assert!(matches!(event, OwnerEvent::Input(Ok(FrameEvent::Frame(frame))) if frame == b"{}"));
        writer.abort();
    }

    #[tokio::test]
    async fn task7_nominal_writer_early_return_is_an_owner_transport_failure_event() {
        let (_input, reader) = tokio::io::duplex(64);
        let mut frames = FrameReader::new(BufReader::new(reader), 64);
        let mut joins = JoinSet::<CompletedCall>::new();
        let mut writer = tokio::spawn(async { Ok(()) });
        let event = tokio::time::timeout(
            Duration::from_secs(1),
            next_owner_event(&mut writer, &mut frames, &mut joins),
        )
        .await
        .expect("nominal writer return must wake the owner");
        match event {
            OwnerEvent::Writer(result) => assert!(matches!(*result, Ok(Ok(())))),
            _ => panic!("writer completion must win while input remains active"),
        }

        let owner = include_str!("mod.rs")
            .split("OwnerEvent::Writer(_result) => {")
            .nth(1)
            .expect("owner has an explicit writer-result arm")
            .split("OwnerEvent::Input(Err(_))")
            .next()
            .unwrap();
        assert!(owner.contains("writer_observed = true;"));
        assert!(owner.contains("transport_failed = true;"));
        assert!(owner.contains("break;"));
    }

    #[test]
    fn task7_prepared_call_line_is_intrinsically_exact_and_bounded() {
        let id = RequestId::try_from(json!("bounded")).unwrap();
        let result = CallToolResult::text("x".repeat(4096));
        let response = BorrowedCallResponse {
            jsonrpc: "2.0",
            id: &id,
            result: &result,
        };
        let exact = serde_json::to_vec(&response).unwrap().len();
        let prepared = PreparedJsonLine::serialize(&response, exact).unwrap();
        assert_eq!(prepared.bytes.len(), exact + 1);
        assert_eq!(prepared.bytes.last(), Some(&b'\n'));
        assert!(PreparedJsonLine::serialize(&response, exact - 1).is_err());

        let huge = CallToolResult::text("x".repeat(2 * 1024 * 1024));
        let huge_response = BorrowedCallResponse {
            jsonrpc: "2.0",
            id: &id,
            result: &huge,
        };
        assert!(PreparedJsonLine::serialize(&huge_response, 1024 * 1024).is_err());
    }
}
