use std::cell::{Cell, RefCell};
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Serialize, Serializer};
use serde_json::{Map, Number, Value};
use tokio_util::sync::CancellationToken;

pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18"];

pub const MAX_JSON_DEPTH: usize = 64;
pub const MAX_JSON_NODES: usize = 262_144;
pub const MAX_JSON_OBJECT_MEMBERS: usize = 131_072;
pub const MAX_JSON_KEY_BYTES: usize = 1_048_576;
pub const MAX_REQUEST_ID_WIRE_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RequestId {
    String(String),
    Number(Number),
}

impl RequestId {
    pub fn synthetic_max_wire() -> Self {
        Self::String("x".repeat(MAX_REQUEST_ID_WIRE_BYTES - 2))
    }

    pub fn try_from_ref(value: &Value) -> Result<Self, RequestIdError> {
        match value {
            Value::String(value) if string_wire_len_at_most(value, MAX_REQUEST_ID_WIRE_BYTES) => {
                Ok(Self::String(value.to_owned()))
            }
            Value::Number(value) if value.is_i64() || value.is_u64() => {
                Ok(Self::Number(value.clone()))
            }
            _ => Err(RequestIdError),
        }
    }
}

impl Serialize for RequestId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::String(value) => serializer.serialize_str(value),
            Self::Number(value) => value.serialize(serializer),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestIdError;

impl fmt::Display for RequestIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid request id")
    }
}

impl Error for RequestIdError {}

impl TryFrom<Value> for RequestId {
    type Error = RequestIdError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Self::try_from_ref(&value)
    }
}

fn string_wire_len_at_most(value: &str, maximum: usize) -> bool {
    escaped_json_string_len(value, maximum).is_some_and(|length| length <= maximum)
}

fn escaped_json_string_len(value: &str, maximum: usize) -> Option<usize> {
    let mut length = 2_usize;
    for byte in value.bytes() {
        let encoded = match byte {
            b'"' | b'\\' | b'\x08' | b'\x09' | b'\x0a' | b'\x0c' | b'\x0d' => 2,
            0x00..=0x1f => 6,
            _ => 1,
        };
        length = length.checked_add(encoded)?;
        if length > maximum {
            return Some(length);
        }
    }
    Some(length)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolState {
    AwaitInitialize,
    AwaitInitialized,
    Ready,
    Closing,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDefinition {
    pub name: String,
    pub title: String,
    pub description: String,
    pub input_schema: Value,
    pub annotations: ToolAnnotations,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolAnnotations {
    pub read_only_hint: bool,
    pub destructive_hint: bool,
    pub idempotent_hint: bool,
    pub open_world_hint: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TextContent {
    #[serde(rename = "type")]
    kind: &'static str,
    text: String,
}

impl TextContent {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            kind: "text",
            text: text.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallToolResult {
    pub content: Vec<TextContent>,
    pub structured_content: Value,
    #[serde(skip_serializing_if = "is_false")]
    pub is_error: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl CallToolResult {
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![TextContent::new(text)],
            structured_content: serde_json::json!({}),
            is_error: false,
        }
    }

    pub fn invalid_argument() -> Self {
        let compact = serde_json::to_string(&serde_json::json!({
            "error": {
                "code": "INVALID_ARGUMENT",
                "message": "invalid tool arguments"
            }
        }))
        .expect("serializing a JSON value cannot fail");
        Self {
            content: vec![TextContent::new(compact)],
            structured_content: serde_json::json!({
                "error": {
                    "code": "INVALID_ARGUMENT",
                    "message": "invalid tool arguments"
                }
            }),
            is_error: true,
        }
    }
}

pub type ToolFuture = Pin<Box<dyn Future<Output = CallToolResult> + Send + 'static>>;
pub type ShutdownFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), crate::BridgeError>> + Send + 'a>>;

#[derive(Debug, Clone, Copy)]
pub struct WireBudget {
    pub result_bytes: usize,
    pub compact_fallback_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct ToolCallContext {
    pub cancel: CancellationToken,
    pub wire_budget: WireBudget,
}

pub trait ToolService: Send + Sync + 'static {
    fn definitions(&self) -> &[ToolDefinition];

    fn call(&self, name: String, arguments: Value, context: ToolCallContext) -> ToolFuture;

    fn shutdown(&self) -> ShutdownFuture<'_> {
        Box::pin(async { Ok(()) })
    }
}

pub fn result_response(id: RequestId, result: Value) -> Value {
    serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result})
}

pub fn parse_error_response() -> Value {
    null_id_error_response(-32700, "Parse error")
}

pub fn invalid_request_response() -> Value {
    null_id_error_response(-32600, "Invalid Request")
}

pub fn invalid_request_id_response(id: RequestId) -> Value {
    id_error_response(id, -32600, "Invalid Request")
}

pub fn duplicate_request_id_response() -> Value {
    null_id_error_response(-32600, "Duplicate request id")
}

pub fn method_not_found_response(id: RequestId) -> Value {
    id_error_response(id, -32601, "Method not found")
}

pub fn invalid_params_response(id: RequestId) -> Value {
    id_error_response(id, -32602, "Invalid params")
}

pub fn internal_error_response(id: RequestId) -> Value {
    id_error_response(id, -32603, "Internal error")
}

pub fn server_not_initialized_response(id: RequestId) -> Value {
    id_error_response(id, -32002, "Server not initialized")
}

pub fn request_too_large_response() -> Value {
    null_id_error_response(-32001, "Request too large")
}

fn null_id_error_response(code: i64, message: &'static str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": Value::Null,
        "error": {"code": code, "message": message}
    })
}

fn id_error_response(id: RequestId, code: i64, message: &'static str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message}
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictJsonError {
    Syntax,
    DuplicateKey,
    StructuralBudget,
}

impl fmt::Display for StrictJsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Syntax => "invalid JSON syntax",
            Self::DuplicateKey => "duplicate JSON object key",
            Self::StructuralBudget => "JSON structural budget exceeded",
        };
        formatter.write_str(message)
    }
}

impl Error for StrictJsonError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StrictFailureMarker {
    None,
    DuplicateKey,
    StructuralBudget,
}

#[derive(Debug, Default)]
struct StructuralCounters {
    nodes: usize,
    object_members: usize,
    key_bytes: usize,
}

#[derive(Clone)]
struct StrictValueSeed {
    depth: usize,
    counters: Rc<RefCell<StructuralCounters>>,
    marker: Rc<Cell<StrictFailureMarker>>,
}

impl StrictValueSeed {
    fn child<E: de::Error>(&self) -> Result<Self, E> {
        let Some(depth) = self.depth.checked_add(1) else {
            return Err(self.reject_structure());
        };
        Ok(Self {
            depth,
            counters: Rc::clone(&self.counters),
            marker: Rc::clone(&self.marker),
        })
    }

    fn reject_structure<E: de::Error>(&self) -> E {
        mark_failure(&self.marker, StrictFailureMarker::StructuralBudget);
        E::custom("JSON structural budget exceeded")
    }

    fn enter_node<E: de::Error>(&self) -> Result<(), E> {
        if self.depth > MAX_JSON_DEPTH {
            return Err(self.reject_structure());
        }
        let mut counters = self.counters.borrow_mut();
        let Some(nodes) = counters.nodes.checked_add(1) else {
            drop(counters);
            return Err(self.reject_structure());
        };
        if nodes > MAX_JSON_NODES {
            drop(counters);
            return Err(self.reject_structure());
        }
        counters.nodes = nodes;
        Ok(())
    }

    fn key_seed(&self) -> StrictKeySeed {
        StrictKeySeed {
            counters: Rc::clone(&self.counters),
            marker: Rc::clone(&self.marker),
        }
    }

    fn reject_duplicate<E: de::Error>(&self) -> E {
        mark_failure(&self.marker, StrictFailureMarker::DuplicateKey);
        E::custom("duplicate JSON object key")
    }
}

fn mark_failure(marker: &Cell<StrictFailureMarker>, failure: StrictFailureMarker) {
    if marker.get() == StrictFailureMarker::None {
        marker.set(failure);
    }
}

#[derive(Clone)]
struct StrictKeySeed {
    counters: Rc<RefCell<StructuralCounters>>,
    marker: Rc<Cell<StrictFailureMarker>>,
}

impl StrictKeySeed {
    fn reject_structure<E: de::Error>(&self) -> E {
        mark_failure(&self.marker, StrictFailureMarker::StructuralBudget);
        E::custom("JSON structural budget exceeded")
    }

    fn reserve_member<E: de::Error>(&self) -> Result<(), E> {
        let mut counters = self.counters.borrow_mut();
        let Some(object_members) = counters.object_members.checked_add(1) else {
            drop(counters);
            return Err(self.reject_structure());
        };
        if object_members > MAX_JSON_OBJECT_MEMBERS {
            drop(counters);
            return Err(self.reject_structure());
        }
        counters.object_members = object_members;
        Ok(())
    }

    fn reserve_decoded_key_bytes<E: de::Error>(&self, bytes: usize) -> Result<(), E> {
        let mut counters = self.counters.borrow_mut();
        let Some(key_bytes) = counters.key_bytes.checked_add(bytes) else {
            drop(counters);
            return Err(self.reject_structure());
        };
        if key_bytes > MAX_JSON_KEY_BYTES {
            drop(counters);
            return Err(self.reject_structure());
        }
        counters.key_bytes = key_bytes;
        Ok(())
    }
}

impl<'de> DeserializeSeed<'de> for StrictKeySeed {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        self.reserve_member()?;
        deserializer.deserialize_str(StrictKeyVisitor { seed: self })
    }
}

struct StrictKeyVisitor {
    seed: StrictKeySeed,
}

impl<'de> Visitor<'de> for StrictKeyVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON object key")
    }

    fn visit_borrowed_str<E: de::Error>(self, value: &'de str) -> Result<Self::Value, E> {
        self.seed.reserve_decoded_key_bytes(value.len())?;
        Ok(value.to_owned())
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.seed.reserve_decoded_key_bytes(value.len())?;
        Ok(value.to_owned())
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        self.seed.reserve_decoded_key_bytes(value.len())?;
        Ok(value)
    }
}

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        self.enter_node()?;
        deserializer.deserialize_any(StrictValueVisitor { seed: self })
    }
}

struct StrictValueVisitor {
    seed: StrictValueSeed,
}

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        let child = self.seed.child()?;
        while let Some(value) = sequence.next_element_seed(child.clone())? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        let child = self.seed.child()?;
        let key_seed = self.seed.key_seed();
        while let Some(key) = entries.next_key_seed(key_seed.clone())? {
            if object.contains_key(&key) {
                return Err(self.seed.reject_duplicate());
            }
            let value = entries.next_value_seed(child.clone())?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

pub fn parse_strict_json(input: &[u8]) -> Result<Value, StrictJsonError> {
    let marker = Rc::new(Cell::new(StrictFailureMarker::None));
    let seed = StrictValueSeed {
        depth: 0,
        counters: Rc::new(RefCell::new(StructuralCounters::default())),
        marker: Rc::clone(&marker),
    };
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let parsed = seed
        .deserialize(&mut deserializer)
        .and_then(|value| deserializer.end().map(|()| value));
    match parsed {
        Ok(value) => Ok(value),
        Err(_) => match marker.get() {
            StrictFailureMarker::None => Err(StrictJsonError::Syntax),
            StrictFailureMarker::DuplicateKey => Err(StrictJsonError::DuplicateKey),
            StrictFailureMarker::StructuralBudget => Err(StrictJsonError::StructuralBudget),
        },
    }
}
