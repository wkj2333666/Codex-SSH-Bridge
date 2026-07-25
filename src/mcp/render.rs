use std::io::{self, Write};
use std::sync::{Arc, OnceLock};

use base64::Engine as _;
use serde::Serialize;
use serde_json::{Map, Value, json};
use tokio_util::sync::CancellationToken;

use crate::error::{BridgeError, ErrorCode, ErrorDetails};
use crate::remote::{
    AggregateKind, ApplyPatchResult, EncodedValue, HostsResult, ListResult, OutputReadResult,
    ReadEntry, ReadResult, RemoteBridge, RemoteContext, RemoteFileKind, RemoteRunResult,
    RetentionProvenance, SearchResult, ShellMetadata, ShellName, StatEntry, StatResult,
    ValueEncoding, WriteResult,
};

use super::{CallToolResult, TextContent, WireBudget};

const MODEL_INLINE_RESULT_BYTES: usize = 32 * 1024;
const SAFE_TEXT_BYTES: usize = 1_024;
const MAX_WARNINGS: usize = 16;

pub fn maximum_compact_fallback_result_bytes() -> usize {
    static MAXIMUM: OnceLock<usize> = OnceLock::new();
    *MAXIMUM.get_or_init(|| {
        let hostile = "\\\"".repeat(SAFE_TEXT_BYTES / 2);
        let mut error = BridgeError::new(ErrorCode::MutationOutcomeUnknown, &hostile, false);
        error.details = ErrorDetails {
            path: Some(hostile.clone()),
            requested_shell: Some("bash".to_owned()),
            available_shells: Some(vec!["sh".to_owned()]),
            mutation_may_have_applied: Some(true),
            changed_paths: Some(vec![hostile.clone(); MAX_WARNINGS]),
            not_changed_paths: Some(vec![hostile.clone(); MAX_WARNINGS]),
            outcome_unknown_paths: Some(vec![hostile; MAX_WARNINGS]),
            ..ErrorDetails::default()
        };
        let error_result = render_error(
            error,
            WireBudget {
                result_bytes: usize::MAX / 4,
                compact_fallback_bytes: usize::MAX / 4,
            },
        );
        let run_result = compact_result(
            json!({
                "exit_code":i32::MIN,
                "output_ref":"f".repeat(32),
                "remote_process_may_continue":true,
                "truncated":true,
            }),
            false,
        );
        let invalid = CallToolResult::invalid_argument();
        [&error_result, &run_result, &invalid]
            .into_iter()
            .map(|result| {
                serde_json::to_vec(result)
                    .expect("the maximum compact MCP fallback is serializable")
                    .len()
            })
            .max()
            .expect("the compact fallback set is nonempty")
    })
}

pub async fn hosts(
    bridge: Arc<RemoteBridge>,
    result: Result<HostsResult, BridgeError>,
    budget: WireBudget,
    cancel: CancellationToken,
) -> CallToolResult {
    match result {
        Ok(result) => {
            let provenance = RetentionProvenance::Aggregate {
                kind: AggregateKind::Hosts,
                source_count: result.hosts.len(),
            };
            let text = result
                .hosts
                .iter()
                .map(|host| host.host.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            render_text_retained(
                bridge,
                text,
                json!({}),
                result,
                provenance,
                None,
                false,
                budget,
                cancel,
            )
            .await
        }
        Err(error) => render_error_retained(bridge, error, budget, cancel).await,
    }
}

pub async fn list(
    bridge: Arc<RemoteBridge>,
    result: Result<ListResult, BridgeError>,
    budget: WireBudget,
    cancel: CancellationToken,
) -> CallToolResult {
    match result {
        Ok(result) => {
            let text = list_text(&result);
            let truncated = result.truncated;
            let provenance = RetentionProvenance::Remote(result.context.clone());
            render_text_retained(
                bridge,
                text,
                json!({}),
                result,
                provenance,
                None,
                truncated,
                budget,
                cancel,
            )
            .await
        }
        Err(error) => render_error_retained(bridge, error, budget, cancel).await,
    }
}

pub async fn stat(
    bridge: Arc<RemoteBridge>,
    result: Result<StatResult, BridgeError>,
    budget: WireBudget,
    cancel: CancellationToken,
) -> CallToolResult {
    match result {
        Ok(result) => {
            let text = stat_text(&result);
            let provenance = RetentionProvenance::Remote(result.context.clone());
            render_text_retained(
                bridge,
                text,
                json!({}),
                result,
                provenance,
                None,
                false,
                budget,
                cancel,
            )
            .await
        }
        Err(error) => render_error_retained(bridge, error, budget, cancel).await,
    }
}

pub async fn search(
    bridge: Arc<RemoteBridge>,
    result: Result<SearchResult, BridgeError>,
    budget: WireBudget,
    cancel: CancellationToken,
) -> CallToolResult {
    match result {
        Ok(result) => {
            let text = search_text(&result);
            let truncated = result.truncated;
            let provenance = RetentionProvenance::Remote(result.context.clone());
            render_text_retained(
                bridge,
                text,
                json!({}),
                result,
                provenance,
                None,
                truncated,
                budget,
                cancel,
            )
            .await
        }
        Err(error) => render_error_retained(bridge, error, budget, cancel).await,
    }
}

pub async fn read(
    bridge: Arc<RemoteBridge>,
    result: Result<ReadResult, BridgeError>,
    budget: WireBudget,
    cancel: CancellationToken,
) -> CallToolResult {
    match result {
        Ok(result) => {
            let truncated = result.files.iter().any(|entry| {
                matches!(
                    entry,
                    ReadEntry::Success {
                        truncated: true,
                        ..
                    }
                )
            });
            let text = read_text(&result);
            let provenance = RetentionProvenance::Remote(result.context.clone());
            render_text_retained(
                bridge,
                text,
                json!({}),
                result,
                provenance,
                None,
                truncated,
                budget,
                cancel,
            )
            .await
        }
        Err(error) => render_error_retained(bridge, error, budget, cancel).await,
    }
}

pub fn output_read(
    output_ref: &str,
    result: Result<OutputReadResult, BridgeError>,
    budget: WireBudget,
) -> CallToolResult {
    let result = match result {
        Ok(result) => result,
        Err(error) => return render_error(error, budget),
    };
    let raw = match result.data.encoding {
        ValueEncoding::Utf8 => result.data.value.into_bytes(),
        ValueEncoding::Base64 => {
            match base64::engine::general_purpose::STANDARD.decode(result.data.value.as_bytes()) {
                Ok(raw) => raw,
                Err(_) => {
                    return render_error(
                        BridgeError::new(
                            ErrorCode::ProtocolError,
                            "retained output encoding was invalid",
                            false,
                        ),
                        budget,
                    );
                }
            }
        }
    };
    let original_next = result.next_offset;
    let original_eof = result.eof;
    let mut inline = raw.len();
    loop {
        if result.data.encoding == ValueEncoding::Utf8 {
            while inline > 0 && std::str::from_utf8(&raw[..inline]).is_err() {
                inline -= 1;
            }
        }
        let next_offset = result.offset.saturating_add(inline as u64);
        let eof = original_eof && next_offset == original_next;
        let text = encoded_bytes_text(&raw[..inline], result.data.encoding);
        let mut metadata = json!({"next_offset":next_offset, "eof":eof});
        if next_offset != original_next {
            metadata["truncated"] = Value::Bool(true);
            metadata["output_ref"] = Value::String(output_ref.to_owned());
        }
        if let Some(rendered) = complete_text_result(text, metadata, budget) {
            return rendered;
        }
        if inline == 0 {
            return bounded_text_result(
                String::new(),
                json!({
                    "next_offset":result.offset,
                    "eof":original_eof && result.offset == original_next,
                    "truncated":result.offset != original_next,
                    "output_ref":output_ref,
                }),
                false,
                budget,
            );
        }
        inline /= 2;
    }
}

pub async fn write(
    bridge: Arc<RemoteBridge>,
    result: Result<WriteResult, BridgeError>,
    budget: WireBudget,
    cancel: CancellationToken,
) -> CallToolResult {
    match result {
        Ok(result) => {
            let text = format!("Wrote {}", encoded_value_text(&result.actual_path));
            let provenance = RetentionProvenance::Remote(result.context.clone());
            render_text_retained(
                bridge,
                text,
                json!({}),
                result,
                provenance,
                None,
                false,
                budget,
                cancel,
            )
            .await
        }
        Err(error) => render_error_retained(bridge, error, budget, cancel).await,
    }
}

pub async fn apply_patch(
    bridge: Arc<RemoteBridge>,
    result: Result<ApplyPatchResult, BridgeError>,
    budget: WireBudget,
    cancel: CancellationToken,
) -> CallToolResult {
    match result {
        Ok(result) => {
            let provenance = RetentionProvenance::Remote(result.context.clone());
            render_text_retained(
                bridge,
                "Done!".to_owned(),
                json!({}),
                result,
                provenance,
                None,
                false,
                budget,
                cancel,
            )
            .await
        }
        Err(error) => render_error_retained(bridge, error, budget, cancel).await,
    }
}

pub async fn run(
    bridge: Arc<RemoteBridge>,
    result: Result<RemoteRunResult, BridgeError>,
    budget: WireBudget,
    cancel: CancellationToken,
) -> CallToolResult {
    match result {
        Ok(mut result) => {
            if result.context.shell.kind == ShellName::Sh
                && !result
                    .warnings
                    .iter()
                    .any(|warning| warning.contains("POSIX sh"))
            {
                result
                    .warnings
                    .push(crate::remote::POSIX_SH_WARNING.to_owned());
            }
            normalize_warnings(&mut result.warnings);
            let text = run_text(&result);
            let mut metadata = json!({"exit_code":result.exit_status});
            if result.remote_process_may_continue {
                metadata["remote_process_may_continue"] = Value::Bool(true);
            }
            let source_truncated = result.stdout.truncated || result.stderr.truncated;
            let provenance = RetentionProvenance::Remote(result.context.clone());
            let existing_ref = result.output_ref.clone();
            render_text_retained(
                bridge,
                text,
                metadata,
                result,
                provenance,
                existing_ref,
                source_truncated,
                budget,
                cancel,
            )
            .await
        }
        Err(error) => render_error_retained(bridge, error, budget, cancel).await,
    }
}

async fn render_text_retained<T: Serialize + Send + 'static>(
    bridge: Arc<RemoteBridge>,
    text: String,
    structured_content: Value,
    retained_detail: T,
    provenance: RetentionProvenance,
    existing_ref: Option<String>,
    source_truncated: bool,
    budget: WireBudget,
    cancel: CancellationToken,
) -> CallToolResult {
    if !source_truncated
        && let Some(rendered) =
            complete_text_result(text.clone(), structured_content.clone(), budget)
    {
        return rendered;
    }

    let retained = match existing_ref {
        Some(output_ref) => Some(output_ref),
        None => bridge
            .retain_serialized_detail(provenance, retained_detail, cancel)
            .await
            .ok()
            .map(|reference| reference.as_str().to_owned()),
    };
    let mut metadata = object(structured_content);
    metadata.insert("truncated".to_owned(), Value::Bool(true));
    if let Some(output_ref) = retained {
        metadata.insert("output_ref".to_owned(), Value::String(output_ref));
    }
    bounded_text_result(text, Value::Object(metadata), false, budget)
}

fn complete_text_result(
    text: String,
    structured_content: Value,
    budget: WireBudget,
) -> Option<CallToolResult> {
    let maximum = model_budget(budget);
    let visible = text
        .len()
        .checked_add(serde_json::to_vec(&structured_content).ok()?.len())?;
    if visible > maximum {
        return None;
    }
    let result = CallToolResult {
        content: vec![TextContent::new(text)],
        structured_content,
        is_error: false,
    };
    serialized_at_most(&result, total_budget(budget)).then_some(result)
}

fn bounded_text_result(
    text: String,
    structured_content: Value,
    is_error: bool,
    budget: WireBudget,
) -> CallToolResult {
    let structured_bytes = serde_json::to_vec(&structured_content)
        .expect("MCP structured content is serializable")
        .len();
    let text_budget = model_budget(budget).saturating_sub(structured_bytes);
    let mut text = truncate_utf8(&text, text_budget);
    loop {
        let result = CallToolResult {
            content: vec![TextContent::new(text.clone())],
            structured_content: structured_content.clone(),
            is_error,
        };
        if serialized_at_most(&result, total_budget(budget)) {
            return result;
        }
        if text.is_empty() {
            return budgeted_compact_result(structured_content, is_error, budget);
        }
        text = truncate_utf8(&text, text.len() / 2);
    }
}

fn truncate_utf8(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let mut end = maximum;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn encoded_value_text(value: &EncodedValue) -> String {
    match value.encoding {
        ValueEncoding::Utf8 => value.value.clone(),
        ValueEncoding::Base64 => format!("base64:{}", value.value),
    }
}

fn encoded_bytes_text(bytes: &[u8], preferred: ValueEncoding) -> String {
    if preferred == ValueEncoding::Utf8
        && let Ok(value) = std::str::from_utf8(bytes)
    {
        return value.to_owned();
    }
    format!(
        "base64:{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )
}

fn remote_kind(kind: RemoteFileKind) -> &'static str {
    match kind {
        RemoteFileKind::File => "file",
        RemoteFileKind::Directory => "directory",
        RemoteFileKind::Symlink => "symlink",
        RemoteFileKind::BlockDevice => "block_device",
        RemoteFileKind::CharacterDevice => "character_device",
        RemoteFileKind::Fifo => "fifo",
        RemoteFileKind::Socket => "socket",
        RemoteFileKind::Other => "other",
    }
}

fn list_text(result: &ListResult) -> String {
    result
        .entries
        .iter()
        .map(|entry| {
            format!(
                "{}\t{}",
                remote_kind(entry.metadata.kind),
                encoded_value_text(&entry.actual_path)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn stat_text(result: &StatResult) -> String {
    result
        .entries
        .iter()
        .map(|entry| {
            let record = match entry {
                StatEntry::Success {
                    actual_path,
                    metadata,
                    ..
                } => json!({
                    "path":encoded_value_text(actual_path),
                    "kind":remote_kind(metadata.kind),
                    "size":metadata.size,
                    "mtime":format!("{}.{:09}", metadata.mtime_seconds, metadata.mtime_nanoseconds),
                    "mode":format!("{:04o}", metadata.mode),
                }),
                StatEntry::Error {
                    actual_path, error, ..
                } => json!({
                    "path":encoded_value_text(actual_path),
                    "error":{"code":error.code, "message":error.message},
                }),
            };
            serde_json::to_string(&record).expect("stat presentation is serializable")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn search_text(result: &SearchResult) -> String {
    result
        .matches
        .iter()
        .map(|matched| {
            format!(
                "{}:{}:{}",
                encoded_value_text(&matched.actual_path),
                matched.line,
                encoded_value_text(&matched.content)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn read_text(result: &ReadResult) -> String {
    let multiple = result.files.len() > 1;
    let mut rendered = Vec::with_capacity(result.files.len());
    for entry in &result.files {
        match entry {
            ReadEntry::Success {
                actual_path,
                content,
                ..
            } => {
                let body = encoded_value_text(content);
                if multiple {
                    rendered.push(format!(
                        "==> {} <==\n{}",
                        encoded_value_text(actual_path),
                        body
                    ));
                } else {
                    rendered.push(body);
                }
            }
            ReadEntry::Error {
                actual_path, error, ..
            } => rendered.push(format!(
                "==> {} <==\nERROR {}: {}",
                encoded_value_text(actual_path),
                serde_json::to_value(error.code)
                    .expect("entry error code is serializable")
                    .as_str()
                    .unwrap_or("UNKNOWN"),
                error.message
            )),
        }
    }
    rendered.join("\n")
}

fn output_preview_text(preview: &crate::remote::EncodedOutputPreview) -> String {
    let head = encoded_value_text(&preview.head);
    if !preview.truncated {
        return head;
    }
    let tail = encoded_value_text(&preview.tail);
    if tail.is_empty() || tail == head {
        format!("{head}\n...[truncated]...")
    } else {
        format!("{head}\n...[truncated]...\n{tail}")
    }
}

fn run_text(result: &RemoteRunResult) -> String {
    let mut sections = Vec::new();
    let stdout = output_preview_text(&result.stdout);
    let stderr = output_preview_text(&result.stderr);
    if !stdout.is_empty() {
        sections.push(format!("stdout:\n{stdout}"));
    }
    if !stderr.is_empty() {
        sections.push(format!("stderr:\n{stderr}"));
    }
    for warning in &result.warnings {
        sections.push(format!("warning:\n{warning}"));
    }
    sections.join("\n")
}

fn compact_result(structured_content: Value, is_error: bool) -> CallToolResult {
    let text = serde_json::to_string(&structured_content)
        .expect("compact MCP presentation metadata is serializable");
    CallToolResult {
        content: vec![TextContent::new(text)],
        structured_content,
        is_error,
    }
}

fn budgeted_compact_result(
    structured_content: Value,
    is_error: bool,
    budget: WireBudget,
) -> CallToolResult {
    let result = compact_result(structured_content, is_error);
    debug_assert!(
        serialized_at_most(&result, budget.compact_fallback_bytes),
        "compact MCP result exceeded its reserved fallback budget"
    );
    result
}

fn render_error(error: BridgeError, budget: WireBudget) -> CallToolResult {
    render_error_borrowed(&error, budget)
}

fn render_error_borrowed(error: &BridgeError, budget: WireBudget) -> CallToolResult {
    full_error_result(error, true, budget).unwrap_or_else(|| {
        bounded_text_result(
            error_text(error),
            error_structured(error, false),
            true,
            budget,
        )
    })
}

fn error_text(error: &BridgeError) -> String {
    let code = serde_json::to_value(error.code)
        .expect("error code is serializable")
        .as_str()
        .unwrap_or("ERROR")
        .to_owned();
    let (message, _) = safe_text(&error.message, SAFE_TEXT_BYTES);
    format!("{code}: {message}")
}

fn error_structured(error: &BridgeError, include_progress: bool) -> Value {
    let details = &error.details;
    let (message, _) = safe_text(&error.message, SAFE_TEXT_BYTES);
    let mut structured = object(json!({
        "error":{"code":error.code, "message":message},
    }));
    if let Some(path) = details
        .failed_path
        .as_deref()
        .or(details.path.as_deref())
        .map(normalize_controls)
    {
        structured.insert("path".to_owned(), Value::String(path));
    }
    if details.mutation_may_have_applied == Some(true) {
        structured.insert("mutation_may_have_applied".to_owned(), Value::Bool(true));
    }
    if details.remote_process_may_continue == Some(true) {
        structured.insert("remote_process_may_continue".to_owned(), Value::Bool(true));
    }
    if let Some(requested) = details.requested_shell.as_deref() {
        structured.insert(
            "requested_shell".to_owned(),
            Value::String(normalize_controls(requested)),
        );
    }
    if let Some(available) = details.available_shells.as_ref() {
        structured.insert(
            "available_shells".to_owned(),
            Value::Array(
                available
                    .iter()
                    .map(|shell| Value::String(normalize_controls(shell)))
                    .collect(),
            ),
        );
    }
    if include_progress {
        for (key, paths) in [
            ("changed_paths", details.changed_paths.as_ref()),
            ("not_changed_paths", details.not_changed_paths.as_ref()),
            (
                "outcome_unknown_paths",
                details.outcome_unknown_paths.as_ref(),
            ),
        ] {
            if let Some(paths) = paths {
                structured.insert(
                    key.to_owned(),
                    Value::Array(
                        paths
                            .iter()
                            .map(|path| Value::String(normalize_controls(path)))
                            .collect(),
                    ),
                );
            }
        }
    }
    Value::Object(structured)
}

fn full_error_result(
    error: &BridgeError,
    include_progress: bool,
    budget: WireBudget,
) -> Option<CallToolResult> {
    let text = error_text(error);
    let structured_content = error_structured(error, include_progress);
    let visible = text
        .len()
        .checked_add(serde_json::to_vec(&structured_content).ok()?.len())?;
    if visible > model_budget(budget) {
        return None;
    }
    let result = CallToolResult {
        content: vec![TextContent::new(text)],
        structured_content,
        is_error: true,
    };
    serialized_at_most(&result, total_budget(budget)).then_some(result)
}

async fn render_error_retained(
    bridge: Arc<RemoteBridge>,
    mut error: BridgeError,
    budget: WireBudget,
    cancel: CancellationToken,
) -> CallToolResult {
    normalize_progress_controls(&mut error.details);
    if let Some(result) = full_error_result(&error, true, budget) {
        return result;
    }
    let changed_paths = error.details.changed_paths.take();
    let not_changed_paths = error.details.not_changed_paths.take();
    let outcome_unknown_paths = error.details.outcome_unknown_paths.take();
    let has_progress =
        changed_paths.is_some() || not_changed_paths.is_some() || outcome_unknown_paths.is_some();
    if !has_progress {
        return render_error(error, budget);
    }
    let provenance = error_retention_provenance(&error.details);
    let detail = RetainedMutationErrorDetail {
        code: error.code,
        mutation_may_have_applied: error.details.mutation_may_have_applied,
        failed_path: error.details.failed_path.as_deref().map(normalize_controls),
        changed_paths,
        not_changed_paths,
        outcome_unknown_paths,
    };
    let retained = match provenance {
        Some(provenance) => bridge
            .retain_serialized_detail(provenance, detail, cancel)
            .await
            .ok()
            .map(|reference| reference.as_str().to_owned()),
        None => None,
    };
    let mut structured = object(error_structured(&error, false));
    structured.insert("truncated".to_owned(), Value::Bool(true));
    if let Some(output_ref) = retained {
        structured.insert("output_ref".to_owned(), Value::String(output_ref));
    }
    bounded_text_result(error_text(&error), Value::Object(structured), true, budget)
}

fn normalize_progress_controls(details: &mut ErrorDetails) {
    for paths in [
        &mut details.changed_paths,
        &mut details.not_changed_paths,
        &mut details.outcome_unknown_paths,
    ]
    .into_iter()
    .flatten()
    {
        for path in paths {
            if path.chars().any(char::is_control) {
                *path = normalize_controls(path);
            }
        }
    }
}

fn error_retention_provenance(details: &ErrorDetails) -> Option<RetentionProvenance> {
    let host = details.host.clone()?;
    let physical_root = details.physical_root.clone()?;
    let shell = details.shell.as_ref()?;
    let kind = match shell.kind.as_str() {
        "bash" => ShellName::Bash,
        "sh" => ShellName::Sh,
        "login" => ShellName::Login,
        _ => return None,
    };
    Some(RetentionProvenance::Remote(RemoteContext {
        remote: true,
        host,
        physical_root,
        shell: ShellMetadata {
            kind,
            version: shell.version.clone(),
            fallback: shell.fallback,
        },
        helper_mode: None,
    }))
}

fn normalize_controls(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '?'
            } else {
                character
            }
        })
        .collect()
}

fn safe_text(value: &str, maximum: usize) -> (String, bool) {
    let mut safe = String::with_capacity(value.len().min(maximum));
    let mut truncated = false;
    for character in value.chars() {
        let character = if character.is_control() {
            '?'
        } else {
            character
        };
        if safe.len() + character.len_utf8() > maximum {
            truncated = true;
            break;
        }
        safe.push(character);
    }
    (safe, truncated)
}

fn normalize_warnings(warnings: &mut Vec<String>) -> bool {
    let mut truncated = warnings.len() > MAX_WARNINGS;
    warnings.truncate(MAX_WARNINGS);
    for warning in warnings {
        let (safe, shortened) = safe_text(warning, SAFE_TEXT_BYTES);
        *warning = safe;
        truncated |= shortened;
    }
    truncated
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(object) => object,
        _ => Map::new(),
    }
}

fn total_budget(budget: WireBudget) -> usize {
    budget
        .result_bytes
        .saturating_add(budget.compact_fallback_bytes)
}

fn model_budget(budget: WireBudget) -> usize {
    MODEL_INLINE_RESULT_BYTES.min(total_budget(budget))
}

fn serialized_at_most<T: Serialize>(value: &T, maximum: usize) -> bool {
    let mut writer = CountingWriter { count: 0, maximum };
    serde_json::to_writer(&mut writer, value).is_ok()
}

struct CountingWriter {
    count: usize,
    maximum: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.count = self
            .count
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("MCP presentation size overflow"))?;
        if self.count > self.maximum {
            return Err(io::Error::other("MCP presentation exceeds its wire budget"));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Serialize)]
struct RetainedMutationErrorDetail {
    code: ErrorCode,
    mutation_may_have_applied: Option<bool>,
    failed_path: Option<String>,
    changed_paths: Option<Vec<String>>,
    not_changed_paths: Option<Vec<String>>,
    outcome_unknown_paths: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use base64::Engine as _;
    use serde_json::json;

    use super::*;
    use crate::config::{Config, HostLimitOverrides, HostProfile};
    use crate::output::{OutputStore, StreamKind};
    use crate::remote::{
        EncodedOutputPreview, HostInfo, ListEntry, ReadEntry, RemoteFileKind, RemoteMetadata,
        SearchEngine, SearchMatch, StatEntry,
    };
    use crate::ssh::{RuntimePaths, SshRunner};

    fn result_value(result: CallToolResult) -> Value {
        serde_json::to_value(result).unwrap()
    }

    fn text_value(result: &Value) -> &str {
        result["content"][0]["text"].as_str().unwrap()
    }

    fn roomy_budget() -> WireBudget {
        WireBudget {
            result_bytes: 2 * 1024 * 1024,
            compact_fallback_bytes: maximum_compact_fallback_result_bytes(),
        }
    }

    fn compact_budget() -> WireBudget {
        WireBudget {
            result_bytes: 0,
            compact_fallback_bytes: 8 * 1024,
        }
    }

    #[test]
    fn model_visible_budget_accepts_exact_fit_and_rejects_one_byte_over() {
        let structured = json!({});
        let metadata_bytes = serde_json::to_vec(&structured).unwrap().len();
        let exact = "x".repeat(MODEL_INLINE_RESULT_BYTES - metadata_bytes);
        assert!(
            complete_text_result(exact, structured.clone(), roomy_budget()).is_some(),
            "an exact 32 KiB model-visible result must fit"
        );
        let over = "x".repeat(MODEL_INLINE_RESULT_BYTES - metadata_bytes + 1);
        assert!(
            complete_text_result(over, structured, roomy_budget()).is_none(),
            "one byte over the model-visible limit must be retained"
        );
    }

    fn bridge_fixture() -> (tempfile::TempDir, Arc<RemoteBridge>) {
        let runtime_base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
        let store = Arc::new(OutputStore::new(&runtime).unwrap());
        let config = Arc::new(Config {
            hosts: BTreeMap::from([(
                "dev".to_owned(),
                HostProfile {
                    root: "/srv/root".to_owned(),
                    description: None,
                    read_only: false,
                    limits: HostLimitOverrides::default(),
                },
            )]),
            ..Config::default()
        });
        let runner = Arc::new(SshRunner::new(config, runtime, store).unwrap());
        (runtime_base, Arc::new(RemoteBridge::new(runner)))
    }

    fn context() -> RemoteContext {
        RemoteContext {
            remote: true,
            host: "dev".to_owned(),
            physical_root: "/srv/root".to_owned(),
            shell: ShellMetadata {
                kind: ShellName::Sh,
                version: None,
                fallback: false,
            },
            helper_mode: None,
        }
    }

    fn encoded(value: impl Into<String>) -> EncodedValue {
        EncodedValue {
            encoding: ValueEncoding::Utf8,
            value: value.into(),
        }
    }

    fn metadata() -> RemoteMetadata {
        RemoteMetadata {
            kind: RemoteFileKind::File,
            size: 1,
            mode: 0o640,
            mtime_seconds: 1,
            mtime_nanoseconds: 2,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn helper_mode_is_omitted_from_remote_run_metadata() {
        let (_runtime, bridge) = bridge_fixture();
        let mut remote_context = context();
        remote_context.helper_mode = Some(crate::ssh::HelperMode::Persistent);
        let rendered = result_value(
            run(
                bridge,
                Ok(RemoteRunResult {
                    context: remote_context,
                    exit_status: 0,
                    elapsed_ms: 1,
                    stdout: EncodedOutputPreview {
                        head: encoded("ok"),
                        tail: encoded("ok"),
                        raw_bytes: 2,
                        truncated: false,
                    },
                    stderr: EncodedOutputPreview {
                        head: encoded(""),
                        tail: encoded(""),
                        raw_bytes: 0,
                        truncated: false,
                    },
                    aggregate_bytes: 2,
                    output_ref: None,
                    remote_process_may_continue: false,
                    warnings: Vec::new(),
                }),
                roomy_budget(),
                CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(rendered["structuredContent"], json!({"exit_code":0}));
        assert_eq!(
            text_value(&rendered),
            "stdout:\nok\nwarning:\nselected POSIX sh does not support Bash arrays, [[ ]], source, pipefail, or Bash substitutions; use POSIX syntax, or request Bash and ensure it is installed"
        );
        assert!(!rendered.to_string().contains("persistent"));
    }

    #[test]
    fn task8_error_rendering_roomy_text_preserves_exact_progress_partitions() {
        let mut error = BridgeError::new(ErrorCode::WriteConflict, "patch failed", false);
        error.details.changed_paths = Some(vec!["a".to_owned()]);
        error.details.not_changed_paths = Some(vec!["b".to_owned(), "c".to_owned()]);
        error.details.outcome_unknown_paths = Some(vec!["d".to_owned()]);
        error.details.mutation_may_have_applied = Some(true);
        let rendered = result_value(
            full_error_result(&error, true, roomy_budget())
                .expect("roomy error must render inline"),
        );
        assert_eq!(rendered["structuredContent"]["changed_paths"], json!(["a"]));
        assert_eq!(
            rendered["structuredContent"]["not_changed_paths"],
            json!(["b", "c"])
        );
        assert_eq!(
            rendered["structuredContent"]["outcome_unknown_paths"],
            json!(["d"])
        );
        assert_eq!(
            rendered["structuredContent"]["mutation_may_have_applied"],
            true
        );
    }

    #[test]
    fn task8_error_rendering_normalizes_context_and_progress_controls() {
        let mut error = BridgeError::new(ErrorCode::WriteConflict, "patch failed", false);
        error.details.host = Some("dev".to_owned());
        error.details.physical_root = Some("/srv/\troot\n".to_owned());
        error.details.changed_paths = Some(vec!["changed\tpath".to_owned()]);
        error.details.not_changed_paths = Some(vec!["not\nchanged".to_owned()]);
        error.details.outcome_unknown_paths = Some(vec!["unknown\rpath".to_owned()]);

        normalize_progress_controls(&mut error.details);
        let rendered = result_value(
            full_error_result(&error, true, roomy_budget())
                .expect("roomy error must render inline"),
        );
        assert_eq!(
            rendered["structuredContent"]["changed_paths"],
            json!(["changed?path"])
        );
        assert_eq!(
            rendered["structuredContent"]["not_changed_paths"],
            json!(["not?changed"])
        );
        assert_eq!(
            rendered["structuredContent"]["outcome_unknown_paths"],
            json!(["unknown?path"])
        );
        assert!(rendered["structuredContent"].get("physical_root").is_none());
        assert!(rendered["structuredContent"].get("host").is_none());
    }

    #[test]
    fn task8_error_output_contains_facts_without_actions() {
        let mut error = BridgeError::new(ErrorCode::RemoteCapabilityMissing, "no bash", false);
        error.details.requested_shell = Some("bash".to_owned());
        error.details.available_shells = Some(vec!["sh".to_owned()]);
        let rendered = result_value(render_error(error, roomy_budget()));
        assert_eq!(rendered["structuredContent"]["requested_shell"], "bash");
        assert_eq!(
            rendered["structuredContent"]["available_shells"],
            json!(["sh"])
        );
        assert!(!rendered.to_string().contains("action"));
    }

    #[test]
    fn task8_error_rendering_normalizes_controls_without_damaging_json_characters() {
        let mut error = BridgeError::new(
            ErrorCode::RemoteExit,
            "bad\0line\nquote=\" slash=\\ snow=雪",
            false,
        );
        error.details.host = Some("dev".to_owned());
        error.details.physical_root = Some("/srv/root".to_owned());
        let rendered = result_value(render_error(error, roomy_budget()));
        let message = rendered["structuredContent"]["error"]["message"]
            .as_str()
            .unwrap();
        assert_eq!(message, "bad?line?quote=\" slash=\\ snow=雪");
        assert!(rendered["structuredContent"].get("shell").is_none());
        assert_eq!(
            text_value(&rendered),
            "REMOTE_EXIT: bad?line?quote=\" slash=\\ snow=雪"
        );
    }

    #[test]
    fn task8_single_copy_output_read_shrinks_utf8_on_raw_boundaries() {
        let original = "雪\"".repeat(8_192);
        let offset = 17_u64;
        let rendered = result_value(output_read(
            "0123456789abcdef0123456789abcdef",
            Ok(OutputReadResult {
                provenance: RetentionProvenance::Aggregate {
                    kind: AggregateKind::Hosts,
                    source_count: 9,
                },
                stream: StreamKind::Stdout,
                offset,
                next_offset: offset + original.len() as u64,
                eof: true,
                data: EncodedValue {
                    encoding: ValueEncoding::Utf8,
                    value: original,
                },
            }),
            WireBudget {
                result_bytes: 0,
                compact_fallback_bytes: 4 * 1024,
            },
        ));
        let inline = text_value(&rendered).len() as u64;
        assert!(inline > 0);
        assert_eq!(
            rendered["structuredContent"]["next_offset"],
            offset + inline
        );
        assert_eq!(rendered["structuredContent"]["eof"], false);
        assert_eq!(rendered["structuredContent"]["truncated"], true);
        assert!(rendered["structuredContent"].get("aggregate").is_none());
    }

    #[test]
    fn task8_single_copy_output_read_shrinks_base64_using_decoded_byte_offsets() {
        let original = (0_u8..=255).cycle().take(32 * 1024).collect::<Vec<_>>();
        let offset = 123_u64;
        let rendered = result_value(output_read(
            "0123456789abcdef0123456789abcdef",
            Ok(OutputReadResult {
                provenance: RetentionProvenance::Aggregate {
                    kind: AggregateKind::Hosts,
                    source_count: 9,
                },
                stream: StreamKind::Stdout,
                offset,
                next_offset: offset + original.len() as u64,
                eof: true,
                data: EncodedValue {
                    encoding: ValueEncoding::Base64,
                    value: base64::engine::general_purpose::STANDARD.encode(&original),
                },
            }),
            WireBudget {
                result_bytes: 0,
                compact_fallback_bytes: 4 * 1024,
            },
        ));
        let text = text_value(&rendered)
            .strip_prefix("base64:")
            .expect("binary output is explicitly marked");
        let inline = base64::engine::general_purpose::STANDARD
            .decode(text)
            .unwrap();
        assert!(!inline.is_empty());
        assert_eq!(
            rendered["structuredContent"]["next_offset"],
            offset + inline.len() as u64
        );
        assert_eq!(rendered["structuredContent"]["eof"], false);
    }

    #[tokio::test]
    async fn task8_retention_all_bulk_compact_fallbacks_preserve_truth_on_admission_failure() {
        let (_runtime, bridge) = bridge_fixture();
        let bulk = "BULK_SENTINEL".repeat(2_048);

        let hosts_result = result_value(
            hosts(
                Arc::clone(&bridge),
                Ok(HostsResult {
                    hosts: vec![HostInfo {
                        remote: true,
                        host: "dev".to_owned(),
                        configured_root: "/srv/root".to_owned(),
                        description: Some(bulk.clone()),
                        read_only: false,
                        physical_root: None,
                        shell: None,
                    }],
                }),
                compact_budget(),
                CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(hosts_result["structuredContent"], json!({}));
        assert_eq!(text_value(&hosts_result), "dev");

        let list_result = result_value(
            list(
                Arc::clone(&bridge),
                Ok(ListResult {
                    context: context(),
                    actual_path: encoded("/srv/root"),
                    relative_path: encoded("."),
                    entries: vec![ListEntry {
                        actual_path: encoded(bulk.clone()),
                        relative_path: encoded("large"),
                        metadata: metadata(),
                    }],
                    truncated: false,
                }),
                compact_budget(),
                CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(list_result["structuredContent"]["truncated"], true);
        assert!(list_result["structuredContent"]["output_ref"].is_string());

        let stat_result = result_value(
            stat(
                Arc::clone(&bridge),
                Ok(StatResult {
                    context: context(),
                    entries: vec![StatEntry::Success {
                        actual_path: encoded(bulk.clone()),
                        relative_path: encoded("large"),
                        metadata: metadata(),
                    }],
                }),
                compact_budget(),
                CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(stat_result["structuredContent"]["truncated"], true);
        assert!(stat_result["structuredContent"]["output_ref"].is_string());

        let search_result = result_value(
            search(
                Arc::clone(&bridge),
                Ok(SearchResult {
                    context: context(),
                    engine: SearchEngine::Rg,
                    matches: vec![SearchMatch {
                        actual_path: encoded("/srv/root/large"),
                        relative_path: encoded("large"),
                        line: 1,
                        column: 1,
                        content: encoded(bulk.clone()),
                    }],
                    truncated: false,
                }),
                compact_budget(),
                CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(search_result["structuredContent"]["truncated"], true);
        assert!(search_result["structuredContent"]["output_ref"].is_string());

        let read_result = result_value(
            read(
                Arc::clone(&bridge),
                Ok(ReadResult {
                    context: context(),
                    files: vec![ReadEntry::Success {
                        actual_path: encoded("/srv/root/large"),
                        relative_path: encoded("large"),
                        content: encoded(bulk.clone()),
                        raw_bytes: bulk.len() as u64,
                        sha256: "0".repeat(64),
                        truncated_before: false,
                        truncated_after: true,
                        truncated: true,
                    }],
                    returned_raw_bytes: bulk.len() as u64,
                }),
                compact_budget(),
                CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(read_result["structuredContent"]["truncated"], true);
        assert!(read_result["structuredContent"]["output_ref"].is_string());

        let run_result = result_value(
            run(
                Arc::clone(&bridge),
                Ok(RemoteRunResult {
                    context: context(),
                    exit_status: 0,
                    elapsed_ms: 1,
                    stdout: EncodedOutputPreview {
                        head: encoded(bulk.clone()),
                        tail: encoded("tail"),
                        raw_bytes: bulk.len() as u64,
                        truncated: true,
                    },
                    stderr: EncodedOutputPreview {
                        head: encoded(""),
                        tail: encoded(""),
                        raw_bytes: 0,
                        truncated: false,
                    },
                    aggregate_bytes: bulk.len() as u64,
                    output_ref: None,
                    remote_process_may_continue: false,
                    warnings: Vec::new(),
                }),
                compact_budget(),
                CancellationToken::new(),
            )
            .await,
        );
        assert_eq!(run_result["structuredContent"]["exit_code"], 0);
        assert_eq!(run_result["structuredContent"]["truncated"], true);
        assert!(run_result["structuredContent"]["output_ref"].is_string());
    }
}
