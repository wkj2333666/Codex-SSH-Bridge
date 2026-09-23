use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::error::BridgeResult;
use crate::output::{InternalSpoolOwner, StreamKind};
use crate::ssh::{FixedOperationKind, FixedRunRequest, RootedPathInputs};

use super::edit_cache::{CacheKey, DesiredState, RemoteBase, RemoteSnapshot};
use super::protocol::{
    context, encode_bytes, entry_error, nul_fields, parse_u64, protocol_error, read_small_stream,
    utf8,
};
use super::{
    EntryError, EntryErrorCode, ReadEntry, ReadResult, RemoteBridge, ResolvedRead,
    attach_fixed_result_context, attach_optional_remote_context,
};

const READ_SCRIPT: &str = r#"
path=$1
start=$2
lines=$3
budget=$4
if [ ! -e "$path" ]; then
    parent=${path%/*};[ -n "$parent" ]||parent=/
    while [ "$parent" != . ]&&[ ! -d "$parent" ];do parent=${parent%/*};[ -n "$parent" ]||parent=.;done
    if [ -d "$parent" ]&&[ ! -x "$parent" ];then printf 'PERMISSION_DENIED\000' >&2;else printf 'NOT_FOUND\000' >&2;fi
    exit 0
fi
if [ ! -r "$path" ]; then printf 'PERMISSION_DENIED\000' >&2; exit 0; fi
if [ ! -f "$path" ]; then printf 'INVALID_ARGUMENT\000' >&2; exit 0; fi
size=$(stat --printf='%s' -- "$path" 2>/dev/null) || { printf 'PERMISSION_DENIED\000' >&2; exit 0; }
mode=$(stat --printf='%a' -- "$path" 2>/dev/null) || { printf 'PERMISSION_DENIED\000' >&2; exit 0; }
count=$(wc -l < "$path") || { printf 'PERMISSION_DENIED\000' >&2; exit 0; }
if [ "$size" -gt 0 ]; then
    final_lf=$(tail -c 1 -- "$path" | wc -l)
    if [ "$final_lf" -eq 0 ]; then count=$((count + 1)); fi
fi
look=$((budget + 1))
tail -n "+$start" -- "$path" 2>/dev/null | head -n "$lines" | head -c "$look"
hash=$(sha256sum -- "$path" 2>/dev/null) || { printf 'PERMISSION_DENIED\000' >&2; exit 0; }
set -- $hash
hash=$1
printf 'OK\000%s\000%s\000%s\000%s\000' "$size" "$count" "$hash" "$mode" >&2
"#;

pub(super) async fn read(
    bridge: &RemoteBridge,
    request: ResolvedRead,
    cancel: CancellationToken,
) -> BridgeResult<ReadResult> {
    let runner = &bridge.runner;
    let limits = runner.config().limits();
    let mut remaining = request.max_bytes;
    let mut files = Vec::with_capacity(request.paths.len());
    let mut returned_raw_bytes = 0u64;
    let mut operation_context = None;
    for path in request.paths {
        if cancel.is_cancelled() {
            return Err(read_cancelled_error(operation_context.as_ref()));
        }
        let cache_key = CacheKey {
            host: request.host.clone(),
            path: path.as_str().to_owned(),
        };
        if bridge.edit_buffering_enabled
            && let Some((desired, desired_sha256)) = bridge
                .edit_cache
                .lookup_complete_with_hash(&cache_key)
                .await
        {
            if operation_context.is_none() {
                operation_context = bridge.edit_backend.context_for(&request.host).await;
            }
            let (entry, raw_bytes) = cached_read_entry(
                &path,
                &desired,
                desired_sha256.as_deref(),
                request.start_line,
                request.max_lines,
                remaining,
            );
            remaining = remaining.saturating_sub(raw_bytes);
            returned_raw_bytes = returned_raw_bytes
                .checked_add(raw_bytes as u64)
                .ok_or_else(|| protocol_error("read byte count overflowed"))
                .map_err(|error| {
                    attach_optional_remote_context(error, operation_context.as_ref())
                })?;
            files.push(entry);
            continue;
        }
        let owner = InternalSpoolOwner::new();
        let stdout_limit = (remaining as u64)
            .checked_add(1)
            .ok_or_else(|| protocol_error("read byte limit overflowed"))
            .map_err(|error| attach_optional_remote_context(error, operation_context.as_ref()))?;
        let result = bridge
            .execute_readonly_fixed(
                FixedRunRequest {
                    kind: FixedOperationKind::ReadOnly,
                    host: request.host.clone(),
                    script: READ_SCRIPT,
                    args: vec![
                        path.as_str().to_owned(),
                        request.start_line.to_string(),
                        request.max_lines.to_string(),
                        remaining.to_string(),
                    ],
                    stdin: None,
                    rooted_paths: RootedPathInputs {
                        argument_indices: &[0],
                        argument_stride: None,
                        stdin_nul_paths: false,
                    },
                    required_capabilities: &["read_slice", "stat_printf", "sha256sum"],
                    stdout_limit,
                    stderr_limit: 1024,
                    timeout: Duration::from_millis(limits.command_timeout_ms),
                    cleanup: owner.registration(),
                },
                cancel.clone(),
            )
            .await
            .map_err(|error| attach_optional_remote_context(error, operation_context.as_ref()))?;
        if operation_context.is_none() {
            operation_context = Some(context(
                request.host.clone(),
                result.capability.physical_root.clone(),
                &result.shell,
                result.helper_mode,
            ));
        }
        bridge
            .edit_backend
            .remember_context(&request.host, &result)
            .await;
        let attach = |error| attach_fixed_result_context(error, &request.host, &result);
        let stderr = read_small_stream(&result.output, StreamKind::Stderr, 1024)
            .await
            .map_err(&attach)?;
        let fields = nul_fields(&stderr).map_err(&attach)?;
        let actual_path = encode_bytes(path.as_str().as_bytes());
        let relative_path = encode_bytes(path.relative().as_bytes());
        if fields.first() != Some(&b"OK".as_slice()) {
            if fields.len() != 1 {
                return Err(attach(protocol_error("read error record is invalid")));
            }
            files.push(ReadEntry::Error {
                actual_path,
                relative_path,
                error: entry_error(
                    fields
                        .first()
                        .ok_or_else(|| protocol_error("read metadata is missing"))
                        .map_err(&attach)?,
                )
                .map_err(&attach)?,
            });
            continue;
        }
        if fields.len() != 5 {
            return Err(attach(protocol_error(
                "read metadata field count is invalid",
            )));
        }
        let size = parse_u64(fields[1]).map_err(&attach)?;
        let total_lines = parse_u64(fields[2]).map_err(&attach)?;
        let remote_sha256 = utf8(fields[3]).map_err(&attach)?;
        let mode = utf8(fields[4]).map_err(&attach)?;
        if !valid_hash(remote_sha256) {
            return Err(attach(protocol_error("read hash is invalid")));
        }
        if mode.is_empty()
            || mode.len() > 4
            || !mode.bytes().all(|byte| (b'0'..=b'7').contains(&byte))
        {
            return Err(attach(protocol_error("read mode is invalid")));
        }
        let mode = u32::from_str_radix(mode, 8)
            .map_err(|_| attach(protocol_error("read mode is invalid")))?;
        let stdout = read_small_stream(
            &result.output,
            StreamKind::Stdout,
            remaining.saturating_add(1),
        )
        .await
        .map_err(&attach)?;
        let byte_truncated = stdout.len() > remaining;
        let retained = &stdout[..stdout.len().min(remaining)];
        let truncated_before = request.start_line > 1 && size != 0;
        let line_end = request
            .start_line
            .saturating_sub(1)
            .saturating_add(request.max_lines);
        let truncated_after = byte_truncated || line_end < total_lines;
        let truncated = truncated_before || truncated_after;
        let sha256 = if !truncated {
            let sha256 = format!("{:x}", Sha256::digest(retained));
            if sha256 != remote_sha256 {
                files.push(ReadEntry::Error {
                    actual_path,
                    relative_path,
                    error: EntryError {
                        code: EntryErrorCode::ReadConflict,
                        message: "remote file changed while being read",
                    },
                });
                continue;
            }
            sha256
        } else {
            remote_sha256.to_owned()
        };
        if bridge.edit_buffering_enabled && !truncated {
            bridge
                .edit_cache
                .cache_clean_if_absent(
                    cache_key,
                    RemoteSnapshot {
                        base: RemoteBase::Regular {
                            sha256: sha256.clone(),
                            mode,
                        },
                        desired: DesiredState::Present(std::sync::Arc::from(retained)),
                    },
                )
                .await;
        }
        remaining -= retained.len();
        returned_raw_bytes = returned_raw_bytes
            .checked_add(retained.len() as u64)
            .ok_or_else(|| protocol_error("read byte count overflowed"))
            .map_err(&attach)?;
        files.push(ReadEntry::Success {
            actual_path,
            relative_path,
            content: encode_bytes(retained),
            raw_bytes: retained.len() as u64,
            sha256,
            truncated_before,
            truncated_after,
            truncated,
        });
    }
    let context =
        operation_context.ok_or_else(|| protocol_error("read operation produced no context"))?;
    Ok(ReadResult {
        context,
        files,
        returned_raw_bytes,
    })
}

fn cached_read_entry(
    path: &crate::path::RemotePath,
    desired: &DesiredState,
    desired_sha256: Option<&str>,
    start_line: u64,
    max_lines: u64,
    maximum_bytes: usize,
) -> (ReadEntry, usize) {
    let actual_path = encode_bytes(path.as_str().as_bytes());
    let relative_path = encode_bytes(path.relative().as_bytes());
    let DesiredState::Present(bytes) = desired else {
        return (
            ReadEntry::Error {
                actual_path,
                relative_path,
                error: EntryError {
                    code: EntryErrorCode::NotFound,
                    message: "remote path was not found",
                },
            },
            0,
        );
    };
    let sha256 = desired_sha256.expect("cached content is missing its precomputed hash");
    let total_lines = logical_line_count(bytes);
    let start = logical_line_offset(bytes, start_line.saturating_sub(1));
    let end = logical_line_offset_from(bytes, start, max_lines);
    let selected = &bytes[start..end];
    let byte_truncated = selected.len() > maximum_bytes;
    let retained = &selected[..selected.len().min(maximum_bytes)];
    let truncated_before = start_line > 1 && !bytes.is_empty();
    let line_end = start_line.saturating_sub(1).saturating_add(max_lines);
    let truncated_after = byte_truncated || line_end < total_lines;
    let truncated = truncated_before || truncated_after;
    (
        ReadEntry::Success {
            actual_path,
            relative_path,
            content: encode_bytes(retained),
            raw_bytes: retained.len() as u64,
            sha256: sha256.to_owned(),
            truncated_before,
            truncated_after,
            truncated,
        },
        retained.len(),
    )
}

fn logical_line_count(bytes: &[u8]) -> u64 {
    let newlines = bytes.iter().filter(|byte| **byte == b'\n').count() as u64;
    newlines + u64::from(!bytes.is_empty() && bytes.last() != Some(&b'\n'))
}

fn logical_line_offset(bytes: &[u8], lines: u64) -> usize {
    logical_line_offset_from(bytes, 0, lines)
}

fn logical_line_offset_from(bytes: &[u8], start: usize, lines: u64) -> usize {
    let mut remaining = lines;
    for (offset, byte) in bytes[start..].iter().enumerate() {
        if remaining == 0 {
            return start + offset;
        }
        if *byte == b'\n' {
            remaining -= 1;
        }
    }
    bytes.len()
}

fn read_cancelled_error(operation_context: Option<&super::RemoteContext>) -> crate::BridgeError {
    let error = crate::error::BridgeError::new(
        crate::error::ErrorCode::Cancelled,
        "remote read was cancelled",
        false,
    );
    attach_optional_remote_context(error, operation_context)
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::super::edit_cache::DesiredState;
    use super::super::{ReadEntry, RemoteContext, ShellMetadata, ShellName, ValueEncoding};
    use crate::ErrorCode;

    #[test]
    fn task78_read_local_cancel_after_known_context_retains_remote_metadata() {
        let context = RemoteContext {
            remote: true,
            host: "dev".to_owned(),
            physical_root: "/srv/app".to_owned(),
            shell: ShellMetadata {
                kind: ShellName::Sh,
                version: None,
                fallback: false,
            },
            helper_mode: None,
        };
        let error = super::read_cancelled_error(Some(&context));
        assert_eq!(error.code, ErrorCode::Cancelled);
        assert_eq!(error.details.host.as_deref(), Some("dev"));
        assert_eq!(error.details.physical_root.as_deref(), Some("/srv/app"));
        assert_eq!(error.details.shell.unwrap().kind, "sh");
    }

    #[test]
    fn task78_read_next_step_error_uses_known_context_without_changing_code() {
        let context = RemoteContext {
            remote: true,
            host: "dev".to_owned(),
            physical_root: "/srv/app".to_owned(),
            shell: ShellMetadata {
                kind: ShellName::Sh,
                version: None,
                fallback: false,
            },
            helper_mode: None,
        };
        let error = super::super::attach_optional_remote_context(
            crate::BridgeError::new(ErrorCode::CommandTimeout, "timeout", false),
            Some(&context),
        );
        assert_eq!(error.code, ErrorCode::CommandTimeout);
        assert_eq!(error.message, "timeout");
        assert_eq!(error.details.host.as_deref(), Some("dev"));
        assert_eq!(error.details.physical_root.as_deref(), Some("/srv/app"));
    }

    #[test]
    fn cached_read_preserves_line_and_byte_truncation_semantics() {
        let path = crate::path::RemotePath::absolute("/srv/app/file").unwrap();
        let desired = DesiredState::Present(Arc::from(&b"one\ntwo\nthree"[..]));
        let hash = "a".repeat(64);
        let (entry, raw_bytes) = super::cached_read_entry(&path, &desired, Some(&hash), 2, 2, 4);

        assert_eq!(raw_bytes, 4);
        let ReadEntry::Success {
            content,
            truncated_before,
            truncated_after,
            truncated,
            ..
        } = entry
        else {
            panic!("cached present file did not produce content");
        };
        assert_eq!(content.encoding, ValueEncoding::Utf8);
        assert_eq!(content.value, "two\n");
        assert!(truncated_before);
        assert!(truncated_after);
        assert!(truncated);
    }

    #[test]
    fn cached_tombstone_reads_as_not_found() {
        let path = crate::path::RemotePath::absolute("/srv/app/missing").unwrap();
        let (entry, raw_bytes) =
            super::cached_read_entry(&path, &DesiredState::Deleted, None, 1, 2_000, 1024);
        assert_eq!(raw_bytes, 0);
        let ReadEntry::Error { error, .. } = entry else {
            panic!("cached tombstone did not produce an error");
        };
        assert_eq!(error.code, super::super::EntryErrorCode::NotFound);
    }
}
