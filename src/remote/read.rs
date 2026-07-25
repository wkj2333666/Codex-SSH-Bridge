use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::error::BridgeResult;
use crate::output::{InternalSpoolOwner, StreamKind};
use crate::ssh::{FixedOperationKind, FixedRunRequest, RootedPathInputs};

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
codex_check_read() (
    codex_read_dir=$(mktemp -d /tmp/codex-sentinel-read.XXXXXX 2>/dev/null) || exit 9
    cleanup_codex_read() { rm -rf -- "$codex_read_dir"; }
    trap cleanup_codex_read EXIT HUP INT TERM
    codex_read_file=$codex_read_dir/codex-sentinel-read
    codex_read_tail=$codex_read_dir/tail
    codex_read_line=$codex_read_dir/line
    codex_read_bytes=$codex_read_dir/bytes
    codex_read_last=$codex_read_dir/last
    codex_read_expected=$codex_read_dir/expected
    printf 'a\000b\nc' >"$codex_read_file" || exit 9
    printf 'a\000b\n' >"$codex_read_expected" || exit 9
    tail -n +1 -- "$codex_read_file" >"$codex_read_tail" 2>/dev/null || exit 1
    head -n 1 "$codex_read_tail" >"$codex_read_line" 2>/dev/null || exit 1
    head -c 4 "$codex_read_line" >"$codex_read_bytes" 2>/dev/null || exit 1
    tail -c 1 -- "$codex_read_file" >"$codex_read_last" 2>/dev/null || exit 1
    codex_read_count=$(wc -l <"$codex_read_file") || exit 1
    codex_read_size=$(stat --printf='%s' -- "$codex_read_file" 2>/dev/null) || exit 2
    codex_read_hash=$(sha256sum -- "$codex_read_file" 2>/dev/null) || exit 3
    set -- $codex_read_hash
    codex_read_hash=$1
    cmp -s "$codex_read_expected" "$codex_read_bytes" &&
    [ "$(cat "$codex_read_last")" = c ] && [ "$codex_read_count" -eq 1 ] || exit 1
    [ "$codex_read_size" -eq 5 ] || exit 2
    [ "$codex_read_hash" = 214df3f68e1a607f5baa40cc3315f4316ae58b282b6c0bf288b89fec4da7aa80 ] || exit 3
)
codex_read_status=0
codex_check_read || codex_read_status=$?
case "$codex_read_status" in
    0) ;;
    1) printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=read_slice\000' >&2; exit 0 ;;
    2) printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=stat_printf\000' >&2; exit 0 ;;
    3) printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=sha256sum\000' >&2; exit 0 ;;
    *) exit 2 ;;
esac
if [ ! -e "$path" ]; then
    parent=${path%/*};[ -n "$parent" ]||parent=/
    while [ "$parent" != . ]&&[ ! -d "$parent" ];do parent=${parent%/*};[ -n "$parent" ]||parent=.;done
    if [ -d "$parent" ]&&[ ! -x "$parent" ];then printf 'PERMISSION_DENIED\000' >&2;else printf 'NOT_FOUND\000' >&2;fi
    exit 0
fi
if [ ! -r "$path" ]; then printf 'PERMISSION_DENIED\000' >&2; exit 0; fi
if [ ! -f "$path" ]; then printf 'INVALID_ARGUMENT\000' >&2; exit 0; fi
size=$(stat --printf='%s' -- "$path" 2>/dev/null) || { printf 'PERMISSION_DENIED\000' >&2; exit 0; }
count=$(wc -l < "$path") || { printf 'PERMISSION_DENIED\000' >&2; exit 0; }
if [ "$size" -gt 0 ]; then
    final_lf=$(tail -c 1 -- "$path" | wc -l)
    if [ "$final_lf" -eq 0 ]; then count=$((count + 1)); fi
fi
hash1=$(sha256sum -- "$path" 2>/dev/null) || { printf 'PERMISSION_DENIED\000' >&2; exit 0; }
set -- $hash1
hash1=$1
look=$((budget + 1))
tail -n "+$start" -- "$path" 2>/dev/null | head -n "$lines" | head -c "$look"
hash2=$(sha256sum -- "$path" 2>/dev/null) || { printf 'PERMISSION_DENIED\000' >&2; exit 0; }
set -- $hash2
hash2=$1
printf 'OK\000%s\000%s\000%s\000%s\000' "$size" "$count" "$hash1" "$hash2" >&2
"#;

pub(super) async fn read(
    bridge: &RemoteBridge,
    request: ResolvedRead,
    cancel: CancellationToken,
) -> BridgeResult<ReadResult> {
    let runner = &bridge.runner;
    let limits = runner.config().host(&request.host)?.limits;
    let mut remaining = request.max_bytes;
    let mut files = Vec::with_capacity(request.paths.len());
    let mut returned_raw_bytes = 0u64;
    let mut operation_context = None;
    for path in request.paths {
        if cancel.is_cancelled() {
            return Err(read_cancelled_error(operation_context.as_ref()));
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
        let hash1 = utf8(fields[3]).map_err(&attach)?;
        let hash2 = utf8(fields[4]).map_err(&attach)?;
        if !valid_hash(hash1) || !valid_hash(hash2) {
            return Err(attach(protocol_error("read hash is invalid")));
        }
        let stdout = read_small_stream(
            &result.output,
            StreamKind::Stdout,
            remaining.saturating_add(1),
        )
        .await
        .map_err(&attach)?;
        if hash1 != hash2 {
            let conflict = crate::error::BridgeError::read_conflict();
            debug_assert_eq!(conflict.code, crate::error::ErrorCode::ReadConflict);
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
            format!("{:x}", Sha256::digest(retained))
        } else {
            hash1.to_owned()
        };
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
    use super::super::{RemoteContext, ShellMetadata, ShellName};
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
}
