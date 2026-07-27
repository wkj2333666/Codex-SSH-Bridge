use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::error::ErrorCode;
use crate::output::{InternalSpoolOwner, StreamKind};
use crate::ssh::{
    FixedOperationKind, FixedRunRequest, RootedArgumentStride, RootedPathInputs, SshRunner,
    render_fixed_command,
};

use super::edit_cache::{
    CacheKey, CommitBatchOutcome, CommitFuture, CommitItem, CommitSuccess, DesiredState,
    EditBackend, EditError, EditErrorKind, EditFuture, RemoteBase, RemoteSnapshot,
};
use super::execute_readonly_fixed;
use super::patch::{
    FileSnapshot, PATCH_SNAPSHOT_SCRIPT, SNAPSHOT_CAPTURE_METADATA_BYTES, SNAPSHOT_PROTOCOL_BYTES,
    parse_snapshot_protocol,
};
use super::protocol::read_small_stream;
use super::write::split_parent_basename;

const ITEM_ARGUMENTS: usize = 8;
const RECORD_BYTES: u64 = 192;

const BATCH_EDIT_SCRIPT: &str = r#"
set -u

[ "$#" -gt 0 ] || exit 2
[ $(( $# % 8 )) -eq 0 ] || exit 2

hash_file() {
    dd if="$1" bs=262144 status=none iflag=nofollow 2>/dev/null |
        sha256sum 2>/dev/null |
        { IFS=' ' read -r digest rest || exit 1
          [ "${#digest}" -eq 64 ] || exit 1
          case "$digest" in *[!0-9a-f]*) exit 1 ;; esac
          printf '%s' "$digest"; }
}

emit_result() {
    printf 'INDEX=%s\000STATUS=%s\000SHA256=%s\000MODE=%s\000' "$1" "$2" "$3" "$4"
}

index=0
while [ "$#" -gt 0 ]; do
    parent=$1
    basename=$2
    base_kind=$3
    base_hash=$4
    desired_kind=$5
    desired_size=$6
    desired_hash=$7
    desired_mode=$8
    shift 8

    case "$basename" in ''|.|..) exit 2 ;; esac
    case "$basename" in */*) exit 2 ;; esac
    case "$desired_size" in ''|*[!0-9]*) exit 2 ;; esac
    target=$parent/$basename

    current_hash=-
    current_mode=0
    if [ "$base_kind" = M ]; then
        if [ -e "$target" ] || [ -L "$target" ]; then
            emit_result "$index" CONFLICT - 0
            exit 0
        fi
    elif [ "$base_kind" = R ]; then
        if [ ! -f "$target" ] || [ -L "$target" ]; then
            emit_result "$index" CONFLICT - 0
            exit 0
        fi
        current_hash=$(hash_file "$target") || exit 4
        [ "$current_hash" = "$base_hash" ] || {
            emit_result "$index" CONFLICT - 0
            exit 0
        }
        current_mode=$(stat --printf='%a' -- "$target" 2>/dev/null) || exit 4
    else
        exit 2
    fi

    if [ "$desired_kind" = D ]; then
        if [ "$base_kind" = M ]; then
            emit_result "$index" UNCHANGED - 0
        else
            recheck_hash=$(hash_file "$target") || exit 5
            [ "$recheck_hash" = "$base_hash" ] || {
                emit_result "$index" CONFLICT - 0
                exit 0
            }
            rm -f -- "$target" || exit 5
            [ ! -e "$target" ] && [ ! -L "$target" ] || exit 5
            emit_result "$index" CHANGED - 0
        fi
    elif [ "$desired_kind" = P ]; then
        case "$desired_hash" in
            ????????????????????????????????????????????????????????????????) ;;
            *) exit 2 ;;
        esac
        case "$desired_hash" in *[!0-9a-f]*) exit 2 ;; esac
        case "$desired_mode" in ''|*[!0-7]*) exit 2 ;; esac
        tmp=$(mktemp --tmpdir="$parent" .codex-ssh-bridge.batch.XXXXXXXXXX) || exit 5
        cleanup_tmp() { rm -f -- "$tmp" >/dev/null 2>&1 || :; }
        trap 'cleanup_tmp; exit 125' HUP INT TERM
        dd of="$tmp" bs=262144 iflag=count_bytes count="$desired_size" \
            status=none conv=notrunc || { cleanup_tmp; exit 4; }
        staged_size=$(stat --printf='%s' -- "$tmp" 2>/dev/null) || {
            cleanup_tmp
            exit 4
        }
        [ "$staged_size" = "$desired_size" ] || { cleanup_tmp; exit 4; }
        staged_hash=$(hash_file "$tmp") || { cleanup_tmp; exit 4; }
        [ "$staged_hash" = "$desired_hash" ] || { cleanup_tmp; exit 4; }
        chmod "$desired_mode" -- "$tmp" || { cleanup_tmp; exit 5; }

        if [ "$base_kind" = M ]; then
            if [ -e "$target" ] || [ -L "$target" ]; then
                cleanup_tmp
                emit_result "$index" CONFLICT - 0
                exit 0
            fi
            ln -T -- "$tmp" "$target" || {
                cleanup_tmp
                emit_result "$index" CONFLICT - 0
                exit 0
            }
            cleanup_tmp
            result_mode=$((0$desired_mode))
            emit_result "$index" CHANGED "$desired_hash" "$result_mode"
        elif [ "$current_hash" = "$desired_hash" ] &&
             [ "$current_mode" = "$desired_mode" ]; then
            cleanup_tmp
            result_mode=$((0$current_mode))
            emit_result "$index" UNCHANGED "$desired_hash" "$result_mode"
        else
            recheck_hash=$(hash_file "$target") || { cleanup_tmp; exit 5; }
            [ "$recheck_hash" = "$base_hash" ] || {
                cleanup_tmp
                emit_result "$index" CONFLICT - 0
                exit 0
            }
            mv -T -- "$tmp" "$target" || { cleanup_tmp; exit 5; }
            trap - HUP INT TERM
            result_mode=$((0$desired_mode))
            emit_result "$index" CHANGED "$desired_hash" "$result_mode"
        fi
        trap - HUP INT TERM
    else
        exit 2
    fi
    index=$((index + 1))
done
"#;

pub(super) struct SshEditBackend {
    runner: Arc<SshRunner>,
    maximum_snapshot_bytes: usize,
}

impl SshEditBackend {
    pub(super) fn new(runner: Arc<SshRunner>, maximum_snapshot_bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            runner,
            maximum_snapshot_bytes,
        })
    }

    async fn fetch_snapshot(&self, key: &CacheKey) -> Result<RemoteSnapshot, EditError> {
        let (parent, basename) = split_parent_basename(&key.path).map_err(map_bridge_error)?;
        let limits = self.runner.config().limits();
        let desired_stdout_limit = u64::try_from(self.maximum_snapshot_bytes)
            .ok()
            .and_then(|maximum| maximum.checked_add(1))
            .ok_or_else(|| permanent("snapshot output limit overflowed"))?;
        let available_stdout = limits
            .max_output_bytes
            .checked_sub(SNAPSHOT_CAPTURE_METADATA_BYTES as u64)
            .filter(|available| *available > 0)
            .ok_or_else(|| permanent("snapshot protocol reserve exceeds the output limit"))?;
        let stdout_limit = desired_stdout_limit.min(available_stdout);
        let snapshot_maximum = usize::try_from(stdout_limit - 1)
            .map_err(|_| permanent("snapshot output limit is not representable"))?;
        let snapshot_read_limit = snapshot_maximum
            .checked_add(1)
            .ok_or_else(|| permanent("snapshot output limit overflowed"))?;
        let owner = InternalSpoolOwner::new();
        let result = execute_readonly_fixed(
            &self.runner,
            FixedRunRequest {
                kind: FixedOperationKind::ReadOnly,
                host: key.host.clone(),
                script: PATCH_SNAPSHOT_SCRIPT,
                args: vec![parent, basename, snapshot_maximum.to_string()],
                stdin: None,
                rooted_paths: RootedPathInputs {
                    argument_indices: &[0],
                    argument_stride: None,
                    stdin_nul_paths: false,
                },
                required_capabilities: &["safe_write"],
                stdout_limit,
                stderr_limit: SNAPSHOT_CAPTURE_METADATA_BYTES as u64,
                timeout: Duration::from_millis(limits.command_timeout_ms),
                cleanup: owner.registration(),
            },
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .map_err(map_runner_error)?;
        let stderr = read_small_stream(&result.output, StreamKind::Stderr, SNAPSHOT_PROTOCOL_BYTES)
            .await
            .map_err(map_runner_error)?;
        let stdout = read_small_stream(&result.output, StreamKind::Stdout, snapshot_read_limit)
            .await
            .map_err(map_runner_error)?;
        drop(owner);
        match parse_snapshot_protocol(&stderr, stdout, snapshot_maximum)
            .map_err(map_runner_error)?
        {
            FileSnapshot::Missing => Ok(RemoteSnapshot {
                base: RemoteBase::Missing,
                desired: DesiredState::Deleted,
            }),
            FileSnapshot::Regular {
                bytes,
                sha256,
                mode,
            } => Ok(RemoteSnapshot {
                base: RemoteBase::Regular { sha256, mode },
                desired: DesiredState::Present(Arc::from(bytes)),
            }),
        }
    }

    async fn commit_partition(
        &self,
        host: &str,
        items: Vec<CommitItem>,
    ) -> Result<CommitBatchOutcome, EditError> {
        let prepared = prepare_batch(&items)?;
        let limits = self.runner.config().limits();
        let transport_bytes = render_fixed_command(BATCH_EDIT_SCRIPT, &prepared.args)
            .map_err(map_bridge_error)?
            .len()
            .checked_add(prepared.stdin.len())
            .ok_or_else(|| permanent("batch transport length overflowed"))?;
        if transport_bytes > limits.max_frame_bytes {
            return Err(permanent("batch exceeds the configured frame limit"));
        }
        let output_limit = RECORD_BYTES
            .checked_mul(u64::try_from(items.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| permanent("batch output limit overflowed"))?;
        if output_limit == 0 || output_limit > limits.max_output_bytes {
            return Err(permanent("batch output exceeds the configured limit"));
        }
        let owner = InternalSpoolOwner::new();
        let request = FixedRunRequest {
            kind: FixedOperationKind::Mutation,
            host: host.to_owned(),
            script: BATCH_EDIT_SCRIPT,
            args: prepared.args,
            stdin: Some(prepared.stdin),
            rooted_paths: RootedPathInputs {
                argument_indices: &[],
                argument_stride: Some(RootedArgumentStride {
                    start: 0,
                    step: ITEM_ARGUMENTS,
                }),
                stdin_nul_paths: false,
            },
            required_capabilities: &["safe_write", "guarded_delete"],
            stdout_limit: output_limit,
            stderr_limit: 1,
            timeout: Duration::from_millis(limits.command_timeout_ms),
            cleanup: owner.registration(),
        };
        let result = self
            .runner
            .execute_fixed_once(request, tokio_util::sync::CancellationToken::new())
            .await
            .map_err(map_runner_error)?;
        let stderr = read_small_stream(&result.output, StreamKind::Stderr, 1)
            .await
            .map_err(map_runner_error)?;
        let stdout = read_small_stream(
            &result.output,
            StreamKind::Stdout,
            usize::try_from(output_limit).unwrap_or(usize::MAX),
        )
        .await
        .map_err(map_runner_error)?;
        drop(owner);
        parse_batch_result(&stdout, &stderr, &items)
    }
}

impl EditBackend for SshEditBackend {
    fn fetch_complete<'a>(&'a self, key: &'a CacheKey) -> EditFuture<'a, RemoteSnapshot> {
        Box::pin(async move { self.fetch_snapshot(key).await })
    }

    fn commit_batch<'a>(&'a self, host: &'a str, items: Vec<CommitItem>) -> CommitFuture<'a> {
        Box::pin(async move {
            if items.is_empty() {
                return successful(Vec::new());
            }
            if items.iter().any(|item| item.key.host != host) {
                return failed(permanent("batch contains a different SSH host"));
            }
            let partitions =
                match partition_items(items, self.runner.config().limits().max_frame_bytes) {
                    Ok(partitions) => partitions,
                    Err(error) => return failed(error),
                };
            let mut committed = Vec::new();
            for partition in partitions {
                match self.commit_partition(host, partition).await {
                    Ok(outcome) => {
                        committed.extend(outcome.successes);
                        if let Some(error) = outcome.error {
                            return CommitBatchOutcome {
                                successes: committed,
                                error: Some(error),
                            };
                        }
                    }
                    Err(error) => {
                        return CommitBatchOutcome {
                            successes: committed,
                            error: Some(error),
                        };
                    }
                }
            }
            successful(committed)
        })
    }
}

struct PreparedBatch {
    args: Vec<String>,
    stdin: Vec<u8>,
}

fn prepare_batch(items: &[CommitItem]) -> Result<PreparedBatch, EditError> {
    let mut args = Vec::with_capacity(items.len().saturating_mul(ITEM_ARGUMENTS));
    let stdin_bytes = items.iter().try_fold(0usize, |total, item| {
        total
            .checked_add(match &item.desired {
                DesiredState::Present(bytes) => bytes.len(),
                DesiredState::Deleted => 0,
            })
            .ok_or_else(|| permanent("batch stdin length overflowed"))
    })?;
    let mut stdin = Vec::with_capacity(stdin_bytes);
    for item in items {
        let (parent, basename) = split_parent_basename(&item.key.path).map_err(map_bridge_error)?;
        let (base_kind, base_hash, mode) = match &item.base {
            RemoteBase::Missing => ("M", "", 0o600),
            RemoteBase::Regular { sha256, mode } => ("R", sha256.as_str(), *mode),
        };
        let (desired_kind, size, hash, desired_mode) = match &item.desired {
            DesiredState::Present(bytes) => {
                let hash = format!("{:x}", Sha256::digest(bytes));
                stdin.extend_from_slice(bytes);
                ("P", bytes.len(), hash, mode)
            }
            DesiredState::Deleted => ("D", 0, String::new(), 0),
        };
        args.extend([
            parent,
            basename,
            base_kind.to_owned(),
            base_hash.to_owned(),
            desired_kind.to_owned(),
            size.to_string(),
            hash,
            format!("{desired_mode:o}"),
        ]);
    }
    Ok(PreparedBatch { args, stdin })
}

fn partition_items(
    items: Vec<CommitItem>,
    maximum_frame_bytes: usize,
) -> Result<Vec<Vec<CommitItem>>, EditError> {
    let mut partitions = Vec::new();
    let mut current = Vec::new();
    for item in items {
        current.push(item);
        if batch_transport_bytes(&current)? <= maximum_frame_bytes {
            continue;
        }
        let item = current
            .pop()
            .expect("candidate batch contains the appended item");
        if current.is_empty() {
            return Err(permanent("one edit cannot fit the configured frame limit"));
        }
        partitions.push(std::mem::take(&mut current));
        current.push(item);
        if batch_transport_bytes(&current)? > maximum_frame_bytes {
            return Err(permanent("one edit cannot fit the configured frame limit"));
        }
    }
    if !current.is_empty() {
        partitions.push(current);
    }
    Ok(partitions)
}

fn batch_transport_bytes(items: &[CommitItem]) -> Result<usize, EditError> {
    let prepared = prepare_batch(items)?;
    render_fixed_command(BATCH_EDIT_SCRIPT, &prepared.args)
        .map_err(map_bridge_error)?
        .len()
        .checked_add(prepared.stdin.len())
        .ok_or_else(|| permanent("batch transport length overflowed"))
}

fn parse_batch_result(
    stdout: &[u8],
    stderr: &[u8],
    items: &[CommitItem],
) -> Result<CommitBatchOutcome, EditError> {
    if !stderr.is_empty() || stdout.last() != Some(&0) {
        return Err(unknown("batch mutation protocol is incomplete"));
    }
    let fields = stdout[..stdout.len() - 1]
        .split(|byte| *byte == 0)
        .collect::<Vec<_>>();
    if fields.len() % 4 != 0 {
        return Err(unknown("batch mutation protocol field count is invalid"));
    }
    let mut successes = Vec::new();
    for (expected, fields) in fields.chunks_exact(4).enumerate() {
        let index = parse_field_usize(fields[0], b"INDEX=")?;
        if index != expected || index >= items.len() {
            return Err(unknown("batch mutation index is invalid"));
        }
        let status = fields[1]
            .strip_prefix(b"STATUS=")
            .ok_or_else(|| unknown("batch mutation status is invalid"))?;
        if status == b"CONFLICT" {
            return Ok(CommitBatchOutcome {
                successes,
                error: Some(EditError {
                    kind: EditErrorKind::Conflict,
                    message: format!("WRITE_CONFLICT: {}", items[index].key.path),
                }),
            });
        }
        if status != b"CHANGED" && status != b"UNCHANGED" {
            return Err(unknown("batch mutation status is invalid"));
        }
        let hash = fields[2]
            .strip_prefix(b"SHA256=")
            .ok_or_else(|| unknown("batch mutation hash is invalid"))?;
        let mode = parse_field_u32(fields[3], b"MODE=")?;
        let base = match &items[index].desired {
            DesiredState::Deleted if hash == b"-" && mode == 0 => RemoteBase::Missing,
            DesiredState::Present(bytes) => {
                let expected_hash = format!("{:x}", Sha256::digest(bytes));
                if hash != expected_hash.as_bytes() || mode > 0o777 {
                    return Err(unknown("batch mutation result does not match its input"));
                }
                RemoteBase::Regular {
                    sha256: expected_hash,
                    mode,
                }
            }
            DesiredState::Deleted => {
                return Err(unknown("batch deletion result is invalid"));
            }
        };
        successes.push(CommitSuccess {
            key: items[index].key.clone(),
            generation: items[index].generation,
            base,
        });
    }
    if successes.len() != items.len() {
        return Err(unknown("batch mutation result is incomplete"));
    }
    Ok(successful(successes))
}

fn successful(successes: Vec<CommitSuccess>) -> CommitBatchOutcome {
    CommitBatchOutcome {
        successes,
        error: None,
    }
}

fn failed(error: EditError) -> CommitBatchOutcome {
    CommitBatchOutcome {
        successes: Vec::new(),
        error: Some(error),
    }
}

fn parse_field_usize(field: &[u8], prefix: &[u8]) -> Result<usize, EditError> {
    parse_decimal(field, prefix)?
        .try_into()
        .map_err(|_| unknown("batch mutation number is out of range"))
}

fn parse_field_u32(field: &[u8], prefix: &[u8]) -> Result<u32, EditError> {
    parse_decimal(field, prefix)?
        .try_into()
        .map_err(|_| unknown("batch mutation number is out of range"))
}

fn parse_decimal(field: &[u8], prefix: &[u8]) -> Result<u64, EditError> {
    let value = field
        .strip_prefix(prefix)
        .ok_or_else(|| unknown("batch mutation numeric field is invalid"))?;
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(unknown("batch mutation numeric field is invalid"));
    }
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| unknown("batch mutation numeric field is invalid"))
}

fn map_runner_error(error: crate::error::BridgeError) -> EditError {
    let kind = match error.code {
        ErrorCode::MutationOutcomeUnknown => EditErrorKind::OutcomeUnknown,
        ErrorCode::WriteConflict => EditErrorKind::Conflict,
        ErrorCode::InvalidArgument | ErrorCode::RequestTooLarge => EditErrorKind::Permanent,
        _ => EditErrorKind::Transient,
    };
    EditError {
        kind,
        message: error.message,
    }
}

fn map_bridge_error(error: crate::error::BridgeError) -> EditError {
    EditError {
        kind: EditErrorKind::Permanent,
        message: error.message,
    }
}

fn permanent(message: &str) -> EditError {
    EditError {
        kind: EditErrorKind::Permanent,
        message: message.to_owned(),
    }
}

fn unknown(message: &str) -> EditError {
    EditError {
        kind: EditErrorKind::OutcomeUnknown,
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::edit_cache::Generation;

    fn item(path: &str, desired: DesiredState) -> CommitItem {
        CommitItem {
            key: CacheKey {
                host: "host".to_owned(),
                path: path.to_owned(),
            },
            base: RemoteBase::Missing,
            desired,
            generation: Generation(7),
        }
    }

    #[test]
    fn batch_arguments_keep_hostile_paths_out_of_shell_syntax_and_stdin_is_exact() {
        let items = [
            item(
                "/repo/a $'\"\\\n-",
                DesiredState::Present(Arc::from(&b"\0binary\n"[..])),
            ),
            item("/repo/deleted", DesiredState::Deleted),
        ];
        let prepared = prepare_batch(&items).unwrap();
        assert_eq!(prepared.args[0], "/repo");
        assert_eq!(prepared.args[1], "a $'\"\\\n-");
        assert_eq!(prepared.stdin, b"\0binary\n");
        let command = render_fixed_command(BATCH_EDIT_SCRIPT, &prepared.args).unwrap();
        assert!(!command.contains("\na $"));
    }

    #[test]
    fn parser_accepts_ordered_changed_and_unchanged_records() {
        let present = item("/repo/a", DesiredState::Present(Arc::from(&b"payload"[..])));
        let deleted = item("/repo/b", DesiredState::Deleted);
        let hash = format!("{:x}", Sha256::digest(b"payload"));
        let output = format!(
            "INDEX=0\0STATUS=CHANGED\0SHA256={hash}\0MODE=384\0\
             INDEX=1\0STATUS=UNCHANGED\0SHA256=-\0MODE=0\0"
        );
        let parsed = parse_batch_result(output.as_bytes(), b"", &[present, deleted]).unwrap();
        assert_eq!(parsed.successes.len(), 2);
        assert_eq!(parsed.successes[1].base, RemoteBase::Missing);
        assert_eq!(parsed.error, None);
    }

    #[test]
    fn parser_keeps_conflicts_factual_and_rejects_incomplete_results() {
        let present = item("/repo/a", DesiredState::Present(Arc::from(&b"payload"[..])));
        let conflict = parse_batch_result(
            b"INDEX=0\0STATUS=CONFLICT\0SHA256=-\0MODE=0\0",
            b"",
            std::slice::from_ref(&present),
        )
        .unwrap();
        assert!(conflict.successes.is_empty());
        let conflict = conflict.error.unwrap();
        assert_eq!(conflict.kind, EditErrorKind::Conflict);
        assert!(conflict.message.contains("/repo/a"));
        assert_eq!(
            parse_batch_result(b"", b"", &[present]).unwrap_err().kind,
            EditErrorKind::OutcomeUnknown
        );
    }

    #[test]
    fn parser_preserves_the_confirmed_prefix_before_a_conflict() {
        let first = item("/repo/a", DesiredState::Present(Arc::from(&b"first"[..])));
        let second = item("/repo/b", DesiredState::Present(Arc::from(&b"second"[..])));
        let first_hash = format!("{:x}", Sha256::digest(b"first"));
        let output = format!(
            "INDEX=0\0STATUS=CHANGED\0SHA256={first_hash}\0MODE=384\0\
             INDEX=1\0STATUS=CONFLICT\0SHA256=-\0MODE=0\0"
        );

        let parsed = parse_batch_result(output.as_bytes(), b"", &[first, second]).unwrap();

        assert_eq!(parsed.successes.len(), 1);
        assert_eq!(parsed.successes[0].key.path, "/repo/a");
        assert_eq!(parsed.error.unwrap().kind, EditErrorKind::Conflict);
    }

    #[test]
    fn partitioning_keeps_each_request_within_the_frame_limit() {
        let items = (0..3)
            .map(|index| {
                item(
                    &format!("/repo/{index}"),
                    DesiredState::Present(Arc::from(vec![b'x'; 128])),
                )
            })
            .collect::<Vec<_>>();
        let one = batch_transport_bytes(&items[..1]).unwrap();
        let two = batch_transport_bytes(&items[..2]).unwrap();
        let partitions = partition_items(items, two - 1).unwrap();
        assert_eq!(partitions.len(), 3);
        assert!(
            partitions
                .iter()
                .all(|partition| batch_transport_bytes(partition).unwrap() < two)
        );
        assert!(one < two);
    }
}
