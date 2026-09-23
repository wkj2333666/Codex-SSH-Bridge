use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::error::{BridgeError, BridgeResult, ErrorCode};
use crate::output::{InternalSpoolOwner, StreamKind};
use crate::ssh::{FixedOperationKind, FixedRunRequest, RootedArgumentStride, RootedPathInputs};

use super::edit_cache::{
    BatchMutationDisposition, CacheKey, DesiredState, LoadEntryDisposition, PreparedEdit,
};
use super::protocol::{context, nul_fields, parse_u64, read_small_stream, utf8};
use super::{
    ApplyPatchRequest, ApplyPatchResult, RemoteBridge, RemoteContext, WriteEncoding, WriteMode,
    attach_fixed_result_context, attach_remote_context, edit_bridge_error,
};

pub(super) const MAX_PATCH_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_PATCH_FILES: usize = 32;
pub(super) const MAX_PATCH_HUNKS: usize = 4_096;
pub(super) const MAX_PATCH_BODY_LINES: usize = 100_000;
pub(super) const MAX_PATCH_PATH_BYTES: usize = 64 * 1024;
pub(super) const SNAPSHOT_PROTOCOL_BYTES: usize = 1024;
pub(super) const SNAPSHOT_CAPTURE_METADATA_BYTES: usize = 2048;

pub(super) const PATCH_SNAPSHOT_SCRIPT: &str = r#"
set -u
[ "$#" -ge 3 ] || exit 2
[ $(( $# % 3 )) -eq 0 ] || exit 2
newline='
'

codex_snapshot_stat() {
    stat --printf='%f:%u:%a:%s:%d:%i:%h\n' -- "$1" 2>/dev/null
}
codex_snapshot_parent_stat_follow() {
    stat -L --printf='%f:%u:%a:%s:%d:%i:%h\n' -- "$1" 2>/dev/null
}
codex_snapshot_decimal_valid() {
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
    [ "${#1}" -le 20 ] || return 1
    [ "${#1}" -lt 20 ] && return 0
    codex_decimal_value=$1
    codex_decimal_limit=18446744073709551615
    while [ -n "$codex_decimal_value" ]; do
        codex_decimal_digit=${codex_decimal_value%"${codex_decimal_value#?}"}
        codex_decimal_limit_digit=${codex_decimal_limit%"${codex_decimal_limit#?}"}
        [ "$codex_decimal_digit" -lt "$codex_decimal_limit_digit" ] && return 0
        [ "$codex_decimal_digit" -gt "$codex_decimal_limit_digit" ] && return 1
        codex_decimal_value=${codex_decimal_value#?}
        codex_decimal_limit=${codex_decimal_limit#?}
    done
    return 0
}
codex_snapshot_decimal_le() {
    [ "${#1}" -lt "${#2}" ] && return 0
    [ "${#1}" -gt "${#2}" ] && return 1
    codex_decimal_value=$1
    codex_decimal_limit=$2
    while [ -n "$codex_decimal_value" ]; do
        codex_decimal_digit=${codex_decimal_value%"${codex_decimal_value#?}"}
        codex_decimal_limit_digit=${codex_decimal_limit%"${codex_decimal_limit#?}"}
        [ "$codex_decimal_digit" -lt "$codex_decimal_limit_digit" ] && return 0
        [ "$codex_decimal_digit" -gt "$codex_decimal_limit_digit" ] && return 1
        codex_decimal_value=${codex_decimal_value#?}
        codex_decimal_limit=${codex_decimal_limit#?}
    done
    return 0
}
codex_snapshot_stat_parse() {
    codex_stat_line=$1
    case "$codex_stat_line" in ''|*[!0-9a-f:]*) return 1 ;; esac
    codex_stat_old_ifs=$IFS
    IFS=:
    set -- $codex_stat_line
    IFS=$codex_stat_old_ifs
    [ "$#" -eq 7 ] || return 1
    [ "${#1}" -eq 4 ] || return 1
    case "$1" in *[!0-9a-f]*) return 1 ;; esac
    codex_snapshot_decimal_valid "$2" || return 1
    [ "${#3}" -le 4 ] || return 1
    case "$3" in ''|*[!0-7]*) return 1 ;; esac
    codex_snapshot_decimal_valid "$4" || return 1
    codex_snapshot_decimal_valid "$5" || return 1
    codex_snapshot_decimal_valid "$6" || return 1
    codex_snapshot_decimal_valid "$7" || return 1
    CODEX_STAT_TYPE=$1
    CODEX_STAT_UID=$2
    CODEX_STAT_MODE=$3
    CODEX_STAT_SIZE=$4
    CODEX_STAT_DEVICE=$5
    CODEX_STAT_INODE=$6
    CODEX_STAT_LINKS=$7
}
codex_snapshot_stat_valid() {
    codex_stat_line=$(codex_snapshot_stat "$1") || return 9
    codex_snapshot_stat_parse "$codex_stat_line"
}
codex_snapshot_parent_stat_follow_valid() {
    codex_stat_line=$(codex_snapshot_parent_stat_follow "$1") || return 9
    codex_snapshot_stat_parse "$codex_stat_line"
}
codex_snapshot_read() {
    dd if="$1" bs=262144 status=none iflag=nofollow 2>/dev/null
}
codex_snapshot_hash() (
    codex_hash_capture=$(
        {
            {
                dd if="$1" bs=262144 status=none iflag=nofollow 2>/dev/null
                printf 'CODEX_DD_STATUS=%s\n' "$?" >&2
            } | sha256sum 2>/dev/null
            printf 'CODEX_SHA_STATUS=%s\n' "$?" >&2
        } 2>&1
    )
    codex_hash_dd=
    codex_hash_sha=
    codex_hash_digest=
    codex_hash_dd_seen=0
    codex_hash_sha_seen=0
    codex_hash_digest_seen=0
    codex_hash_valid=1
    set -f
    IFS="$newline"
    for codex_hash_line in $codex_hash_capture; do
        case "$codex_hash_line" in
            CODEX_DD_STATUS=*)
                [ "$codex_hash_dd_seen" -eq 0 ] || { codex_hash_valid=0; break; }
                codex_hash_dd_seen=1
                codex_hash_dd=${codex_hash_line#CODEX_DD_STATUS=}
                ;;
            CODEX_SHA_STATUS=*)
                [ "$codex_hash_sha_seen" -eq 0 ] || { codex_hash_valid=0; break; }
                codex_hash_sha_seen=1
                codex_hash_sha=${codex_hash_line#CODEX_SHA_STATUS=}
                ;;
            *'  -')
                [ "$codex_hash_digest_seen" -eq 0 ] || { codex_hash_valid=0; break; }
                codex_hash_digest_seen=1
                codex_hash_digest=${codex_hash_line%  -}
                ;;
            *) codex_hash_valid=0; break ;;
        esac
    done
    if [ "$codex_hash_dd_seen" -ne 1 ] || [ "$codex_hash_sha_seen" -ne 1 ]; then
        codex_hash_valid=0
    fi
    if [ "$codex_hash_valid" -ne 1 ]; then
        codex_hash_status=1
    elif [ "$codex_hash_dd" != 0 ] || [ "$codex_hash_sha" != 0 ]; then
        codex_hash_status=9
    elif [ "$codex_hash_digest_seen" -ne 1 ] || [ "${#codex_hash_digest}" -ne 64 ]; then
        codex_hash_status=1
    else
        case "$codex_hash_digest" in *[!0-9a-f]*) codex_hash_valid=0 ;; esac
        if [ "$codex_hash_valid" -eq 1 ]; then
            printf '%s\n' "$codex_hash_digest"
            codex_hash_status=0
        else
            codex_hash_status=1
        fi
    fi
    exit "$codex_hash_status"
)

codex_patch_snapshot_sentinel() (
    umask 077
    codex_sentinel_dir=$(mktemp -d "${TMPDIR:-/tmp}/codex-sentinel-patch-snapshot.XXXXXX" 2>/dev/null) || exit 9
    cleanup_codex_sentinel() {
        rm -rf -- "$codex_sentinel_dir" >/dev/null 2>&1 || return 1
        [ ! -e "$codex_sentinel_dir" ] && [ ! -L "$codex_sentinel_dir" ]
    }
    on_codex_sentinel_signal() {
        trap - 0 HUP INT TERM
        cleanup_codex_sentinel >/dev/null 2>&1 || :
        exit 9
    }
    trap 'cleanup_codex_sentinel >/dev/null 2>&1 || :' 0
    trap on_codex_sentinel_signal HUP INT TERM
    codex_sentinel_parent=$codex_sentinel_dir/parent
    codex_sentinel_parent_link=$codex_sentinel_dir/parent-link
    mkdir -m 700 -- "$codex_sentinel_parent" || exit 9
    ln -s "$codex_sentinel_parent" "$codex_sentinel_parent_link" || exit 9
    codex_snapshot_parent_stat_follow_valid "$codex_sentinel_parent" || exit $?
    codex_sentinel_parent_identity=$CODEX_STAT_DEVICE:$CODEX_STAT_INODE
    codex_snapshot_parent_stat_follow_valid "$codex_sentinel_parent_link" || exit $?
    [ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE" = "$codex_sentinel_parent_identity" ] || exit 1
    case "$CODEX_STAT_TYPE" in 4???) ;; *) exit 1 ;; esac
    codex_sentinel_file=$codex_sentinel_parent/file
    printf payload >"$codex_sentinel_file" || exit 9
    codex_snapshot_stat_valid "$codex_sentinel_file" || exit $?
    case "$CODEX_STAT_TYPE" in 8???) ;; *) exit 1 ;; esac
    [ "$CODEX_STAT_SIZE" = 7 ] || exit 1
    codex_sentinel_hash=$(codex_snapshot_hash "$codex_sentinel_file") || exit $?
    [ "$codex_sentinel_hash" = 239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5 ] || exit 1
    codex_sentinel_content=$(codex_snapshot_read "$codex_sentinel_file") || exit 9
    [ "$codex_sentinel_content" = payload ] || exit 1
    codex_sentinel_link=$codex_sentinel_parent/link
    ln -s "$codex_sentinel_file" "$codex_sentinel_link" || exit 9
    codex_snapshot_stat_valid "$codex_sentinel_link" || exit $?
    case "$CODEX_STAT_TYPE" in a???) ;; *) exit 1 ;; esac
    if codex_snapshot_read "$codex_sentinel_link" >/dev/null 2>&1; then exit 1; fi
    cleanup_codex_sentinel || exit 9
    trap - 0 HUP INT TERM
    exit 0
)

for codex_required_command in stat mktemp dd sha256sum ln rm mkdir cat; do
    command -v "$codex_required_command" >/dev/null 2>&1 || {
        printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=safe_write\000' >&2
        exit 0
    }
done
codex_sentinel_status=0
codex_patch_snapshot_sentinel || codex_sentinel_status=$?
case "$codex_sentinel_status" in
    0) ;;
    1) printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=safe_write\000' >&2; exit 0 ;;
    *) exit 9 ;;
esac

codex_snapshot_one() (
parent=$1
basename=$2
maximum_size=$3
[ -n "$basename" ] || exit 2
case "$basename" in .|..|*/*) exit 2 ;; esac
codex_snapshot_decimal_valid "$maximum_size" || exit 2
emit_one() {
    printf 'STATUS=%s\000' "$1" >&2
    exit 10
}
codex_classify_unreachable_parent() {
    codex_parent_candidate=$parent
    codex_parent_unresolved=0
    codex_parent_classification_steps=0
    while :; do
        [ "$codex_parent_classification_steps" -lt 32 ] || return 1
        codex_parent_classification_steps=$((codex_parent_classification_steps + 1))
        codex_parent_lstat_status=0
        codex_snapshot_stat_valid "$codex_parent_candidate" || codex_parent_lstat_status=$?
        case "$codex_parent_lstat_status" in
        0)
            case "$CODEX_STAT_TYPE" in
                4???)
                    if [ ! -x "$codex_parent_candidate" ]; then emit_one PERMISSION_DENIED; fi
                    [ "$codex_parent_unresolved" -gt 0 ] && emit_one NOT_FOUND
                    return 1
                    ;;
                a???)
                    codex_parent_follow_status=0
                    codex_snapshot_parent_stat_follow_valid "$codex_parent_candidate" || codex_parent_follow_status=$?
                    [ "$codex_parent_follow_status" -eq 0 ] || return 1
                    case "$CODEX_STAT_TYPE" in
                        4???)
                            if [ ! -x "$codex_parent_candidate" ]; then emit_one PERMISSION_DENIED; fi
                            [ "$codex_parent_unresolved" -gt 0 ] && emit_one NOT_FOUND
                            return 1
                            ;;
                        *) [ "$codex_parent_unresolved" -gt 0 ] && emit_one NOT_DIRECTORY; return 1 ;;
                    esac
                    ;;
                *) [ "$codex_parent_unresolved" -gt 0 ] && emit_one NOT_DIRECTORY; return 1 ;;
            esac
            ;;
        9) ;;
        *) return 1 ;;
        esac
        [ "$codex_parent_candidate" = . ] && return 1
        codex_parent_candidate=${codex_parent_candidate%/*}
        [ -n "$codex_parent_candidate" ] || codex_parent_candidate=.
        codex_parent_unresolved=$((codex_parent_unresolved + 1))
    done
}

codex_parent_line=$(codex_snapshot_parent_stat_follow "$parent") || {
    codex_classify_unreachable_parent
    exit 3
}
codex_snapshot_stat_parse "$codex_parent_line" || exit 3
case "$CODEX_STAT_TYPE" in 4???) ;; *) emit_one NOT_DIRECTORY ;; esac
parent_device=$CODEX_STAT_DEVICE
parent_inode=$CODEX_STAT_INODE
if ! CDPATH= cd -P -- "$parent" 2>/dev/null; then
    if codex_snapshot_parent_stat_follow_valid "$parent" &&
       [ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE" = "$parent_device:$parent_inode" ]; then
        case "$CODEX_STAT_TYPE" in 4???) emit_one PERMISSION_DENIED ;; esac
    fi
    exit 3
fi
codex_snapshot_parent_stat_follow_valid . || exit 3
[ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE" = "$parent_device:$parent_inode" ] || exit 3

target=./$basename
target_status=0
codex_snapshot_stat_valid "$target" || target_status=$?
if [ "$target_status" -ne 0 ]; then
    if [ ! -e "$target" ] && [ ! -L "$target" ]; then
        emit_one MISSING
    fi
    exit 4
fi
case "$CODEX_STAT_TYPE" in 8???) ;; *) emit_one WRITE_CONFLICT ;; esac
target_size=$CODEX_STAT_SIZE
target_device=$CODEX_STAT_DEVICE
target_inode=$CODEX_STAT_INODE
target_mode=$CODEX_STAT_MODE
target_links=$CODEX_STAT_LINKS
target_mode_decimal=$((0$target_mode))
[ $((target_mode_decimal & 07000)) -eq 0 ] || emit_one WRITE_CONFLICT
codex_snapshot_decimal_le "$target_size" "$maximum_size" || emit_one REQUEST_TOO_LARGE

target_hash1_status=0
target_hash1=$(codex_snapshot_hash "$target") || target_hash1_status=$?
if [ "$target_hash1_status" -ne 0 ]; then
    if codex_snapshot_stat_valid "$target"; then
        case "$CODEX_STAT_TYPE" in 8???) ;; *) emit_one READ_CONFLICT ;; esac
        [ "$CODEX_STAT_SIZE:$CODEX_STAT_DEVICE:$CODEX_STAT_INODE:$CODEX_STAT_MODE:$CODEX_STAT_LINKS" = "$target_size:$target_device:$target_inode:$target_mode:$target_links" ] || emit_one READ_CONFLICT
        if [ ! -r "$target" ]; then emit_one PERMISSION_DENIED; fi
        exit 4
    fi
    emit_one READ_CONFLICT
fi
target_read_status=0
codex_snapshot_read "$target" || target_read_status=$?
if [ "$target_read_status" -ne 0 ]; then
    if codex_snapshot_stat_valid "$target"; then
        case "$CODEX_STAT_TYPE" in 8???) ;; *) emit_one READ_CONFLICT ;; esac
        [ "$CODEX_STAT_SIZE:$CODEX_STAT_DEVICE:$CODEX_STAT_INODE:$CODEX_STAT_MODE:$CODEX_STAT_LINKS" = "$target_size:$target_device:$target_inode:$target_mode:$target_links" ] || emit_one READ_CONFLICT
        if [ ! -r "$target" ]; then emit_one PERMISSION_DENIED; fi
    fi
    emit_one READ_CONFLICT
fi
target_status=0
codex_snapshot_stat_valid "$target" || target_status=$?
if [ "$target_status" -ne 0 ]; then emit_one READ_CONFLICT; fi
case "$CODEX_STAT_TYPE" in 8???) ;; *) emit_one READ_CONFLICT ;; esac
[ "$CODEX_STAT_SIZE:$CODEX_STAT_DEVICE:$CODEX_STAT_INODE:$CODEX_STAT_MODE:$CODEX_STAT_LINKS" = "$target_size:$target_device:$target_inode:$target_mode:$target_links" ] || emit_one READ_CONFLICT
target_final_mode_decimal=$((0$CODEX_STAT_MODE))
[ $((target_final_mode_decimal & 07000)) -eq 0 ] || emit_one READ_CONFLICT
target_hash2=$(codex_snapshot_hash "$target") || emit_one READ_CONFLICT
[ "$target_hash1" = "$target_hash2" ] || emit_one READ_CONFLICT
printf 'STATUS=SUCCESS\000SIZE=%s\000SHA256=%s\000MODE=%s\000DEVICE=%s\000INODE=%s\000LINKS=%s\000' \
    "$target_size" "$target_hash1" "$target_mode" "$target_device" "$target_inode" "$target_links" >&2
exit 0
)

batch_maximum=$3
codex_snapshot_decimal_valid "$batch_maximum" || exit 2
remaining_size=$batch_maximum
codex_batch_dir=$(mktemp -d "${TMPDIR:-/tmp}/codex-patch-snapshot-batch.XXXXXX" 2>/dev/null) || exit 9
cleanup_codex_batch() {
    rm -rf -- "$codex_batch_dir" >/dev/null 2>&1 || return 1
    [ ! -e "$codex_batch_dir" ] && [ ! -L "$codex_batch_dir" ]
}
on_codex_batch_signal() {
    trap - 0 HUP INT TERM
    cleanup_codex_batch >/dev/null 2>&1 || :
    exit 9
}
trap 'cleanup_codex_batch >/dev/null 2>&1 || :' 0
trap on_codex_batch_signal HUP INT TERM
codex_batch_content=$codex_batch_dir/content
while [ "$#" -gt 0 ]; do
    [ "$3" = "$batch_maximum" ] || exit 2
    codex_item_status=0
    codex_snapshot_one "$1" "$2" "$remaining_size" >"$codex_batch_content" || codex_item_status=$?
    case "$codex_item_status" in
        0)
            codex_item_size=$(stat --printf='%s' -- "$codex_batch_content" 2>/dev/null) || exit 9
            codex_snapshot_decimal_valid "$codex_item_size" || exit 9
            cat -- "$codex_batch_content" || exit 9
            if codex_snapshot_decimal_le "$codex_item_size" "$remaining_size"; then
                remaining_size=$((remaining_size - codex_item_size))
            else
                cleanup_codex_batch || exit 9
                trap - 0 HUP INT TERM
                exit 0
            fi
            ;;
        10) ;;
        *) exit "$codex_item_status" ;;
    esac
    shift 3
done
cleanup_codex_batch || exit 9
trap - 0 HUP INT TERM
exit 0
"#;

type ParsedFilePatch = super::codex_patch::CodexFilePatch;

fn patch_path(patch: &ParsedFilePatch) -> &str {
    &patch.path
}

fn move_path(patch: &ParsedFilePatch) -> Option<&str> {
    patch.move_path.as_deref()
}

fn mutation_paths(patch: &ParsedFilePatch) -> Vec<String> {
    match move_path(patch) {
        Some(destination) if destination != patch_path(patch) => {
            vec![destination.to_owned(), patch.path.clone()]
        }
        _ => vec![patch.path.clone()],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilePatchOperation {
    Create,
    Update,
    Delete,
}

pub(super) fn validate_absolute_patch_path(path: &str) -> BridgeResult<()> {
    if path.len() > MAX_PATCH_PATH_BYTES {
        return Err(patch_too_large(
            "patch path exceeds the compiled byte limit",
        ));
    }
    if path.len() < 2 || !path.starts_with('/') {
        return Err(invalid_patch("patch path is not canonical"));
    }
    for component in path[1..].split('/') {
        if component == ".." {
            return Err(BridgeError::new(
                ErrorCode::PathOutsideRoot,
                "patch path contains traversal",
                false,
            ));
        }
        if component.is_empty() || component == "." {
            return Err(invalid_patch("patch path is not canonical"));
        }
    }
    Ok(())
}

pub(super) fn invalid_patch(message: &'static str) -> BridgeError {
    BridgeError::invalid_argument(message)
}

pub(super) fn patch_too_large(message: &'static str) -> BridgeError {
    BridgeError::new(ErrorCode::RequestTooLarge, message, false)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PatchedFile {
    Write(Vec<u8>),
    Delete,
}

pub(super) fn write_conflict(message: &'static str) -> BridgeError {
    BridgeError::new(ErrorCode::WriteConflict, message, false)
}

#[derive(Debug)]
struct ResolvedFilePatch {
    patch: ParsedFilePatch,
    source: super::write::PreparedMutationPath,
    destination: Option<super::write::PreparedMutationPath>,
}

#[derive(Debug)]
struct PatchSnapshots {
    source: FileSnapshot,
    destination: Option<FileSnapshot>,
}

#[derive(Debug)]
pub(super) enum FileSnapshot {
    Missing,
    Regular {
        bytes: Vec<u8>,
        sha256: String,
        mode: u32,
    },
}

impl FileSnapshot {
    fn base(&self) -> Option<(&[u8], &str)> {
        match self {
            Self::Missing => None,
            Self::Regular { bytes, sha256, .. } => Some((bytes, sha256)),
        }
    }

    fn sha256(&self) -> Option<&str> {
        match self {
            Self::Missing => None,
            Self::Regular { sha256, .. } => Some(sha256),
        }
    }
}

enum PreparedMutation {
    Write(Box<super::write::ResolvedWrite>),
    Delete(Box<super::write::ResolvedDelete>),
}

fn resolve_patch_files(
    bridge: &RemoteBridge,
    host: &str,
    patches: Vec<ParsedFilePatch>,
) -> BridgeResult<Vec<ResolvedFilePatch>> {
    patches
        .into_iter()
        .map(|patch| {
            let failed_path = patch_path(&patch).to_owned();
            (|| {
                let source = super::write::prepare_patch_path(bridge, host, patch_path(&patch))?;
                let destination = match move_path(&patch) {
                    Some(destination) if destination != patch_path(&patch) => Some(
                        super::write::prepare_patch_path(bridge, host, destination).map_err(
                            |mut error| {
                                error.details.failed_path = Some(destination.to_owned());
                                error
                            },
                        )?,
                    ),
                    _ => None,
                };
                Ok(ResolvedFilePatch {
                    patch,
                    source,
                    destination,
                })
            })()
            .map_err(|mut error: BridgeError| {
                if error.details.failed_path.is_none() {
                    error.details.failed_path = Some(failed_path);
                }
                error
            })
        })
        .collect()
}

#[derive(Clone, Copy)]
struct SnapshotBatchItem<'a> {
    path: &'a super::write::PreparedMutationPath,
    display_path: &'a str,
}

async fn snapshot_files(
    bridge: &RemoteBridge,
    host: &str,
    items: &[SnapshotBatchItem<'_>],
    maximum_bytes: usize,
    cancel: CancellationToken,
) -> BridgeResult<(Vec<FileSnapshot>, RemoteContext)> {
    if items.is_empty() {
        return Err(snapshot_protocol_error("snapshot batch is empty"));
    }
    let limits = bridge.runner.config().limits();
    let protocol_limit = SNAPSHOT_PROTOCOL_BYTES
        .checked_mul(items.len())
        .ok_or_else(|| patch_too_large("snapshot protocol limit overflowed"))?;
    let capture_metadata_limit = SNAPSHOT_CAPTURE_METADATA_BYTES
        .checked_mul(items.len())
        .ok_or_else(|| patch_too_large("snapshot metadata limit overflowed"))?;
    let desired_stdout_limit = u64::try_from(maximum_bytes)
        .ok()
        .and_then(|maximum| maximum.checked_add(1))
        .ok_or_else(|| patch_too_large("snapshot output limit overflowed"))?;
    let available_stdout = limits
        .max_output_bytes
        .checked_sub(
            u64::try_from(capture_metadata_limit)
                .map_err(|_| patch_too_large("snapshot metadata limit is not representable"))?,
        )
        .filter(|available| *available > 0)
        .ok_or_else(|| patch_too_large("snapshot protocol reserve exceeds the output limit"))?;
    let stdout_limit = desired_stdout_limit.min(available_stdout);
    let snapshot_maximum = usize::try_from(stdout_limit - 1)
        .map_err(|_| patch_too_large("snapshot output limit is not representable"))?;
    let snapshot_read_limit = snapshot_maximum
        .checked_add(1)
        .ok_or_else(|| patch_too_large("snapshot output limit overflowed"))?;
    let mut args = Vec::with_capacity(items.len().saturating_mul(3));
    for item in items {
        args.extend([
            item.path.parent().to_owned(),
            item.path.basename().to_owned(),
            snapshot_maximum.to_string(),
        ]);
    }
    let owner = InternalSpoolOwner::new();
    let result = bridge
        .execute_readonly_fixed(
            FixedRunRequest {
                kind: FixedOperationKind::ReadOnly,
                host: host.to_owned(),
                script: PATCH_SNAPSHOT_SCRIPT,
                args,
                stdin: None,
                rooted_paths: RootedPathInputs {
                    argument_indices: &[],
                    argument_stride: Some(RootedArgumentStride { start: 0, step: 3 }),
                    stdin_nul_paths: false,
                },
                required_capabilities: &["safe_write"],
                stdout_limit,
                stderr_limit: u64::try_from(capture_metadata_limit)
                    .map_err(|_| patch_too_large("snapshot metadata limit is not representable"))?,
                timeout: Duration::from_millis(limits.command_timeout_ms),
                cleanup: owner.registration(),
            },
            cancel,
        )
        .await
        .map_err(|error| {
            let error = snapshot_runner_error(error);
            if error.code == ErrorCode::RequestTooLarge {
                snapshot_item_error(
                    error,
                    items
                        .last()
                        .expect("non-empty snapshot batch has no final item")
                        .display_path,
                )
            } else {
                error
            }
        })?;
    let operation_context = context(
        host.to_owned(),
        result.capability.physical_root.clone(),
        &result.shell,
        result.helper_mode,
    );
    let attach = |error| attach_fixed_result_context(error, host, &result);
    let stderr = read_small_stream(&result.output, StreamKind::Stderr, protocol_limit)
        .await
        .map_err(|error| {
            let error = if error.code == ErrorCode::OutputLimit {
                snapshot_protocol_error("snapshot metadata exceeds the protocol limit")
            } else {
                error
            };
            snapshot_item_error(
                error,
                items
                    .last()
                    .expect("non-empty snapshot batch has no final item")
                    .display_path,
            )
        })
        .map_err(&attach)?;
    let stdout = read_small_stream(&result.output, StreamKind::Stdout, snapshot_read_limit)
        .await
        .map_err(|error| {
            let error = if error.code == ErrorCode::OutputLimit {
                patch_too_large("snapshot exceeded the aggregate base limit")
            } else {
                error
            };
            snapshot_item_error(
                error,
                items
                    .last()
                    .expect("non-empty snapshot batch has no final item")
                    .display_path,
            )
        })
        .map_err(&attach)?;
    let snapshots =
        parse_snapshot_batch_protocol(&stderr, stdout, snapshot_maximum, items).map_err(&attach)?;
    drop(owner);
    Ok((snapshots, operation_context))
}

fn snapshot_runner_error(mut error: BridgeError) -> BridgeError {
    if error.code == ErrorCode::OutputLimit {
        error.code = ErrorCode::RequestTooLarge;
        error.message = "snapshot exceeded the aggregate base limit".to_owned();
        error.retryable = false;
    }
    error
}

pub(super) fn parse_snapshot_protocol(
    stderr: &[u8],
    stdout: Vec<u8>,
    maximum_bytes: usize,
) -> BridgeResult<FileSnapshot> {
    let fields = nul_fields(stderr)?;
    parse_snapshot_fields(&fields, stdout, maximum_bytes)
}

fn parse_snapshot_batch_protocol(
    stderr: &[u8],
    stdout: Vec<u8>,
    maximum_bytes: usize,
    items: &[SnapshotBatchItem<'_>],
) -> BridgeResult<Vec<FileSnapshot>> {
    if stdout.len() > maximum_bytes {
        let mut error = patch_too_large("patch base exceeds the configured write limit");
        if let Some(item) = items.last() {
            error.details.failed_path = Some(item.display_path.to_owned());
        }
        return Err(error);
    }
    let fields = nul_fields(stderr).map_err(|error| match items.last() {
        Some(item) => snapshot_item_error(error, item.display_path),
        None => error,
    })?;
    let mut field_offset = 0usize;
    let mut stdout_offset = 0usize;
    let mut snapshots = Vec::with_capacity(items.len());
    for item in items {
        let status = fields.get(field_offset).copied().ok_or_else(|| {
            snapshot_item_error(
                snapshot_protocol_error("snapshot status is missing"),
                item.display_path,
            )
        })?;
        let field_count = if status == b"STATUS=SUCCESS" { 7 } else { 1 };
        let field_end = field_offset.checked_add(field_count).ok_or_else(|| {
            snapshot_item_error(
                snapshot_protocol_error("snapshot field count overflowed"),
                item.display_path,
            )
        })?;
        let record = fields.get(field_offset..field_end).ok_or_else(|| {
            snapshot_item_error(
                snapshot_protocol_error("snapshot protocol record is incomplete"),
                item.display_path,
            )
        })?;
        let raw = if status == b"STATUS=SUCCESS" {
            let size = parse_snapshot_u64(record[1], b"SIZE=")
                .and_then(|size| {
                    usize::try_from(size)
                        .map_err(|_| snapshot_protocol_error("snapshot size is not representable"))
                })
                .map_err(|error| snapshot_item_error(error, item.display_path))?;
            if size > maximum_bytes {
                return Err(snapshot_item_error(
                    patch_too_large("patch base exceeds the configured write limit"),
                    item.display_path,
                ));
            }
            let stdout_end = stdout_offset.checked_add(size).ok_or_else(|| {
                snapshot_item_error(BridgeError::read_conflict(), item.display_path)
            })?;
            let bytes = stdout.get(stdout_offset..stdout_end).ok_or_else(|| {
                snapshot_item_error(BridgeError::read_conflict(), item.display_path)
            })?;
            stdout_offset = stdout_end;
            bytes.to_vec()
        } else {
            Vec::new()
        };
        let snapshot = parse_snapshot_fields(record, raw, maximum_bytes)
            .map_err(|error| snapshot_item_error(error, item.display_path))?;
        snapshots.push(snapshot);
        field_offset = field_end;
    }
    if field_offset != fields.len() || stdout_offset != stdout.len() {
        let mut error = snapshot_protocol_error("snapshot batch contains trailing data");
        if let Some(item) = items.last() {
            error.details.failed_path = Some(item.display_path.to_owned());
        }
        return Err(error);
    }
    Ok(snapshots)
}

fn snapshot_item_error(mut error: BridgeError, display_path: &str) -> BridgeError {
    if error.details.failed_path.is_none() {
        error.details.failed_path = Some(display_path.to_owned());
    }
    error
}

fn parse_snapshot_fields(
    fields: &[&[u8]],
    stdout: Vec<u8>,
    maximum_bytes: usize,
) -> BridgeResult<FileSnapshot> {
    let status = fields
        .first()
        .copied()
        .ok_or_else(|| snapshot_protocol_error("snapshot status is missing"))?;
    if status == b"STATUS=READ_CONFLICT" {
        if fields.len() != 1 {
            return Err(snapshot_protocol_error(
                "snapshot read-conflict record is invalid",
            ));
        }
        return Err(BridgeError::read_conflict());
    }
    if status != b"STATUS=SUCCESS" && !stdout.is_empty() {
        return Err(snapshot_protocol_error(
            "snapshot non-success produced raw content",
        ));
    }
    if status == b"STATUS=SUCCESS" && stdout.len() > maximum_bytes {
        return Err(patch_too_large(
            "patch base exceeds the configured write limit",
        ));
    }
    match (status, fields) {
        (b"STATUS=MISSING", [_]) => Ok(FileSnapshot::Missing),
        (b"STATUS=WRITE_CONFLICT", [_]) => {
            Err(write_conflict("patch base conflicts with the request"))
        }
        (b"STATUS=NOT_FOUND", [_]) => Err(BridgeError::not_found()),
        (b"STATUS=PERMISSION_DENIED", [_]) => Err(BridgeError::permission_denied()),
        (b"STATUS=NOT_DIRECTORY", [_]) => Err(BridgeError::not_directory()),
        (b"STATUS=REQUEST_TOO_LARGE", [_]) => Err(patch_too_large(
            "patch base exceeds the configured write limit",
        )),
        (b"STATUS=SUCCESS", [_, size, sha256, mode, device, inode, links]) => {
            let size = parse_snapshot_u64(size, b"SIZE=")?;
            let device = parse_snapshot_u64(device, b"DEVICE=")?;
            let inode = parse_snapshot_u64(inode, b"INODE=")?;
            let links = parse_snapshot_u64(links, b"LINKS=")?;
            let mode = snapshot_text(mode, b"MODE=")?;
            if mode.is_empty()
                || mode.len() > 4
                || !mode.bytes().all(|byte| (b'0'..=b'7').contains(&byte))
            {
                return Err(snapshot_protocol_error("snapshot mode is invalid"));
            }
            let mode = u32::from_str_radix(mode, 8)
                .map_err(|_| snapshot_protocol_error("snapshot mode is invalid"))?;
            if mode & 0o7000 != 0 {
                return Err(write_conflict("patch base has unsafe special mode bits"));
            }
            let _identity = (device, inode, links, mode);
            let sha256 = snapshot_text(sha256, b"SHA256=")?;
            if !valid_snapshot_hash(sha256) {
                return Err(snapshot_protocol_error("snapshot hash is invalid"));
            }
            let expected_size = usize::try_from(size)
                .map_err(|_| snapshot_protocol_error("snapshot size is not representable"))?;
            if expected_size > maximum_bytes {
                return Err(patch_too_large(
                    "patch base exceeds the configured write limit",
                ));
            }
            let actual_hash = format!("{:x}", Sha256::digest(&stdout));
            if stdout.len() != expected_size || actual_hash != sha256 {
                return Err(BridgeError::read_conflict());
            }
            Ok(FileSnapshot::Regular {
                bytes: stdout,
                sha256: sha256.to_owned(),
                mode,
            })
        }
        _ => Err(snapshot_protocol_error(
            "snapshot protocol record is invalid",
        )),
    }
}

fn parse_snapshot_u64(record: &[u8], prefix: &[u8]) -> BridgeResult<u64> {
    let value = record
        .strip_prefix(prefix)
        .ok_or_else(|| snapshot_protocol_error("snapshot numeric field is invalid"))?;
    parse_u64(value).map_err(|_| snapshot_protocol_error("snapshot numeric field is invalid"))
}

fn snapshot_text<'a>(record: &'a [u8], prefix: &[u8]) -> BridgeResult<&'a str> {
    let value = record
        .strip_prefix(prefix)
        .ok_or_else(|| snapshot_protocol_error("snapshot text field is invalid"))?;
    utf8(value).map_err(|_| snapshot_protocol_error("snapshot text field is invalid"))
}

fn valid_snapshot_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn snapshot_protocol_error(message: &'static str) -> BridgeError {
    BridgeError::new(ErrorCode::ProtocolError, message, false)
}

fn attach_preparation_progress(
    mut error: BridgeError,
    failed_path: Option<&str>,
    all_paths: &[String],
) -> BridgeError {
    if let Some(failed_path) = failed_path {
        error.details.failed_path = Some(failed_path.to_owned());
    }
    error.details.changed_paths = Some(Vec::new());
    error.details.not_changed_paths = Some(all_paths.to_vec());
    error.details.outcome_unknown_paths = Some(Vec::new());
    error
}

fn attach_mutation_progress(
    mut error: BridgeError,
    current: usize,
    all_paths: &[String],
) -> BridgeError {
    let current_path = &all_paths[current];
    let outcome_unknown = error.code == ErrorCode::MutationOutcomeUnknown
        || error.details.mutation_may_have_applied == Some(true);
    error.details.changed_paths = Some(all_paths[..current].to_vec());
    if outcome_unknown {
        error.details.failed_path = Some(current_path.clone());
        error.details.not_changed_paths = Some(all_paths[current + 1..].to_vec());
        error.details.outcome_unknown_paths = Some(vec![current_path.clone()]);
    } else {
        error.details.failed_path =
            (error.code != ErrorCode::Cancelled).then(|| current_path.clone());
        error.details.not_changed_paths = Some(all_paths[current..].to_vec());
        error.details.outcome_unknown_paths = Some(Vec::new());
    }
    error
}

fn attach_mutation_progress_context(
    error: BridgeError,
    current: usize,
    all_paths: &[String],
    context: &RemoteContext,
) -> BridgeError {
    attach_remote_context(attach_mutation_progress(error, current, all_paths), context)
}

pub(super) async fn apply_patch(
    bridge: &RemoteBridge,
    request: ApplyPatchRequest,
    cancel: CancellationToken,
) -> BridgeResult<ApplyPatchResult> {
    if !bridge.edit_buffering_enabled {
        return apply_patch_immediate(bridge, request, cancel).await;
    }
    let immediate_request = request.clone();
    let ApplyPatchRequest { host, patch } = request;
    bridge.runner.config().require_discovered_alias(&host)?;
    let maximum_bytes = bridge.runner.config().limits().max_write_bytes;
    if patch.len() > maximum_bytes {
        return Err(patch_too_large(
            "patch exceeds the effective host write limit",
        ));
    }
    let payload_bytes = patch.len();
    let patches = super::codex_patch::parse_codex_patch(&patch, &host)?;
    let all_paths = patches.iter().flat_map(mutation_paths).collect::<Vec<_>>();
    let resolved = resolve_patch_files(bridge, &host, patches)
        .map_err(|error| attach_preparation_progress(error, None, &all_paths))?;
    if resolved.is_empty() {
        return Err(attach_preparation_progress(
            invalid_patch("patch contains no file operations"),
            None,
            &all_paths,
        ));
    }
    if cancel.is_cancelled() {
        return Err(attach_preparation_progress(
            BridgeError::new(ErrorCode::Cancelled, "remote patch was cancelled", false),
            None,
            &all_paths,
        ));
    }
    let mut prepared = Vec::with_capacity(all_paths.len());
    let mut remaining_output_bytes = maximum_bytes;
    let mut remaining_payload_bytes = payload_bytes;
    for file in resolved {
        if cancel.is_cancelled() {
            return Err(attach_preparation_progress(
                BridgeError::new(ErrorCode::Cancelled, "remote patch was cancelled", false),
                Some(patch_path(&file.patch)),
                &all_paths,
            ));
        }
        let source_key = CacheKey {
            host: host.clone(),
            path: patch_path(&file.patch).to_owned(),
        };
        let source_current = match bridge
            .edit_cache
            .load_entry_complete(source_key.clone())
            .await
            .map_err(edit_bridge_error)
            .map_err(|error| {
                attach_preparation_progress(error, Some(patch_path(&file.patch)), &all_paths)
            })? {
            LoadEntryDisposition::Cached(current) => current,
            LoadEntryDisposition::ImmediateWriteRequired => {
                bridge
                    .edit_cache
                    .flush_host(&host)
                    .await
                    .map_err(edit_bridge_error)?;
                let result = apply_patch_immediate(bridge, immediate_request, cancel).await?;
                bridge.edit_cache.invalidate_clean_host(&host).await;
                return Ok(result);
            }
        };
        let destination_current = if let Some(destination) = move_path(&file.patch) {
            if destination == patch_path(&file.patch) {
                None
            } else {
                let destination_key = CacheKey {
                    host: host.clone(),
                    path: destination.to_owned(),
                };
                let current = match bridge
                    .edit_cache
                    .load_entry_complete(destination_key.clone())
                    .await
                    .map_err(edit_bridge_error)
                    .map_err(|error| {
                        attach_preparation_progress(error, Some(destination), &all_paths)
                    })? {
                    LoadEntryDisposition::Cached(current) => current,
                    LoadEntryDisposition::ImmediateWriteRequired => {
                        bridge
                            .edit_cache
                            .flush_host(&host)
                            .await
                            .map_err(edit_bridge_error)?;
                        let result =
                            apply_patch_immediate(bridge, immediate_request, cancel).await?;
                        bridge.edit_cache.invalidate_clean_host(&host).await;
                        return Ok(result);
                    }
                };
                Some((destination_key, current))
            }
        } else {
            None
        };
        let current_hash = match &source_current.desired {
            DesiredState::Present(bytes) => Some(format!("{:x}", Sha256::digest(bytes))),
            DesiredState::Deleted => None,
        };
        let base = match &source_current.desired {
            DesiredState::Present(bytes) => {
                Some((bytes.as_ref(), current_hash.as_deref().unwrap()))
            }
            DesiredState::Deleted => None,
        };
        let output = super::codex_patch::apply_codex_file(
            base.map(|(bytes, _sha256)| bytes),
            &file.patch,
            remaining_output_bytes,
        )
        .map_err(|error| {
            attach_preparation_progress(error, Some(patch_path(&file.patch)), &all_paths)
        })?;
        let desired = match output {
            PatchedFile::Write(bytes) => {
                remaining_output_bytes = remaining_output_bytes
                    .checked_sub(bytes.len())
                    .ok_or_else(|| {
                        attach_preparation_progress(
                            patch_too_large("patch outputs exceed the aggregate write limit"),
                            Some(patch_path(&file.patch)),
                            &all_paths,
                        )
                    })?;
                DesiredState::Present(bytes.into())
            }
            PatchedFile::Delete => DesiredState::Deleted,
        };
        if let Some((destination_key, destination_current)) = destination_current {
            let DesiredState::Present(bytes) = desired else {
                return Err(attach_preparation_progress(
                    invalid_patch("Codex patch move did not produce file content"),
                    Some(patch_path(&file.patch)),
                    &all_paths,
                ));
            };
            prepared.push(PreparedEdit {
                key: destination_key,
                expected_generation: destination_current.generation,
                desired: DesiredState::Present(bytes),
                payload_bytes: std::mem::take(&mut remaining_payload_bytes),
            });
            prepared.push(PreparedEdit {
                key: source_key,
                expected_generation: source_current.generation,
                desired: DesiredState::Deleted,
                payload_bytes: 0,
            });
        } else {
            prepared.push(PreparedEdit {
                key: source_key,
                expected_generation: source_current.generation,
                desired,
                payload_bytes: std::mem::take(&mut remaining_payload_bytes),
            });
        }
    }
    match bridge
        .edit_cache
        .mutate_prepared_batch(prepared)
        .await
        .map_err(edit_bridge_error)?
    {
        BatchMutationDisposition::Buffered(_) => {
            let context = bridge
                .edit_backend
                .context_for(&host)
                .await
                .ok_or_else(|| {
                    BridgeError::new(ErrorCode::ProtocolError, "edit context is missing", false)
                })?;
            Ok(ApplyPatchResult {
                context,
                changed_paths: all_paths,
            })
        }
        BatchMutationDisposition::ImmediateWriteRequired => {
            bridge
                .edit_cache
                .flush_host(&host)
                .await
                .map_err(edit_bridge_error)?;
            let result = apply_patch_immediate(bridge, immediate_request, cancel).await?;
            bridge.edit_cache.invalidate_clean_host(&host).await;
            Ok(result)
        }
    }
}

async fn apply_patch_immediate(
    bridge: &RemoteBridge,
    request: ApplyPatchRequest,
    cancel: CancellationToken,
) -> BridgeResult<ApplyPatchResult> {
    let ApplyPatchRequest { host, patch } = request;
    bridge.runner.config().require_discovered_alias(&host)?;
    let maximum_bytes = bridge.runner.config().limits().max_write_bytes;
    if patch.len() > maximum_bytes {
        return Err(patch_too_large(
            "patch exceeds the effective host write limit",
        ));
    }
    let patches = super::codex_patch::parse_codex_patch(&patch, &host)?;
    drop(patch);
    let all_paths = patches.iter().flat_map(mutation_paths).collect::<Vec<_>>();
    let resolved = resolve_patch_files(bridge, &host, patches)
        .map_err(|error| attach_preparation_progress(error, None, &all_paths))?;
    if cancel.is_cancelled() {
        return Err(attach_preparation_progress(
            BridgeError::new(ErrorCode::Cancelled, "remote patch was cancelled", false),
            None,
            &all_paths,
        ));
    }
    let mut batch_items = Vec::with_capacity(resolved.len().saturating_mul(2));
    for file in &resolved {
        batch_items.push(SnapshotBatchItem {
            path: &file.source,
            display_path: patch_path(&file.patch),
        });
        if let Some(destination_path) = &file.destination {
            let display_path = file
                .patch
                .move_path
                .as_deref()
                .expect("resolved move destination has no patch path");
            batch_items.push(SnapshotBatchItem {
                path: destination_path,
                display_path,
            });
        }
    }
    let (batch_snapshots, operation_context) =
        snapshot_files(bridge, &host, &batch_items, maximum_bytes, cancel.clone())
            .await
            .map_err(|error| {
                let failed_path = error.details.failed_path.clone();
                attach_preparation_progress(error, failed_path.as_deref(), &all_paths)
            })?;
    let mut batch_snapshots = batch_snapshots.into_iter();
    let mut snapshots = Vec::with_capacity(resolved.len());
    let mut remaining_base_bytes = maximum_bytes;
    for file in &resolved {
        let source = batch_snapshots.next().ok_or_else(|| {
            attach_remote_context(
                attach_preparation_progress(
                    snapshot_protocol_error("snapshot batch result is incomplete"),
                    Some(patch_path(&file.patch)),
                    &all_paths,
                ),
                &operation_context,
            )
        })?;
        if let FileSnapshot::Regular { bytes, .. } = &source {
            remaining_base_bytes =
                remaining_base_bytes
                    .checked_sub(bytes.len())
                    .ok_or_else(|| {
                        attach_remote_context(
                            attach_preparation_progress(
                                patch_too_large("patch bases exceed the aggregate write limit"),
                                Some(patch_path(&file.patch)),
                                &all_paths,
                            ),
                            &operation_context,
                        )
                    })?;
        }
        let destination = if file.destination.is_some() {
            let display_path = file
                .patch
                .move_path
                .as_deref()
                .expect("resolved move destination has no patch path");
            let destination = batch_snapshots.next().ok_or_else(|| {
                attach_remote_context(
                    attach_preparation_progress(
                        snapshot_protocol_error("snapshot batch result is incomplete"),
                        Some(display_path),
                        &all_paths,
                    ),
                    &operation_context,
                )
            })?;
            if let FileSnapshot::Regular { bytes, .. } = &destination {
                remaining_base_bytes =
                    remaining_base_bytes
                        .checked_sub(bytes.len())
                        .ok_or_else(|| {
                            attach_remote_context(
                                attach_preparation_progress(
                                    patch_too_large("patch bases exceed the aggregate write limit"),
                                    Some(display_path),
                                    &all_paths,
                                ),
                                &operation_context,
                            )
                        })?;
            }
            Some(destination)
        } else {
            None
        };
        snapshots.push(PatchSnapshots {
            source,
            destination,
        });
    }
    if batch_snapshots.next().is_some() {
        return Err(attach_remote_context(
            attach_preparation_progress(
                snapshot_protocol_error("snapshot batch contains excess results"),
                None,
                &all_paths,
            ),
            &operation_context,
        ));
    }
    let attach_after_snapshots = |error, failed_path: Option<String>| {
        attach_remote_context(
            attach_preparation_progress(error, failed_path.as_deref(), &all_paths),
            &operation_context,
        )
    };

    let mut outputs = Vec::with_capacity(resolved.len());
    let mut remaining_output_bytes = maximum_bytes;
    for (file, snapshots) in resolved.into_iter().zip(snapshots) {
        let output = super::codex_patch::apply_codex_file(
            snapshots.source.base().map(|(bytes, _sha256)| bytes),
            &file.patch,
            remaining_output_bytes,
        )
        .map_err(|error| attach_after_snapshots(error, Some(file.patch.path.clone())))?;
        if let PatchedFile::Write(bytes) = &output {
            remaining_output_bytes =
                remaining_output_bytes
                    .checked_sub(bytes.len())
                    .ok_or_else(|| {
                        attach_after_snapshots(
                            patch_too_large("patch outputs exceed the aggregate write limit"),
                            Some(file.patch.path.clone()),
                        )
                    })?;
        }
        outputs.push((file, output, snapshots));
    }

    let mut prepared_mutations = Vec::with_capacity(all_paths.len());
    for (file, output, snapshots) in outputs {
        let source_path = file.patch.path.clone();
        let source_expected_sha256 = snapshots.source.sha256().map(str::to_owned);
        if let Some(destination) = file.destination {
            let destination_path = file
                .patch
                .move_path
                .as_deref()
                .expect("resolved move destination has no patch path")
                .to_owned();
            let bytes = match output {
                PatchedFile::Write(bytes) => bytes,
                PatchedFile::Delete => {
                    return Err(attach_after_snapshots(
                        invalid_patch("Codex patch move did not produce file content"),
                        Some(source_path),
                    ));
                }
            };
            let destination_snapshot = snapshots.destination.ok_or_else(|| {
                attach_after_snapshots(
                    snapshot_protocol_error("move destination snapshot is missing"),
                    Some(destination_path.clone()),
                )
            })?;
            let mode = match destination_snapshot {
                FileSnapshot::Missing => WriteMode::Create,
                FileSnapshot::Regular { sha256, .. } => WriteMode::Replace {
                    expected_sha256: Some(sha256),
                },
            };
            let content = String::from_utf8(bytes).map_err(|_| {
                attach_after_snapshots(
                    snapshot_protocol_error("prepared patch output is not UTF-8"),
                    Some(source_path.clone()),
                )
            })?;
            let write = super::write::preflight_write_resolved(
                bridge,
                destination,
                content,
                WriteEncoding::Utf8,
                mode,
            )
            .map_err(|error| attach_after_snapshots(error, Some(destination_path)))?;
            prepared_mutations.push(PreparedMutation::Write(Box::new(write)));

            let expected_sha256 = source_expected_sha256.ok_or_else(|| {
                attach_after_snapshots(
                    write_conflict("patch move source has no regular base"),
                    Some(source_path.clone()),
                )
            })?;
            let delete =
                super::write::preflight_delete_resolved(bridge, file.source, expected_sha256)
                    .map_err(|error| attach_after_snapshots(error, Some(source_path)))?;
            prepared_mutations.push(PreparedMutation::Delete(Box::new(delete)));
            continue;
        }

        let prepared = match output {
            PatchedFile::Write(bytes) => {
                let mode = match file.patch.operation {
                    FilePatchOperation::Create => WriteMode::Create,
                    FilePatchOperation::Update => WriteMode::Replace {
                        expected_sha256: source_expected_sha256,
                    },
                    FilePatchOperation::Delete => {
                        return Err(attach_after_snapshots(
                            invalid_patch("patch delete produced a write frame"),
                            Some(source_path),
                        ));
                    }
                };
                let content = String::from_utf8(bytes).map_err(|_| {
                    attach_after_snapshots(
                        snapshot_protocol_error("prepared patch output is not UTF-8"),
                        Some(source_path.clone()),
                    )
                })?;
                PreparedMutation::Write(Box::new(
                    super::write::preflight_write_resolved(
                        bridge,
                        file.source,
                        content,
                        WriteEncoding::Utf8,
                        mode,
                    )
                    .map_err(|error| attach_after_snapshots(error, Some(source_path)))?,
                ))
            }
            PatchedFile::Delete => {
                let expected_sha256 = source_expected_sha256.ok_or_else(|| {
                    attach_after_snapshots(
                        write_conflict("patch delete has no regular base"),
                        Some(source_path.clone()),
                    )
                })?;
                PreparedMutation::Delete(Box::new(
                    super::write::preflight_delete_resolved(bridge, file.source, expected_sha256)
                        .map_err(|error| attach_after_snapshots(error, Some(source_path)))?,
                ))
            }
        };
        prepared_mutations.push(prepared);
    }
    let mut changed_paths = Vec::with_capacity(prepared_mutations.len());
    for (index, prepared) in prepared_mutations.into_iter().enumerate() {
        if cancel.is_cancelled() {
            return Err(attach_mutation_progress_context(
                BridgeError::new(ErrorCode::Cancelled, "remote patch was cancelled", false),
                index,
                &all_paths,
                &operation_context,
            ));
        }
        let result = match prepared {
            PreparedMutation::Write(resolved) => {
                super::write::execute_preflighted_write_at_root(bridge, *resolved, cancel.clone())
                    .await
                    .map(|result| result.context)
            }
            PreparedMutation::Delete(resolved) => {
                super::write::execute_preflighted_delete_at_root(bridge, *resolved, cancel.clone())
                    .await
                    .map(|(_result, context)| context)
            }
        };
        match result {
            Ok(_) => changed_paths.push(all_paths[index].clone()),
            Err(error) => {
                return Err(attach_mutation_progress_context(
                    error,
                    index,
                    &all_paths,
                    &operation_context,
                ));
            }
        }
    }
    Ok(ApplyPatchResult {
        context: operation_context,
        changed_paths,
    })
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use crate::{BridgeError, ErrorCode};

    #[test]
    fn mutation_progress_classifies_pre_spawn_cancel_as_definite_suffix() {
        let paths = ["a", "b", "c"].map(str::to_owned);
        let error = super::attach_mutation_progress(
            BridgeError::new(ErrorCode::Cancelled, "keep this cancellation", false),
            1,
            &paths,
        );

        assert_eq!(error.code, ErrorCode::Cancelled);
        assert_eq!(error.message, "keep this cancellation");
        assert_eq!(error.details.failed_path, None);
        assert_eq!(error.details.changed_paths, Some(vec!["a".to_owned()]));
        assert_eq!(
            error.details.not_changed_paths,
            Some(vec!["b".to_owned(), "c".to_owned()])
        );
        assert_eq!(error.details.outcome_unknown_paths, Some(Vec::new()));
        assert_eq!(error.details.mutation_may_have_applied, None);
    }

    #[test]
    fn local_post_snapshot_cancel_retains_context_and_definite_suffix() {
        let paths = ["a", "b", "c"].map(str::to_owned);
        let context = super::RemoteContext {
            remote: true,
            host: "dev".to_owned(),
            physical_root: "/srv/app".to_owned(),
            shell: super::super::ShellMetadata {
                kind: super::super::ShellName::Sh,
                version: None,
                fallback: false,
            },
            helper_mode: None,
        };
        let error = super::attach_mutation_progress_context(
            BridgeError::new(ErrorCode::Cancelled, "cancelled", false),
            1,
            &paths,
            &context,
        );

        assert_eq!(error.code, ErrorCode::Cancelled);
        assert_eq!(error.details.failed_path, None);
        assert_eq!(error.details.changed_paths, Some(vec!["a".to_owned()]));
        assert_eq!(
            error.details.not_changed_paths,
            Some(vec!["b".to_owned(), "c".to_owned()])
        );
        assert_eq!(error.details.outcome_unknown_paths, Some(Vec::new()));
        assert_eq!(error.details.host.as_deref(), Some("dev"));
        assert_eq!(error.details.physical_root.as_deref(), Some("/srv/app"));
        assert_eq!(error.details.shell.unwrap().kind, "sh");
    }

    #[test]
    fn patch_preflight_consumes_the_already_resolved_path() {
        let production = include_str!("patch.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let resolved_write = concat!("preflight_write", "_resolved(");
        let resolved_delete = concat!("preflight_delete", "_resolved(");
        let public_write = concat!("preflight_", "write(bridge");
        let public_delete = concat!("preflight_", "delete(");

        assert!(production.contains(resolved_write));
        assert!(production.contains(resolved_delete));
        assert!(!production.contains(public_write));
        assert!(!production.contains(public_delete));
    }

    #[test]
    fn snapshot_script_and_protocol_are_closed() {
        assert!(super::PATCH_SNAPSHOT_SCRIPT.contains("[ \"$#\" -ge 3 ]"));
        assert!(super::PATCH_SNAPSHOT_SCRIPT.contains("$(( $# % 3 ))"));
        assert!(super::PATCH_SNAPSHOT_SCRIPT.contains("while [ \"$#\" -gt 0 ]"));
        assert!(!super::PATCH_SNAPSHOT_SCRIPT.contains("operation=$3"));

        let raw = vec![b'x'; 1_048_577];
        let hash = format!("{:x}", Sha256::digest(&raw));
        let metadata = format!(
            "STATUS=SUCCESS\0SIZE={}\0SHA256={hash}\0MODE=600\0DEVICE=1\0INODE=2\0LINKS=1\0",
            raw.len()
        );
        let snapshot =
            super::parse_snapshot_protocol(metadata.as_bytes(), raw.clone(), raw.len()).unwrap();
        let super::FileSnapshot::Regular {
            bytes,
            sha256,
            mode,
        } = snapshot
        else {
            panic!("success did not produce a regular snapshot");
        };
        assert_eq!(bytes, raw);
        assert_eq!(sha256, hash);
        assert_eq!(mode, 0o600);

        let maximum = 64;
        let declared = vec![b'x'; maximum];
        let declared_hash = format!("{:x}", Sha256::digest(&declared));
        let success_metadata = format!(
            "STATUS=SUCCESS\0SIZE={maximum}\0SHA256={declared_hash}\0MODE=600\0DEVICE=1\0INODE=2\0LINKS=1\0"
        );
        let maximum_plus_one = vec![b'x'; maximum + 1];
        assert_eq!(
            super::parse_snapshot_protocol(
                success_metadata.as_bytes(),
                maximum_plus_one.clone(),
                maximum,
            )
            .unwrap_err()
            .code,
            ErrorCode::RequestTooLarge
        );

        assert_eq!(
            super::parse_snapshot_protocol(
                b"STATUS=READ_CONFLICT\0",
                maximum_plus_one.clone(),
                maximum,
            )
            .unwrap_err()
            .code,
            ErrorCode::ReadConflict
        );
        assert_eq!(
            super::parse_snapshot_protocol(b"STATUS=WRITE_CONFLICT\0", maximum_plus_one, maximum)
                .unwrap_err()
                .code,
            ErrorCode::ProtocolError
        );
        for malformed in [
            b"STATUS=SUCCESS\0".as_slice(),
            b"STATUS=MISSING".as_slice(),
            b"STATUS=MISSING\0EXTRA=1\0".as_slice(),
            b"STATUS=READ_CONFLICT\0EXTRA=1\0".as_slice(),
        ] {
            assert_eq!(
                super::parse_snapshot_protocol(malformed, Vec::new(), 64)
                    .unwrap_err()
                    .code,
                ErrorCode::ProtocolError,
                "metadata={malformed:?}"
            );
        }
    }
}
