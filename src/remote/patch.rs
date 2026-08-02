use std::collections::BTreeSet;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::error::{BridgeError, BridgeResult, ErrorCode};
use crate::output::{InternalSpoolOwner, StreamKind};
use crate::ssh::{FixedOperationKind, FixedRunRequest, RootedPathInputs};

use super::edit_cache::{
    BatchMutationDisposition, CacheKey, DesiredState, LoadEntryDisposition, PreparedEdit,
};
use super::protocol::{context, nul_fields, parse_u64, read_small_stream, utf8};
use super::{
    ApplyPatchRequest, ApplyPatchResult, RemoteBridge, RemoteContext, WriteEncoding, WriteMode,
    attach_fixed_result_context, attach_optional_remote_context, attach_remote_context,
    edit_bridge_error,
};

pub(super) const MAX_PATCH_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_PATCH_FILES: usize = 32;
pub(super) const MAX_PATCH_HUNKS: usize = 4_096;
pub(super) const MAX_PATCH_BODY_LINES: usize = 100_000;
pub(super) const MAX_PATCH_PATH_BYTES: usize = 64 * 1024;
const NO_NEWLINE_MARKER: &str = "\\ No newline at end of file";
pub(super) const SNAPSHOT_PROTOCOL_BYTES: usize = 1024;
pub(super) const SNAPSHOT_CAPTURE_METADATA_BYTES: usize = 2048;

pub(super) const PATCH_SNAPSHOT_SCRIPT: &str = r#"
set -u
[ "$#" -eq 3 ] || exit 2
parent=$1
basename=$2
maximum_size=$3
[ -n "$basename" ] || exit 2
case "$basename" in .|..|*/*) exit 2 ;; esac
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

codex_snapshot_decimal_valid "$maximum_size" || exit 2
emit_one() {
    printf 'STATUS=%s\000' "$1" >&2
    exit 0
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
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilePatch {
    pub path: String,
    pub operation: FilePatchOperation,
    pub hunks: Vec<Hunk>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParsedFilePatch {
    Unified(FilePatch),
    Codex(super::codex_patch::CodexFilePatch),
}

impl ParsedFilePatch {
    fn path(&self) -> &str {
        match self {
            Self::Unified(patch) => &patch.path,
            Self::Codex(patch) => &patch.path,
        }
    }

    fn operation(&self) -> FilePatchOperation {
        match self {
            Self::Unified(patch) => patch.operation,
            Self::Codex(patch) => patch.operation,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilePatchOperation {
    Create,
    Update,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hunk {
    pub old: HunkRange,
    pub new: HunkRange,
    pub lines: Vec<HunkLine>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HunkRange {
    pub start: usize,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HunkLine {
    pub kind: HunkLineKind,
    pub text: String,
    pub has_lf: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HunkLineKind {
    Context,
    Remove,
    Add,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HeaderPath {
    Null,
    Relative(String),
    Absolute(String),
}

#[derive(Debug, Clone, Copy)]
struct RecordCursor<'a> {
    remainder: &'a str,
    finished: bool,
}

impl<'a> RecordCursor<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            remainder: input,
            finished: input.is_empty(),
        }
    }

    fn peek(&self) -> Option<&'a str> {
        if self.finished {
            return None;
        }
        Some(match self.remainder.find('\n') {
            Some(end) => &self.remainder[..end],
            None => self.remainder,
        })
    }

    fn next(&mut self) -> Option<&'a str> {
        if self.finished {
            return None;
        }
        match self.remainder.find('\n') {
            Some(end) => {
                let record = &self.remainder[..end];
                self.remainder = &self.remainder[end + 1..];
                self.finished = self.remainder.is_empty();
                Some(record)
            }
            None => {
                self.finished = true;
                Some(self.remainder)
            }
        }
    }
}

pub(crate) fn parse_patch(input: &str) -> BridgeResult<Vec<FilePatch>> {
    if input.len() > MAX_PATCH_BYTES {
        return Err(patch_too_large("patch exceeds the compiled byte limit"));
    }
    if input.as_bytes().contains(&0) {
        return Err(invalid_patch("patch contains NUL"));
    }

    let mut records = RecordCursor::new(input);
    if records.peek().is_none() {
        return Err(invalid_patch("patch is empty"));
    }

    let mut patches = Vec::new();
    let mut paths = BTreeSet::new();
    let mut total_hunks = 0usize;
    let mut total_body_lines = 0usize;

    while records.peek().is_some() {
        if patches.len() == MAX_PATCH_FILES {
            return Err(patch_too_large("patch contains too many files"));
        }
        let old = parse_header_path(
            records
                .next()
                .ok_or_else(|| invalid_patch("patch old-file header is missing"))?,
            "--- ",
            "a/",
            "patch old-file header is invalid",
        )?;
        let new_record = records
            .next()
            .ok_or_else(|| invalid_patch("patch new-file header is missing"))?;
        let new = parse_header_path(new_record, "+++ ", "b/", "patch new-file header is invalid")?;

        let (path, operation) = classify_headers(old, new)?;
        if !paths.insert(path.clone()) {
            return Err(invalid_patch("patch contains a duplicate path"));
        }

        let mut hunks = Vec::new();
        let mut changed = false;
        while records
            .peek()
            .is_some_and(|record| record.starts_with("@@ -"))
        {
            total_hunks = total_hunks
                .checked_add(1)
                .ok_or_else(|| patch_too_large("patch hunk count overflowed"))?;
            if total_hunks > MAX_PATCH_HUNKS {
                return Err(patch_too_large("patch contains too many hunks"));
            }

            let header = records
                .next()
                .ok_or_else(|| invalid_patch("patch hunk header is missing"))?;
            let (old, new) = parse_hunk_header(header)?;
            let mut lines = Vec::new();
            let mut old_used = 0usize;
            let mut new_used = 0usize;

            while old_used < old.count || new_used < new.count {
                let record = records
                    .peek()
                    .ok_or_else(|| invalid_patch("patch hunk body is incomplete"))?;
                if record == NO_NEWLINE_MARKER {
                    mark_previous_no_newline(&mut lines)?;
                    records.next();
                    continue;
                }

                let (kind, text) = parse_body_record(record)?;
                match kind {
                    HunkLineKind::Context => {
                        old_used = increment_hunk_count(old_used, old.count)?;
                        new_used = increment_hunk_count(new_used, new.count)?;
                    }
                    HunkLineKind::Remove => {
                        old_used = increment_hunk_count(old_used, old.count)?;
                        changed = true;
                    }
                    HunkLineKind::Add => {
                        new_used = increment_hunk_count(new_used, new.count)?;
                        changed = true;
                    }
                }
                total_body_lines = total_body_lines
                    .checked_add(1)
                    .ok_or_else(|| patch_too_large("patch body count overflowed"))?;
                if total_body_lines > MAX_PATCH_BODY_LINES {
                    return Err(patch_too_large("patch contains too many body lines"));
                }
                lines.push(HunkLine {
                    kind,
                    text: text.to_owned(),
                    has_lf: true,
                });
                records.next();
            }
            if records.peek() == Some(NO_NEWLINE_MARKER) {
                mark_previous_no_newline(&mut lines)?;
                records.next();
            }
            if old_used != old.count || new_used != new.count {
                return Err(invalid_patch("patch hunk body count is invalid"));
            }
            hunks.push(Hunk { old, new, lines });
        }

        if hunks.is_empty() {
            return Err(invalid_patch("patch file has no hunks"));
        }
        if !changed {
            return Err(invalid_patch("patch file has no changes"));
        }
        validate_operation_hunks(operation, &hunks)?;
        validate_no_newline_positions(&hunks)?;
        if records
            .peek()
            .is_some_and(|record| !record.starts_with("--- "))
        {
            return Err(invalid_patch("patch contains an unexpected record"));
        }
        patches.push(FilePatch {
            path,
            operation,
            hunks,
        });
    }

    Ok(patches)
}

pub(crate) fn parse_request_patch(input: &str) -> BridgeResult<Vec<ParsedFilePatch>> {
    if input.len() > MAX_PATCH_BYTES {
        return Err(patch_too_large("patch exceeds the compiled byte limit"));
    }
    if input.as_bytes().contains(&0) {
        return Err(invalid_patch("patch contains NUL"));
    }
    let input = input.trim_start_matches('\n');
    let first = input
        .lines()
        .next()
        .ok_or_else(|| invalid_patch("patch is empty"))?;
    if first == "*** Begin Patch" {
        return super::codex_patch::parse_codex_patch(input)
            .map(|patches| patches.into_iter().map(ParsedFilePatch::Codex).collect());
    }
    if first.starts_with("--- ") {
        return parse_patch(input)
            .map(|patches| patches.into_iter().map(ParsedFilePatch::Unified).collect());
    }
    Err(invalid_patch("patch syntax is not recognized"))
}

fn parse_header_path(
    record: &str,
    header_prefix: &str,
    path_prefix: &str,
    message: &'static str,
) -> BridgeResult<HeaderPath> {
    let value = record
        .strip_prefix(header_prefix)
        .ok_or_else(|| invalid_patch(message))?;
    if value.contains(['\0', '\t', '\r', '\n']) {
        return Err(invalid_patch(message));
    }
    if value == "/dev/null" {
        return Ok(HeaderPath::Null);
    }
    let path = if let Some(path) = value.strip_prefix(path_prefix) {
        path
    } else if value.starts_with('/') {
        value
    } else {
        return Err(invalid_patch(message));
    };
    if path.starts_with('/') {
        validate_absolute_patch_path(path)?;
        Ok(HeaderPath::Absolute(path.to_owned()))
    } else {
        validate_patch_path(path)?;
        Ok(HeaderPath::Relative(path.to_owned()))
    }
}

fn validate_patch_path(path: &str) -> BridgeResult<()> {
    if path.len() > MAX_PATCH_PATH_BYTES {
        return Err(patch_too_large(
            "patch path exceeds the compiled byte limit",
        ));
    }
    if path.is_empty() || path.starts_with('/') {
        return Err(invalid_patch("patch path is not canonical"));
    }
    for component in path.split('/') {
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

fn classify_headers(
    old: HeaderPath,
    new: HeaderPath,
) -> BridgeResult<(String, FilePatchOperation)> {
    match (old, new) {
        (HeaderPath::Relative(old), HeaderPath::Relative(new)) if old == new => {
            Ok((old, FilePatchOperation::Update))
        }
        (HeaderPath::Absolute(old), HeaderPath::Absolute(new)) if old == new => {
            Ok((old, FilePatchOperation::Update))
        }
        (HeaderPath::Null, HeaderPath::Relative(new)) => Ok((new, FilePatchOperation::Create)),
        (HeaderPath::Null, HeaderPath::Absolute(new)) => Ok((new, FilePatchOperation::Create)),
        (HeaderPath::Relative(old), HeaderPath::Null) => Ok((old, FilePatchOperation::Delete)),
        (HeaderPath::Absolute(old), HeaderPath::Null) => Ok((old, FilePatchOperation::Delete)),
        _ => Err(invalid_patch(
            "patch file headers do not name one operation",
        )),
    }
}

fn parse_hunk_header(record: &str) -> BridgeResult<(HunkRange, HunkRange)> {
    if record.contains(['\0', '\r', '\n']) {
        return Err(invalid_patch("patch hunk header is invalid"));
    }
    let rest = record
        .strip_prefix("@@ -")
        .ok_or_else(|| invalid_patch("patch hunk header is invalid"))?;
    let (old, rest) = rest
        .split_once(" +")
        .ok_or_else(|| invalid_patch("patch hunk header is invalid"))?;
    let (new, suffix) = rest
        .split_once(" @@")
        .ok_or_else(|| invalid_patch("patch hunk header is invalid"))?;
    if !suffix.is_empty()
        && suffix
            .strip_prefix(' ')
            .is_none_or(|section| section.is_empty())
    {
        return Err(invalid_patch("patch hunk header is invalid"));
    }
    Ok((parse_range(old)?, parse_range(new)?))
}

fn parse_range(value: &str) -> BridgeResult<HunkRange> {
    let mut fields = value.split(',');
    let start = parse_usize(fields.next().unwrap_or_default())?;
    let count = match fields.next() {
        Some(count) => parse_usize(count)?,
        None => 1,
    };
    if fields.next().is_some() || (count > 0 && start == 0) {
        return Err(invalid_patch("patch hunk range is invalid"));
    }
    if count > 0 {
        start
            .checked_sub(1)
            .and_then(|zero_based| zero_based.checked_add(count))
            .ok_or_else(|| invalid_patch("patch hunk range end overflowed"))?;
    }
    Ok(HunkRange { start, count })
}

fn parse_usize(value: &str) -> BridgeResult<usize> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_patch("patch hunk number is invalid"));
    }
    value
        .parse::<usize>()
        .map_err(|_| invalid_patch("patch hunk number is invalid"))
}

fn parse_body_record(record: &str) -> BridgeResult<(HunkLineKind, &str)> {
    let (prefix, text) = record
        .split_at_checked(1)
        .ok_or_else(|| invalid_patch("patch hunk body record is invalid"))?;
    let kind = match prefix.as_bytes()[0] {
        b' ' => HunkLineKind::Context,
        b'-' => HunkLineKind::Remove,
        b'+' => HunkLineKind::Add,
        _ => return Err(invalid_patch("patch hunk body record is invalid")),
    };
    Ok((kind, text))
}

fn increment_hunk_count(current: usize, maximum: usize) -> BridgeResult<usize> {
    let next = current
        .checked_add(1)
        .ok_or_else(|| invalid_patch("patch hunk body count overflowed"))?;
    if next > maximum {
        return Err(invalid_patch("patch hunk body count is invalid"));
    }
    Ok(next)
}

fn mark_previous_no_newline(lines: &mut [HunkLine]) -> BridgeResult<()> {
    let line = lines
        .last_mut()
        .ok_or_else(|| invalid_patch("patch no-newline marker is orphaned"))?;
    if !line.has_lf {
        return Err(invalid_patch("patch no-newline marker is duplicated"));
    }
    if line.text.is_empty() {
        return Err(invalid_patch(
            "patch no-newline marker cannot describe an empty record",
        ));
    }
    line.has_lf = false;
    Ok(())
}

fn validate_operation_hunks(operation: FilePatchOperation, hunks: &[Hunk]) -> BridgeResult<()> {
    match operation {
        FilePatchOperation::Create
            if hunks
                .iter()
                .any(|hunk| hunk.old != (HunkRange { start: 0, count: 0 })) =>
        {
            Err(invalid_patch("patch create has old-file content"))
        }
        FilePatchOperation::Delete if hunks.iter().any(|hunk| hunk.new.count != 0) => {
            Err(invalid_patch("patch delete has new-file content"))
        }
        _ => Ok(()),
    }
}

fn validate_no_newline_positions(hunks: &[Hunk]) -> BridgeResult<()> {
    let mut last_old = None;
    let mut last_new = None;
    for (hunk_index, hunk) in hunks.iter().enumerate() {
        for (line_index, line) in hunk.lines.iter().enumerate() {
            let position = (hunk_index, line_index);
            match line.kind {
                HunkLineKind::Context => {
                    last_old = Some(position);
                    last_new = Some(position);
                }
                HunkLineKind::Remove => last_old = Some(position),
                HunkLineKind::Add => last_new = Some(position),
            }
        }
    }
    for (hunk_index, hunk) in hunks.iter().enumerate() {
        for (line_index, line) in hunk.lines.iter().enumerate() {
            if line.has_lf {
                continue;
            }
            let position = Some((hunk_index, line_index));
            let valid = match line.kind {
                HunkLineKind::Context => position == last_old && position == last_new,
                HunkLineKind::Remove => position == last_old,
                HunkLineKind::Add => position == last_new,
            };
            if !valid {
                return Err(invalid_patch("patch no-newline marker is not final"));
            }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LogicalLine<'a> {
    text: &'a str,
    has_lf: bool,
}

#[derive(Debug, Clone, Copy)]
struct LogicalLineCursor<'a> {
    remainder: &'a str,
    consumed: usize,
}

impl<'a> LogicalLineCursor<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            remainder: input,
            consumed: 0,
        }
    }

    fn next(&mut self) -> BridgeResult<Option<LogicalLine<'a>>> {
        if self.remainder.is_empty() {
            return Ok(None);
        }
        let (text, has_lf, remainder) = match self.remainder.find('\n') {
            Some(end) => (&self.remainder[..end], true, &self.remainder[end + 1..]),
            None => (self.remainder, false, ""),
        };
        self.remainder = remainder;
        self.consumed = self
            .consumed
            .checked_add(1)
            .ok_or_else(|| invalid_patch("base logical-line count overflowed"))?;
        Ok(Some(LogicalLine { text, has_lf }))
    }
}

struct OutputBuilder {
    bytes: Vec<u8>,
    logical_lines: usize,
    can_append: bool,
    maximum_bytes: usize,
}

impl OutputBuilder {
    fn new(maximum_bytes: usize) -> Self {
        Self {
            bytes: Vec::new(),
            logical_lines: 0,
            can_append: true,
            maximum_bytes,
        }
    }

    fn append(&mut self, line: LogicalLine<'_>) -> BridgeResult<()> {
        if !self.can_append {
            return Err(write_conflict("patch output follows a non-LF logical line"));
        }
        let added = line
            .text
            .len()
            .checked_add(usize::from(line.has_lf))
            .ok_or_else(|| patch_too_large("patched file size overflowed"))?;
        let new_len = self
            .bytes
            .len()
            .checked_add(added)
            .ok_or_else(|| patch_too_large("patched file size overflowed"))?;
        if new_len > self.maximum_bytes {
            return Err(patch_too_large(
                "patched file exceeds the compiled byte limit",
            ));
        }
        self.logical_lines = self
            .logical_lines
            .checked_add(1)
            .ok_or_else(|| patch_too_large("patched logical-line count overflowed"))?;
        self.bytes.extend_from_slice(line.text.as_bytes());
        if line.has_lf {
            self.bytes.push(b'\n');
        }
        self.can_append = line.has_lf;
        Ok(())
    }
}

pub(super) fn apply_file_patch(
    base: Option<(&[u8], &str)>,
    patch: &FilePatch,
    maximum_output_bytes: usize,
) -> BridgeResult<PatchedFile> {
    let base_bytes = match (patch.operation, base) {
        (FilePatchOperation::Create, None) => &[][..],
        (FilePatchOperation::Update | FilePatchOperation::Delete, Some((bytes, sha256))) => {
            let _expected_sha256 = sha256;
            bytes
        }
        _ => {
            return Err(write_conflict(
                "patch base presence does not match operation",
            ));
        }
    };
    let base_text =
        std::str::from_utf8(base_bytes).map_err(|_| invalid_patch("patch base is not UTF-8"))?;
    if base_bytes.contains(&0) {
        return Err(invalid_patch("patch base contains NUL"));
    }

    let mut base_lines = LogicalLineCursor::new(base_text);
    let mut output = OutputBuilder::new(maximum_output_bytes);
    let mut previous_zero_old_anchor = None;
    let mut previous_zero_new_anchor = None;

    for hunk in &patch.hunks {
        let old_anchor = range_anchor(hunk.old)?;
        let new_anchor = range_anchor(hunk.new)?;
        if hunk.old.count == 0 {
            if previous_zero_old_anchor == Some(old_anchor) {
                return Err(invalid_patch("patch repeats a zero-count old anchor"));
            }
            previous_zero_old_anchor = Some(old_anchor);
        }
        if hunk.new.count == 0 {
            if previous_zero_new_anchor == Some(new_anchor) {
                return Err(invalid_patch("patch repeats a zero-count new anchor"));
            }
            previous_zero_new_anchor = Some(new_anchor);
        }
        if old_anchor < base_lines.consumed {
            return Err(invalid_patch("patch hunks overlap or move backwards"));
        }
        while base_lines.consumed < old_anchor {
            let line = base_lines
                .next()?
                .ok_or_else(|| write_conflict("patch old position exceeds the base"))?;
            output.append(line)?;
        }
        if output.logical_lines != new_anchor {
            return Err(invalid_patch("patch new position is inconsistent"));
        }

        for line in &hunk.lines {
            match line.kind {
                HunkLineKind::Context | HunkLineKind::Remove => {
                    let base_line = base_lines
                        .next()?
                        .ok_or_else(|| write_conflict("patch expects missing base content"))?;
                    if base_line.text != line.text || base_line.has_lf != line.has_lf {
                        return Err(write_conflict("patch base content does not match"));
                    }
                    if line.kind == HunkLineKind::Context {
                        output.append(base_line)?;
                    }
                }
                HunkLineKind::Add => output.append(LogicalLine {
                    text: &line.text,
                    has_lf: line.has_lf,
                })?,
            }
        }
    }

    while let Some(line) = base_lines.next()? {
        output.append(line)?;
    }

    match patch.operation {
        FilePatchOperation::Create if output.bytes.is_empty() => {
            Err(invalid_patch("patch create produced an empty file"))
        }
        FilePatchOperation::Delete if !output.bytes.is_empty() => {
            Err(invalid_patch("patch delete produced file content"))
        }
        FilePatchOperation::Delete => Ok(PatchedFile::Delete),
        FilePatchOperation::Update if output.bytes.as_slice() == base_bytes => Err(write_conflict(
            "patch update would leave the file unchanged",
        )),
        FilePatchOperation::Create | FilePatchOperation::Update => {
            Ok(PatchedFile::Write(output.bytes))
        }
    }
}

pub(crate) fn apply_parsed_file(
    base: Option<(&[u8], &str)>,
    patch: &ParsedFilePatch,
    maximum_output_bytes: usize,
) -> BridgeResult<PatchedFile> {
    match patch {
        ParsedFilePatch::Unified(patch) => apply_file_patch(base, patch, maximum_output_bytes),
        ParsedFilePatch::Codex(patch) => super::codex_patch::apply_codex_file(
            base.map(|(bytes, _sha256)| bytes),
            patch,
            maximum_output_bytes,
        ),
    }
}

fn range_anchor(range: HunkRange) -> BridgeResult<usize> {
    if range.count == 0 {
        Ok(range.start)
    } else {
        range
            .start
            .checked_sub(1)
            .ok_or_else(|| invalid_patch("patch hunk range is invalid"))
    }
}

pub(super) fn write_conflict(message: &'static str) -> BridgeError {
    BridgeError::new(ErrorCode::WriteConflict, message, false)
}

#[derive(Debug)]
struct ResolvedFilePatch {
    patch: ParsedFilePatch,
    path: super::write::PreparedMutationPath,
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
            let failed_path = patch.path().to_owned();
            (|| {
                let path = super::write::prepare_patch_path(bridge, host, patch.path())?;
                Ok(ResolvedFilePatch { patch, path })
            })()
            .map_err(|mut error: BridgeError| {
                error.details.failed_path = Some(failed_path);
                error
            })
        })
        .collect()
}

async fn snapshot_file(
    bridge: &RemoteBridge,
    host: &str,
    resolved: &ResolvedFilePatch,
    maximum_bytes: usize,
    cancel: CancellationToken,
) -> BridgeResult<(FileSnapshot, RemoteContext)> {
    let limits = bridge.runner.config().limits();
    let desired_stdout_limit = u64::try_from(maximum_bytes)
        .ok()
        .and_then(|maximum| maximum.checked_add(1))
        .ok_or_else(|| patch_too_large("snapshot output limit overflowed"))?;
    let available_stdout = limits
        .max_output_bytes
        .checked_sub(SNAPSHOT_CAPTURE_METADATA_BYTES as u64)
        .filter(|available| *available > 0)
        .ok_or_else(|| patch_too_large("snapshot protocol reserve exceeds the output limit"))?;
    let stdout_limit = desired_stdout_limit.min(available_stdout);
    let snapshot_maximum = usize::try_from(stdout_limit - 1)
        .map_err(|_| patch_too_large("snapshot output limit is not representable"))?;
    let snapshot_read_limit = snapshot_maximum
        .checked_add(1)
        .ok_or_else(|| patch_too_large("snapshot output limit overflowed"))?;
    let owner = InternalSpoolOwner::new();
    let result = bridge
        .execute_readonly_fixed(
            FixedRunRequest {
                kind: FixedOperationKind::ReadOnly,
                host: host.to_owned(),
                script: PATCH_SNAPSHOT_SCRIPT,
                args: vec![
                    resolved.path.parent().to_owned(),
                    resolved.path.basename().to_owned(),
                    snapshot_maximum.to_string(),
                ],
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
            cancel,
        )
        .await
        .map_err(snapshot_runner_error)?;
    let operation_context = context(
        host.to_owned(),
        result.capability.physical_root.clone(),
        &result.shell,
        result.helper_mode,
    );
    let attach = |error| attach_fixed_result_context(error, host, &result);
    let stderr = read_small_stream(&result.output, StreamKind::Stderr, SNAPSHOT_PROTOCOL_BYTES)
        .await
        .map_err(|error| {
            if error.code == ErrorCode::OutputLimit {
                snapshot_protocol_error("snapshot metadata exceeds the protocol limit")
            } else {
                error
            }
        })
        .map_err(&attach)?;
    let stdout = read_small_stream(&result.output, StreamKind::Stdout, snapshot_read_limit)
        .await
        .map_err(|error| {
            if error.code == ErrorCode::OutputLimit {
                patch_too_large("snapshot exceeded the aggregate base limit")
            } else {
                error
            }
        })
        .map_err(&attach)?;
    let snapshot = parse_snapshot_protocol(&stderr, stdout, snapshot_maximum).map_err(&attach)?;
    drop(owner);
    Ok((snapshot, operation_context))
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
    match (status, fields.as_slice()) {
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
    let patches = parse_request_patch(&patch)?;
    let all_paths = patches
        .iter()
        .map(|patch| patch.path().to_owned())
        .collect::<Vec<_>>();
    let resolved = resolve_patch_files(bridge, &host, patches)
        .map_err(|error| attach_preparation_progress(error, None, &all_paths))?;
    if cancel.is_cancelled() {
        return Err(attach_preparation_progress(
            BridgeError::new(ErrorCode::Cancelled, "remote patch was cancelled", false),
            None,
            &all_paths,
        ));
    }
    let mut prepared = Vec::with_capacity(resolved.len());
    let mut remaining_output_bytes = maximum_bytes;
    for (index, file) in resolved.into_iter().enumerate() {
        if cancel.is_cancelled() {
            return Err(attach_preparation_progress(
                BridgeError::new(ErrorCode::Cancelled, "remote patch was cancelled", false),
                Some(file.patch.path()),
                &all_paths,
            ));
        }
        let key = CacheKey {
            host: host.clone(),
            path: file.patch.path().to_owned(),
        };
        let current = match bridge
            .edit_cache
            .load_entry_complete(key.clone())
            .await
            .map_err(edit_bridge_error)
            .map_err(|error| {
                attach_preparation_progress(error, Some(file.patch.path()), &all_paths)
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
        let current_hash = match &current.desired {
            DesiredState::Present(bytes) => Some(format!("{:x}", Sha256::digest(bytes))),
            DesiredState::Deleted => None,
        };
        let base = match &current.desired {
            DesiredState::Present(bytes) => {
                Some((bytes.as_ref(), current_hash.as_deref().unwrap()))
            }
            DesiredState::Deleted => None,
        };
        let output =
            apply_parsed_file(base, &file.patch, remaining_output_bytes).map_err(|error| {
                attach_preparation_progress(error, Some(file.patch.path()), &all_paths)
            })?;
        let desired = match output {
            PatchedFile::Write(bytes) => {
                remaining_output_bytes = remaining_output_bytes
                    .checked_sub(bytes.len())
                    .ok_or_else(|| {
                        attach_preparation_progress(
                            patch_too_large("patch outputs exceed the aggregate write limit"),
                            Some(file.patch.path()),
                            &all_paths,
                        )
                    })?;
                DesiredState::Present(bytes.into())
            }
            PatchedFile::Delete => DesiredState::Deleted,
        };
        prepared.push(PreparedEdit {
            key,
            expected_generation: current.generation,
            desired,
            payload_bytes: if index == 0 { payload_bytes } else { 0 },
        });
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
    let patches = parse_request_patch(&patch)?;
    drop(patch);
    let all_paths = patches
        .iter()
        .map(|patch| patch.path().to_owned())
        .collect::<Vec<_>>();
    let resolved = resolve_patch_files(bridge, &host, patches)
        .map_err(|error| attach_preparation_progress(error, None, &all_paths))?;
    let mut snapshots = Vec::with_capacity(resolved.len());
    let mut remaining_base_bytes = maximum_bytes;
    let mut operation_context: Option<RemoteContext> = None;
    for file in &resolved {
        if cancel.is_cancelled() {
            let error = attach_preparation_progress(
                BridgeError::new(ErrorCode::Cancelled, "remote patch was cancelled", false),
                None,
                &all_paths,
            );
            return Err(match &operation_context {
                Some(context) => attach_remote_context(error, context),
                None => error,
            });
        }
        let (snapshot, snapshot_context) =
            snapshot_file(bridge, &host, file, remaining_base_bytes, cancel.clone())
                .await
                .map_err(|error| {
                    attach_optional_remote_context(
                        attach_preparation_progress(error, Some(file.patch.path()), &all_paths),
                        operation_context.as_ref(),
                    )
                })?;
        if let Some(context) = &operation_context
            && context.host != snapshot_context.host
        {
            return Err(attach_remote_context(
                attach_preparation_progress(
                    BridgeError::read_conflict(),
                    Some(file.patch.path()),
                    &all_paths,
                ),
                &snapshot_context,
            ));
        }
        if let FileSnapshot::Regular { bytes, .. } = &snapshot {
            remaining_base_bytes =
                remaining_base_bytes
                    .checked_sub(bytes.len())
                    .ok_or_else(|| {
                        attach_remote_context(
                            attach_preparation_progress(
                                patch_too_large("patch bases exceed the aggregate write limit"),
                                Some(file.patch.path()),
                                &all_paths,
                            ),
                            &snapshot_context,
                        )
                    })?;
        }
        if operation_context.is_none() {
            operation_context = Some(snapshot_context);
        }
        snapshots.push(snapshot);
    }

    let operation_context = operation_context.ok_or_else(|| {
        attach_preparation_progress(
            invalid_patch("patch contains no file operations"),
            None,
            &all_paths,
        )
    })?;
    let attach_after_snapshots = |error, failed_path: Option<String>| {
        attach_remote_context(
            attach_preparation_progress(error, failed_path.as_deref(), &all_paths),
            &operation_context,
        )
    };

    let mut outputs = Vec::with_capacity(resolved.len());
    let mut remaining_output_bytes = maximum_bytes;
    for (file, snapshot) in resolved.into_iter().zip(snapshots) {
        let output = apply_parsed_file(snapshot.base(), &file.patch, remaining_output_bytes)
            .map_err(|error| attach_after_snapshots(error, Some(file.patch.path().to_owned())))?;
        if let PatchedFile::Write(bytes) = &output {
            remaining_output_bytes =
                remaining_output_bytes
                    .checked_sub(bytes.len())
                    .ok_or_else(|| {
                        attach_after_snapshots(
                            patch_too_large("patch outputs exceed the aggregate write limit"),
                            Some(file.patch.path().to_owned()),
                        )
                    })?;
        }
        let expected_sha256 = snapshot.sha256().map(str::to_owned);
        outputs.push((file, output, expected_sha256));
    }

    let mut prepared_mutations = Vec::with_capacity(outputs.len());
    for (file, output, expected_sha256) in outputs {
        let prepared = match output {
            PatchedFile::Write(bytes) => {
                let mode = match file.patch.operation() {
                    FilePatchOperation::Create => WriteMode::Create,
                    FilePatchOperation::Update => WriteMode::Replace { expected_sha256 },
                    FilePatchOperation::Delete => {
                        return Err(attach_after_snapshots(
                            invalid_patch("patch delete produced a write frame"),
                            Some(file.patch.path().to_owned()),
                        ));
                    }
                };
                let content = String::from_utf8(bytes).map_err(|_| {
                    attach_after_snapshots(
                        snapshot_protocol_error("prepared patch output is not UTF-8"),
                        Some(file.patch.path().to_owned()),
                    )
                })?;
                PreparedMutation::Write(Box::new(
                    super::write::preflight_write_resolved(
                        bridge,
                        file.path,
                        content,
                        WriteEncoding::Utf8,
                        mode,
                    )
                    .map_err(|error| {
                        attach_after_snapshots(error, Some(file.patch.path().to_owned()))
                    })?,
                ))
            }
            PatchedFile::Delete => {
                let expected_sha256 = expected_sha256.ok_or_else(|| {
                    attach_after_snapshots(
                        write_conflict("patch delete has no regular base"),
                        Some(file.patch.path().to_owned()),
                    )
                })?;
                PreparedMutation::Delete(Box::new(
                    super::write::preflight_delete_resolved(bridge, file.path, expected_sha256)
                        .map_err(|error| {
                            attach_after_snapshots(error, Some(file.patch.path().to_owned()))
                        })?,
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
    use std::fmt::Write as _;

    use sha2::{Digest, Sha256};

    use crate::{BridgeError, ErrorCode};

    fn apply(base: Option<&[u8]>, patch: &str) -> crate::BridgeResult<super::PatchedFile> {
        let parsed = super::parse_patch(patch)?;
        assert_eq!(parsed.len(), 1);
        let sha256 = base.map(|bytes| format!("{:x}", Sha256::digest(bytes)));
        super::apply_file_patch(
            base.zip(sha256.as_deref()),
            &parsed[0],
            super::MAX_PATCH_BYTES,
        )
    }

    fn apply_request(base: Option<&[u8]>, patch: &str) -> crate::BridgeResult<super::PatchedFile> {
        let parsed = super::parse_request_patch(patch)?;
        assert_eq!(parsed.len(), 1);
        let sha256 = base.map(|bytes| format!("{:x}", Sha256::digest(bytes)));
        super::apply_parsed_file(
            base.zip(sha256.as_deref()),
            &parsed[0],
            super::MAX_PATCH_BYTES,
        )
    }

    #[test]
    fn codex_and_unified_create_produce_identical_bytes() {
        let codex = concat!(
            "*** Begin Patch\n",
            "*** Add File: /srv/repo/new.txt\n",
            "+alpha\n",
            "+beta\n",
            "*** End Patch\n",
        );
        let unified = concat!(
            "--- /dev/null\n",
            "+++ /srv/repo/new.txt\n",
            "@@ -0,0 +1,2 @@\n",
            "+alpha\n",
            "+beta\n",
        );

        assert_eq!(
            apply_request(None, codex).unwrap(),
            apply_request(None, unified).unwrap(),
        );
    }

    #[test]
    fn codex_update_uses_ordered_context_matching() {
        let patch = concat!(
            "*** Begin Patch\n",
            "*** Update File: /srv/repo/a.txt\n",
            "@@ section two\n",
            "-old\n",
            "+new\n",
            "*** End Patch\n",
        );

        assert_eq!(
            apply_request(Some(b"old\nsection two\nold\n"), patch).unwrap(),
            super::PatchedFile::Write(b"old\nsection two\nnew\n".to_vec()),
        );
    }

    #[test]
    fn codex_pure_addition_inserts_after_context() {
        let patch = concat!(
            "*** Begin Patch\n",
            "*** Update File: /srv/repo/a.txt\n",
            "@@ fn target()\n",
            "+inserted\n",
            "*** End Patch\n",
        );

        assert_eq!(
            apply_request(Some(b"fn target()\nend\n"), patch).unwrap(),
            super::PatchedFile::Write(b"fn target()\ninserted\nend\n".to_vec()),
        );
    }

    #[test]
    fn codex_end_of_file_matches_only_the_final_sequence() {
        let patch = concat!(
            "*** Begin Patch\n",
            "*** Update File: /srv/repo/a.txt\n",
            "-repeat\n",
            "+final\n",
            "*** End of File\n",
            "\n",
            "*** End Patch\n",
        );

        assert_eq!(
            apply_request(Some(b"repeat\nmiddle\nrepeat\n"), patch).unwrap(),
            super::PatchedFile::Write(b"repeat\nmiddle\nfinal\n".to_vec()),
        );
    }

    #[test]
    fn codex_update_normalizes_a_missing_terminal_newline() {
        let patch = concat!(
            "*** Begin Patch\n",
            "*** Update File: /srv/repo/a.txt\n",
            "-old\n",
            "+new\n",
            "*** End Patch\n",
        );

        assert_eq!(
            apply_request(Some(b"old"), patch).unwrap(),
            super::PatchedFile::Write(b"new\n".to_vec()),
        );
    }

    #[test]
    fn codex_delete_matches_unified_delete() {
        let codex = concat!(
            "*** Begin Patch\n",
            "*** Delete File: /srv/repo/old.txt\n",
            "*** End Patch\n",
        );
        let unified = concat!(
            "--- /srv/repo/old.txt\n",
            "+++ /dev/null\n",
            "@@ -1 +0,0 @@\n",
            "-old\n",
        );

        assert_eq!(
            apply_request(Some(b"old\n"), codex).unwrap(),
            apply_request(Some(b"old\n"), unified).unwrap(),
        );
    }

    #[test]
    fn request_parser_rejects_unsupported_or_mixed_codex_syntax() {
        for input in [
            "*** Begin Patch\n*** Move to: /srv/repo/b\n*** End Patch\n",
            "*** Begin Patch\n*** Add File: relative.txt\n+x\n*** End Patch\n",
            "*** Begin Patch\n*** Add File: /srv/repo/a\n+x\n*** End Patch\ntrailing\n",
            concat!(
                "*** Begin Patch\n",
                "--- /dev/null\n",
                "+++ /srv/repo/a\n",
                "@@ -0,0 +1 @@\n",
                "+x\n",
                "*** End Patch\n",
            ),
        ] {
            assert_eq!(
                super::parse_request_patch(input).unwrap_err().code,
                ErrorCode::InvalidArgument,
                "{input:?}",
            );
        }
    }

    #[test]
    fn task6_mutation_progress_classifies_pre_spawn_cancel_as_definite_suffix() {
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
    fn task78_local_post_snapshot_cancel_retains_context_and_definite_suffix() {
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
    fn task6_patch_preflight_consumes_the_already_resolved_path() {
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
    fn task6_snapshot_script_and_protocol_are_closed() {
        assert!(super::PATCH_SNAPSHOT_SCRIPT.contains("[ \"$#\" -eq 3 ]"));
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
            super::parse_snapshot_protocol(b"STATUS=WRITE_CONFLICT\0", maximum_plus_one, maximum,)
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

    #[test]
    fn task6_parse_accepts_multiple_files_hunks_and_terminal_eof() {
        let patch = concat!(
            "--- a/a.txt\n",
            "+++ b/a.txt\n",
            "@@ -1,2 +1,2 @@ first\n",
            " one\n",
            "-two\n",
            "+TWO\n",
            "@@ -4 +4 @@\n",
            "-four\n",
            "+FOUR\n",
            "--- /dev/null\n",
            "+++ b/new.txt\n",
            "@@ -0,0 +1 @@\n",
            "+created",
        );
        let parsed = super::parse_patch(patch).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].path, "a.txt");
        assert_eq!(parsed[0].operation, super::FilePatchOperation::Update);
        assert_eq!(parsed[0].hunks.len(), 2);
        assert_eq!(parsed[1].path, "new.txt");
        assert_eq!(parsed[1].operation, super::FilePatchOperation::Create);
        assert_eq!(
            parsed[1].hunks[0].new,
            super::HunkRange { start: 1, count: 1 }
        );
        assert_eq!(parsed[1].hunks[0].lines[0].text, "created");
        assert!(parsed[1].hunks[0].lines[0].has_lf);
    }

    #[test]
    fn task6_parse_freezes_no_newline_marker_on_the_preceding_side() {
        let patch = concat!(
            "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
            "-old\n\\ No newline at end of file\n",
            "+new\n\\ No newline at end of file\n",
        );
        let parsed = super::parse_patch(patch).unwrap();
        assert!(!parsed[0].hunks[0].lines[0].has_lf);
        assert!(!parsed[0].hunks[0].lines[1].has_lf);
    }

    #[test]
    fn task6_parse_rejects_every_non_language_form() {
        let cases = [
            ("", ErrorCode::InvalidArgument),
            (
                "diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-a\n+b\n",
                ErrorCode::InvalidArgument,
            ),
            (
                "--- a/a\tstamp\n+++ b/a\tstamp\n@@ -1 +1 @@\n-a\n+b\n",
                ErrorCode::InvalidArgument,
            ),
            (
                "--- a/a\n+++ b/b\n@@ -1 +1 @@\n-a\n+b\n",
                ErrorCode::InvalidArgument,
            ),
            (
                "--- /dev/null\n+++ /dev/null\n@@ -0,0 +1 @@\n+x\n",
                ErrorCode::InvalidArgument,
            ),
            (
                "--- a/../a\n+++ b/../a\n@@ -1 +1 @@\n-a\n+b\n",
                ErrorCode::PathOutsideRoot,
            ),
            (
                "--- a/a//b\n+++ b/a//b\n@@ -1 +1 @@\n-a\n+b\n",
                ErrorCode::InvalidArgument,
            ),
            (
                "--- a/a\n+++ b/a\n@@ -184467440737095516160 +1 @@\n-a\n+b\n",
                ErrorCode::InvalidArgument,
            ),
            (
                "--- a/a\n+++ b/a\n@@ -1,2 +1 @@\n-a\n+b\n",
                ErrorCode::InvalidArgument,
            ),
            (
                "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-a\n+b\n\\ no newline at end of file\n",
                ErrorCode::InvalidArgument,
            ),
            (
                "--- /dev/null\n+++ b/empty\n@@ -0,0 +0,0 @@\n",
                ErrorCode::InvalidArgument,
            ),
            ("GIT binary patch\n", ErrorCode::InvalidArgument),
            (
                "--- a/a\n+++ b/a\n@@ -1 +1 @@ trailing\r\n-a\n+b\n",
                ErrorCode::InvalidArgument,
            ),
            (
                "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-a\n+b\ntrailing prose\n",
                ErrorCode::InvalidArgument,
            ),
        ];
        for (input, code) in cases {
            assert_eq!(
                super::parse_patch(input).unwrap_err().code,
                code,
                "{input:?}"
            );
        }
    }

    #[test]
    fn task6_parse_rejects_duplicate_canonical_paths() {
        let patch = concat!(
            "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-a\n+b\n",
            "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-b\n+c\n",
        );
        assert_eq!(
            super::parse_patch(patch).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn task6_parse_rejects_nonfinal_or_duplicate_no_newline_marker() {
        let cases = [
            concat!(
                "--- a/a\n+++ b/a\n@@ -1,2 +1 @@\n",
                "-one\n\\ No newline at end of file\n",
                "-two\n",
                "+new\n",
            ),
            concat!(
                "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
                "-old\n\\ No newline at end of file\n",
                "\\ No newline at end of file\n",
                "+new\n",
            ),
            concat!(
                "--- a/a\n+++ b/a\n@@ -1 +1,2 @@\n",
                " old\n\\ No newline at end of file\n",
                "+new\n",
            ),
            concat!(
                "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
                "-old\n",
                "+new\n\\ No newline at end of file\n",
                "@@ -2 +2 @@\n",
                "-later\n",
                "+LATER\n",
            ),
        ];
        for patch in cases {
            assert_eq!(
                super::parse_patch(patch).unwrap_err().code,
                ErrorCode::InvalidArgument,
                "{patch:?}"
            );
        }
    }

    #[test]
    fn task6_parse_rejects_file_hunk_and_body_count_ceilings() {
        let mut files = String::new();
        for index in 0..=super::MAX_PATCH_FILES {
            write!(files, "--- /dev/null\n+++ b/f{index}\n@@ -0,0 +1 @@\n+x\n").unwrap();
        }
        assert_eq!(
            super::parse_patch(&files).unwrap_err().code,
            ErrorCode::RequestTooLarge
        );

        let mut hunks = String::from("--- a/a\n+++ b/a\n");
        for index in 1..=super::MAX_PATCH_HUNKS + 1 {
            write!(hunks, "@@ -{index} +{index} @@\n-x\n+y\n").unwrap();
        }
        assert_eq!(
            super::parse_patch(&hunks).unwrap_err().code,
            ErrorCode::RequestTooLarge
        );

        let mut lines = format!(
            "--- /dev/null\n+++ b/a\n@@ -0,0 +1,{} @@\n",
            super::MAX_PATCH_BODY_LINES + 1
        );
        for _ in 0..=super::MAX_PATCH_BODY_LINES {
            lines.push_str("+\n");
        }
        assert_eq!(
            super::parse_patch(&lines).unwrap_err().code,
            ErrorCode::RequestTooLarge
        );
    }

    #[test]
    fn task6_parse_rejects_patch_and_path_byte_ceilings() {
        let oversized_patch = "x".repeat(super::MAX_PATCH_BYTES + 1);
        assert_eq!(
            super::parse_patch(&oversized_patch).unwrap_err().code,
            ErrorCode::RequestTooLarge
        );

        let path = "p".repeat(super::MAX_PATCH_PATH_BYTES + 1);
        let patch = format!("--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+x\n");
        assert_eq!(
            super::parse_patch(&patch).unwrap_err().code,
            ErrorCode::RequestTooLarge
        );
    }

    #[test]
    fn task6_parse_accepts_every_exact_compiled_ceiling() {
        let mut files = String::new();
        for index in 0..super::MAX_PATCH_FILES {
            write!(files, "--- /dev/null\n+++ b/f{index}\n@@ -0,0 +1 @@\n+x\n").unwrap();
        }
        assert_eq!(
            super::parse_patch(&files).unwrap().len(),
            super::MAX_PATCH_FILES
        );

        let mut hunks = String::from("--- a/a\n+++ b/a\n");
        for index in 1..=super::MAX_PATCH_HUNKS {
            write!(hunks, "@@ -{index} +{index} @@\n-x\n+y\n").unwrap();
        }
        assert_eq!(
            super::parse_patch(&hunks).unwrap()[0].hunks.len(),
            super::MAX_PATCH_HUNKS
        );

        let mut body = format!(
            "--- /dev/null\n+++ b/body\n@@ -0,0 +1,{} @@\n",
            super::MAX_PATCH_BODY_LINES
        );
        for _ in 0..super::MAX_PATCH_BODY_LINES {
            body.push_str("+x\n");
        }
        assert_eq!(
            super::parse_patch(&body).unwrap()[0].hunks[0].lines.len(),
            super::MAX_PATCH_BODY_LINES
        );

        let path = "é".repeat(super::MAX_PATCH_PATH_BYTES / "é".len());
        assert_eq!(path.len(), super::MAX_PATCH_PATH_BYTES);
        let path_patch = format!("--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+x\n");
        assert_eq!(super::parse_patch(&path_patch).unwrap()[0].path, path);

        let prefix = "--- /dev/null\n+++ b/exact\n@@ -0,0 +1 @@\n+";
        let exact_patch = format!(
            "{prefix}{}",
            "x".repeat(super::MAX_PATCH_BYTES - prefix.len())
        );
        assert_eq!(exact_patch.len(), super::MAX_PATCH_BYTES);
        super::parse_patch(&exact_patch).unwrap();
    }

    #[test]
    fn task6_parse_create_requires_exact_zero_old_range_shape() {
        let patch = concat!("--- /dev/null\n+++ b/a\n", "@@ -1,0 +1 @@\n", "+x\n",);
        assert_eq!(
            super::parse_patch(patch).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn task6_parse_rejects_empty_non_lf_logical_records_of_every_kind() {
        let cases = [
            concat!(
                "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
                "-\n\\ No newline at end of file\n",
                "+x\n",
            ),
            concat!(
                "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
                "+\n\\ No newline at end of file\n",
                "-x\n",
            ),
            concat!(
                "--- a/a\n+++ b/a\n@@ -1,2 +1,2 @@\n",
                "-old\n",
                "+new\n",
                " \n\\ No newline at end of file\n",
            ),
            concat!(
                "--- /dev/null\n+++ b/zero\n@@ -0,0 +1 @@\n",
                "+\n\\ No newline at end of file\n",
            ),
        ];
        for patch in cases {
            assert_eq!(
                super::parse_patch(patch).unwrap_err().code,
                ErrorCode::InvalidArgument,
                "{patch:?}"
            );
        }
    }

    #[test]
    fn task6_parse_no_newline_finality_is_side_aware() {
        let remove_then_add = concat!(
            "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
            "-old\n\\ No newline at end of file\n",
            "+new\n\\ No newline at end of file\n",
        );
        super::parse_patch(remove_then_add).unwrap();

        let add_then_remove = concat!(
            "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
            "+new\n\\ No newline at end of file\n",
            "-old\n\\ No newline at end of file\n",
        );
        super::parse_patch(add_then_remove).unwrap();

        let context_finishes_both_sides = concat!(
            "--- a/a\n+++ b/a\n@@ -1,2 +1,2 @@\n",
            "-old\n",
            "+new\n",
            " tail\n\\ No newline at end of file\n",
        );
        super::parse_patch(context_finishes_both_sides).unwrap();
    }

    #[test]
    fn task6_parse_freezes_crlf_eof_overflow_and_zero_anchor_boundaries() {
        let body_cr_is_literal = concat!("--- a/a\n+++ b/a\n@@ -1 +1 @@\n", "-old\r\n", "+new\r",);
        let parsed = super::parse_patch(body_cr_is_literal).unwrap();
        assert_eq!(parsed[0].hunks[0].lines[0].text, "old\r");
        assert_eq!(parsed[0].hunks[0].lines[1].text, "new\r");
        assert!(parsed[0].hunks[0].lines[1].has_lf);

        for patch in [
            "--- a/a\r\n+++ b/a\r\n@@ -1 +1 @@\r\n-a\r\n+b\r\n",
            "--- a/a\n+++ b/a\n@@ -0 +1 @@\n-a\n+b\n",
            "--- a/a\n+++ b/a\n@@ -1 +0 @@\n-a\n+b\n",
            "--- a/a\n+++ b/a\n@@ -1,184467440737095516160 +1 @@\n-a\n+b\n",
        ] {
            assert_eq!(
                super::parse_patch(patch).unwrap_err().code,
                ErrorCode::InvalidArgument,
                "{patch:?}"
            );
        }

        let exclusive_end_overflow =
            format!("--- a/a\n+++ b/a\n@@ -{},2 +1 @@\n-a\n-b\n+c\n", usize::MAX);
        assert_eq!(
            super::parse_patch(&exclusive_end_overflow)
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );

        let zero_anchors = concat!(
            "--- a/a\n+++ b/a\n",
            "@@ -0,0 +1 @@\n+first\n",
            "@@ -1 +2,0 @@\n-first\n",
        );
        super::parse_patch(zero_anchors).unwrap();
    }

    #[test]
    fn task6_parser_record_cursor_has_constant_pointer_sized_state() {
        assert!(std::mem::size_of::<super::RecordCursor<'_>>() <= 3 * std::mem::size_of::<usize>());
    }

    #[test]
    fn task6_apply_preserves_untouched_terminal_lf_state() {
        let patch = concat!("--- a/a\n+++ b/a\n@@ -1 +1 @@\n", "-old\n+new\n",);
        assert_eq!(
            apply(Some(b"old\ntail"), patch).unwrap(),
            super::PatchedFile::Write(b"new\ntail".to_vec())
        );
        assert_eq!(
            apply(Some(b"old\ntail\n"), patch).unwrap(),
            super::PatchedFile::Write(b"new\ntail\n".to_vec())
        );
    }

    #[test]
    fn task6_apply_changes_terminal_lf_only_with_exact_markers() {
        let remove_lf = concat!(
            "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
            "-old\n",
            "\\ No newline at end of file\n",
            "+new\n",
        );
        assert_eq!(
            apply(Some(b"old"), remove_lf).unwrap(),
            super::PatchedFile::Write(b"new\n".to_vec())
        );

        let add_no_lf = concat!(
            "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
            "-old\n",
            "+new\n",
            "\\ No newline at end of file\n",
        );
        assert_eq!(
            apply(Some(b"old\n"), add_no_lf).unwrap(),
            super::PatchedFile::Write(b"new".to_vec())
        );
    }

    #[test]
    fn task6_apply_supports_create_empty_update_and_delete() {
        let create = concat!("--- /dev/null\n+++ b/a\n@@ -0,0 +1 @@\n", "+made\n",);
        assert_eq!(
            apply(None, create).unwrap(),
            super::PatchedFile::Write(b"made\n".to_vec())
        );

        let empty = concat!("--- a/a\n+++ b/a\n@@ -1 +0,0 @@\n", "-old\n",);
        assert_eq!(
            apply(Some(b"old\n"), empty).unwrap(),
            super::PatchedFile::Write(Vec::new())
        );

        let delete = concat!("--- a/a\n+++ /dev/null\n@@ -1 +0,0 @@\n", "-old\n",);
        assert_eq!(
            apply(Some(b"old\n"), delete).unwrap(),
            super::PatchedFile::Delete
        );
    }

    #[test]
    fn task6_apply_validates_old_and_new_positions_not_only_counts() {
        let wrong_old = concat!("--- a/a\n+++ b/a\n@@ -2 +2 @@\n", "-one\n+ONE\n",);
        assert_eq!(
            apply(Some(b"one\ntwo\n"), wrong_old).unwrap_err().code,
            ErrorCode::WriteConflict
        );

        let wrong_new = concat!("--- a/a\n+++ b/a\n@@ -1 +2 @@\n", "-one\n+ONE\n",);
        assert_eq!(
            apply(Some(b"one\n"), wrong_new).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn task6_apply_rejects_overlapping_and_repeated_zero_anchor_hunks() {
        let overlap = concat!(
            "--- a/a\n+++ b/a\n",
            "@@ -1 +1 @@\n-one\n+ONE\n",
            "@@ -1 +1 @@\n-one\n+again\n",
        );
        assert_eq!(
            apply(Some(b"one\n"), overlap).unwrap_err().code,
            ErrorCode::InvalidArgument
        );

        let repeated_zero = concat!(
            "--- a/a\n+++ b/a\n",
            "@@ -0,0 +1 @@\n+first\n",
            "@@ -0,0 +2 @@\n+second\n",
        );
        assert_eq!(
            apply(Some(b"tail\n"), repeated_zero).unwrap_err().code,
            ErrorCode::InvalidArgument
        );

        let repeated_new_zero = concat!(
            "--- a/a\n+++ b/a\n",
            "@@ -1 +0,0 @@\n-a\n",
            "@@ -2 +0,0 @@\n-b\n",
        );
        assert_eq!(
            apply(Some(b"a\nb\n"), repeated_new_zero).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn task6_apply_rejects_update_whose_complete_output_equals_base() {
        let patch = concat!("--- a/a\n+++ b/a\n@@ -1 +1 @@\n", "-old\n", "+old\n",);
        assert_eq!(
            apply(Some(b"old\n"), patch).unwrap_err().code,
            ErrorCode::WriteConflict
        );
    }

    #[test]
    fn task6_apply_matches_context_removal_and_lf_state_byte_for_byte() {
        for (base, patch) in [
            (&b"OLD\n"[..], "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n"),
            (&b"old"[..], "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n"),
            (
                &b"old\n"[..],
                concat!(
                    "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
                    "-old\n\\ No newline at end of file\n",
                    "+new\n",
                ),
            ),
        ] {
            assert_eq!(
                apply(Some(base), patch).unwrap_err().code,
                ErrorCode::WriteConflict
            );
        }

        let crlf = "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\r\n+new\r\n";
        assert_eq!(
            apply(Some(b"old\r\n"), crlf).unwrap(),
            super::PatchedFile::Write(b"new\r\n".to_vec())
        );
    }

    #[test]
    fn task6_apply_rejects_non_utf8_nul_and_wrong_base_presence() {
        let update = "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n";
        for base in [&b"\xff"[..], &b"old\0\n"[..]] {
            assert_eq!(
                apply(Some(base), update).unwrap_err().code,
                ErrorCode::InvalidArgument
            );
        }
        assert_eq!(
            apply(None, update).unwrap_err().code,
            ErrorCode::WriteConflict
        );

        let create = "--- /dev/null\n+++ b/a\n@@ -0,0 +1 @@\n+x\n";
        assert_eq!(
            apply(Some(b"exists\n"), create).unwrap_err().code,
            ErrorCode::WriteConflict
        );
    }

    #[test]
    fn task6_apply_rejects_delete_with_nonempty_output() {
        let patch = "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n";
        let mut parsed = super::parse_patch(patch).unwrap().remove(0);
        parsed.operation = super::FilePatchOperation::Delete;
        let sha256 = format!("{:x}", Sha256::digest(b"old\n"));
        assert_eq!(
            super::apply_file_patch(Some((b"old\n", &sha256)), &parsed, super::MAX_PATCH_BYTES,)
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn task6_apply_rejects_per_file_output_overflow_before_allocation() {
        let patch = "--- /dev/null\n+++ b/a\n@@ -0,0 +1 @@\n+large\n";
        let parsed = super::parse_patch(patch).unwrap().remove(0);
        assert_eq!(
            super::apply_file_patch(None, &parsed, 5).unwrap_err().code,
            ErrorCode::RequestTooLarge
        );
    }

    #[test]
    fn task6_apply_non_lf_output_cannot_precede_untouched_or_added_suffix() {
        let untouched_suffix = concat!(
            "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
            "-old\n",
            "+new\n\\ No newline at end of file\n",
        );
        assert_eq!(
            apply(Some(b"old\ntail\n"), untouched_suffix)
                .unwrap_err()
                .code,
            ErrorCode::WriteConflict
        );

        let added_suffix = concat!(
            "--- a/a\n+++ b/a\n",
            "@@ -1 +1 @@\n-old\n+new\n",
            "@@ -2 +2 @@\n-tail\n+TAIL\n",
        );
        let mut parsed = super::parse_patch(added_suffix).unwrap().remove(0);
        parsed.hunks[0].lines[1].has_lf = false;
        let sha256 = format!("{:x}", Sha256::digest(b"old\ntail\n"));
        assert_eq!(
            super::apply_file_patch(
                Some((b"old\ntail\n", &sha256)),
                &parsed,
                super::MAX_PATCH_BYTES,
            )
            .unwrap_err()
            .code,
            ErrorCode::WriteConflict
        );
    }

    #[test]
    fn task6_apply_accepts_valid_zero_anchors_at_file_boundaries() {
        let insert_first = concat!("--- a/a\n+++ b/a\n@@ -0,0 +1 @@\n", "+head\n",);
        assert_eq!(
            apply(Some(b"tail\n"), insert_first).unwrap(),
            super::PatchedFile::Write(b"head\ntail\n".to_vec())
        );

        let insert_last = concat!("--- a/a\n+++ b/a\n@@ -1,0 +2 @@\n", "+tail\n",);
        assert_eq!(
            apply(Some(b"head\n"), insert_last).unwrap(),
            super::PatchedFile::Write(b"head\ntail\n".to_vec())
        );
    }

    #[test]
    fn task6_logical_line_cursor_has_constant_pointer_sized_state() {
        assert!(
            std::mem::size_of::<super::LogicalLineCursor<'_>>() <= 3 * std::mem::size_of::<usize>()
        );
    }

    #[test]
    fn task6_apply_streams_newline_dense_four_mib_base() {
        let base = b"x\n".repeat(super::MAX_PATCH_BYTES / 2);
        let patch = "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-x\n+y\n";
        let result = apply(Some(&base), patch).unwrap();
        let super::PatchedFile::Write(output) = result else {
            panic!("update returned delete");
        };
        assert_eq!(output.len(), base.len());
        assert_eq!(&output[..2], b"y\n");
        assert_eq!(&output[2..], &base[2..]);
    }
}
