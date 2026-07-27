use std::sync::Arc;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::error::{BridgeError, BridgeResult, ErrorCode};
use crate::output::{InternalSpoolOwner, StreamKind};
use crate::path::RemotePath;
use crate::ssh::{
    FixedOperationKind, FixedRunRequest, FixedRunResult, RootedPathInputs, render_fixed_command,
};

use super::edit_cache::{
    BatchMutationDisposition, CacheKey, DesiredState, PreparedEdit, RemoteBase,
};
use super::protocol::{context, encode_bytes, read_small_stream};
use super::{
    GuardedDeleteRequest, GuardedDeleteResult, MAX_INPUT_PATH_BYTES, RemoteBridge, WriteEncoding,
    WriteMode, WriteOperation, WriteRequest, WriteResult, attach_fixed_result_context,
    edit_bridge_error,
};

const WRITE_PROTOCOL_LIMIT: u64 = 512;

pub(super) const WRITE_SCRIPT: &str = r#"
set -u

[ "$#" -eq 7 ] || exit 2

parent=$1
basename=$2
operation=$3
expected_size=$4
expected_content_hash=$5
expected_hash_present=$6
expected_target_hash=$7

newline='
'

codex_mutation_stat() {
    stat --printf='%f:%u:%a:%s:%d:%i:%h\n' -- "$1" 2>/dev/null
}

codex_mutation_parent_stat_follow() {
    stat -L --printf='%f:%u:%a:%s:%d:%i:%h\n' -- "$1" 2>/dev/null
}

codex_mutation_mktemp() {
    mktemp --tmpdir="$1" .codex-ssh-bridge.XXXXXXXXXX
}

codex_mutation_stage() (
    on_codex_mutation_stage_signal() {
        trap - HUP INT TERM
        exit 125
    }
    trap on_codex_mutation_stage_signal HUP INT TERM
    dd of="$1" bs=262144 status=none conv=notrunc oflag=nofollow
)

codex_mutation_link() {
    ln -T -- "$1" "$2"
}

codex_mutation_replace() {
    mv -T -- "$1" "$2"
}

codex_mutation_mode() {
    codex_mode=$1
    codex_mode_path=$2
    codex_mutation_stat_valid "$codex_mode_path" || return 1
    case "$CODEX_STAT_TYPE" in 8???) ;; *) return 1 ;; esac
    codex_mode_device=$CODEX_STAT_DEVICE
    codex_mode_inode=$CODEX_STAT_INODE
    exec 9<>"$codex_mode_path" || return 1
    codex_mutation_parent_stat_follow_valid /proc/self/fd/9 || {
        exec 9>&-
        return 1
    }
    case "$CODEX_STAT_TYPE" in 8???) ;; *)
        exec 9>&-
        return 1
        ;;
    esac
    if [ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE" != "$codex_mode_device:$codex_mode_inode" ]; then
        exec 9>&-
        return 1
    fi
    chmod "$codex_mode" -- /proc/self/fd/9
    codex_mode_status=$?
    exec 9>&-
    return "$codex_mode_status"
}

codex_mutation_remove() {
    rm -f -- "$1"
}

codex_mutation_decimal_valid() {
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

codex_mutation_stat_parse() {
    codex_stat_line=$1
    case "$codex_stat_line" in ''|*[!0-9a-f:]*) return 1 ;; esac
    codex_stat_old_ifs=$IFS
    IFS=:
    set -- $codex_stat_line
    IFS=$codex_stat_old_ifs
    [ "$#" -eq 7 ] || return 1
    [ "${#1}" -eq 4 ] || return 1
    case "$1" in *[!0-9a-f]*) return 1 ;; esac
    codex_mutation_decimal_valid "$2" || return 1
    [ "${#3}" -le 4 ] || return 1
    case "$3" in ''|*[!0-7]*) return 1 ;; esac
    codex_mutation_decimal_valid "$4" || return 1
    codex_mutation_decimal_valid "$5" || return 1
    codex_mutation_decimal_valid "$6" || return 1
    codex_mutation_decimal_valid "$7" || return 1
    CODEX_STAT_TYPE=$1
    CODEX_STAT_UID=$2
    CODEX_STAT_MODE=$3
    CODEX_STAT_SIZE=$4
    CODEX_STAT_DEVICE=$5
    CODEX_STAT_INODE=$6
    CODEX_STAT_LINKS=$7
}

codex_mutation_stat_valid() {
    codex_stat_line=$(codex_mutation_stat "$1") || return 9
    codex_mutation_stat_parse "$codex_stat_line"
}

codex_mutation_parent_stat_follow_valid() {
    codex_stat_line=$(codex_mutation_parent_stat_follow "$1") || return 9
    codex_mutation_stat_parse "$codex_stat_line"
}

codex_mutation_hash() (
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
                if [ "$codex_hash_dd_seen" -ne 0 ]; then
                    codex_hash_valid=0
                    break
                fi
                codex_hash_dd_seen=1
                codex_hash_dd=${codex_hash_line#CODEX_DD_STATUS=}
                ;;
            CODEX_SHA_STATUS=*)
                if [ "$codex_hash_sha_seen" -ne 0 ]; then
                    codex_hash_valid=0
                    break
                fi
                codex_hash_sha_seen=1
                codex_hash_sha=${codex_hash_line#CODEX_SHA_STATUS=}
                ;;
            *'  -')
                if [ "$codex_hash_digest_seen" -ne 0 ]; then
                    codex_hash_valid=0
                    break
                fi
                codex_hash_digest_seen=1
                codex_hash_digest=${codex_hash_line%  -}
                ;;
            *)
                codex_hash_valid=0
                break
                ;;
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

codex_safe_write_sentinel() (
    umask 077
    codex_sentinel_dir=$(mktemp -d "${TMPDIR:-/tmp}/codex-sentinel-safe-write.XXXXXX" 2>/dev/null) || exit 9
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

    codex_sentinel_work=$codex_sentinel_dir/work
    codex_sentinel_parent=$codex_sentinel_work/parent
    codex_sentinel_parent_link=$codex_sentinel_work/parent-link
    mkdir -m 700 -- "$codex_sentinel_work" "$codex_sentinel_parent" || exit 9
    ln -s "$codex_sentinel_parent" "$codex_sentinel_parent_link" || exit 9
    codex_mutation_parent_stat_follow_valid "$codex_sentinel_parent" || exit $?
    codex_sentinel_parent_identity=$CODEX_STAT_DEVICE:$CODEX_STAT_INODE
    codex_sentinel_parent_device=$CODEX_STAT_DEVICE
    codex_mutation_parent_stat_follow_valid "$codex_sentinel_parent_link" || exit $?
    [ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE" = "$codex_sentinel_parent_identity" ] || exit 1
    case "$CODEX_STAT_TYPE" in 4???) ;; *) exit 1 ;; esac

    codex_sentinel_tmp=$(codex_mutation_mktemp "$codex_sentinel_work") || exit 9
    printf payload | codex_mutation_stage "$codex_sentinel_tmp" || exit 9
    codex_mutation_stat_valid "$codex_sentinel_tmp" || exit $?
    codex_sentinel_uid=$(id -u) || exit 9
    codex_sentinel_stage_identity=$CODEX_STAT_DEVICE:$CODEX_STAT_INODE
    case "$CODEX_STAT_TYPE" in 8???) ;; *) exit 1 ;; esac
    [ "$CODEX_STAT_UID" = "$codex_sentinel_uid" ] || exit 1
    [ "$CODEX_STAT_MODE:$CODEX_STAT_SIZE:$CODEX_STAT_LINKS" = 600:7:1 ] || exit 1
    [ "$CODEX_STAT_DEVICE" = "$codex_sentinel_parent_device" ] || exit 1
    codex_sentinel_hash=$(codex_mutation_hash "$codex_sentinel_tmp") || exit $?
    [ "$codex_sentinel_hash" = 239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5 ] || exit 1

    codex_sentinel_created=$codex_sentinel_work/created
    codex_mutation_link "$codex_sentinel_tmp" "$codex_sentinel_created" || exit 9
    if codex_mutation_link "$codex_sentinel_tmp" "$codex_sentinel_created" 2>/dev/null; then exit 1; fi
    codex_sentinel_link_directory=$codex_sentinel_work/link-directory
    codex_sentinel_directory_link=$codex_sentinel_work/directory-link
    mkdir -m 700 -- "$codex_sentinel_link_directory" || exit 9
    ln -s "$codex_sentinel_link_directory" "$codex_sentinel_directory_link" || exit 9
    if codex_mutation_link "$codex_sentinel_tmp" "$codex_sentinel_directory_link" 2>/dev/null; then exit 1; fi
    codex_sentinel_nested_link=$codex_sentinel_link_directory/${codex_sentinel_tmp##*/}
    [ -L "$codex_sentinel_directory_link" ] || exit 1
    [ ! -e "$codex_sentinel_nested_link" ] && [ ! -L "$codex_sentinel_nested_link" ] || exit 1
    codex_mutation_stat_valid "$codex_sentinel_created" || exit $?
    [ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE" = "$codex_sentinel_stage_identity" ] || exit 1
    codex_mutation_remove "$codex_sentinel_created" || exit 9
    [ ! -e "$codex_sentinel_created" ] && [ ! -L "$codex_sentinel_created" ] || exit 1

    codex_sentinel_replaced=$codex_sentinel_work/replaced
    printf old >"$codex_sentinel_replaced" || exit 9
    codex_mutation_replace "$codex_sentinel_tmp" "$codex_sentinel_replaced" || exit 9
    [ ! -e "$codex_sentinel_tmp" ] && [ ! -L "$codex_sentinel_tmp" ] || exit 1
    codex_mutation_mode 0640 "$codex_sentinel_replaced" || exit 9
    codex_mutation_stat_valid "$codex_sentinel_replaced" || exit $?
    [ "$CODEX_STAT_MODE" = 640 ] || exit 1
    codex_sentinel_hash=$(codex_mutation_hash "$codex_sentinel_replaced") || exit $?
    [ "$codex_sentinel_hash" = 239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5 ] || exit 1

    codex_sentinel_outside=$codex_sentinel_work/outside
    codex_sentinel_link=$codex_sentinel_work/link
    printf OUTSIDE >"$codex_sentinel_outside" || exit 9
    chmod 0600 -- "$codex_sentinel_outside" || exit 9
    ln -s "$codex_sentinel_outside" "$codex_sentinel_link" || exit 9
    codex_mutation_stat_valid "$codex_sentinel_link" || exit $?
    case "$CODEX_STAT_TYPE" in a???) ;; *) exit 1 ;; esac
    if printf CHANGED | codex_mutation_stage "$codex_sentinel_link" 2>/dev/null; then exit 1; fi
    codex_sentinel_hash_status=0
    codex_sentinel_hash=$(codex_mutation_hash "$codex_sentinel_link") || codex_sentinel_hash_status=$?
    [ "$codex_sentinel_hash_status" -eq 9 ] || exit 1
    codex_sentinel_outside_content=$(cat "$codex_sentinel_outside") || exit 9
    [ "$codex_sentinel_outside_content" = OUTSIDE ] || exit 1

    cleanup_codex_sentinel || exit 9
    trap - 0 HUP INT TERM
    exit 0
)

codex_safe_write_preflight() {
    for codex_required_command in stat mktemp dd sha256sum ln mv chmod rm mkdir id cat; do
        command -v "$codex_required_command" >/dev/null 2>&1 || return 1
    done
}

if ! codex_safe_write_preflight; then
    printf 'STATUS=CAPABILITY_MISMATCH\000CAPABILITY=safe_write\000'
    exit 0
fi

codex_sentinel_status=0
codex_safe_write_sentinel || codex_sentinel_status=$?
case "$codex_sentinel_status" in
    0) ;;
    1)
        printf 'STATUS=CAPABILITY_MISMATCH\000CAPABILITY=safe_write\000'
        exit 0
        ;;
    *) exit 9 ;;
esac

case "$operation:$expected_hash_present" in
    CREATE:0) ;;
    REPLACE:0|REPLACE:1) ;;
    *) exit 2 ;;
esac
case "$expected_size" in ''|*[!0-9]*) exit 2 ;; esac
case "$expected_content_hash" in *[!0-9a-f]*) exit 2 ;; esac
[ "${#expected_content_hash}" -eq 64 ] || exit 2
if [ "$expected_hash_present" = 1 ]; then
    case "$expected_target_hash" in *[!0-9a-f]*) exit 2 ;; esac
    [ "${#expected_target_hash}" -eq 64 ] || exit 2
else
    [ -z "$expected_target_hash" ] || exit 2
fi

tmp=
cleanup_tmp() {
    [ -z "$tmp" ] && return 0
    codex_mutation_remove "$tmp" >/dev/null 2>&1 || return 1
    [ ! -e "$tmp" ] && [ ! -L "$tmp" ] || return 1
    tmp=
}
on_write_signal() {
    trap - 0 HUP INT TERM
    cleanup_tmp >/dev/null 2>&1 || :
    exit 125
}
trap 'cleanup_tmp >/dev/null 2>&1 || :' 0
trap on_write_signal HUP INT TERM

emit_one() {
    cleanup_tmp || exit 90
    trap - 0 HUP INT TERM
    printf 'STATUS=%s\000' "$1"
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
        codex_mutation_stat_valid "$codex_parent_candidate" || codex_parent_lstat_status=$?
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
                    codex_mutation_parent_stat_follow_valid "$codex_parent_candidate" || codex_parent_follow_status=$?
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

codex_parent_line=$(codex_mutation_parent_stat_follow "$parent") || {
    codex_classify_unreachable_parent
    exit 3
}
codex_mutation_stat_parse "$codex_parent_line" || exit 3
case "$CODEX_STAT_TYPE" in 4???) ;; *) emit_one NOT_DIRECTORY ;; esac
parent_device=$CODEX_STAT_DEVICE
parent_inode=$CODEX_STAT_INODE

if ! CDPATH= cd -P -- "$parent" 2>/dev/null; then
    if codex_mutation_parent_stat_follow_valid "$parent" &&
       [ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE" = "$parent_device:$parent_inode" ]; then
        case "$CODEX_STAT_TYPE" in 4???) emit_one PERMISSION_DENIED ;; esac
    fi
    exit 3
fi
codex_mutation_parent_stat_follow_valid . || exit 3
[ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE" = "$parent_device:$parent_inode" ] || exit 3

target=./$basename
target_initial_status=0
codex_mutation_stat_valid "$target" || target_initial_status=$?
if [ "$target_initial_status" -eq 0 ]; then
    if [ "$operation" = CREATE ]; then
        emit_one WRITE_CONFLICT
    fi
    case "$CODEX_STAT_TYPE" in 8???) ;; *) emit_one WRITE_CONFLICT ;; esac
    target_device=$CODEX_STAT_DEVICE
    target_inode=$CODEX_STAT_INODE
    target_mode=$CODEX_STAT_MODE
    target_mode_decimal=$((0$target_mode))
    [ $((target_mode_decimal & 07000)) -eq 0 ] || emit_one WRITE_CONFLICT
else
    if [ "$operation" = CREATE ]; then
        if [ -e "$target" ] || [ -L "$target" ]; then
            emit_one WRITE_CONFLICT
        fi
    else
        if [ ! -e "$target" ] && [ ! -L "$target" ]; then
            emit_one NOT_FOUND
        fi
        exit 3
    fi
fi

umask 077
tmp=$(codex_mutation_mktemp .) || exit 4
codex_mutation_stage "$tmp" || exit 4
codex_mutation_stat_valid "$tmp" || exit 4
stage_device=$CODEX_STAT_DEVICE
stage_inode=$CODEX_STAT_INODE
stage_uid=$(id -u) || exit 4
case "$CODEX_STAT_TYPE" in 8???) ;; *) exit 4 ;; esac
[ "$CODEX_STAT_UID" = "$stage_uid" ] || exit 4
[ "$CODEX_STAT_MODE" = 600 ] || exit 4
[ "$CODEX_STAT_SIZE" = "$expected_size" ] || exit 4
[ "$CODEX_STAT_DEVICE" = "$parent_device" ] || exit 4
[ "$CODEX_STAT_LINKS" = 1 ] || exit 4
stage_hash=$(codex_mutation_hash "$tmp") || exit 4
[ "$stage_hash" = "$expected_content_hash" ] || exit 4

if [ "$operation" = CREATE ]; then
    if ! codex_mutation_link "$tmp" "$target" 2>/dev/null; then
        if codex_mutation_stat_valid "$target" || [ -e "$target" ] || [ -L "$target" ]; then
            emit_one WRITE_CONFLICT
        fi
        exit 5
    fi

    codex_mutation_stat_valid "$target" || exit 5
    case "$CODEX_STAT_TYPE" in 8???) ;; *) exit 5 ;; esac
    [ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE" = "$stage_device:$stage_inode" ] || exit 5
    [ "$CODEX_STAT_UID:$CODEX_STAT_MODE:$CODEX_STAT_SIZE:$CODEX_STAT_LINKS" = "$stage_uid:600:$expected_size:2" ] || exit 5
    target_hash=$(codex_mutation_hash "$target") || exit 5
    [ "$target_hash" = "$expected_content_hash" ] || exit 5

    codex_mutation_remove "$tmp" || exit 5
    [ ! -e "$tmp" ] && [ ! -L "$tmp" ] || exit 5
    tmp=

    codex_mutation_stat_valid "$target" || exit 5
    case "$CODEX_STAT_TYPE" in 8???) ;; *) exit 5 ;; esac
    [ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE" = "$stage_device:$stage_inode" ] || exit 5
    [ "$CODEX_STAT_UID:$CODEX_STAT_MODE:$CODEX_STAT_SIZE:$CODEX_STAT_LINKS" = "$stage_uid:600:$expected_size:1" ] || exit 5
    target_hash=$(codex_mutation_hash "$target") || exit 5
    [ "$target_hash" = "$expected_content_hash" ] || exit 5

    mode_decimal=$((0$CODEX_STAT_MODE))
    trap - 0 HUP INT TERM
    printf 'STATUS=SUCCESS\000OPERATION=CREATE\000SIZE=%s\000SHA256=%s\000MODE=%s\000TEMPORARY_CLEANUP_CONFIRMED=1\000' "$expected_size" "$expected_content_hash" "$mode_decimal"
    exit 0
fi

target_final_status=0
codex_mutation_stat_valid "$target" || target_final_status=$?
if [ "$target_final_status" -ne 0 ]; then
    if [ ! -e "$target" ] && [ ! -L "$target" ]; then
        emit_one WRITE_CONFLICT
    fi
    exit 5
fi
case "$CODEX_STAT_TYPE" in 8???) ;; *) emit_one WRITE_CONFLICT ;; esac
[ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE:$CODEX_STAT_MODE" = "$target_device:$target_inode:$target_mode" ] || emit_one WRITE_CONFLICT
target_final_mode_decimal=$((0$CODEX_STAT_MODE))
[ $((target_final_mode_decimal & 07000)) -eq 0 ] || emit_one WRITE_CONFLICT

if [ "$expected_hash_present" = 1 ]; then
    target_hash_status=0
    target_hash=$(codex_mutation_hash "$target") || target_hash_status=$?
    if [ "$target_hash_status" -ne 0 ]; then
        if codex_mutation_stat_valid "$target"; then
            case "$CODEX_STAT_TYPE" in 8???) ;; *) emit_one WRITE_CONFLICT ;; esac
            [ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE:$CODEX_STAT_MODE" = "$target_device:$target_inode:$target_mode" ] || emit_one WRITE_CONFLICT
        else
            exit 5
        fi
        exit 5
    fi
    codex_mutation_stat_valid "$target" || exit 5
    [ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE:$CODEX_STAT_MODE" = "$target_device:$target_inode:$target_mode" ] || emit_one WRITE_CONFLICT
    [ "$target_hash" = "$expected_target_hash" ] || emit_one WRITE_CONFLICT
fi

# Apply mode before exposing the staged inode at the target path.  This keeps
# chmod from ever following an attacker-replaced target symlink.
codex_mutation_mode "$target_mode" "$tmp" || exit 5
codex_mutation_stat_valid "$tmp" || exit 5
case "$CODEX_STAT_TYPE" in 8???) ;; *) exit 5 ;; esac
[ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE:$CODEX_STAT_MODE:$CODEX_STAT_SIZE:$CODEX_STAT_LINKS" = "$stage_device:$stage_inode:$target_mode:$expected_size:1" ] || exit 5

codex_mutation_replace "$tmp" "$target" || exit 5
[ ! -e "$tmp" ] && [ ! -L "$tmp" ] || exit 5
tmp=

codex_mutation_stat_valid "$target" || exit 5
case "$CODEX_STAT_TYPE" in 8???) ;; *) exit 5 ;; esac
[ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE" = "$stage_device:$stage_inode" ] || exit 5
[ "$CODEX_STAT_UID:$CODEX_STAT_MODE:$CODEX_STAT_SIZE:$CODEX_STAT_LINKS" = "$stage_uid:$target_mode:$expected_size:1" ] || exit 5

[ ! -e "$tmp" ] && [ ! -L "$tmp" ] || exit 5

mode_decimal=$((0$CODEX_STAT_MODE))
trap - 0 HUP INT TERM
printf 'STATUS=SUCCESS\000OPERATION=REPLACE\000SIZE=%s\000SHA256=%s\000MODE=%s\000TEMPORARY_CLEANUP_CONFIRMED=1\000' "$expected_size" "$expected_content_hash" "$mode_decimal"
exit 0
"#;

pub(super) const GUARDED_DELETE_SCRIPT: &str = r#"
set -u

[ "$#" -eq 3 ] || exit 2

parent=$1
basename=$2
expected_hash=$3

newline='
'

codex_mutation_stat() {
    stat --printf='%f:%u:%a:%s:%d:%i:%h\n' -- "$1" 2>/dev/null
}

codex_mutation_parent_stat_follow() {
    stat -L --printf='%f:%u:%a:%s:%d:%i:%h\n' -- "$1" 2>/dev/null
}

codex_mutation_remove() {
    rm -f -- "$1"
}

codex_mutation_decimal_valid() {
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

codex_mutation_stat_parse() {
    codex_stat_line=$1
    case "$codex_stat_line" in ''|*[!0-9a-f:]*) return 1 ;; esac
    codex_stat_old_ifs=$IFS
    IFS=:
    set -- $codex_stat_line
    IFS=$codex_stat_old_ifs
    [ "$#" -eq 7 ] || return 1
    [ "${#1}" -eq 4 ] || return 1
    case "$1" in *[!0-9a-f]*) return 1 ;; esac
    codex_mutation_decimal_valid "$2" || return 1
    [ "${#3}" -le 4 ] || return 1
    case "$3" in ''|*[!0-7]*) return 1 ;; esac
    codex_mutation_decimal_valid "$4" || return 1
    codex_mutation_decimal_valid "$5" || return 1
    codex_mutation_decimal_valid "$6" || return 1
    codex_mutation_decimal_valid "$7" || return 1
    CODEX_STAT_TYPE=$1
    CODEX_STAT_UID=$2
    CODEX_STAT_MODE=$3
    CODEX_STAT_SIZE=$4
    CODEX_STAT_DEVICE=$5
    CODEX_STAT_INODE=$6
    CODEX_STAT_LINKS=$7
}

codex_mutation_stat_valid() {
    codex_stat_line=$(codex_mutation_stat "$1") || return 9
    codex_mutation_stat_parse "$codex_stat_line"
}

codex_mutation_parent_stat_follow_valid() {
    codex_stat_line=$(codex_mutation_parent_stat_follow "$1") || return 9
    codex_mutation_stat_parse "$codex_stat_line"
}

codex_mutation_hash() (
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
                if [ "$codex_hash_dd_seen" -ne 0 ]; then
                    codex_hash_valid=0
                    break
                fi
                codex_hash_dd_seen=1
                codex_hash_dd=${codex_hash_line#CODEX_DD_STATUS=}
                ;;
            CODEX_SHA_STATUS=*)
                if [ "$codex_hash_sha_seen" -ne 0 ]; then
                    codex_hash_valid=0
                    break
                fi
                codex_hash_sha_seen=1
                codex_hash_sha=${codex_hash_line#CODEX_SHA_STATUS=}
                ;;
            *'  -')
                if [ "$codex_hash_digest_seen" -ne 0 ]; then
                    codex_hash_valid=0
                    break
                fi
                codex_hash_digest_seen=1
                codex_hash_digest=${codex_hash_line%  -}
                ;;
            *)
                codex_hash_valid=0
                break
                ;;
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

codex_guarded_delete_sentinel() (
    umask 077
    codex_sentinel_dir=$(mktemp -d "${TMPDIR:-/tmp}/codex-sentinel-guarded-delete.XXXXXX" 2>/dev/null) || exit 9
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
    codex_mutation_parent_stat_follow_valid "$codex_sentinel_parent" || exit $?
    codex_sentinel_parent_identity=$CODEX_STAT_DEVICE:$CODEX_STAT_INODE
    codex_mutation_parent_stat_follow_valid "$codex_sentinel_parent_link" || exit $?
    [ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE" = "$codex_sentinel_parent_identity" ] || exit 1
    case "$CODEX_STAT_TYPE" in 4???) ;; *) exit 1 ;; esac

    codex_sentinel_victim=$codex_sentinel_parent/victim
    printf payload >"$codex_sentinel_victim" || exit 9
    codex_mutation_stat_valid "$codex_sentinel_victim" || exit $?
    case "$CODEX_STAT_TYPE" in 8???) ;; *) exit 1 ;; esac
    [ "$CODEX_STAT_MODE:$CODEX_STAT_SIZE:$CODEX_STAT_LINKS" = 600:7:1 ] || exit 1
    codex_sentinel_identity=$CODEX_STAT_DEVICE:$CODEX_STAT_INODE
    codex_sentinel_hash=$(codex_mutation_hash "$codex_sentinel_victim") || exit $?
    [ "$codex_sentinel_hash" = 239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5 ] || exit 1
    codex_mutation_stat_valid "$codex_sentinel_victim" || exit $?
    case "$CODEX_STAT_TYPE" in 8???) ;; *) exit 1 ;; esac
    [ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE" = "$codex_sentinel_identity" ] || exit 1
    codex_sentinel_hash=$(codex_mutation_hash "$codex_sentinel_victim") || exit $?
    [ "$codex_sentinel_hash" = 239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5 ] || exit 1
    codex_mutation_remove "$codex_sentinel_victim" || exit 9
    [ ! -e "$codex_sentinel_victim" ] && [ ! -L "$codex_sentinel_victim" ] || exit 1

    codex_sentinel_outside=$codex_sentinel_dir/outside
    codex_sentinel_link=$codex_sentinel_parent/link
    printf OUTSIDE >"$codex_sentinel_outside" || exit 9
    ln -s "$codex_sentinel_outside" "$codex_sentinel_link" || exit 9
    codex_mutation_stat_valid "$codex_sentinel_link" || exit $?
    case "$CODEX_STAT_TYPE" in a???) ;; *) exit 1 ;; esac
    codex_sentinel_hash_status=0
    codex_sentinel_hash=$(codex_mutation_hash "$codex_sentinel_link") || codex_sentinel_hash_status=$?
    [ "$codex_sentinel_hash_status" -eq 9 ] || exit 1
    codex_sentinel_outside_content=$(cat "$codex_sentinel_outside") || exit 9
    [ "$codex_sentinel_outside_content" = OUTSIDE ] || exit 1

    cleanup_codex_sentinel || exit 9
    trap - 0 HUP INT TERM
    exit 0
)

codex_guarded_delete_preflight() {
    for codex_required_command in stat mktemp dd sha256sum ln rm mkdir cat; do
        command -v "$codex_required_command" >/dev/null 2>&1 || return 1
    done
}

if ! codex_guarded_delete_preflight; then
    printf 'STATUS=CAPABILITY_MISMATCH\000CAPABILITY=guarded_delete\000'
    exit 0
fi

codex_sentinel_status=0
codex_guarded_delete_sentinel || codex_sentinel_status=$?
case "$codex_sentinel_status" in
    0) ;;
    1)
        printf 'STATUS=CAPABILITY_MISMATCH\000CAPABILITY=guarded_delete\000'
        exit 0
        ;;
    *) exit 9 ;;
esac

case "$expected_hash" in *[!0-9a-f]*) exit 2 ;; esac
[ "${#expected_hash}" -eq 64 ] || exit 2

emit_one() {
    trap - HUP INT TERM
    printf 'STATUS=%s\000' "$1"
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
        codex_mutation_stat_valid "$codex_parent_candidate" || codex_parent_lstat_status=$?
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
                    codex_mutation_parent_stat_follow_valid "$codex_parent_candidate" || codex_parent_follow_status=$?
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

codex_parent_line=$(codex_mutation_parent_stat_follow "$parent") || {
    codex_classify_unreachable_parent
    exit 3
}
codex_mutation_stat_parse "$codex_parent_line" || exit 3
case "$CODEX_STAT_TYPE" in 4???) ;; *) emit_one NOT_DIRECTORY ;; esac
parent_device=$CODEX_STAT_DEVICE
parent_inode=$CODEX_STAT_INODE

if ! CDPATH= cd -P -- "$parent" 2>/dev/null; then
    if codex_mutation_parent_stat_follow_valid "$parent" &&
       [ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE" = "$parent_device:$parent_inode" ]; then
        case "$CODEX_STAT_TYPE" in 4???) emit_one PERMISSION_DENIED ;; esac
    fi
    exit 3
fi
codex_mutation_parent_stat_follow_valid . || exit 3
[ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE" = "$parent_device:$parent_inode" ] || exit 3

target=./$basename
target_status=0
codex_mutation_stat_valid "$target" || target_status=$?
if [ "$target_status" -ne 0 ]; then
    if [ ! -e "$target" ] && [ ! -L "$target" ]; then emit_one NOT_FOUND; fi
    exit 4
fi
case "$CODEX_STAT_TYPE" in 8???) ;; *) emit_one WRITE_CONFLICT ;; esac
target_device=$CODEX_STAT_DEVICE
target_inode=$CODEX_STAT_INODE

target_hash_status=0
target_hash=$(codex_mutation_hash "$target") || target_hash_status=$?
if [ "$target_hash_status" -ne 0 ]; then
    if codex_mutation_stat_valid "$target"; then
        case "$CODEX_STAT_TYPE" in 8???) ;; *) emit_one WRITE_CONFLICT ;; esac
        [ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE" = "$target_device:$target_inode" ] || emit_one WRITE_CONFLICT
    else
        if [ ! -e "$target" ] && [ ! -L "$target" ]; then emit_one WRITE_CONFLICT; fi
    fi
    exit 4
fi
[ "$target_hash" = "$expected_hash" ] || emit_one WRITE_CONFLICT

target_status=0
codex_mutation_stat_valid "$target" || target_status=$?
if [ "$target_status" -ne 0 ]; then
    if [ ! -e "$target" ] && [ ! -L "$target" ]; then emit_one WRITE_CONFLICT; fi
    exit 4
fi
case "$CODEX_STAT_TYPE" in 8???) ;; *) emit_one WRITE_CONFLICT ;; esac
[ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE" = "$target_device:$target_inode" ] || emit_one WRITE_CONFLICT

target_hash_status=0
target_hash=$(codex_mutation_hash "$target") || target_hash_status=$?
if [ "$target_hash_status" -ne 0 ]; then
    if codex_mutation_stat_valid "$target"; then
        case "$CODEX_STAT_TYPE" in 8???) ;; *) emit_one WRITE_CONFLICT ;; esac
        [ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE" = "$target_device:$target_inode" ] || emit_one WRITE_CONFLICT
    else
        if [ ! -e "$target" ] && [ ! -L "$target" ]; then emit_one WRITE_CONFLICT; fi
    fi
    exit 4
fi
[ "$target_hash" = "$expected_hash" ] || emit_one WRITE_CONFLICT

codex_mutation_remove "$target" || exit 5
[ ! -e "$target" ] && [ ! -L "$target" ] || exit 5
printf 'STATUS=SUCCESS\000OPERATION=DELETE\000SHA256=%s\000ABSENCE_CONFIRMED=1\000' "$expected_hash"
exit 0
"#;

#[derive(Debug)]
pub(super) struct ResolvedWrite {
    host: String,
    path: RemotePath,
    parent: String,
    basename: String,
    content: Vec<u8>,
    operation: WriteOperation,
    expected_sha256: Option<String>,
    raw_bytes: u64,
    sha256: String,
}

#[derive(Debug)]
pub(super) struct ResolvedDelete {
    host: String,
    path: RemotePath,
    parent: String,
    basename: String,
    expected_sha256: String,
}

#[derive(Debug)]
pub(super) struct PreparedMutationPath {
    host: String,
    path: RemotePath,
    parent: String,
    basename: String,
}

impl PreparedMutationPath {
    pub(super) fn parent(&self) -> &str {
        &self.parent
    }

    pub(super) fn basename(&self) -> &str {
        &self.basename
    }
}

#[derive(Clone, Copy)]
enum MutationTarget {
    Write,
    Delete,
    Patch,
}

#[derive(Debug, PartialEq, Eq)]
enum WriteProtocol {
    Success {
        operation: WriteOperation,
        size: u64,
        sha256: String,
        mode: u32,
    },
    Domain(ErrorCode),
    CapabilityMismatch,
}

#[derive(Debug, PartialEq, Eq)]
enum DeleteProtocol {
    Success { sha256: String },
    Domain(ErrorCode),
    CapabilityMismatch,
}

pub(super) async fn write(
    bridge: &RemoteBridge,
    request: WriteRequest,
    cancel: CancellationToken,
) -> BridgeResult<WriteResult> {
    let mut resolved = preflight_write(bridge, request)?;
    if cancel.is_cancelled() {
        return Err(BridgeError::new(
            ErrorCode::Cancelled,
            "remote write was cancelled",
            false,
        ));
    }
    let key = CacheKey {
        host: resolved.host.clone(),
        path: resolved.path.as_str().to_owned(),
    };
    let current = bridge
        .edit_cache
        .load_entry_complete(key.clone())
        .await
        .map_err(edit_bridge_error)?;
    match (&resolved.operation, &current.desired) {
        (WriteOperation::Create, DesiredState::Deleted)
        | (WriteOperation::Replace, DesiredState::Present(_)) => {}
        _ => {
            return Err(BridgeError::new(
                ErrorCode::WriteConflict,
                "remote write base conflicts with the request",
                false,
            ));
        }
    }
    if let Some(expected) = &resolved.expected_sha256 {
        let DesiredState::Present(bytes) = &current.desired else {
            return Err(BridgeError::new(
                ErrorCode::WriteConflict,
                "remote write base conflicts with the request",
                false,
            ));
        };
        let actual = format!("{:x}", Sha256::digest(bytes));
        if actual != *expected {
            return Err(BridgeError::new(
                ErrorCode::WriteConflict,
                "remote write base hash conflicts with the request",
                false,
            ));
        }
    }
    let desired = DesiredState::Present(Arc::from(std::mem::take(&mut resolved.content)));
    let disposition = bridge
        .edit_cache
        .mutate_prepared_batch(vec![PreparedEdit {
            key,
            expected_generation: current.generation,
            desired: desired.clone(),
            payload_bytes: desired.len(),
        }])
        .await
        .map_err(edit_bridge_error)?;
    if disposition == BatchMutationDisposition::ImmediateWriteRequired {
        resolved.content = desired.as_ref().to_vec();
        bridge
            .edit_cache
            .flush_host(&resolved.host)
            .await
            .map_err(edit_bridge_error)?;
        let host = resolved.host.clone();
        let result = execute_preflighted_write(bridge, resolved, cancel).await?;
        bridge.edit_cache.invalidate_clean_host(&host).await;
        return Ok(result);
    }
    let context = bridge
        .edit_backend
        .context_for(&resolved.host)
        .await
        .ok_or_else(|| {
            BridgeError::new(ErrorCode::ProtocolError, "edit context is missing", false)
        })?;
    let mode = match current.base {
        RemoteBase::Missing => 0o600,
        RemoteBase::Regular { mode, .. } => mode,
    };
    Ok(WriteResult {
        context,
        actual_path: encode_bytes(resolved.path.as_str().as_bytes()),
        relative_path: encode_bytes(resolved.path.relative().as_bytes()),
        operation: resolved.operation,
        raw_bytes: resolved.raw_bytes,
        sha256: resolved.sha256,
        mode,
        temporary_cleanup_confirmed: false,
    })
}

pub(super) async fn execute_preflighted_write(
    bridge: &RemoteBridge,
    resolved: ResolvedWrite,
    cancel: CancellationToken,
) -> BridgeResult<WriteResult> {
    execute_preflighted_write_at_root(bridge, resolved, cancel).await
}

pub(super) async fn execute_preflighted_write_at_root(
    bridge: &RemoteBridge,
    mut resolved: ResolvedWrite,
    cancel: CancellationToken,
) -> BridgeResult<WriteResult> {
    let limits = bridge.runner.config().limits();
    let args = fixed_args(&resolved);
    let stdin = std::mem::take(&mut resolved.content);
    let owner = InternalSpoolOwner::new();
    let request = FixedRunRequest {
        kind: FixedOperationKind::Mutation,
        host: resolved.host.clone(),
        script: WRITE_SCRIPT,
        args,
        stdin: Some(stdin),
        rooted_paths: RootedPathInputs {
            argument_indices: &[0],
            argument_stride: None,
            stdin_nul_paths: false,
        },
        required_capabilities: &["safe_write"],
        stdout_limit: WRITE_PROTOCOL_LIMIT,
        stderr_limit: 1,
        timeout: Duration::from_millis(limits.command_timeout_ms),
        cleanup: owner.registration(),
    };
    let (_owner, result) = execute_owned_mutation(bridge, request, owner, cancel).await?;

    let protocol = parse_write_protocol(&result, &resolved)
        .await
        .map_err(|_| BridgeError::mutation_outcome_unknown())
        .map_err(|error| attach_fixed_result_context(error, &resolved.host, &result))?;
    match protocol {
        WriteProtocol::Success {
            operation,
            size,
            sha256,
            mode,
        } => Ok(WriteResult {
            context: context(
                resolved.host,
                result.capability.physical_root.clone(),
                &result.shell,
                result.helper_mode,
            ),
            actual_path: encode_bytes(resolved.path.as_str().as_bytes()),
            relative_path: encode_bytes(resolved.path.relative().as_bytes()),
            operation,
            raw_bytes: size,
            sha256,
            mode,
            temporary_cleanup_confirmed: true,
        }),
        WriteProtocol::Domain(code) => Err(attach_fixed_result_context(
            domain_error(code),
            &resolved.host,
            &result,
        )),
        WriteProtocol::CapabilityMismatch => {
            bridge.runner.invalidate_capability(&resolved.host).await;
            Err(attach_fixed_result_context(
                BridgeError::new(
                    ErrorCode::RemoteCapabilityMissing,
                    "remote safe-write capability is unavailable",
                    false,
                ),
                &resolved.host,
                &result,
            ))
        }
    }
}

pub(super) async fn guarded_delete(
    bridge: &RemoteBridge,
    request: GuardedDeleteRequest,
    cancel: CancellationToken,
) -> BridgeResult<GuardedDeleteResult> {
    let resolved = preflight_delete(bridge, request)?;
    execute_preflighted_delete(bridge, resolved, cancel)
        .await
        .map(|(result, _context)| result)
}

pub(super) async fn execute_preflighted_delete(
    bridge: &RemoteBridge,
    resolved: ResolvedDelete,
    cancel: CancellationToken,
) -> BridgeResult<(GuardedDeleteResult, super::RemoteContext)> {
    execute_preflighted_delete_at_root(bridge, resolved, cancel).await
}

pub(super) async fn execute_preflighted_delete_at_root(
    bridge: &RemoteBridge,
    resolved: ResolvedDelete,
    cancel: CancellationToken,
) -> BridgeResult<(GuardedDeleteResult, super::RemoteContext)> {
    let limits = bridge.runner.config().limits();
    let owner = InternalSpoolOwner::new();
    let request = FixedRunRequest {
        kind: FixedOperationKind::Mutation,
        host: resolved.host.clone(),
        script: GUARDED_DELETE_SCRIPT,
        args: delete_fixed_args(&resolved),
        stdin: None,
        rooted_paths: RootedPathInputs {
            argument_indices: &[0],
            argument_stride: None,
            stdin_nul_paths: false,
        },
        required_capabilities: &["guarded_delete"],
        stdout_limit: WRITE_PROTOCOL_LIMIT,
        stderr_limit: 1,
        timeout: Duration::from_millis(limits.command_timeout_ms),
        cleanup: owner.registration(),
    };
    let (_owner, result) = execute_owned_mutation(bridge, request, owner, cancel).await?;

    let protocol = parse_delete_protocol(&result, &resolved)
        .await
        .map_err(|_| BridgeError::mutation_outcome_unknown())
        .map_err(|error| attach_fixed_result_context(error, &resolved.host, &result))?;
    match protocol {
        DeleteProtocol::Success { sha256 } => Ok((
            GuardedDeleteResult {
                actual_path: encode_bytes(resolved.path.as_str().as_bytes()),
                relative_path: encode_bytes(resolved.path.relative().as_bytes()),
                deleted_sha256: sha256,
                absence_confirmed: true,
            },
            context(
                resolved.host,
                result.capability.physical_root.clone(),
                &result.shell,
                result.helper_mode,
            ),
        )),
        DeleteProtocol::Domain(code) => Err(attach_fixed_result_context(
            delete_domain_error(code),
            &resolved.host,
            &result,
        )),
        DeleteProtocol::CapabilityMismatch => {
            bridge.runner.invalidate_capability(&resolved.host).await;
            Err(attach_fixed_result_context(
                BridgeError::new(
                    ErrorCode::RemoteCapabilityMissing,
                    "remote guarded-delete capability is unavailable",
                    false,
                ),
                &resolved.host,
                &result,
            ))
        }
    }
}

async fn execute_owned_mutation(
    bridge: &RemoteBridge,
    request: FixedRunRequest,
    owner: InternalSpoolOwner,
    cancel: CancellationToken,
) -> BridgeResult<(InternalSpoolOwner, FixedRunResult)> {
    let child_cancel = cancel.child_token();
    let cancellation_on_drop = child_cancel.clone().drop_guard();
    let runner = Arc::clone(&bridge.runner);
    let owner_task = tokio::spawn(async move {
        let result = runner.execute_fixed_once(request, child_cancel).await;
        (owner, result)
    });
    let joined = owner_task
        .await
        .map_err(|_| BridgeError::mutation_outcome_unknown())?;
    let _child_cancel = cancellation_on_drop.disarm();
    let (owner, result) = joined;
    result.map(|result| (owner, result))
}

pub(super) fn preflight_write(
    bridge: &RemoteBridge,
    request: WriteRequest,
) -> BridgeResult<ResolvedWrite> {
    let WriteRequest {
        host,
        path,
        content,
        encoding,
        mode,
    } = request;
    let path = prepare_mutation_path(bridge, host, &path, MutationTarget::Write)?;
    preflight_write_resolved(bridge, path, content, encoding, mode)
}

pub(super) fn preflight_write_resolved(
    bridge: &RemoteBridge,
    prepared: PreparedMutationPath,
    content: String,
    encoding: WriteEncoding,
    mode: WriteMode,
) -> BridgeResult<ResolvedWrite> {
    let limits = bridge.runner.config().limits();
    let (operation, expected_sha256) = match mode {
        WriteMode::Create => (WriteOperation::Create, None),
        WriteMode::Replace { expected_sha256 } => {
            if let Some(expected) = &expected_sha256 {
                validate_hash(expected)?;
            }
            (WriteOperation::Replace, expected_sha256)
        }
    };
    let content = match encoding {
        WriteEncoding::Utf8 => {
            if content.len() > limits.max_write_bytes {
                return Err(write_too_large());
            }
            content.into_bytes()
        }
        WriteEncoding::Base64 => {
            preflight_base64_length(&content, limits.max_write_bytes)?;
            let decoded = STANDARD.decode(content).map_err(|_| {
                BridgeError::invalid_argument("write content is not canonical Base64")
            })?;
            if decoded.len() > limits.max_write_bytes {
                return Err(write_too_large());
            }
            decoded
        }
    };
    let raw_bytes = u64::try_from(content.len())
        .map_err(|_| BridgeError::new(ErrorCode::RequestTooLarge, "write is too large", false))?;
    let sha256 = format!("{:x}", Sha256::digest(&content));
    let PreparedMutationPath {
        host,
        path,
        parent,
        basename,
    } = prepared;
    let resolved = ResolvedWrite {
        host,
        path,
        parent,
        basename,
        content,
        operation,
        expected_sha256,
        raw_bytes,
        sha256,
    };
    let command = render_fixed_command(WRITE_SCRIPT, &fixed_args(&resolved))?;
    let transport_bytes = command
        .len()
        .checked_add(resolved.content.len())
        .ok_or_else(request_too_large)?;
    if transport_bytes > limits.max_frame_bytes {
        return Err(request_too_large());
    }
    Ok(resolved)
}

pub(super) fn preflight_delete(
    bridge: &RemoteBridge,
    request: GuardedDeleteRequest,
) -> BridgeResult<ResolvedDelete> {
    let GuardedDeleteRequest {
        host,
        path,
        expected_sha256,
    } = request;
    let path = prepare_mutation_path(bridge, host, &path, MutationTarget::Delete)?;
    preflight_delete_resolved(bridge, path, expected_sha256)
}

pub(super) fn prepare_patch_path(
    bridge: &RemoteBridge,
    host: &str,
    requested: &str,
) -> BridgeResult<PreparedMutationPath> {
    prepare_mutation_path(bridge, host.to_owned(), requested, MutationTarget::Patch)
}

pub(super) fn preflight_delete_resolved(
    bridge: &RemoteBridge,
    prepared: PreparedMutationPath,
    expected_sha256: String,
) -> BridgeResult<ResolvedDelete> {
    let max_frame_bytes = bridge
        .runner
        .config()
        .host(&prepared.host)?
        .limits
        .max_frame_bytes;
    validate_hash(&expected_sha256)?;
    let PreparedMutationPath {
        host,
        path,
        parent,
        basename,
    } = prepared;
    let resolved = ResolvedDelete {
        host,
        path,
        parent,
        basename,
        expected_sha256,
    };
    let command = render_fixed_command(GUARDED_DELETE_SCRIPT, &delete_fixed_args(&resolved))?;
    if command.len() > max_frame_bytes {
        return Err(request_too_large());
    }
    Ok(resolved)
}

fn prepare_mutation_path(
    bridge: &RemoteBridge,
    host: String,
    requested: &str,
    target: MutationTarget,
) -> BridgeResult<PreparedMutationPath> {
    bridge.runner.config().require_discovered_alias(&host)?;
    validate_write_path(requested)?;
    let path = super::resolve_path(requested)?;
    if path.as_str() == "/" {
        let message = match target {
            MutationTarget::Write => "write target must not be the remote filesystem root",
            MutationTarget::Delete => "delete target must not be the remote filesystem root",
            MutationTarget::Patch => "patch target must not be the remote filesystem root",
        };
        return Err(BridgeError::invalid_argument(message));
    }
    let (parent, basename) = split_parent_basename(path.as_str())?;
    Ok(PreparedMutationPath {
        host,
        path,
        parent,
        basename,
    })
}

fn fixed_args(resolved: &ResolvedWrite) -> Vec<String> {
    vec![
        resolved.parent.clone(),
        resolved.basename.clone(),
        match resolved.operation {
            WriteOperation::Create => "CREATE",
            WriteOperation::Replace => "REPLACE",
        }
        .to_owned(),
        resolved.raw_bytes.to_string(),
        resolved.sha256.clone(),
        if resolved.expected_sha256.is_some() {
            "1"
        } else {
            "0"
        }
        .to_owned(),
        resolved.expected_sha256.clone().unwrap_or_default(),
    ]
}

fn delete_fixed_args(resolved: &ResolvedDelete) -> Vec<String> {
    vec![
        resolved.parent.clone(),
        resolved.basename.clone(),
        resolved.expected_sha256.clone(),
    ]
}

fn validate_write_path(path: &str) -> BridgeResult<()> {
    if path.is_empty() || path == "." {
        return Err(BridgeError::invalid_argument(
            "write target must not be empty or dot",
        ));
    }
    if path.len() > MAX_INPUT_PATH_BYTES {
        return Err(request_too_large());
    }
    if path.as_bytes().contains(&0) {
        return Err(BridgeError::invalid_argument(
            "NUL is not valid in a remote path",
        ));
    }
    Ok(())
}

pub(super) fn split_parent_basename(path: &str) -> BridgeResult<(String, String)> {
    let (parent, basename) = path
        .rsplit_once('/')
        .ok_or_else(|| BridgeError::invalid_argument("write target is invalid"))?;
    if basename.is_empty() || basename == "." || basename == ".." {
        return Err(BridgeError::invalid_argument("write target is invalid"));
    }
    Ok((
        if parent.is_empty() { "/" } else { parent }.to_owned(),
        basename.to_owned(),
    ))
}

fn validate_hash(hash: &str) -> BridgeResult<()> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BridgeError::invalid_argument(
            "expected SHA-256 must be 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

fn preflight_base64_length(content: &str, max_write_bytes: usize) -> BridgeResult<()> {
    if content.is_empty() {
        return Ok(());
    }
    if !content.len().is_multiple_of(4) {
        return Err(BridgeError::invalid_argument(
            "write content is not canonical Base64",
        ));
    }
    let padding = content
        .bytes()
        .rev()
        .take_while(|byte| *byte == b'=')
        .count();
    if padding > 2 || content.as_bytes()[..content.len() - padding].contains(&b'=') {
        return Err(BridgeError::invalid_argument(
            "write content is not canonical Base64",
        ));
    }
    let decoded_length = (content.len() / 4)
        .checked_mul(3)
        .and_then(|length| length.checked_sub(padding))
        .ok_or_else(write_too_large)?;
    if decoded_length > max_write_bytes {
        return Err(write_too_large());
    }
    Ok(())
}

async fn parse_write_protocol(
    result: &crate::ssh::FixedRunResult,
    resolved: &ResolvedWrite,
) -> BridgeResult<WriteProtocol> {
    let stderr = read_small_stream(&result.output, StreamKind::Stderr, 1).await?;
    let stdout = read_small_stream(
        &result.output,
        StreamKind::Stdout,
        WRITE_PROTOCOL_LIMIT as usize,
    )
    .await?;
    parse_write_protocol_bytes(&stdout, &stderr, resolved)
}

fn parse_write_protocol_bytes(
    stdout: &[u8],
    stderr: &[u8],
    resolved: &ResolvedWrite,
) -> BridgeResult<WriteProtocol> {
    if !stderr.is_empty() {
        return Err(protocol_error("write protocol stderr is not empty"));
    }
    let records = parse_records(stdout)?;
    match records.as_slice() {
        [status] if status.as_slice() == b"STATUS=WRITE_CONFLICT" => {
            Ok(WriteProtocol::Domain(ErrorCode::WriteConflict))
        }
        [status] if status.as_slice() == b"STATUS=NOT_FOUND" => {
            Ok(WriteProtocol::Domain(ErrorCode::NotFound))
        }
        [status] if status.as_slice() == b"STATUS=NOT_DIRECTORY" => {
            Ok(WriteProtocol::Domain(ErrorCode::NotDirectory))
        }
        [status] if status.as_slice() == b"STATUS=PERMISSION_DENIED" => {
            Ok(WriteProtocol::Domain(ErrorCode::PermissionDenied))
        }
        [status, capability]
            if status.as_slice() == b"STATUS=CAPABILITY_MISMATCH"
                && capability.as_slice() == b"CAPABILITY=safe_write" =>
        {
            Ok(WriteProtocol::CapabilityMismatch)
        }
        [status, operation, size, sha256, mode, cleanup]
            if status.as_slice() == b"STATUS=SUCCESS" =>
        {
            let operation = match operation.as_slice() {
                b"OPERATION=CREATE" => WriteOperation::Create,
                b"OPERATION=REPLACE" => WriteOperation::Replace,
                _ => return Err(protocol_error("write operation is invalid")),
            };
            let size = parse_decimal_field(size, b"SIZE=")?;
            let sha256 = parse_text_field(sha256, b"SHA256=")?;
            validate_hash(&sha256).map_err(|_| protocol_error("write hash is invalid"))?;
            let mode = parse_decimal_field(mode, b"MODE=")?;
            let mode = u32::try_from(mode).map_err(|_| protocol_error("write mode is invalid"))?;
            if mode > 0o777 {
                return Err(protocol_error("write mode is invalid"));
            }
            if cleanup.as_slice() != b"TEMPORARY_CLEANUP_CONFIRMED=1" {
                return Err(protocol_error("write cleanup proof is invalid"));
            }
            if operation != resolved.operation
                || size != resolved.raw_bytes
                || sha256 != resolved.sha256
                || (operation == WriteOperation::Create && mode != 0o600)
            {
                return Err(protocol_error("write success does not match the request"));
            }
            Ok(WriteProtocol::Success {
                operation,
                size,
                sha256,
                mode,
            })
        }
        _ => Err(protocol_error("write protocol record is invalid")),
    }
}

async fn parse_delete_protocol(
    result: &crate::ssh::FixedRunResult,
    resolved: &ResolvedDelete,
) -> BridgeResult<DeleteProtocol> {
    let stderr = read_small_stream(&result.output, StreamKind::Stderr, 1).await?;
    let stdout = read_small_stream(
        &result.output,
        StreamKind::Stdout,
        WRITE_PROTOCOL_LIMIT as usize,
    )
    .await?;
    parse_delete_protocol_bytes(&stdout, &stderr, resolved)
}

fn parse_delete_protocol_bytes(
    stdout: &[u8],
    stderr: &[u8],
    resolved: &ResolvedDelete,
) -> BridgeResult<DeleteProtocol> {
    if !stderr.is_empty() {
        return Err(protocol_error("delete protocol stderr is not empty"));
    }
    let records = parse_records(stdout)?;
    match records.as_slice() {
        [status] if status.as_slice() == b"STATUS=WRITE_CONFLICT" => {
            Ok(DeleteProtocol::Domain(ErrorCode::WriteConflict))
        }
        [status] if status.as_slice() == b"STATUS=NOT_FOUND" => {
            Ok(DeleteProtocol::Domain(ErrorCode::NotFound))
        }
        [status] if status.as_slice() == b"STATUS=NOT_DIRECTORY" => {
            Ok(DeleteProtocol::Domain(ErrorCode::NotDirectory))
        }
        [status] if status.as_slice() == b"STATUS=PERMISSION_DENIED" => {
            Ok(DeleteProtocol::Domain(ErrorCode::PermissionDenied))
        }
        [status, capability]
            if status.as_slice() == b"STATUS=CAPABILITY_MISMATCH"
                && capability.as_slice() == b"CAPABILITY=guarded_delete" =>
        {
            Ok(DeleteProtocol::CapabilityMismatch)
        }
        [status, operation, sha256, absence]
            if status.as_slice() == b"STATUS=SUCCESS"
                && operation.as_slice() == b"OPERATION=DELETE"
                && absence.as_slice() == b"ABSENCE_CONFIRMED=1" =>
        {
            let sha256 = parse_text_field(sha256, b"SHA256=")?;
            validate_hash(&sha256).map_err(|_| protocol_error("delete hash is invalid"))?;
            if sha256 != resolved.expected_sha256 {
                return Err(protocol_error("delete success does not match the request"));
            }
            Ok(DeleteProtocol::Success { sha256 })
        }
        _ => Err(protocol_error("delete protocol record is invalid")),
    }
}

fn parse_records(bytes: &[u8]) -> BridgeResult<Vec<Vec<u8>>> {
    if bytes.last() != Some(&0) {
        return Err(protocol_error("write protocol is not NUL terminated"));
    }
    let mut records = Vec::new();
    for record in bytes[..bytes.len() - 1].split(|byte| *byte == 0) {
        if record.is_empty() {
            return Err(protocol_error("write protocol contains an empty record"));
        }
        records.push(record.to_vec());
    }
    if records.is_empty() {
        return Err(protocol_error("write protocol is empty"));
    }
    Ok(records)
}

fn parse_decimal_field(record: &[u8], prefix: &[u8]) -> BridgeResult<u64> {
    let value = record
        .strip_prefix(prefix)
        .ok_or_else(|| protocol_error("write numeric field is invalid"))?;
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(protocol_error("write numeric field is invalid"));
    }
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| protocol_error("write numeric field is invalid"))
}

fn parse_text_field(record: &[u8], prefix: &[u8]) -> BridgeResult<String> {
    let value = record
        .strip_prefix(prefix)
        .ok_or_else(|| protocol_error("write text field is invalid"))?;
    std::str::from_utf8(value)
        .map(str::to_owned)
        .map_err(|_| protocol_error("write text field is invalid"))
}

fn domain_error(code: ErrorCode) -> BridgeError {
    match code {
        ErrorCode::WriteConflict => BridgeError::new(
            ErrorCode::WriteConflict,
            "remote write target conflicts with the request",
            false,
        ),
        ErrorCode::NotFound => BridgeError::not_found(),
        ErrorCode::NotDirectory => BridgeError::not_directory(),
        ErrorCode::PermissionDenied => BridgeError::permission_denied(),
        _ => BridgeError::mutation_outcome_unknown(),
    }
}

fn delete_domain_error(code: ErrorCode) -> BridgeError {
    match code {
        ErrorCode::WriteConflict => BridgeError::new(
            ErrorCode::WriteConflict,
            "remote delete target conflicts with the expected content",
            false,
        ),
        ErrorCode::NotFound => BridgeError::not_found(),
        ErrorCode::NotDirectory => BridgeError::not_directory(),
        ErrorCode::PermissionDenied => BridgeError::permission_denied(),
        _ => BridgeError::mutation_outcome_unknown(),
    }
}

fn protocol_error(message: &str) -> BridgeError {
    BridgeError::new(ErrorCode::ProtocolError, message, false)
}

fn request_too_large() -> BridgeError {
    BridgeError::new(
        ErrorCode::RequestTooLarge,
        "write request exceeds the configured frame limit",
        false,
    )
}

fn write_too_large() -> BridgeError {
    BridgeError::new(
        ErrorCode::RequestTooLarge,
        "write content exceeds the configured limit",
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        DeleteProtocol, GuardedDeleteRequest, ResolvedDelete, ResolvedWrite, WriteOperation,
        WriteProtocol, parse_delete_protocol_bytes, parse_write_protocol_bytes,
    };
    use crate::config::{Config, HostProfile};
    use crate::error::{BridgeResult, ErrorCode};
    use crate::output::OutputStore;
    use crate::path::RemotePath;
    use crate::remote::RemoteBridge;
    use crate::ssh::{RuntimePaths, SshRunner};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::sync::Arc;
    use tokio_util::sync::CancellationToken;

    const ABC_HASH: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn resolved(operation: WriteOperation) -> ResolvedWrite {
        ResolvedWrite {
            host: "dev".to_owned(),
            path: RemotePath::resolve("/root", "file").unwrap(),
            parent: "/root".to_owned(),
            basename: "file".to_owned(),
            content: Vec::new(),
            operation,
            expected_sha256: None,
            raw_bytes: 3,
            sha256: ABC_HASH.to_owned(),
        }
    }

    fn parse_create(stdout: &[u8], stderr: &[u8]) -> BridgeResult<WriteProtocol> {
        parse_write_protocol_bytes(stdout, stderr, &resolved(WriteOperation::Create))
    }

    fn assert_protocol_error(stdout: &[u8], stderr: &[u8]) {
        assert_eq!(
            parse_create(stdout, stderr).unwrap_err().code,
            ErrorCode::ProtocolError,
            "stdout={stdout:?}, stderr={stderr:?}"
        );
    }

    fn delete_fixture(root: &std::path::Path) -> (tempfile::TempDir, RemoteBridge) {
        delete_fixture_with_options(root, false, &[])
    }

    fn delete_fixture_with_options(
        root: &std::path::Path,
        read_only: bool,
        extra: &[(&str, OsString)],
    ) -> (tempfile::TempDir, RemoteBridge) {
        let runtime_base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
        let output = Arc::new(OutputStore::new(&runtime).unwrap());
        let mut config = Config::default();
        config.hosts.insert(
            "dev".to_owned(),
            HostProfile {
                root: root.to_str().unwrap().to_owned(),
                description: None,
                read_only,
                limits: Default::default(),
            },
        );
        let mut environment = BTreeMap::from([
            (
                OsString::from("FAKE_SSH_MODE"),
                OsString::from("local-fixed"),
            ),
            (OsString::from("FAKE_SSH_ROOT"), root.as_os_str().to_owned()),
        ]);
        for (key, value) in extra {
            environment.insert(OsString::from(key), value.clone());
        }
        let runner = SshRunner::with_executable(
            Arc::new(config),
            runtime,
            output,
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-ssh.sh"),
            environment,
        )
        .unwrap();
        (runtime_base, RemoteBridge::new(Arc::new(runner)))
    }

    fn sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn absolute(root: &std::path::Path, path: &str) -> String {
        root.join(path).to_str().unwrap().to_owned()
    }

    fn ssh_call_count(log: &std::path::Path, marker: &str) -> usize {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .filter(|line| *line == marker)
            .count()
    }

    fn assert_no_dispatcher_request_artifacts(directory: &std::path::Path) {
        let unexpected = std::fs::read_dir(directory)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .filter(|name| {
                !name
                    .to_string_lossy()
                    .starts_with("codex-ssh-bridge-dispatcher.")
            })
            .collect::<Vec<_>>();
        assert!(
            unexpected.is_empty(),
            "dispatcher request artifacts remain: {unexpected:?}"
        );
    }

    fn resolved_delete() -> ResolvedDelete {
        ResolvedDelete {
            host: "dev".to_owned(),
            path: RemotePath::resolve("/root", "victim").unwrap(),
            parent: "/root".to_owned(),
            basename: "victim".to_owned(),
            expected_sha256: sha256(b"victim"),
        }
    }

    #[tokio::test]
    async fn task5_guarded_delete_success_confirms_absence() {
        let remote = tempfile::TempDir::new().unwrap();
        std::fs::write(remote.path().join("victim"), b"victim").unwrap();
        let (_runtime, bridge) = delete_fixture(remote.path());
        let result = bridge
            .guarded_delete(
                GuardedDeleteRequest {
                    host: "dev".to_owned(),
                    path: absolute(remote.path(), "victim"),
                    expected_sha256: sha256(b"victim"),
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(result.deleted_sha256, sha256(b"victim"));
        assert!(result.absence_confirmed);
        assert!(!remote.path().join("victim").exists());
    }

    #[test]
    fn task5_guarded_delete_protocol_parser_is_closed() {
        let expected = sha256(b"victim");
        let success =
            format!("STATUS=SUCCESS\0OPERATION=DELETE\0SHA256={expected}\0ABSENCE_CONFIRMED=1\0");
        assert_eq!(
            parse_delete_protocol_bytes(success.as_bytes(), b"", &resolved_delete()).unwrap(),
            DeleteProtocol::Success {
                sha256: expected.clone()
            }
        );
        for (record, result) in [
            (
                "STATUS=WRITE_CONFLICT\0",
                DeleteProtocol::Domain(ErrorCode::WriteConflict),
            ),
            (
                "STATUS=NOT_FOUND\0",
                DeleteProtocol::Domain(ErrorCode::NotFound),
            ),
            (
                "STATUS=NOT_DIRECTORY\0",
                DeleteProtocol::Domain(ErrorCode::NotDirectory),
            ),
            (
                "STATUS=PERMISSION_DENIED\0",
                DeleteProtocol::Domain(ErrorCode::PermissionDenied),
            ),
        ] {
            assert_eq!(
                parse_delete_protocol_bytes(record.as_bytes(), b"", &resolved_delete()).unwrap(),
                result
            );
        }
        assert_eq!(
            parse_delete_protocol_bytes(
                b"STATUS=CAPABILITY_MISMATCH\0CAPABILITY=guarded_delete\0",
                b"",
                &resolved_delete(),
            )
            .unwrap(),
            DeleteProtocol::CapabilityMismatch
        );

        let invalid = [
            Vec::new(),
            b"STATUS=NOT_FOUND".to_vec(),
            b"STATUS=NOT_FOUND\0EXTRA=1\0".to_vec(),
            b"STATUS=CAPABILITY_MISMATCH\0CAPABILITY=safe_write\0".to_vec(),
            format!("STATUS=SUCCESS\0OPERATION=REMOVE\0SHA256={expected}\0ABSENCE_CONFIRMED=1\0")
                .into_bytes(),
            format!(
                "STATUS=SUCCESS\0OPERATION=DELETE\0SHA256={}\0ABSENCE_CONFIRMED=1\0",
                "0".repeat(64)
            )
            .into_bytes(),
            format!("STATUS=SUCCESS\0OPERATION=DELETE\0SHA256={expected}\0ABSENCE_CONFIRMED=0\0")
                .into_bytes(),
        ];
        for stdout in invalid {
            assert_eq!(
                parse_delete_protocol_bytes(&stdout, b"", &resolved_delete())
                    .unwrap_err()
                    .code,
                ErrorCode::ProtocolError,
                "stdout={stdout:?}"
            );
        }
        assert_eq!(
            parse_delete_protocol_bytes(b"STATUS=NOT_FOUND\0", b"x", &resolved_delete())
                .unwrap_err()
                .code,
            ErrorCode::ProtocolError
        );
    }

    #[test]
    fn task5_mutation_scripts_reject_extra_arguments_before_sentinel_io() {
        let scratch = tempfile::TempDir::new().unwrap();
        let hash = "0".repeat(64);
        let write = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                super::WRITE_SCRIPT,
                "probe",
                "/definitely-missing-parent",
                "target",
                "CREATE",
                "0",
                &hash,
                "0",
                "",
                "extra",
            ])
            .env("TMPDIR", scratch.path())
            .output()
            .unwrap();
        assert_eq!(write.status.code(), Some(2));
        assert!(write.stdout.is_empty());
        assert!(write.stderr.is_empty());
        assert_no_dispatcher_request_artifacts(scratch.path());

        let delete = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                super::GUARDED_DELETE_SCRIPT,
                "probe",
                "/definitely-missing-parent",
                "target",
                &hash,
                "extra",
            ])
            .env("TMPDIR", scratch.path())
            .output()
            .unwrap();
        assert_eq!(delete.status.code(), Some(2));
        assert!(delete.stdout.is_empty());
        assert!(delete.stderr.is_empty());
        assert_no_dispatcher_request_artifacts(scratch.path());
    }

    #[test]
    fn task5_shell_stat_parsers_declare_closed_numeric_shapes() {
        for script in [super::WRITE_SCRIPT, super::GUARDED_DELETE_SCRIPT] {
            assert!(script.contains("[ \"${#1}\" -le 20 ]"));
            assert!(script.contains("[ \"${#1}\" -eq 4 ] || return 1"));
            assert!(script.contains("[ \"${#3}\" -le 4 ] || return 1"));
            assert!(script.contains("codex_mutation_decimal_valid \"$2\" || return 1"));
            assert!(script.contains("codex_mutation_decimal_valid \"$4\" || return 1"));
            assert!(script.contains("codex_mutation_decimal_valid \"$5\" || return 1"));
            assert!(script.contains("codex_mutation_decimal_valid \"$6\" || return 1"));
            assert!(script.contains("codex_mutation_decimal_valid \"$7\" || return 1"));
        }
        assert!(!super::WRITE_SCRIPT.contains("chmod -h"));
        assert!(super::WRITE_SCRIPT.contains("codex_mutation_mode \"$target_mode\" \"$tmp\""));
        assert!(!super::WRITE_SCRIPT.contains("codex_mutation_mode \"$target_mode\" \"$target\""));
        assert!(super::WRITE_SCRIPT.contains("exec 9<>\"$codex_mode_path\""));
        assert!(super::WRITE_SCRIPT.contains("chmod \"$codex_mode\" -- /proc/self/fd/9"));
    }

    #[test]
    fn task5_unreachable_parent_classification_has_a_strict_stat_call_bound() {
        use std::os::unix::fs::PermissionsExt;

        const CLASSIFIER_STAT_CALL_LIMIT: usize = 33;

        let fixture = tempfile::TempDir::new().unwrap();
        let shim_directory = fixture.path().join("shim");
        std::fs::create_dir(&shim_directory).unwrap();
        let missing_prefix = fixture.path().join("missing-root");
        let deep_parent = (0..128).fold(missing_prefix.clone(), |path, _| path.join("child"));
        let marker = fixture.path().join("stat-count");
        let stat = shim_directory.join("stat");
        std::fs::write(
            &stat,
            format!(
                "#!/bin/sh\nlast=\nfor last do :; done\ncase \"$last\" in\n  {prefix}|{prefix}/*) count=$(/usr/bin/cat {marker} 2>/dev/null || printf 0); count=$((count + 1)); printf %s \"$count\" >{marker}; exit 1;;\nesac\nexec /usr/bin/stat \"$@\"\n",
                prefix = crate::quote::shell_word(missing_prefix.to_str().unwrap()).unwrap(),
                marker = crate::quote::shell_word(marker.to_str().unwrap()).unwrap(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stat, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = format!("{}:/usr/local/bin:/usr/bin:/bin", shim_directory.display());
        let hash = "0".repeat(64);

        for (script, arguments) in [
            (
                super::WRITE_SCRIPT,
                vec![
                    deep_parent.to_str().unwrap(),
                    "target",
                    "CREATE",
                    "0",
                    &hash,
                    "0",
                    "",
                ],
            ),
            (
                super::GUARDED_DELETE_SCRIPT,
                vec![deep_parent.to_str().unwrap(), "target", &hash],
            ),
        ] {
            let _ = std::fs::remove_file(&marker);
            let output = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(script)
                .arg("codex-ssh-bridge-op")
                .args(arguments)
                .env("PATH", &path)
                .env("TMPDIR", fixture.path())
                .output()
                .unwrap();
            let calls = std::fs::read_to_string(&marker)
                .unwrap()
                .parse::<usize>()
                .unwrap();
            assert_eq!(output.status.code(), Some(3), "stdout={:?}", output.stdout);
            assert!(output.stdout.is_empty());
            assert!(output.stderr.is_empty());
            assert!(
                calls <= CLASSIFIER_STAT_CALL_LIMIT,
                "classifier launched {calls} stat commands"
            );
        }
    }

    #[test]
    fn task5_unreachable_parent_malformed_lstat_stops_classification() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = tempfile::TempDir::new().unwrap();
        let shim_directory = fixture.path().join("shim");
        std::fs::create_dir(&shim_directory).unwrap();
        let missing_prefix = fixture.path().join("missing-root");
        let deep_parent = (0..8).fold(missing_prefix.clone(), |path, _| path.join("child"));
        let marker = fixture.path().join("lstat-count");
        let stat = shim_directory.join("stat");
        std::fs::write(
            &stat,
            format!(
                "#!/bin/sh\nlast=\nfor last do :; done\ncase \"$last\" in\n  {prefix}|{prefix}/*)\n    case \" $* \" in *\" -L \"*) exit 1;; esac\n    count=$(/usr/bin/cat {marker} 2>/dev/null || printf 0)\n    count=$((count + 1))\n    printf %s \"$count\" >{marker}\n    if [ \"$count\" -eq 1 ]; then printf 'malformed\\n'; exit 0; fi\n    exit 1;;\nesac\nexec /usr/bin/stat \"$@\"\n",
                prefix = crate::quote::shell_word(missing_prefix.to_str().unwrap()).unwrap(),
                marker = crate::quote::shell_word(marker.to_str().unwrap()).unwrap(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stat, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = format!("{}:/usr/local/bin:/usr/bin:/bin", shim_directory.display());
        let hash = "0".repeat(64);

        for (script, arguments) in [
            (
                super::WRITE_SCRIPT,
                vec![
                    deep_parent.to_str().unwrap(),
                    "target",
                    "CREATE",
                    "0",
                    &hash,
                    "0",
                    "",
                ],
            ),
            (
                super::GUARDED_DELETE_SCRIPT,
                vec![deep_parent.to_str().unwrap(), "target", &hash],
            ),
        ] {
            let _ = std::fs::remove_file(&marker);
            let output = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(script)
                .arg("codex-ssh-bridge-op")
                .args(arguments)
                .env("PATH", &path)
                .env("TMPDIR", fixture.path())
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(3));
            assert!(output.stdout.is_empty());
            assert!(output.stderr.is_empty());
            assert_eq!(std::fs::read_to_string(&marker).unwrap(), "1");
        }
    }

    #[tokio::test]
    async fn task5_guarded_delete_rejects_missing_wrong_hash_and_non_regular_entries() {
        use std::os::unix::fs::symlink;

        let remote = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(remote.path().join("directory")).unwrap();
        let fifo = remote.path().join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        std::fs::write(remote.path().join("outside"), b"outside").unwrap();
        symlink("outside", remote.path().join("live-link")).unwrap();
        symlink("missing", remote.path().join("dangling-link")).unwrap();
        std::fs::write(remote.path().join("wrong-hash"), b"old").unwrap();
        let (_runtime, bridge) = delete_fixture(remote.path());

        for (path, hash, expected_code) in [
            ("missing", sha256(b"missing"), ErrorCode::NotFound),
            ("directory", sha256(b"directory"), ErrorCode::WriteConflict),
            ("fifo", sha256(b"fifo"), ErrorCode::WriteConflict),
            ("live-link", sha256(b"outside"), ErrorCode::WriteConflict),
            (
                "dangling-link",
                sha256(b"missing"),
                ErrorCode::WriteConflict,
            ),
            ("wrong-hash", sha256(b"different"), ErrorCode::WriteConflict),
        ] {
            let error = bridge
                .guarded_delete(
                    GuardedDeleteRequest {
                        host: "dev".to_owned(),
                        path: absolute(remote.path(), path),
                        expected_sha256: hash,
                    },
                    CancellationToken::new(),
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, expected_code, "path={path}");
        }
        assert_eq!(
            std::fs::read(remote.path().join("outside")).unwrap(),
            b"outside"
        );
        assert_eq!(
            std::fs::read(remote.path().join("wrong-hash")).unwrap(),
            b"old"
        );
        assert!(
            std::fs::symlink_metadata(&fifo)
                .unwrap()
                .file_type()
                .is_fifo()
        );
    }

    #[tokio::test]
    async fn task5_guarded_delete_classifies_missing_and_non_directory_parents() {
        let remote = tempfile::TempDir::new().unwrap();
        std::fs::write(remote.path().join("regular-parent"), b"regular").unwrap();
        let (_runtime, bridge) = delete_fixture(remote.path());
        for (path, expected) in [
            ("missing-parent/victim", ErrorCode::NotFound),
            ("regular-parent/victim", ErrorCode::NotDirectory),
        ] {
            let error = bridge
                .guarded_delete(
                    GuardedDeleteRequest {
                        host: "dev".to_owned(),
                        path: absolute(remote.path(), path),
                        expected_sha256: sha256(b"victim"),
                    },
                    CancellationToken::new(),
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, expected, "path={path}");
        }
    }

    #[tokio::test]
    async fn task5_delete_inaccessible_ancestor_is_not_reported_as_not_found() {
        let remote = tempfile::TempDir::new().unwrap();
        let locked = remote.path().join("locked");
        let parent = locked.join("parent");
        std::fs::create_dir_all(&parent).unwrap();
        std::fs::write(parent.join("victim"), b"victim").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let (_runtime, bridge) = delete_fixture(remote.path());

        let error = bridge
            .guarded_delete(
                GuardedDeleteRequest {
                    host: "dev".to_owned(),
                    path: absolute(remote.path(), "locked/parent/victim"),
                    expected_sha256: sha256(b"victim"),
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert_eq!(std::fs::read(parent.join("victim")).unwrap(), b"victim");
    }

    #[tokio::test]
    async fn task5_guarded_delete_local_rejections_launch_nothing() {
        let remote = tempfile::TempDir::new().unwrap();
        let controls = tempfile::TempDir::new().unwrap();
        let log = controls.path().join("ssh.log");
        let (_runtime, bridge) = delete_fixture_with_options(
            remote.path(),
            false,
            &[("FAKE_SSH_LOG", log.as_os_str().to_owned())],
        );
        for (path, hash, expected) in [
            (".", sha256(b"victim"), ErrorCode::InvalidArgument),
            ("victim", "A".repeat(64), ErrorCode::InvalidArgument),
        ] {
            assert_eq!(
                bridge
                    .guarded_delete(
                        GuardedDeleteRequest {
                            host: "dev".to_owned(),
                            path: if path == "." {
                                path.to_owned()
                            } else {
                                absolute(remote.path(), path)
                            },
                            expected_sha256: hash,
                        },
                        CancellationToken::new(),
                    )
                    .await
                    .unwrap_err()
                    .code,
                expected
            );
        }
        assert!(!log.exists());
    }

    #[tokio::test]
    async fn task5_guarded_delete_sentinel_closes_second_stat_and_hash_drift() {
        for (tool, expected_code) in [
            ("stat", ErrorCode::RemoteCapabilityMissing),
            ("dd", ErrorCode::MutationOutcomeUnknown),
        ] {
            let remote = tempfile::TempDir::new().unwrap();
            let target = remote.path().join(tool);
            std::fs::write(&target, b"victim").unwrap();
            let controls = tempfile::TempDir::new().unwrap();
            let log = controls.path().join("ssh.log");
            let marker = controls.path().join(format!("{tool}-count"));
            let scratch = controls.path().join("scratch");
            std::fs::create_dir(&scratch).unwrap();
            let shim = tempfile::TempDir::new().unwrap();
            let executable = shim.path().join(tool);
            let body = if tool == "stat" {
                format!(
                    "#!/bin/sh\ncase \" $* \" in *codex-sentinel-guarded-delete*/parent/victim*) marker={}; count=$(/usr/bin/cat \"$marker\" 2>/dev/null || printf 0); count=$((count + 1)); if [ \"$count\" -eq 2 ]; then /usr/bin/rm -f \"$marker\"; printf 'a1ff:0:777:7:1:2:1\\n'; exit 0; fi; printf %s \"$count\" >\"$marker\";; esac\nexec /usr/bin/stat \"$@\"\n",
                    crate::quote::shell_word(marker.to_str().unwrap()).unwrap()
                )
            } else {
                format!(
                    "#!/bin/sh\ncase \" $* \" in *codex-sentinel-guarded-delete*/parent/victim*bs=262144*iflag=nofollow*) marker={}; count=$(/usr/bin/cat \"$marker\" 2>/dev/null || printf 0); count=$((count + 1)); if [ \"$count\" -eq 2 ]; then /usr/bin/rm -f \"$marker\"; exit 64; fi; printf %s \"$count\" >\"$marker\";; esac\nexec /usr/bin/dd \"$@\"\n",
                    crate::quote::shell_word(marker.to_str().unwrap()).unwrap()
                )
            };
            std::fs::write(&executable, body).unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
            let path = OsString::from(format!(
                "{}:/usr/local/bin:/usr/bin:/bin",
                shim.path().display()
            ));
            let (_runtime, bridge) = delete_fixture_with_options(
                remote.path(),
                false,
                &[
                    ("PATH", path),
                    ("TMPDIR", scratch.as_os_str().to_owned()),
                    ("FAKE_SSH_LOG", log.as_os_str().to_owned()),
                ],
            );
            let error = bridge
                .guarded_delete(
                    GuardedDeleteRequest {
                        host: "dev".to_owned(),
                        path: absolute(remote.path(), tool),
                        expected_sha256: sha256(b"victim"),
                    },
                    CancellationToken::new(),
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, expected_code, "tool={tool}");
            assert_eq!(std::fs::read(&target).unwrap(), b"victim", "tool={tool}");
            assert_eq!(ssh_call_count(&log, "P"), 1, "tool={tool}");
            assert_eq!(ssh_call_count(&log, "C"), 1, "tool={tool}");
            assert_no_dispatcher_request_artifacts(&scratch);
        }
    }

    #[tokio::test]
    async fn task5_guarded_delete_races_close_before_unlink_or_become_unknown_after_it() {
        for race in ["identity", "second-hash", "rm-fail", "reappear"] {
            let remote = tempfile::TempDir::new().unwrap();
            let target = remote.path().join(race);
            std::fs::write(&target, b"victim").unwrap();
            let controls = tempfile::TempDir::new().unwrap();
            let log = controls.path().join("ssh.log");
            let marker = controls.path().join("hash-count");
            let shim = tempfile::TempDir::new().unwrap();
            let (tool, body) = match race {
                "identity" => (
                    "dd",
                    format!(
                        "#!/bin/sh\ncase \" $* \" in *\" if=./identity \"*bs=262144*iflag=nofollow*) /usr/bin/dd \"$@\"; status=$?; printf raced >{}; /usr/bin/mv -T -- {} {}; exit \"$status\";; esac\nexec /usr/bin/dd \"$@\"\n",
                        crate::quote::shell_word(
                            remote.path().join("identity-swap").to_str().unwrap()
                        )
                        .unwrap(),
                        crate::quote::shell_word(
                            remote.path().join("identity-swap").to_str().unwrap()
                        )
                        .unwrap(),
                        crate::quote::shell_word(target.to_str().unwrap()).unwrap(),
                    ),
                ),
                "second-hash" => (
                    "dd",
                    format!(
                        "#!/bin/sh\ncase \" $* \" in *\" if=./second-hash \"*bs=262144*iflag=nofollow*) marker={}; count=$(/usr/bin/cat \"$marker\" 2>/dev/null || printf 0); count=$((count + 1)); printf %s \"$count\" >\"$marker\"; if [ \"$count\" -eq 2 ]; then printf changed >{}; fi;; esac\nexec /usr/bin/dd \"$@\"\n",
                        crate::quote::shell_word(marker.to_str().unwrap()).unwrap(),
                        crate::quote::shell_word(target.to_str().unwrap()).unwrap(),
                    ),
                ),
                "rm-fail" => (
                    "rm",
                    "#!/bin/sh\ncase \" $* \" in *\" ./rm-fail \"*) exit 64;; esac\nexec /usr/bin/rm \"$@\"\n"
                        .to_owned(),
                ),
                "reappear" => (
                    "rm",
                    format!(
                        "#!/bin/sh\ncase \" $* \" in *\" ./reappear \"*) /usr/bin/rm \"$@\"; status=$?; printf raced >{}; exit \"$status\";; esac\nexec /usr/bin/rm \"$@\"\n",
                        crate::quote::shell_word(target.to_str().unwrap()).unwrap()
                    ),
                ),
                _ => unreachable!(),
            };
            let executable = shim.path().join(tool);
            std::fs::write(&executable, body).unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
            let path = OsString::from(format!(
                "{}:/usr/local/bin:/usr/bin:/bin",
                shim.path().display()
            ));
            let (_runtime, bridge) = delete_fixture_with_options(
                remote.path(),
                false,
                &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
            );
            let error = bridge
                .guarded_delete(
                    GuardedDeleteRequest {
                        host: "dev".to_owned(),
                        path: absolute(remote.path(), race),
                        expected_sha256: sha256(b"victim"),
                    },
                    CancellationToken::new(),
                )
                .await
                .unwrap_err();
            let expected = if matches!(race, "identity" | "second-hash") {
                ErrorCode::WriteConflict
            } else {
                ErrorCode::MutationOutcomeUnknown
            };
            assert_eq!(error.code, expected, "race={race}");
            assert!(target.exists(), "race={race}");
            assert_eq!(ssh_call_count(&log, "C"), 1, "race={race}");
        }
    }

    #[tokio::test]
    async fn task5_guarded_delete_postcommit_ambiguity_is_unknown_without_retry() {
        for post in ["disconnect", "malformed", "trailing", "stderr"] {
            let remote = tempfile::TempDir::new().unwrap();
            let target = remote.path().join(post);
            std::fs::write(&target, b"victim").unwrap();
            let controls = tempfile::TempDir::new().unwrap();
            let log = controls.path().join("ssh.log");
            let (_runtime, bridge) = delete_fixture_with_options(
                remote.path(),
                false,
                &[
                    ("FAKE_SSH_LOG", log.as_os_str().to_owned()),
                    ("FAKE_SSH_LOCAL_FIXED_POST", OsString::from(post)),
                ],
            );
            let error = bridge
                .guarded_delete(
                    GuardedDeleteRequest {
                        host: "dev".to_owned(),
                        path: absolute(remote.path(), post),
                        expected_sha256: sha256(b"victim"),
                    },
                    CancellationToken::new(),
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown, "post={post}");
            assert_eq!(error.details.mutation_may_have_applied, Some(true));
            assert!(!target.exists(), "post={post}");
            assert_eq!(ssh_call_count(&log, "C"), 1, "post={post}");
        }
    }

    #[tokio::test]
    async fn task5_guarded_delete_stale_sentinel_reprobes_only_the_next_call() {
        let remote = tempfile::TempDir::new().unwrap();
        let target = remote.path().join("victim");
        std::fs::write(&target, b"victim").unwrap();
        let controls = tempfile::TempDir::new().unwrap();
        let log = controls.path().join("ssh.log");
        let marker = controls.path().join("mismatch-used");
        let shim = tempfile::TempDir::new().unwrap();
        let stat = shim.path().join("stat");
        std::fs::write(
            &stat,
            format!(
                "#!/bin/sh\ncase \" $* \" in *codex-sentinel-guarded-delete*parent-link*) marker={}; if [ ! -e \"$marker\" ]; then : >\"$marker\"; printf '41c0:0:700:0:1:2:1:extra\\n'; exit 0; fi;; esac\nexec /usr/bin/stat \"$@\"\n",
                crate::quote::shell_word(marker.to_str().unwrap()).unwrap()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stat, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = OsString::from(format!(
            "{}:/usr/local/bin:/usr/bin:/bin",
            shim.path().display()
        ));
        let (_runtime, bridge) = delete_fixture_with_options(
            remote.path(),
            false,
            &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
        );
        let request = || GuardedDeleteRequest {
            host: "dev".to_owned(),
            path: absolute(remote.path(), "victim"),
            expected_sha256: sha256(b"victim"),
        };
        let first = bridge
            .guarded_delete(request(), CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(first.code, ErrorCode::RemoteCapabilityMissing);
        assert_eq!(std::fs::read(&target).unwrap(), b"victim");
        assert_eq!(ssh_call_count(&log, "P"), 1);
        assert_eq!(ssh_call_count(&log, "C"), 1);

        let second = bridge
            .guarded_delete(request(), CancellationToken::new())
            .await
            .unwrap();
        assert!(second.absence_confirmed);
        assert!(!target.exists());
        assert_eq!(ssh_call_count(&log, "P"), 2);
        assert_eq!(ssh_call_count(&log, "C"), 2);
    }

    #[tokio::test]
    async fn task5_missing_required_delete_command_is_a_future_only_capability_mismatch() {
        let remote = tempfile::TempDir::new().unwrap();
        let first_target = remote.path().join("first");
        let second_target = remote.path().join("second");
        std::fs::write(&first_target, b"first payload").unwrap();
        std::fs::write(&second_target, b"second payload").unwrap();
        let controls = tempfile::TempDir::new().unwrap();
        let log = controls.path().join("ssh.log");
        let marker = controls.path().join("missing-path-used");
        let empty_path = controls.path().join("empty-path");
        let scratch = controls.path().join("scratch");
        std::fs::create_dir(&empty_path).unwrap();
        std::os::unix::fs::symlink("/bin/sh", empty_path.join("sh")).unwrap();
        std::os::unix::fs::symlink("/usr/bin/stat", empty_path.join("stat")).unwrap();
        std::fs::create_dir(&scratch).unwrap();
        let (_runtime, bridge) = delete_fixture_with_options(
            remote.path(),
            false,
            &[
                ("FAKE_SSH_LOG", log.as_os_str().to_owned()),
                (
                    "FAKE_SSH_LOCAL_FIXED_PATH_ONCE",
                    empty_path.as_os_str().to_owned(),
                ),
                (
                    "FAKE_SSH_LOCAL_FIXED_PATH_MARKER",
                    marker.as_os_str().to_owned(),
                ),
                ("TMPDIR", scratch.as_os_str().to_owned()),
            ],
        );

        let first = bridge
            .guarded_delete(
                GuardedDeleteRequest {
                    host: "dev".to_owned(),
                    path: absolute(remote.path(), "first"),
                    expected_sha256: sha256(b"first payload"),
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(first.code, ErrorCode::RemoteCapabilityMissing);
        assert_eq!(std::fs::read(&first_target).unwrap(), b"first payload");
        assert_no_dispatcher_request_artifacts(&scratch);
        assert_eq!(ssh_call_count(&log, "P"), 1);
        assert_eq!(ssh_call_count(&log, "C"), 1);

        bridge
            .guarded_delete(
                GuardedDeleteRequest {
                    host: "dev".to_owned(),
                    path: absolute(remote.path(), "second"),
                    expected_sha256: sha256(b"second payload"),
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(!second_target.exists());
        assert_eq!(ssh_call_count(&log, "P"), 2);
        assert_eq!(ssh_call_count(&log, "C"), 2);
    }

    #[tokio::test]
    async fn task5_delete_exact_form_sentinel_matrix_is_semantic_and_future_only() {
        struct Case {
            form: &'static str,
            tool: &'static str,
            rule: &'static str,
        }

        let cases = [
            Case {
                form: "parent-follow",
                tool: "stat",
                rule: r#"case " $* " in
  *" -L --printf=%f:%u:%a:%s:%d:%i:%h\n -- "*codex-sentinel-guarded-delete*/parent-link*)
    if [ ! -e "$marker" ]; then : >"$marker"; printf '41ed:0:700:0:0:0:2\n'; exit 0; fi;;
esac"#,
            },
            Case {
                form: "lstat",
                tool: "stat",
                rule: r#"case " $* " in
  *" --printf=%f:%u:%a:%s:%d:%i:%h\n -- "*codex-sentinel-guarded-delete*/parent/victim*)
    if [ ! -e "$marker" ]; then : >"$marker"; printf '8180:0:640:8:0:0:1\n'; exit 0; fi;;
esac"#,
            },
            Case {
                form: "dd-input",
                tool: "dd",
                rule: r#"case " $* " in
  *codex-sentinel-guarded-delete*/parent/victim*bs=262144*status=none*iflag=nofollow*)
    if [ ! -e "$marker" ]; then : >"$marker"; printf corrupt; exit 0; fi;;
esac"#,
            },
            Case {
                form: "sha256sum-hash",
                tool: "sha256sum",
                rule: r#"if [ -e "$armed" ] && [ ! -e "$marker" ]; then
  : >"$marker"
  /usr/bin/rm -f -- "$armed"
  /usr/bin/dd of=/dev/null status=none
  printf '0000000000000000000000000000000000000000000000000000000000000000  -\n'
  exit 0
fi"#,
            },
            Case {
                form: "rm",
                tool: "rm",
                rule: r#"case " $* " in
  *" -f -- "*codex-sentinel-guarded-delete*/parent/victim*)
    if [ ! -e "$marker" ]; then : >"$marker"; exit 0; fi;;
esac"#,
            },
        ];

        for case in cases {
            let remote = tempfile::TempDir::new().unwrap();
            let first_target = remote.path().join("first");
            let second_target = remote.path().join("second");
            std::fs::write(&first_target, b"first payload").unwrap();
            std::fs::write(&second_target, b"second payload").unwrap();
            let controls = tempfile::TempDir::new().unwrap();
            let log = controls.path().join("ssh.log");
            let marker = controls.path().join("semantic-drift-used");
            let armed = controls.path().join("sentinel-hash-armed");
            let scratch = controls.path().join("scratch");
            std::fs::create_dir(&scratch).unwrap();
            let shim = tempfile::TempDir::new().unwrap();
            let executable = shim.path().join(case.tool);
            std::fs::write(
                &executable,
                format!(
                    "#!/bin/sh\nmarker={}\narmed={}\n{}\nexec /usr/bin/{} \"$@\"\n",
                    crate::quote::shell_word(marker.to_str().unwrap()).unwrap(),
                    crate::quote::shell_word(armed.to_str().unwrap()).unwrap(),
                    case.rule,
                    case.tool,
                ),
            )
            .unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
            if case.tool == "sha256sum" {
                let stat = shim.path().join("stat");
                std::fs::write(
                    &stat,
                    format!(
                        "#!/bin/sh\ncase \" $* \" in *\" --printf=%f:%u:%a:%s:%d:%i:%h\\n -- \"*codex-sentinel-guarded-delete*/parent/victim*) : >{};; esac\nexec /usr/bin/stat \"$@\"\n",
                        crate::quote::shell_word(armed.to_str().unwrap()).unwrap(),
                    ),
                )
                .unwrap();
                std::fs::set_permissions(&stat, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let path = OsString::from(format!(
                "{}:/usr/local/bin:/usr/bin:/bin",
                shim.path().display()
            ));
            let (_runtime, bridge) = delete_fixture_with_options(
                remote.path(),
                false,
                &[
                    ("PATH", path),
                    ("TMPDIR", scratch.as_os_str().to_owned()),
                    ("FAKE_SSH_LOG", log.as_os_str().to_owned()),
                ],
            );

            let first = bridge
                .guarded_delete(
                    GuardedDeleteRequest {
                        host: "dev".to_owned(),
                        path: absolute(remote.path(), "first"),
                        expected_sha256: sha256(b"first payload"),
                    },
                    CancellationToken::new(),
                )
                .await
                .unwrap_err();
            assert_eq!(
                first.code,
                ErrorCode::RemoteCapabilityMissing,
                "form={}",
                case.form
            );
            assert!(marker.exists(), "form={}", case.form);
            assert_eq!(
                std::fs::read(&first_target).unwrap(),
                b"first payload",
                "form={}",
                case.form
            );
            assert_eq!(ssh_call_count(&log, "P"), 1, "form={}", case.form);
            assert_eq!(ssh_call_count(&log, "C"), 1, "form={}", case.form);
            assert_no_dispatcher_request_artifacts(&scratch);

            let second = bridge
                .guarded_delete(
                    GuardedDeleteRequest {
                        host: "dev".to_owned(),
                        path: absolute(remote.path(), "second"),
                        expected_sha256: sha256(b"second payload"),
                    },
                    CancellationToken::new(),
                )
                .await
                .unwrap();
            assert!(second.absence_confirmed, "form={}", case.form);
            assert!(!second_target.exists(), "form={}", case.form);
            assert_eq!(ssh_call_count(&log, "P"), 2, "form={}", case.form);
            assert_eq!(ssh_call_count(&log, "C"), 2, "form={}", case.form);
        }
    }

    #[test]
    fn task5_write_protocol_parser_accepts_only_closed_success_and_domain_shapes() {
        let create = format!(
            "STATUS=SUCCESS\0OPERATION=CREATE\0SIZE=3\0SHA256={ABC_HASH}\0MODE=384\0TEMPORARY_CLEANUP_CONFIRMED=1\0"
        );
        assert_eq!(
            parse_create(create.as_bytes(), b"").unwrap(),
            WriteProtocol::Success {
                operation: WriteOperation::Create,
                size: 3,
                sha256: ABC_HASH.to_owned(),
                mode: 0o600,
            }
        );

        let replace = format!(
            "STATUS=SUCCESS\0OPERATION=REPLACE\0SIZE=3\0SHA256={ABC_HASH}\0MODE=416\0TEMPORARY_CLEANUP_CONFIRMED=1\0"
        );
        assert_eq!(
            parse_write_protocol_bytes(
                replace.as_bytes(),
                b"",
                &resolved(WriteOperation::Replace),
            )
            .unwrap(),
            WriteProtocol::Success {
                operation: WriteOperation::Replace,
                size: 3,
                sha256: ABC_HASH.to_owned(),
                mode: 0o640,
            }
        );

        for (record, expected) in [
            ("STATUS=WRITE_CONFLICT\0", ErrorCode::WriteConflict),
            ("STATUS=NOT_FOUND\0", ErrorCode::NotFound),
            ("STATUS=NOT_DIRECTORY\0", ErrorCode::NotDirectory),
            ("STATUS=PERMISSION_DENIED\0", ErrorCode::PermissionDenied),
        ] {
            assert_eq!(
                parse_create(record.as_bytes(), b"").unwrap(),
                WriteProtocol::Domain(expected)
            );
        }
        assert_eq!(
            parse_create(b"STATUS=CAPABILITY_MISMATCH\0CAPABILITY=safe_write\0", b"",).unwrap(),
            WriteProtocol::CapabilityMismatch
        );
    }

    #[test]
    fn task5_write_protocol_parser_rejects_every_open_or_mismatched_shape() {
        let invalid: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"STATUS=WRITE_CONFLICT".to_vec(),
            b"STATUS=WRITE_CONFLICT\0\0".to_vec(),
            b"STATUS=WRITE_CONFLICT\0STATUS=WRITE_CONFLICT\0".to_vec(),
            b"STATUS=WRITE_CONFLICT\0EXTRA=1\0".to_vec(),
            b"STATUS=UNKNOWN\0".to_vec(),
            b"STATUS=CAPABILITY_MISMATCH\0CAPABILITY=guarded_delete\0".to_vec(),
            format!(
                "STATUS=SUCCESS\0OPERATION=UPSERT\0SIZE=3\0SHA256={ABC_HASH}\0MODE=384\0TEMPORARY_CLEANUP_CONFIRMED=1\0"
            )
            .into_bytes(),
            format!(
                "STATUS=SUCCESS\0OPERATION=REPLACE\0SIZE=3\0SHA256={ABC_HASH}\0MODE=384\0TEMPORARY_CLEANUP_CONFIRMED=1\0"
            )
            .into_bytes(),
            format!(
                "STATUS=SUCCESS\0OPERATION=CREATE\0SIZE=4\0SHA256={ABC_HASH}\0MODE=384\0TEMPORARY_CLEANUP_CONFIRMED=1\0"
            )
            .into_bytes(),
            format!(
                "STATUS=SUCCESS\0OPERATION=CREATE\0SIZE=x\0SHA256={ABC_HASH}\0MODE=384\0TEMPORARY_CLEANUP_CONFIRMED=1\0"
            )
            .into_bytes(),
            format!(
                "STATUS=SUCCESS\0OPERATION=CREATE\0SIZE=18446744073709551616\0SHA256={ABC_HASH}\0MODE=384\0TEMPORARY_CLEANUP_CONFIRMED=1\0"
            )
            .into_bytes(),
            format!(
                "STATUS=SUCCESS\0OPERATION=CREATE\0SIZE=3\0SHA256={}\0MODE=384\0TEMPORARY_CLEANUP_CONFIRMED=1\0",
                "0".repeat(64)
            )
            .into_bytes(),
            format!(
                "STATUS=SUCCESS\0OPERATION=CREATE\0SIZE=3\0SHA256={}\0MODE=384\0TEMPORARY_CLEANUP_CONFIRMED=1\0",
                "A".repeat(64)
            )
            .into_bytes(),
            format!(
                "STATUS=SUCCESS\0OPERATION=CREATE\0SIZE=3\0SHA256={ABC_HASH}\0MODE=416\0TEMPORARY_CLEANUP_CONFIRMED=1\0"
            )
            .into_bytes(),
            format!(
                "STATUS=SUCCESS\0OPERATION=CREATE\0SIZE=3\0SHA256={ABC_HASH}\0MODE=512\0TEMPORARY_CLEANUP_CONFIRMED=1\0"
            )
            .into_bytes(),
            format!(
                "STATUS=SUCCESS\0OPERATION=CREATE\0SIZE=3\0SHA256={ABC_HASH}\0MODE=384\0TEMPORARY_CLEANUP_CONFIRMED=0\0"
            )
            .into_bytes(),
        ];
        for stdout in invalid {
            assert_protocol_error(&stdout, b"");
        }
        assert_protocol_error(b"STATUS=WRITE_CONFLICT\0", b"diagnostic");
    }
}
