#![allow(
    clippy::result_large_err,
    reason = "Task 1 fixes BridgeResult<T> to an inline BridgeError representation"
)]

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::Arc;

use tokio::sync::{Mutex, OnceCell, watch};

use crate::config::MAX_REMOTE_CONTEXT_ROOT_BYTES;
use crate::error::{BridgeError, BridgeResult, ErrorCode};
use crate::path::RemotePath;

const TOOL_NAMES: &[&str] = &[
    "mktemp",
    "dd_nofollow",
    "sha256sum",
    "stat",
    "find",
    "grep",
    "rg",
    "timeout",
    "ln",
    "mv",
    "read_slice",
    "find_nul",
    "stat_printf",
    "rg_json",
    "grep_nul",
    "xargs_nul",
    "search_bound",
    "safe_write",
    "guarded_delete",
];

pub const CAPABILITY_PROBE_SCRIPT: &str = r#"
set -u
LC_ALL=C
export LC_ALL

requested_root=$1
cd "$requested_root" || exit 1
physical_plus=$(pwd -P && printf x) || exit 1
physical_with_delimiter=${physical_plus%x}
newline='
'
physical_root=${physical_with_delimiter%"$newline"}
root_identity=$(stat -L --printf='%d:%i' -- . 2>/dev/null) ||
    root_identity=$(stat -f '%d:%i' . 2>/dev/null) || exit 78
case "$root_identity" in
    *[!0-9:]*|:*|*:|*:*:*) exit 78 ;;
esac
root_device=${root_identity%%:*}
root_inode=${root_identity#*:}

login_shell=
uid_plus=$(id -u 2>/dev/null && printf x)
uid_status=$?
current_uid=
if [ "$uid_status" -eq 0 ]; then
    uid_with_delimiter=${uid_plus%x}
    case "$uid_with_delimiter" in
        *"$newline")
            uid_record=${uid_with_delimiter%"$newline"}
            case "$uid_record" in ''|*"$newline"*|*[!0-9]*) ;; *) current_uid=$uid_record ;; esac
            ;;
    esac
fi
passwd_record_matches_uid=0
passwd_record_shell=
parse_passwd_record() {
    passwd_record_matches_uid=0
    passwd_record_shell=
    record=$1
    case "$record" in *"$newline"*) return 1 ;; esac
    rest=$record
    passwd_name=${rest%%:*}; [ "$passwd_name" != "$rest" ] || return 1; rest=${rest#*:}
    passwd_secret=${rest%%:*}; [ "$passwd_secret" != "$rest" ] || return 1; rest=${rest#*:}
    passwd_uid=${rest%%:*}; [ "$passwd_uid" != "$rest" ] || return 1; rest=${rest#*:}
    [ "$passwd_uid" = "$current_uid" ] || return 1
    passwd_record_matches_uid=1
    passwd_gid=${rest%%:*}; [ "$passwd_gid" != "$rest" ] || return 1; rest=${rest#*:}
    passwd_gecos=${rest%%:*}; [ "$passwd_gecos" != "$rest" ] || return 1; rest=${rest#*:}
    passwd_home=${rest%%:*}; [ "$passwd_home" != "$rest" ] || return 1; rest=${rest#*:}
    candidate_shell=$rest
    case "$candidate_shell" in *:*) return 1 ;; esac
    if [ -z "$candidate_shell" ]; then candidate_shell=/bin/sh; fi
    case "$candidate_shell" in /*) ;; *) return 1 ;; esac
    [ "${#candidate_shell}" -le 4096 ] || return 1
    [ -f "$candidate_shell" ] && [ -x "$candidate_shell" ] || return 1
    passwd_record_shell=$candidate_shell
}
if [ -n "$current_uid" ]; then
    getent_available=0
    getent_status=127
    if command -v getent >/dev/null 2>&1; then
        getent_available=1
        getent_plus=$(getent passwd "$current_uid" 2>/dev/null && printf x)
        getent_status=$?
        if [ "$getent_status" -eq 0 ]; then
            getent_with_delimiter=${getent_plus%x}
            case "$getent_with_delimiter" in
                *"$newline")
                    getent_record=${getent_with_delimiter%"$newline"}
                    case "$getent_record" in
                        ''|*"$newline"*) ;;
                        *)
                            if parse_passwd_record "$getent_record" &&
                               [ "$passwd_record_matches_uid" -eq 1 ]; then
                                login_shell=$passwd_record_shell
                            fi
                            ;;
                    esac
                    ;;
            esac
        fi
    fi
    if [ "$getent_available" -eq 0 ] && [ -f /etc/passwd ] && [ -r /etc/passwd ]; then
        passwd_match_count=0
        passwd_invalid_match=0
        passwd_fallback_shell=
        while IFS= read -r passwd_record || [ -n "$passwd_record" ]; do
            if parse_passwd_record "$passwd_record"; then
                if [ "$passwd_record_matches_uid" -eq 1 ]; then
                    passwd_match_count=$((passwd_match_count + 1))
                    passwd_fallback_shell=$passwd_record_shell
                fi
            elif [ "$passwd_record_matches_uid" -eq 1 ]; then
                passwd_match_count=$((passwd_match_count + 1))
                passwd_invalid_match=1
            fi
        done </etc/passwd
        if [ "$passwd_match_count" -eq 1 ] && [ "$passwd_invalid_match" -eq 0 ]; then
            login_shell=$passwd_fallback_shell
        fi
    fi
fi

emit_record() {
    printf '%s=%s\000' "$1" "$2"
}

has_tool() {
    if command -v "$1" >/dev/null 2>&1; then
        printf 1
    else
        printf 0
    fi
}

has_gnu_timeout() {
    if timeout --signal=TERM --kill-after=1s 1.000s sh -c 'exit 0' >/dev/null 2>&1; then
        printf 1
    else
        printf 0
    fi
}

shell_kind=sh
bash_version=
if command -v bash >/dev/null 2>&1; then
    candidate=$(bash --noprofile --norc -c 'printf %s "$BASH_VERSION"') || candidate=
    if [ -n "$candidate" ]; then
        shell_kind=bash
        bash_version=$candidate
    fi
fi

tool_mktemp=$(has_tool mktemp)
tool_dd_nofollow=0
probe_tmp=
cleanup_probe_tmp() {
    if [ -n "$probe_tmp" ]; then
        rm -rf -- "$probe_tmp"
        probe_tmp=
    fi
}
on_probe_signal() {
    trap - 0 HUP INT TERM
    cleanup_probe_tmp
    exit 1
}
trap cleanup_probe_tmp 0
trap on_probe_signal HUP INT TERM

if [ "$tool_mktemp" = 1 ]; then
    probe_tmp=$(mktemp -d "${TMPDIR:-/tmp}/codex-ssh-bridge.XXXXXX") || {
        tool_mktemp=0
        probe_tmp=
    }
fi
if [ -n "$probe_tmp" ] && command -v dd >/dev/null 2>&1; then
    if dd if=/dev/null of="$probe_tmp/dd-output" bs=262144 oflag=nofollow >/dev/null 2>&1; then
        tool_dd_nofollow=1
    fi
fi

tool_read_slice=0
tool_find_nul=0
tool_stat_printf=0
tool_rg_json=0
tool_grep_nul=0
tool_xargs_nul=0
tool_search_bound=0
tool_safe_write=0
tool_guarded_delete=0
if [ -n "$probe_tmp" ]; then
    read_file=$probe_tmp/codex-probe-read
    read_tail=$probe_tmp/read-tail
    read_lines=$probe_tmp/read-lines
    read_bytes=$probe_tmp/read-bytes
    read_last=$probe_tmp/read-last
    read_expected=$probe_tmp/read-expected
    printf 'a\000b\nc' >"$read_file"
    printf 'a\000b\n' >"$read_expected"
    if tail -n +1 -- "$read_file" >"$read_tail" 2>/dev/null &&
       head -n 1 "$read_tail" >"$read_lines" 2>/dev/null &&
       head -c 4 "$read_lines" >"$read_bytes" 2>/dev/null &&
       tail -c 1 -- "$read_file" >"$read_last" 2>/dev/null &&
       read_count=$(wc -l <"$read_file") &&
       cmp -s "$read_expected" "$read_bytes" &&
       [ "$(cat "$read_last")" = c ] && [ "$read_count" -eq 1 ]; then
        tool_read_slice=1
    fi

    find_actual=$probe_tmp/codex-probe-find
    find_link=$probe_tmp/codex-probe-find-link
    find_out=$probe_tmp/find-output
    find_expected=$probe_tmp/find-expected
    mkdir -p "$find_actual/visible/nested" "$find_actual/.hidden" "$probe_tmp/find-outside"
    newline_name='line
name'
    printf xy >"$find_actual/visible/$newline_name"
    : >"$find_actual/visible/nested/too-deep"
    : >"$find_actual/.hidden/secret"
    : >"$probe_tmp/find-outside/not-followed"
    find_link_target=$probe_tmp/find-outside
    ln -s "$find_link_target" "$find_actual/descendant-link"
    ln -s "$find_actual" "$find_link"
    chmod 640 "$find_actual/visible/$newline_name"
    touch -d '@7.25' -- "$find_actual/visible/$newline_name"
    touch -h -d '@8.5' -- "$find_actual/descendant-link"
    find_link_size=${#find_link_target}
    if (cd "$probe_tmp" &&
        find -H codex-probe-find-link -mindepth 1 -maxdepth 2 \
        \( -path '*/.*' -prune -o -type f -printf '%P\000%y\000%s\000%m\000%T@\000' \) &&
        find -H codex-probe-find-link -mindepth 1 -maxdepth 2 \
        \( -path '*/.*' -prune -o -type l -printf '%P\000%y\000%s\000%m\000%T@\000' \)) \
        >"$find_out" 2>/dev/null; then
        {
            printf 'visible/%s\000f\0002\000640\0007.2500000000\000' "$newline_name"
            printf 'descendant-link\000l\000%s\000777\0008.5000000000\000' "$find_link_size"
        } >"$find_expected"
        if cmp -s "$find_expected" "$find_out"; then tool_find_nul=1; fi
    fi

    stat_file=$probe_tmp/codex-probe-stat
    printf x >"$stat_file"
    if touch -d '@-1.123456789' -- "$stat_file" 2>/dev/null; then
        stat_mode=$(stat --printf='%f' -- "$stat_file" 2>/dev/null) || stat_mode=
        stat_size=$(stat --printf='%s' -- "$stat_file" 2>/dev/null) || stat_size=
        stat_seconds=$(stat --printf='%Y' -- "$stat_file" 2>/dev/null) || stat_seconds=
        stat_human=$(stat --printf='%y' -- "$stat_file" 2>/dev/null) || stat_human=
        stat_fraction=$(printf '%s' "$stat_human" | cut -d. -f2 | cut -d' ' -f1)
        case "$stat_mode:$stat_size:$stat_seconds:$stat_fraction" in
            [0-9a-f]*:1:-2:876543211) tool_stat_printf=1 ;;
        esac
    fi

    rg_file=$probe_tmp/codex-probe-rg-text
    rg_bytes_file=$probe_tmp/codex-probe-rg-bytes
    rg_binary_file=$probe_tmp/codex-probe-rg-binary
    rg_error_file=$probe_tmp/codex-probe-rg-error
    printf 'before needle after\n' >"$rg_file"
    printf '\377needle\n' >"$rg_bytes_file"
    printf 'before\000needle\n' >"$rg_binary_file"
    if command -v rg >/dev/null 2>&1; then
        rg_json=$(rg --json --fixed-strings --hidden --no-ignore -- needle "$rg_file" 2>/dev/null)
        rg_status=$?
        rg_bytes_json=$(rg --json --fixed-strings --hidden --no-ignore --text -- needle "$rg_bytes_file" 2>/dev/null)
        rg_bytes_status=$?
        rg_binary_json=$(rg --json --fixed-strings --hidden --no-ignore -- needle "$rg_binary_file" 2>/dev/null)
        rg_binary_status=$?
        rg_binary_text_json=$(rg --json --fixed-strings --hidden --no-ignore --text -- needle "$rg_binary_file" 2>/dev/null)
        rg_binary_text_status=$?
        rg --json --fixed-strings --hidden --no-ignore -- absent "$rg_file" >/dev/null 2>&1
        rg_empty_status=$?
        rg --json --fixed-strings --hidden --no-ignore -- needle "$rg_error_file" >/dev/null 2>&1
        rg_error_status=$?
        rg_text_ok=0
        rg_bytes_ok=0
        rg_binary_ok=0
        case "$rg_json" in
            *'"type":"begin"'*) rg_text_ok=1 ;;
        esac
        case "$rg_json" in
            *'"type":"match"'*) [ "$rg_text_ok" -eq 1 ] && rg_text_ok=1 || rg_text_ok=0 ;;
            *) rg_text_ok=0 ;;
        esac
        case "$rg_json" in
            *'"type":"end"'*) [ "$rg_text_ok" -eq 1 ] && rg_text_ok=1 || rg_text_ok=0 ;;
            *) rg_text_ok=0 ;;
        esac
        case "$rg_json" in
            *'"type":"summary"'*) [ "$rg_text_ok" -eq 1 ] && rg_text_ok=1 || rg_text_ok=0 ;;
            *) rg_text_ok=0 ;;
        esac
        case "$rg_bytes_json" in
            *'"type":"match"'*'"lines":{"bytes":'*) rg_bytes_ok=1 ;;
        esac
        case "$rg_binary_json:$rg_binary_text_json" in
            *'"binary_offset":'*:*'"binary_offset":null'*) rg_binary_ok=1 ;;
        esac
        if [ "$rg_status" -eq 0 ] && [ "$rg_bytes_status" -eq 0 ] &&
           [ "$rg_binary_status" -eq 0 ] && [ "$rg_binary_text_status" -eq 0 ] &&
           [ "$rg_empty_status" -eq 1 ] && [ "$rg_error_status" -gt 1 ] &&
           [ "$rg_text_ok" -eq 1 ] && [ "$rg_bytes_ok" -eq 1 ] &&
           [ "$rg_binary_ok" -eq 1 ]; then tool_rg_json=1; fi
    fi

    grep_file=$probe_tmp/codex-probe-grep
    grep_binary=$probe_tmp/grep-binary
    grep_out=$probe_tmp/grep-output
    grep_expected=$probe_tmp/grep-expected
    printf 'needle\n' >"$grep_file"
    printf 'before\000needle\n' >"$grep_binary"
    if grep -IHnZ -F -- needle "$grep_file" "$grep_binary" >"$grep_out" 2>/dev/null; then
        { printf '%s\000' "$grep_file"; printf '1:needle\n'; } >"$grep_expected"
        if cmp -s "$grep_expected" "$grep_out"; then tool_grep_nul=1; fi
    fi

    xargs_out=$probe_tmp/xargs-output
    printf 'line\nname\000' |
        xargs -0 -r sh -c 'printf %s "$1"' codex-ssh-probe-xargs >"$xargs_out" 2>/dev/null
    xargs_ok=$?
    printf 'x\000' |
        xargs -0 -r sh -c 'exit 7' codex-ssh-probe-xargs >/dev/null 2>&1
    xargs_failure=$?
    if [ "$xargs_ok" -eq 0 ] && [ "$xargs_failure" -ne 0 ] &&
       [ "$(cat "$xargs_out")" = "$newline_name" ]; then
        tool_xargs_nul=1
    fi

    if command -v mkfifo >/dev/null 2>&1; then
        bound_dir=$(mktemp -d "$probe_tmp/codex-probe-bound.XXXXXX" 2>/dev/null) || bound_dir=
        if [ -n "$bound_dir" ] && (
            cleanup_bound() { rm -rf -- "$bound_dir"; }
            on_bound_signal() {
                trap - 0 HUP INT TERM
                cleanup_bound
                exit 1
            }
            trap cleanup_bound 0
            trap on_bound_signal HUP INT TERM
            bound_fifo=$bound_dir/success-fifo
            bound_status=$bound_dir/success-status
            bound_out=$bound_dir/success-output
            bound_error_fifo=$bound_dir/error-fifo
            bound_error_status=$bound_dir/error-status
            bound_error_out=$bound_dir/error-output
            bound_mode=$(stat -c '%a' -- "$bound_dir" 2>/dev/null || printf 0)
            [ "$bound_mode" = 700 ] || exit 1
            mkfifo "$bound_fifo" "$bound_error_fifo" || exit 1
            (
                printf 'ab\000cd\000' |
                    xargs -0 -r -n 1 sh -c 'printf %s "$1"' codex-ssh-probe-bound-xargs >"$bound_fifo" 2>/dev/null
                printf '%s' "$?" >"$bound_status"
            ) &
            bound_pid=$!
            exec 3<"$bound_fifo"
            head -c 3 <&3 >"$bound_out" 2>/dev/null
            bound_head_status=$?
            cat <&3 >/dev/null
            bound_drain_status=$?
            exec 3<&-
            wait "$bound_pid" 2>/dev/null
            bound_wait_status=$?
            bound_producer_status=$(cat "$bound_status" 2>/dev/null || printf 2)
            [ "$bound_head_status" -eq 0 ] && [ "$bound_drain_status" -eq 0 ] &&
            [ "$bound_wait_status" -eq 0 ] && [ "$bound_producer_status" -eq 0 ] &&
            [ "$(cat "$bound_out")" = abc ] || exit 1

            (
                printf 'abcdef\000' |
                    xargs -0 -r sh -c 'printf %s "$1"; exit 7' codex-ssh-probe-bound-xargs >"$bound_error_fifo" 2>/dev/null
                printf '%s' "$?" >"$bound_error_status"
            ) &
            bound_error_pid=$!
            exec 3<"$bound_error_fifo"
            head -c 3 <&3 >"$bound_error_out" 2>/dev/null
            bound_error_head_status=$?
            cat <&3 >/dev/null
            bound_error_drain_status=$?
            exec 3<&-
            wait "$bound_error_pid" 2>/dev/null
            bound_error_wait_status=$?
            bound_error_final=$(cat "$bound_error_status" 2>/dev/null || printf 0)
            [ "$bound_error_head_status" -eq 0 ] && [ "$bound_error_drain_status" -eq 0 ] &&
            [ "$bound_error_wait_status" -eq 0 ] && [ "$bound_error_final" -ne 0 ] &&
            [ "$(cat "$bound_error_out")" = abc ] || exit 1
        ); then
            if [ ! -e "$bound_dir" ]; then tool_search_bound=1; fi
        else
            rm -rf -- "$bound_dir"
        fi
    fi

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

    safe_dir=$probe_tmp/codex-probe-safe-write
    if (
        umask 077
        mkdir -m 700 -- "$safe_dir" || exit 9
        cleanup_safe_write() { rm -rf -- "$safe_dir"; }
        on_safe_write_signal() {
            trap - 0 HUP INT TERM
            cleanup_safe_write
            exit 1
        }
        trap cleanup_safe_write 0
        trap on_safe_write_signal HUP INT TERM
        safe_hostile=$safe_dir/"hostile:
name' value"
        safe_parent_actual=$safe_dir/followed-parent
        safe_parent_link=$safe_dir/followed-parent-link
        mkdir -m 700 -- "$safe_parent_actual" || exit 9
        ln -s "$safe_parent_actual" "$safe_parent_link" || exit 9
        codex_mutation_parent_stat_follow_valid "$safe_parent_actual" || exit 1
        safe_follow_device=$CODEX_STAT_DEVICE
        safe_follow_inode=$CODEX_STAT_INODE
        codex_mutation_parent_stat_follow_valid "$safe_parent_link" || exit 1
        [ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE" = "$safe_follow_device:$safe_follow_inode" ] || exit 1
        case "$CODEX_STAT_TYPE" in 4???) ;; *) exit 1 ;; esac

        codex_mutation_parent_stat_follow_valid "$safe_dir" || exit 1
        safe_parent_device=$CODEX_STAT_DEVICE
        safe_tmp=$(codex_mutation_mktemp "$safe_dir") || exit 1
        printf payload | codex_mutation_stage "$safe_tmp" || exit 1
        codex_mutation_stat_valid "$safe_tmp" || exit 1
        safe_uid=$(id -u) || exit 1
        case "$CODEX_STAT_TYPE" in 8???) ;; *) exit 1 ;; esac
        [ "$CODEX_STAT_UID" = "$safe_uid" ] &&
        [ "$CODEX_STAT_MODE" = 600 ] &&
        [ "$CODEX_STAT_SIZE" = 7 ] &&
        [ "$CODEX_STAT_DEVICE" = "$safe_parent_device" ] &&
        [ "$CODEX_STAT_LINKS" = 1 ] || exit 1
        CODEX_HASH_DIGEST=$(codex_mutation_hash "$safe_tmp") || exit 1
        [ "$CODEX_HASH_DIGEST" = 239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5 ] || exit 1

        printf OUTSIDE >"$safe_hostile" || exit 9
        ln -s "$safe_hostile" "$safe_dir/dd-link" || exit 9
        codex_mutation_stat_valid "$safe_dir/dd-link" || exit 1
        case "$CODEX_STAT_TYPE" in a???) ;; *) exit 1 ;; esac
        if printf CHANGED | codex_mutation_stage "$safe_dir/dd-link" 2>/dev/null; then exit 1; fi
        [ "$(cat "$safe_hostile")" = OUTSIDE ] || exit 1
        if CODEX_HASH_DIGEST=$(codex_mutation_hash "$safe_dir/dd-link"); then exit 1; fi

        safe_created=$safe_dir/created
        codex_mutation_link "$safe_tmp" "$safe_created" || exit 1
        if codex_mutation_link "$safe_tmp" "$safe_created" 2>/dev/null; then exit 1; fi
        safe_link_directory=$safe_dir/link-directory
        safe_directory_link=$safe_dir/directory-link
        mkdir -m 700 -- "$safe_link_directory" || exit 9
        ln -s "$safe_link_directory" "$safe_directory_link" || exit 9
        if codex_mutation_link "$safe_tmp" "$safe_directory_link" 2>/dev/null; then exit 1; fi
        safe_nested_link=$safe_link_directory/${safe_tmp##*/}
        [ -L "$safe_directory_link" ] || exit 1
        [ ! -e "$safe_nested_link" ] && [ ! -L "$safe_nested_link" ] || exit 1
        codex_mutation_remove "$safe_created" || exit 1
        [ ! -e "$safe_created" ] && [ ! -L "$safe_created" ] || exit 1
        safe_replaced=$safe_dir/replaced
        printf old >"$safe_replaced" || exit 9
        codex_mutation_mode 0640 "$safe_tmp" || exit 1
        codex_mutation_stat_valid "$safe_tmp" || exit 1
        [ "$CODEX_STAT_MODE" = 640 ] || exit 1
        codex_mutation_replace "$safe_tmp" "$safe_replaced" || exit 1
        [ ! -e "$safe_tmp" ] && [ ! -L "$safe_tmp" ] || exit 1
        codex_mutation_stat_valid "$safe_replaced" || exit 1
        [ "$CODEX_STAT_MODE" = 640 ] || exit 1
        CODEX_HASH_DIGEST=$(codex_mutation_hash "$safe_replaced") || exit 1
        [ "$CODEX_HASH_DIGEST" = 239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5 ] || exit 1

    ); then
        if [ ! -e "$safe_dir" ]; then tool_safe_write=1; fi
    else
        rm -rf -- "$safe_dir"
    fi

    delete_dir=$probe_tmp/codex-probe-guarded-delete
    if (
        umask 077
        mkdir -m 700 -- "$delete_dir" || exit 9
        cleanup_guarded_delete() { rm -rf -- "$delete_dir"; }
        on_guarded_delete_signal() {
            trap - 0 HUP INT TERM
            cleanup_guarded_delete
            exit 1
        }
        trap cleanup_guarded_delete 0
        trap on_guarded_delete_signal HUP INT TERM
        delete_target=$delete_dir/"target:
name' value"
        codex_mutation_parent_stat_follow_valid "$delete_dir" || exit 1
        case "$CODEX_STAT_TYPE" in 4???) ;; *) exit 1 ;; esac
        printf guarded >"$delete_target" || exit 9
        codex_mutation_stat_valid "$delete_target" || exit 1
        case "$CODEX_STAT_TYPE" in 8???) ;; *) exit 1 ;; esac
        delete_device=$CODEX_STAT_DEVICE
        delete_inode=$CODEX_STAT_INODE
        CODEX_HASH_DIGEST=$(codex_mutation_hash "$delete_target") || exit 1
        [ "$CODEX_HASH_DIGEST" = e7da2135b6d3a82d5242bbb5d7b8534e5841356c6973e1d479ce41e41dd6215b ] || exit 1
        codex_mutation_stat_valid "$delete_target" || exit 1
        case "$CODEX_STAT_TYPE" in 8???) ;; *) exit 1 ;; esac
        [ "$CODEX_STAT_DEVICE:$CODEX_STAT_INODE" = "$delete_device:$delete_inode" ] || exit 1
        CODEX_HASH_DIGEST=$(codex_mutation_hash "$delete_target") || exit 1
        [ "$CODEX_HASH_DIGEST" = e7da2135b6d3a82d5242bbb5d7b8534e5841356c6973e1d479ce41e41dd6215b ] || exit 1
        codex_mutation_remove "$delete_target" || exit 1
        [ ! -e "$delete_target" ] && [ ! -L "$delete_target" ] || exit 1

        printf keep >"$delete_dir/referent" || exit 9
        ln -s "$delete_dir/referent" "$delete_dir/link" || exit 9
        codex_mutation_stat_valid "$delete_dir/link" || exit 1
        case "$CODEX_STAT_TYPE" in a???) ;; *) exit 1 ;; esac
        [ "$(cat "$delete_dir/referent")" = keep ] || exit 1
    ); then
        if [ ! -e "$delete_dir" ]; then tool_guarded_delete=1; fi
    else
        rm -rf -- "$delete_dir"
    fi
fi

emit_record CODEX_SSH_PROBE 1
emit_record REQUESTED_ROOT "$requested_root"
emit_record ROOT "$physical_root"
emit_record ROOT_DEVICE "$root_device"
emit_record ROOT_INODE "$root_inode"
emit_record KERNEL_NAME "$(uname -s 2>/dev/null || printf unknown)"
emit_record MACHINE_ARCH "$(uname -m 2>/dev/null || printf unknown)"
emit_record SHELL_KIND "$shell_kind"
emit_record BASH_VERSION "$bash_version"
emit_record LOGIN_SHELL "$login_shell"
emit_record TOOL_mktemp "$tool_mktemp"
emit_record TOOL_dd_nofollow "$tool_dd_nofollow"
emit_record TOOL_sha256sum "$(has_tool sha256sum)"
emit_record TOOL_stat "$(has_tool stat)"
emit_record TOOL_find "$(has_tool find)"
emit_record TOOL_grep "$(has_tool grep)"
emit_record TOOL_rg "$(has_tool rg)"
emit_record TOOL_timeout "$(has_gnu_timeout)"
emit_record TOOL_ln "$(has_tool ln)"
emit_record TOOL_mv "$(has_tool mv)"
emit_record TOOL_read_slice "$tool_read_slice"
emit_record TOOL_find_nul "$tool_find_nul"
emit_record TOOL_stat_printf "$tool_stat_printf"
emit_record TOOL_rg_json "$tool_rg_json"
emit_record TOOL_grep_nul "$tool_grep_nul"
emit_record TOOL_xargs_nul "$tool_xargs_nul"
emit_record TOOL_search_bound "$tool_search_bound"
emit_record TOOL_safe_write "$tool_safe_write"
emit_record TOOL_guarded_delete "$tool_guarded_delete"
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellKind {
    Bash { version: String },
    PosixSh,
    Login,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub physical_root: String,
    pub root_device: u64,
    pub root_inode: u64,
    pub kernel_name: Option<String>,
    pub machine_arch: Option<String>,
    pub shell: ShellKind,
    pub bash_version: Option<String>,
    pub login_shell: Option<String>,
    pub tools: BTreeMap<String, bool>,
}

pub const MAX_SHELL_VERSION_BYTES: usize = 256;
pub const MAX_LOGIN_SHELL_BYTES: usize = 4096;
pub const MAX_KERNEL_NAME_BYTES: usize = 64;
pub const MAX_MACHINE_ARCH_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellRequest {
    Auto,
    Bash,
    Sh,
    Login,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellSelection {
    pub shell: ShellKind,
    pub fallback: bool,
}

pub fn select_shell(
    capability: &Capability,
    requested: ShellRequest,
) -> BridgeResult<ShellSelection> {
    match requested {
        ShellRequest::Auto => match &capability.shell {
            shell @ ShellKind::Bash { .. } => Ok(ShellSelection {
                shell: shell.clone(),
                fallback: false,
            }),
            ShellKind::PosixSh | ShellKind::Login => Ok(ShellSelection {
                shell: ShellKind::PosixSh,
                fallback: true,
            }),
        },
        ShellRequest::Bash => match &capability.shell {
            shell @ ShellKind::Bash { .. } => Ok(ShellSelection {
                shell: shell.clone(),
                fallback: false,
            }),
            ShellKind::PosixSh | ShellKind::Login => {
                let mut error = BridgeError::new(
                    ErrorCode::RemoteCapabilityMissing,
                    "Bash is not available on the remote host",
                    false,
                );
                error.details.requested_shell = Some("bash".to_owned());
                error.details.available_shells = Some(vec!["sh".to_owned()]);
                Err(error)
            }
        },
        ShellRequest::Sh => Ok(ShellSelection {
            shell: ShellKind::PosixSh,
            fallback: false,
        }),
        ShellRequest::Login => {
            if capability.login_shell.is_none() {
                return Err(BridgeError::new(
                    ErrorCode::RemoteCapabilityMissing,
                    "remote account login shell could not be resolved safely",
                    false,
                ));
            }
            Ok(ShellSelection {
                shell: ShellKind::Login,
                fallback: false,
            })
        }
    }
}

pub fn parse_probe_output(
    output: &[u8],
    expected_requested_root: &RemotePath,
) -> BridgeResult<Capability> {
    if output.last() != Some(&0) {
        return Err(protocol_error("capability output is not NUL terminated"));
    }

    let mut records = BTreeMap::new();
    for raw_record in output[..output.len() - 1].split(|byte| *byte == 0) {
        if raw_record.is_empty() {
            return Err(protocol_error("capability output contains an empty record"));
        }
        let record = std::str::from_utf8(raw_record)
            .map_err(|_| protocol_error("capability output is not valid UTF-8"))?;
        let (key, value) = record
            .split_once('=')
            .ok_or_else(|| protocol_error("capability record has no value"))?;
        validate_key_value(key, value)?;
        if records.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(protocol_error("capability output contains a duplicate key"));
        }
    }

    if required(&records, "CODEX_SSH_PROBE")? != "1" {
        return Err(protocol_error("unsupported capability protocol version"));
    }
    if required(&records, "REQUESTED_ROOT")? != expected_requested_root.absolute() {
        return Err(protocol_error(
            "capability output does not match the requested root",
        ));
    }

    let physical_root = required(&records, "ROOT")?;
    if physical_root.len() > MAX_REMOTE_CONTEXT_ROOT_BYTES {
        return Err(protocol_error(
            "physical root exceeds the safe context limit",
        ));
    }
    if !physical_root.starts_with('/') {
        return Err(protocol_error("physical root is not absolute"));
    }
    let normalized = RemotePath::resolve("/", physical_root)
        .map_err(|_| protocol_error("physical root is invalid"))?;
    if normalized.absolute() != physical_root {
        return Err(protocol_error("physical root is not normalized"));
    }
    let root_device = parse_root_identity_number(required(&records, "ROOT_DEVICE")?)?;
    let root_inode = parse_root_identity_number(required(&records, "ROOT_INODE")?)?;
    let kernel_name = optional_bounded_record(&records, "KERNEL_NAME", MAX_KERNEL_NAME_BYTES)?;
    let machine_arch = optional_bounded_record(&records, "MACHINE_ARCH", MAX_MACHINE_ARCH_BYTES)?;

    let bash_version = required(&records, "BASH_VERSION")?;
    if bash_version.len() > MAX_SHELL_VERSION_BYTES {
        return Err(protocol_error(
            "shell version exceeds the safe metadata limit",
        ));
    }
    let (shell, bash_version) = match required(&records, "SHELL_KIND")? {
        "bash" if !bash_version.is_empty() => (
            ShellKind::Bash {
                version: bash_version.to_owned(),
            },
            Some(bash_version.to_owned()),
        ),
        "bash" => return Err(protocol_error("Bash capability has no version")),
        "sh" if bash_version.is_empty() => (ShellKind::PosixSh, None),
        "sh" => return Err(protocol_error("sh capability has a Bash version")),
        _ => return Err(protocol_error("unknown shell capability")),
    };
    let login_shell = match required(&records, "LOGIN_SHELL")? {
        "" => None,
        value => {
            if value.len() > MAX_LOGIN_SHELL_BYTES
                || value.bytes().any(|byte| byte.is_ascii_control())
                || !value.starts_with('/')
            {
                return Err(protocol_error("login shell path is invalid"));
            }
            Some(value.to_owned())
        }
    };

    let tools = records
        .iter()
        .filter_map(|(key, value)| {
            key.strip_prefix("TOOL_")
                .map(|name| (name.to_owned(), value == "1"))
        })
        .collect();

    Ok(Capability {
        physical_root: physical_root.to_owned(),
        root_device,
        root_inode,
        kernel_name,
        machine_arch,
        shell,
        bash_version,
        login_shell,
        tools,
    })
}

fn validate_key_value(key: &str, value: &str) -> BridgeResult<()> {
    match key {
        "CODEX_SSH_PROBE" | "REQUESTED_ROOT" | "ROOT" | "ROOT_DEVICE" | "ROOT_INODE"
        | "KERNEL_NAME" | "MACHINE_ARCH" | "SHELL_KIND" | "BASH_VERSION" | "LOGIN_SHELL" => Ok(()),
        _ => match key.strip_prefix("TOOL_") {
            Some(name) if TOOL_NAMES.contains(&name) && matches!(value, "0" | "1") => Ok(()),
            Some(name) if !TOOL_NAMES.contains(&name) => {
                Err(protocol_error("unknown capability tool key"))
            }
            Some(_) => Err(protocol_error("capability tool value must be 0 or 1")),
            None => Err(protocol_error("unknown capability key")),
        },
    }
}

fn optional_bounded_record(
    records: &BTreeMap<String, String>,
    key: &str,
    max_bytes: usize,
) -> BridgeResult<Option<String>> {
    let Some(value) = records.get(key) else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > max_bytes || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(protocol_error("capability platform record is invalid"));
    }
    Ok(Some(value.clone()))
}

fn parse_root_identity_number(value: &str) -> BridgeResult<u64> {
    if value.is_empty() || value.bytes().any(|byte| !byte.is_ascii_digit()) {
        return Err(protocol_error("root identity is invalid"));
    }
    value
        .parse()
        .map_err(|_| protocol_error("root identity is invalid"))
}

fn required<'a>(records: &'a BTreeMap<String, String>, key: &str) -> BridgeResult<&'a str> {
    records
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| protocol_error("capability output is missing a required key"))
}

fn protocol_error(message: &str) -> BridgeError {
    BridgeError::new(ErrorCode::ProtocolError, message, false)
}

#[derive(Debug, Default)]
struct CacheState {
    entries: HashMap<String, Arc<OnceCell<Arc<Capability>>>>,
    in_flight: HashMap<String, Arc<ProbeFlight>>,
}

#[derive(Debug)]
struct ProbeFlight {
    cell: Arc<OnceCell<Arc<Capability>>>,
    outcome: watch::Receiver<Option<BridgeResult<Arc<Capability>>>>,
}

enum CacheLookup {
    Ready(Arc<Capability>),
    Leader {
        flight: Arc<ProbeFlight>,
        sender: watch::Sender<Option<BridgeResult<Arc<Capability>>>>,
    },
    Follower(Arc<ProbeFlight>),
}

#[derive(Debug, Default)]
pub struct CapabilityCache {
    state: Mutex<CacheState>,
}

impl CapabilityCache {
    pub(crate) async fn get(&self, host: &str) -> Option<Arc<Capability>> {
        let state = self.state.lock().await;
        state
            .entries
            .get(host)
            .and_then(|cell| cell.get())
            .map(Arc::clone)
    }

    pub async fn get_or_probe<F, Fut>(&self, host: &str, probe: F) -> BridgeResult<Arc<Capability>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = BridgeResult<Capability>>,
    {
        let mut probe = Some(probe);
        loop {
            let lookup = {
                let mut state = self.state.lock().await;
                let cell = Arc::clone(
                    state
                        .entries
                        .entry(host.to_owned())
                        .or_insert_with(|| Arc::new(OnceCell::new())),
                );
                if let Some(capability) = cell.get() {
                    CacheLookup::Ready(Arc::clone(capability))
                } else if let Some(flight) = state.in_flight.get(host) {
                    CacheLookup::Follower(Arc::clone(flight))
                } else {
                    let (sender, outcome) = watch::channel(None);
                    let flight = Arc::new(ProbeFlight { cell, outcome });
                    state.in_flight.insert(host.to_owned(), Arc::clone(&flight));
                    CacheLookup::Leader { flight, sender }
                }
            };

            match lookup {
                CacheLookup::Ready(capability) => return Ok(capability),
                CacheLookup::Follower(flight) => match wait_for_probe(&flight).await {
                    ProbeWait::Completed(outcome) => return *outcome,
                    ProbeWait::Abandoned => {
                        self.remove_generation(host, &flight, true).await;
                    }
                },
                CacheLookup::Leader { flight, sender } => {
                    let run_probe = probe.take().expect("only a leader consumes its probe");
                    let outcome = run_probe().await.map(Arc::new);
                    if let Ok(capability) = &outcome {
                        let _ = flight.cell.set(Arc::clone(capability));
                    }

                    self.remove_generation(host, &flight, outcome.is_err())
                        .await;
                    sender.send_replace(Some(outcome.clone()));
                    return outcome;
                }
            }
        }
    }

    async fn remove_generation(&self, host: &str, flight: &Arc<ProbeFlight>, remove_cell: bool) {
        let mut state = self.state.lock().await;
        if remove_cell
            && state
                .entries
                .get(host)
                .is_some_and(|current| Arc::ptr_eq(current, &flight.cell))
        {
            state.entries.remove(host);
        }
        if state
            .in_flight
            .get(host)
            .is_some_and(|current| Arc::ptr_eq(current, flight))
        {
            state.in_flight.remove(host);
        }
    }

    pub async fn invalidate(&self, host: &str) -> bool {
        let mut state = self.state.lock().await;
        let entry_removed = state.entries.remove(host).is_some();
        let flight_removed = state.in_flight.remove(host).is_some();
        entry_removed || flight_removed
    }
}

enum ProbeWait {
    Completed(Box<BridgeResult<Arc<Capability>>>),
    Abandoned,
}

async fn wait_for_probe(flight: &ProbeFlight) -> ProbeWait {
    let mut receiver = flight.outcome.clone();
    loop {
        if let Some(outcome) = receiver.borrow().clone() {
            return ProbeWait::Completed(Box::new(outcome));
        }
        if receiver.changed().await.is_err() {
            if let Some(outcome) = receiver.borrow().clone() {
                return ProbeWait::Completed(Box::new(outcome));
            }
            return ProbeWait::Abandoned;
        }
    }
}
