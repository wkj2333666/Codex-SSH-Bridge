#!/bin/sh
set -u
umask 077
PROTOCOL_TAG=${1-}
[ "$PROTOCOL_TAG" = codex-ssh-dispatcher-1 ] || exit 64
MAX_FRAME_BYTES=${2-8388608}
case "$MAX_FRAME_BYTES" in
    ''|*[!0-9]*) exit 65 ;;
esac
[ "$MAX_FRAME_BYTES" -gt 0 ] || exit 65
STREAM_CHUNK_BYTES=262144
[ "$MAX_FRAME_BYTES" -lt "$STREAM_CHUNK_BYTES" ] && STREAM_CHUNK_BYTES=$MAX_FRAME_BYTES
BASE_ROOT=${TMPDIR:-/tmp}
BASE=$BASE_ROOT/codex-ssh-bridge-dispatcher.$$
base_suffix=0
while ! mkdir "$BASE" 2>/dev/null; do
    base_suffix=$((base_suffix + 1))
    [ "$base_suffix" -le 100 ] || exit 73
    BASE=$BASE_ROOT/codex-ssh-bridge-dispatcher.$$.$base_suffix
done
OUTPUT_LOCK=$BASE/output.lock
DD_FULLBLOCK=0
if dd if=/dev/zero of=/dev/null count=0 iflag=fullblock 2>/dev/null; then
    DD_FULLBLOCK=1
fi

cleanup_request() {
    request_dir=$1
    if [ -f "$request_dir/pid" ]; then
        request_pid=$(cat "$request_dir/pid" 2>/dev/null || true)
        case "$request_pid" in
            ''|*[!0-9]*) ;;
            *)
                kill -TERM -"$request_pid" 2>/dev/null || true
                setsid sh -c 'sleep 0.05; kill -KILL -"$1" 2>/dev/null || true' codex-ssh-killer "$request_pid" &
                ;;
        esac
    fi
    rm -rf "$request_dir"
}
cleanup() {
    for request_dir in "$BASE"/[0-9]*; do
        [ -d "$request_dir" ] || continue
        cleanup_request "$request_dir"
    done
    rm -rf "$BASE"
}
trap cleanup EXIT HUP INT TERM

has_command() { command -v "$1" >/dev/null 2>&1; }

send_file() {
    send_kind=$1
    send_id=$2
    send_path=$3
    send_length=$(wc -c <"$send_path" | tr -d '[:space:]')
    case "$send_length" in ''|*[!0-9]*) exit 74 ;; esac
    [ "$send_length" -le "$MAX_FRAME_BYTES" ] || exit 75
    while ! mkdir "$OUTPUT_LOCK" 2>/dev/null; do sleep 0; done
    printf 'CXSB1 %s %s %s\n' "$send_kind" "$send_id" "$send_length"
    if [ "$send_length" -gt 0 ]; then cat "$send_path"; fi
    rmdir "$OUTPUT_LOCK" 2>/dev/null || true
}
send_text() {
    send_kind=$1
    send_id=$2
    send_value=$3
    send_path=$BASE/text.$send_kind.$send_id
    printf '%s' "$send_value" >"$send_path"
    send_file "$send_kind" "$send_id" "$send_path"
    rm -f "$send_path"
}

record_test_call() {
    if [ -n "${CODEX_SSH_BRIDGE_TEST_CALL_LOG-}" ]; then
        record_kind=$1
        record_path=$2
        record_log=$CODEX_SSH_BRIDGE_TEST_CALL_LOG
        record_lock=$record_log.lock
        record_wait=0
        while ! mkdir "$record_lock" 2>/dev/null; do
            sleep 0
            record_wait=$((record_wait + 1))
            [ "$record_wait" -lt 10000 ] || return 0
        done
        {
            printf '%s\narg=' "$record_kind"
            cat "$record_path"
            printf '\nEND\n'
        } >>"$record_log" 2>/dev/null || true
        rmdir "$record_lock" 2>/dev/null || true
    fi
}

record_test_command() { record_test_call C "$1"; }

record_test_phase() {
    if [ -n "${FAKE_SSH_PHASE_LOG-}" ]; then
        case "$(cat "$1")" in
            *codex_patch_snapshot_sentinel*) printf 'S\n' >>"$FAKE_SSH_PHASE_LOG" ;;
            *codex_safe_write_sentinel*|*codex_guarded_delete_sentinel*) printf 'M\n' >>"$FAKE_SSH_PHASE_LOG" ;;
        esac
    fi
}

copy_exact_fd3() {
    copy_exact_path=$1
    copy_exact_length=$2
    copy_exact_read=0
    : >"$copy_exact_path"
    while [ "$copy_exact_read" -lt "$copy_exact_length" ]; do
        copy_exact_chunk=$((copy_exact_length - copy_exact_read))
        [ "$copy_exact_chunk" -le 65536 ] || copy_exact_chunk=65536
        dd bs="$copy_exact_chunk" count=1 >>"$copy_exact_path" <&3 2>/dev/null || return 1
        copy_exact_now=$(wc -c <"$copy_exact_path" | tr -d '[:space:]')
        case "$copy_exact_now" in ''|*[!0-9]*) return 1 ;; esac
        [ "$copy_exact_now" -gt "$copy_exact_read" ] || return 1
        copy_exact_read=$copy_exact_now
    done
}

copy_capped() {
    input_path=$1
    output_path=$2
    marker_path=$3
    limit=$4
    full_path=$output_path.full
    remainder_path=$output_path.remainder
    extra_path=$output_path.extra
    done_path=$output_path.done
    : >"$full_path"
    : >"$remainder_path"
    : >"$extra_path"
    rm -f "$marker_path"
    rm -f "$done_path"
    exec 3<"$input_path" || { : >"$done_path"; return 74; }
    full_blocks=$((limit / 65536))
    remainder_bytes=$((limit % 65536))
    if [ "$full_blocks" -gt 0 ]; then
        if [ "$DD_FULLBLOCK" -eq 1 ]; then
            dd of="$full_path" bs=65536 count="$full_blocks" iflag=fullblock <&3 2>/dev/null || true
        else
            copy_exact_fd3 "$full_path" $((full_blocks * 65536)) || true
        fi
    fi
    if [ "$remainder_bytes" -gt 0 ]; then
        dd of="$remainder_path" bs=1 count="$remainder_bytes" <&3 2>/dev/null || true
    fi
    dd of="$extra_path" bs=1 count=1 <&3 2>/dev/null || true
    if [ "$(wc -c <"$extra_path" | tr -d '[:space:]')" -gt 0 ]; then printf 1 >"$marker_path"; fi
    cat <&3 >/dev/null 2>&1 || true
    exec 3<&-
    cat "$full_path" "$remainder_path" >"$output_path"
    rm -f "$full_path" "$remainder_path" "$extra_path"
    : >"$done_path"
}
send_stream() {
    stream_kind=$1
    stream_id=$2
    stream_path=$3
    stream_dir=$4
    stream_source=$stream_path
    if [ ! -e "$stream_source" ]; then
        # A bounded continuation may run before copy_capped reaches its final
        # concatenation.  Snapshot the bytes collected so far instead of
        # treating the missing final file as a dispatcher failure.
        stream_source=$stream_dir/$stream_kind.partial
        cat "$stream_path.full" "$stream_path.remainder" >"$stream_source" 2>/dev/null || : >"$stream_source"
        if [ -e "$stream_path" ]; then
            rm -f "$stream_source"
            stream_source=$stream_path
        fi
    fi
    stream_block=0
    while :; do
        stream_chunk=$stream_dir/chunk.$stream_block
        dd if="$stream_source" of="$stream_chunk" bs="$STREAM_CHUNK_BYTES" skip="$stream_block" count=1 2>/dev/null || true
        stream_length=$(wc -c <"$stream_chunk" | tr -d '[:space:]')
        [ "$stream_length" -gt 0 ] || { rm -f "$stream_chunk"; break; }
        send_file "$stream_kind" "$stream_id" "$stream_chunk"
        rm -f "$stream_chunk"
        stream_block=$((stream_block + 1))
        [ "$stream_length" -lt "$STREAM_CHUNK_BYTES" ] && break
    done
    [ "$stream_source" = "$stream_path" ] || rm -f "$stream_source"
}

run_request() {
    run_id=$1
    run_shell=$2
    run_cwd_file=$3
    run_command_file=$4
    run_stdin_file=$5
    run_login_shell=$6
    run_timeout_ms=$7
    run_stdout_limit=$8
    run_stderr_limit=$9
    run_dir=$BASE/$run_id
    run_stdout_fifo=$run_dir/stdout.fifo
    run_stderr_fifo=$run_dir/stderr.fifo
    run_stdout=$run_dir/stdout
    run_stderr=$run_dir/stderr
    run_stdout_marker=$run_dir/stdout.truncated
    run_stderr_marker=$run_dir/stderr.truncated
    run_cwd=$(cat "$run_cwd_file"; printf .) || exit 74
    run_cwd=${run_cwd%.}
    if [ -n "${CODEX_SSH_BRIDGE_TEST_MODE-}" ] &&
       [ "${FAKE_SSH_MODE-}" != local-fixed ]; then
        run_cwd=/
    fi
    run_command=$(cat "$run_command_file"; printf .) || exit 74
    run_command=${run_command%.}
    run_original_command=$run_dir/original-command
    printf '%s' "$run_command" >"$run_original_command"
    mkfifo "$run_stdout_fifo" "$run_stderr_fifo" || exit 74
    copy_capped "$run_stdout_fifo" "$run_stdout" "$run_stdout_marker" "$run_stdout_limit" &
    run_stdout_collector=$!
    copy_capped "$run_stderr_fifo" "$run_stderr" "$run_stderr_marker" "$run_stderr_limit" &
    run_stderr_collector=$!
    run_command_path=
    test_sleep_seconds=0
    if [ -n "${CODEX_SSH_BRIDGE_TEST_MODE-}" ]; then
        test_sleep_seconds=${FAKE_SSH_FIXED_SLEEP_SECONDS-${FAKE_SSH_SLEEP_SECONDS-}}
    fi
    case "${FAKE_SSH_MODE-}" in
        sleep|orphan-streams|orphan-stdin) test_sleep_seconds=0 ;;
    esac
    case "$test_sleep_seconds" in
        ''|*[!0-9]*) test_sleep_seconds=0 ;;
    esac
    if [ -n "${CODEX_SSH_LOCAL_FIXED_PATH_ONCE-}" ] &&
       [ -n "${CODEX_SSH_LOCAL_FIXED_PATH_MARKER-}" ]; then
        if [ ! -e "$CODEX_SSH_LOCAL_FIXED_PATH_MARKER" ]; then
            : >"$CODEX_SSH_LOCAL_FIXED_PATH_MARKER"
            run_command_path=$CODEX_SSH_LOCAL_FIXED_PATH_ONCE
        fi
    fi
    if [ -n "${CODEX_SSH_BRIDGE_TEST_MODE-}" ]; then
        if [ -n "${FAKE_SSH_FIXED_STDOUT_BYTES-}" ] ||
           [ -n "${FAKE_SSH_FIXED_STDERR_BYTES-}" ]; then
            test_stdout_bytes=${FAKE_SSH_FIXED_STDOUT_BYTES-0}
            test_stderr_bytes=${FAKE_SSH_FIXED_STDERR_BYTES-0}
            case "$test_stdout_bytes:$test_stderr_bytes" in
                *[!0-9:]*|:*:) test_stdout_bytes=0; test_stderr_bytes=0 ;;
            esac
            run_command="dd if=/dev/zero bs=1 count=$test_stdout_bytes 2>/dev/null; dd if=/dev/zero bs=1 count=$test_stderr_bytes >&2 2>/dev/null; $run_command"
        fi
    fi
    if [ -n "${FAKE_SSH_MISMATCH_FILE-}" ] &&
       [ ! -e "$FAKE_SSH_MISMATCH_FILE" ]; then
        : >"$FAKE_SSH_MISMATCH_FILE"
        mismatch_stdout=$run_dir/mismatch.stdout
        mismatch_stderr=$run_dir/mismatch.stderr
        printf '%s' "${FAKE_SSH_MISMATCH_STDOUT-}" >"$mismatch_stdout"
        printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=%s\000' \
            "${FAKE_SSH_MISMATCH_KEY-find_nul}" >"$mismatch_stderr"
        run_command="cat \"$mismatch_stdout\"; cat \"$mismatch_stderr\" >&2; exit 0"
    fi
    if [ -n "${CODEX_SSH_BRIDGE_TEST_MODE-}" ]; then
                case "${FAKE_SSH_MODE-}" in
                    echo-command)
                        run_command="cat '$run_original_command'"
                        ;;
                    stdin)
                        run_command='cat'
                        ;;
                    sleep)
                        test_sleep_seconds=${FAKE_SSH_SLEEP_SECONDS-1}
                        case "$test_sleep_seconds" in
                            ''|*[!0-9.]*|*.*.*) test_sleep_seconds=1 ;;
                        esac
                        if [ "${FAKE_SSH_IGNORE_TERM-0}" = 1 ]; then
                            run_command="trap '' TERM; sleep $test_sleep_seconds"
                        else
                            run_command="sleep $test_sleep_seconds"
                        fi
                        ;;
                    orphan-streams)
                        if [ -n "${FAKE_SSH_ORPHAN_ONCE_MARKER-}" ] &&
                           [ -e "$FAKE_SSH_ORPHAN_ONCE_MARKER" ]; then
                            :
                        else
                            [ -z "${FAKE_SSH_ORPHAN_ONCE_MARKER-}" ] ||
                                : >"$FAKE_SSH_ORPHAN_ONCE_MARKER"
                            run_command="(
    trap '' TERM HUP
    sleep \"\${FAKE_SSH_SLEEP_SECONDS-10}\"
) &
orphan_pid=\$!
if [ -n \"\${FAKE_SSH_CHILD_PID_FILE-}\" ]; then printf \"%s\\\\n\" \"\$orphan_pid\" >\"\$FAKE_SSH_CHILD_PID_FILE\"; fi
if [ -n \"\${FAKE_SSH_PARENT_EXIT_FILE-}\" ]; then printf \"%s\\\\n\" exited >\"\$FAKE_SSH_PARENT_EXIT_FILE\"; fi
exit 0"
                        fi
                        ;;
                    orphan-stdin)
                        run_command="exec 3<&0
(
    trap '' TERM HUP
    exec 0<&3 3<&-
    if [ -n \"\${FAKE_SSH_CHILD_READY_FILE-}\" ]; then printf \"%s\\\\n\" ready >\"\$FAKE_SSH_CHILD_READY_FILE\"; fi
    sleep \"\${FAKE_SSH_SLEEP_SECONDS-10}\"
) &
orphan_pid=\$!
exec 3<&-
if [ -n \"\${FAKE_SSH_CHILD_PID_FILE-}\" ]; then printf \"%s\\\\n\" \"\$orphan_pid\" >\"\$FAKE_SSH_CHILD_PID_FILE\"; fi
if [ -n \"\${FAKE_SSH_CHILD_READY_FILE-}\" ]; then while [ ! -f \"\$FAKE_SSH_CHILD_READY_FILE\" ]; do sleep 0.005; done; fi
if [ -n \"\${FAKE_SSH_PARENT_EXIT_FILE-}\" ]; then printf \"%s\\\\n\" exited >\"\$FAKE_SSH_PARENT_EXIT_FILE\"; fi
exit 0"
                        ;;
                    error)
                        case "${FAKE_SSH_ERROR-remote}" in
                            diagnostic)
                                test_status=${FAKE_SSH_ERROR_STATUS-255}
                                test_diagnostic=${FAKE_SSH_DIAGNOSTIC-}
                                ;;
                            host-key)
                                test_status=255
                                test_diagnostic='Host key verification failed.'
                                ;;
                            auth)
                                test_status=255
                                test_diagnostic='fixture@fake.internal: Permission denied (publickey).'
                                ;;
                            connect-timeout)
                                test_status=255
                                test_diagnostic='ssh: connect to host fake.internal port 22: Connection timed out'
                                ;;
                            *)
                                test_status=${FAKE_SSH_EXIT_STATUS-7}
                                test_diagnostic=VERY_SECRET_REMOTE_DIAGNOSTIC
                                ;;
                        esac
                        case "$test_status" in ''|*[!0-9]*) test_status=7 ;; esac
                        run_command="printf '%s\\n' '$test_diagnostic' >&2; exit $test_status"
                        ;;
                    bytes)
                        test_stdout_bytes=${FAKE_SSH_STDOUT_BYTES-${FAKE_SSH_FIXED_STDOUT_BYTES-0}}
                        test_stderr_bytes=${FAKE_SSH_STDERR_BYTES-${FAKE_SSH_FIXED_STDERR_BYTES-0}}
                        test_status=${FAKE_SSH_EXIT_STATUS-0}
                        case "$test_stdout_bytes:$test_stderr_bytes:$test_status" in
                            *[!0-9:]*|:*:*:) test_stdout_bytes=0; test_stderr_bytes=0; test_status=0 ;;
                        esac
                        test_stdout_blocks=$((test_stdout_bytes / 65536))
                        test_stdout_remainder=$((test_stdout_bytes % 65536))
                        test_stderr_blocks=$((test_stderr_bytes / 65536))
                        test_stderr_remainder=$((test_stderr_bytes % 65536))
                        run_command="(dd if=/dev/zero bs=65536 count=$test_stdout_blocks 2>/dev/null; dd if=/dev/zero bs=1 count=$test_stdout_remainder 2>/dev/null) & test_stdout_pid=\$!; (dd if=/dev/zero bs=65536 count=$test_stderr_blocks >&2 2>/dev/null; dd if=/dev/zero bs=1 count=$test_stderr_remainder >&2 2>/dev/null) & test_stderr_pid=\$!; wait \$test_stdout_pid; wait \$test_stderr_pid; exit $test_status"
                        ;;
                    streams)
                        test_status=${FAKE_SSH_EXIT_STATUS-0}
                        case "$test_status" in ''|*[!0-9]*) test_status=0 ;; esac
                        run_command="printf '%s' '${FAKE_SSH_STDOUT-stdout}'; printf '%s' '${FAKE_SSH_STDERR-stderr}' >&2; exit $test_status"
                        ;;
                    large-candidates|large-candidates-all-match)
                        case "$run_command" in
                            *codex-sentinel-search-find*)
                                run_command='record_bytes=838; leaf_bytes=$((record_bytes - 10)); leaf=$(dd if=/dev/zero bs=1 count="$leaf_bytes" 2>/dev/null | tr "\000" x); if [ "${FAKE_SSH_MODE-}" = large-candidates-all-match ]; then i=0; while [ "$i" -lt 10000 ]; do printf "./accept/%s\000" "$leaf"; i=$((i + 1)); done; else printf "./accept/%s\000" "$leaf"; i=1; while [ "$i" -lt 10000 ]; do printf "./reject/%s\000" "$leaf"; i=$((i + 1)); done; fi; lookahead_leaf_bytes=$((8608 - 10)); lookahead_leaf=$(dd if=/dev/zero bs=1 count="$lookahead_leaf_bytes" 2>/dev/null | tr "\000" y); if [ "${FAKE_SSH_MODE-}" = large-candidates-all-match ]; then printf "./accept/%s\000" "$lookahead_leaf"; else printf "./reject/%s\000" "$lookahead_leaf"; fi'
                                ;;
                            *) run_command='cat >/dev/null' ;;
                        esac
                        ;;
                esac
    fi
    case "${FAKE_SSH_MODE-}" in
        sleep|orphan-streams|orphan-stdin) ;;
        *)
            if [ "$test_sleep_seconds" -gt 0 ]; then
                run_command="sleep $test_sleep_seconds; $run_command"
            fi
            ;;
    esac
    setsid sh -c '
        run_cwd=$1
        run_shell=$2
        run_command=$3
        run_pid_file=$4
        run_command_path=$5
        run_login_shell=$6
        printf "%s\\n" "$$" >"$run_pid_file" || exit 74
        CDPATH= cd -P -- "$run_cwd" || exit 126
        if [ -n "$run_command_path" ]; then
            PATH=$run_command_path
            export PATH
        fi
        case "$run_shell" in
            bash) exec bash --noprofile --norc -c "$run_command" ;;
            sh) exec sh -c "$run_command" ;;
            login) exec "$run_login_shell" -c "$run_command" ;;
            *) exit 126 ;;
        esac
    ' codex-ssh-dispatcher "$run_cwd" "$run_shell" "$run_command" "$run_dir/pid" "$run_command_path" "$run_login_shell" \
        <"$run_stdin_file" >"$run_stdout_fifo" 2>"$run_stderr_fifo" &
    run_job_pid=$!
    run_pid=
    run_pid_wait=0
    while :; do
        run_pid=$(cat "$run_dir/pid" 2>/dev/null || true)
        case "$run_pid" in
            ''|*[!0-9]*)
                run_pid_wait=$((run_pid_wait + 1))
                [ "$run_pid_wait" -lt 10000 ] || exit 74
                sleep 0
                ;;
            *) break ;;
        esac
    done
    if [ -n "${CODEX_SSH_BRIDGE_TEST_MODE-}" ] &&
       [ -n "${FAKE_SSH_CHILD_PID_FILE-}" ]; then
        printf '%s\n' "$run_pid" >"$FAKE_SSH_CHILD_PID_FILE" 2>/dev/null || true
    fi
    if [ -n "${CODEX_SSH_BRIDGE_TEST_MODE-}" ]; then
        if [ -n "${FAKE_SSH_FIXED_READY_FILE-}" ]; then
            : >"$FAKE_SSH_FIXED_READY_FILE"
        fi
        case "$run_command" in
            *codex_safe_write_sentinel*)
                if [ -n "${FAKE_SSH_MUTATION_READY_DIR-}" ]; then
                    mkdir -p "$FAKE_SSH_MUTATION_READY_DIR"
                    : >"$FAKE_SSH_MUTATION_READY_DIR/$run_id"
                fi
                if [ -n "${FAKE_SSH_MUTATION_READY_FILE-}" ] &&
                   [ -n "${FAKE_SSH_MUTATION_READY_AFTER-}" ]; then
                    ready_count_file=$FAKE_SSH_MUTATION_READY_FILE.count
                    ready_count=$(cat "$ready_count_file" 2>/dev/null || printf 0)
                    case "$ready_count" in ''|*[!0-9]*) ready_count=0 ;; esac
                    ready_count=$((ready_count + 1))
                    printf '%s\n' "$ready_count" >"$ready_count_file"
                    if [ "$ready_count" -eq "$FAKE_SSH_MUTATION_READY_AFTER" ]; then
                        : >"$FAKE_SSH_MUTATION_READY_FILE"
                    fi
                fi
                ;;
        esac
    fi
    send_text READY "$run_id" started
    run_watchdog=
    run_timeout_marker=$run_dir/timed-out
    case "$run_timeout_ms" in ''|*[!0-9]*) run_timeout_ms=0 ;; esac
    if [ "$run_timeout_ms" -gt 0 ]; then
        run_timeout_seconds=$(( (run_timeout_ms + 999) / 1000 ))
        setsid sh -c '
            sleep "$1"
            if kill -0 "$2" 2>/dev/null; then
                : >"$3"
                kill -TERM -"$2" 2>/dev/null || true
                sleep 1
                kill -KILL -"$2" 2>/dev/null || true
            fi
        ' codex-ssh-watchdog "$run_timeout_seconds" "$run_pid" "$run_timeout_marker" &
        run_watchdog=$!
    fi
    if wait "$run_job_pid"; then run_status=$?; else run_status=$?; fi
    if [ -n "$run_watchdog" ]; then
        kill -TERM -"$run_watchdog" 2>/dev/null || true
        wait "$run_watchdog" 2>/dev/null || true
    fi
    # A shell can exit while a long-lived child (for example an HTTP server)
    # still owns the request FIFOs.  Waiting indefinitely for those collectors
    # would withhold EXIT and consume a host request slot forever.  Give normal
    # output a bounded drain window, then complete the request and let the
    # collectors finish in the background.  The fourth EXIT field tells the
    # local session that a child may still be running.
    run_process_group_alive=0
    if kill -0 -"$run_pid" 2>/dev/null; then run_process_group_alive=1; fi
    if [ "$run_process_group_alive" -eq 1 ]; then
        run_drain_wait=0
        while :; do
            [ -f "$run_stdout.done" ] && [ -f "$run_stderr.done" ] && break
            [ "$run_drain_wait" -lt 12 ] || break
            sleep 0.01
            run_drain_wait=$((run_drain_wait + 1))
        done
    else
        # With no descendant process group left, preserve complete output even
        # when the streams are still flushing a large finite payload.
        wait "$run_stdout_collector" 2>/dev/null || true
        wait "$run_stderr_collector" 2>/dev/null || true
    fi
    run_process_may_continue=0
    if [ ! -f "$run_stdout.done" ] || [ ! -f "$run_stderr.done" ]; then
        run_process_may_continue=1
    fi
    if [ "$run_process_group_alive" -eq 1 ] || kill -0 -"$run_pid" 2>/dev/null; then
        run_process_may_continue=1
    fi
    send_stream STDOUT "$run_id" "$run_stdout" "$run_dir"
    send_stream STDERR "$run_id" "$run_stderr" "$run_dir"
    if [ "${FAKE_SSH_MODE-}" = local-fixed ] &&
       [ "$run_status" -eq 0 ] && [ -n "${FAKE_SSH_LOCAL_FIXED_POST-}" ]; then
        case "$FAKE_SSH_LOCAL_FIXED_POST" in
            stderr)
                send_text ERROR "$run_id" POST_COMMIT_DIAGNOSTIC
                rm -rf "$run_dir"
                return 0
                ;;
            *)
                kill -TERM "$PPID" 2>/dev/null || true
                exit 0
                ;;
        esac
    fi
    run_stdout_truncated=0
    run_stderr_truncated=0
    run_timed_out=0
    [ -e "$run_stdout_marker" ] && run_stdout_truncated=1
    [ -e "$run_stderr_marker" ] && run_stderr_truncated=1
    [ -e "$run_timeout_marker" ] && run_timed_out=1
    run_exit_file=$run_dir/exit
    printf '%s\n%s\n%s\n%s\n%s\n' "$run_status" "$run_stdout_truncated" "$run_stderr_truncated" "$run_process_may_continue" "$run_timed_out" >"$run_exit_file"
    send_file EXIT "$run_id" "$run_exit_file"
    # The request is complete from the protocol's point of view.  Remove the
    # temporary directory separately once both collectors mark EOF, so a
    # service that intentionally outlives the command cannot retain this
    # request worker or block later frames on the SSH session.
    (
        while :; do
            [ -d "$run_dir" ] || exit 0
            [ -f "$run_stdout.done" ] && [ -f "$run_stderr.done" ] && break
            sleep 0.05
        done
        rm -rf "$run_dir"
    ) </dev/null >/dev/null 2>&1 &
}

read_frame() {
    frame_magic=
    frame_kind=
    frame_id=
    frame_length=
    frame_extra=
    IFS=' ' read -r frame_magic frame_kind frame_id frame_length frame_extra || return 1
    [ "$frame_magic" = CXSB1 ] || return 1
    [ -n "$frame_kind" ] && [ -n "$frame_id" ] && [ -n "$frame_length" ] || return 1
    [ -z "$frame_extra" ] || return 1
    case "$frame_id" in ''|*[!0-9]*) return 1 ;; esac
    case "$frame_length" in ''|*[!0-9]*) return 1 ;; esac
    [ "$frame_length" -le "$MAX_FRAME_BYTES" ] || return 1
    frame_path=$BASE/input.$frame_id
    : >"$frame_path"
    if [ "$frame_length" -gt 0 ]; then
        if [ "$DD_FULLBLOCK" -eq 1 ]; then
            dd of="$frame_path" bs="$frame_length" count=1 iflag=fullblock 2>/dev/null || return 1
        else
            frame_read=0
            while [ "$frame_read" -lt "$frame_length" ]; do
                frame_chunk=$((frame_length - frame_read))
                [ "$frame_chunk" -le 65536 ] || frame_chunk=65536
                dd bs="$frame_chunk" count=1 >>"$frame_path" 2>/dev/null || return 1
                frame_now=$(wc -c <"$frame_path" | tr -d '[:space:]')
                case "$frame_now" in ''|*[!0-9]*) return 1 ;; esac
                [ "$frame_now" -gt "$frame_read" ] || return 1
                frame_read=$frame_now
            done
        fi
    fi
    return 0
}
expect_data() {
    expected_id=$1
    expected_length=$2
    expected_path=$3
    if [ "$expected_length" -eq 0 ]; then : >"$expected_path"; return 0; fi
    read_frame || return 1
    [ "$frame_kind" = DATA ] || return 1
    [ "$frame_id" = "$expected_id" ] || return 1
    [ "$frame_length" -eq "$expected_length" ] || return 1
    mv "$frame_path" "$expected_path"
}
handle_open() {
    open_id=$1
    open_meta=$2
    open_dir=$BASE/$open_id
    [ "$open_id" -gt 0 ] || return 1
    if [ -e "$open_dir" ]; then send_text ERROR "$open_id" duplicate-request-id; return 0; fi
    mkdir "$open_dir" || return 1
    open_shell=
    open_cwd_length=
    open_command_length=
    open_stdin_length=
    open_login_shell=
    open_timeout_ms=0
    open_stdout_limit=0
    open_stderr_limit=0
    while IFS='=' read -r open_key open_value; do
        case "$open_key" in
            shell) open_shell=$open_value ;;
            cwd_length) open_cwd_length=$open_value ;;
            command_length) open_command_length=$open_value ;;
            stdin_length) open_stdin_length=$open_value ;;
            login_shell) open_login_shell=$open_value ;;
            timeout_ms) open_timeout_ms=$open_value ;;
            stdout_limit) open_stdout_limit=$open_value ;;
            stderr_limit) open_stderr_limit=$open_value ;;
            '') ;;
            *) send_text ERROR "$open_id" invalid-open-metadata; rm -rf "$open_dir"; return 0 ;;
        esac
    done <"$open_meta"
    case "$open_shell" in
        bash|sh) [ -z "$open_login_shell" ] || { send_text ERROR "$open_id" invalid-open-metadata; rm -rf "$open_dir"; return 0; } ;;
        login)
            case "$open_login_shell" in
                /*) [ -f "$open_login_shell" ] && [ -x "$open_login_shell" ] || { send_text ERROR "$open_id" login-shell-unavailable; rm -rf "$open_dir"; return 0; } ;;
                *) send_text ERROR "$open_id" invalid-login-shell; rm -rf "$open_dir"; return 0 ;;
            esac
            ;;
        *) send_text ERROR "$open_id" unsupported-shell; rm -rf "$open_dir"; return 0 ;;
    esac
    for open_number in "$open_cwd_length" "$open_command_length" "$open_stdin_length" "$open_timeout_ms" "$open_stdout_limit" "$open_stderr_limit"; do
        case "$open_number" in ''|*[!0-9]*) send_text ERROR "$open_id" invalid-open-number; rm -rf "$open_dir"; return 0 ;; esac
    done
    cwd_file=$open_dir/cwd
    command_file=$open_dir/command
    stdin_file=$open_dir/stdin
    expect_data "$open_id" "$open_cwd_length" "$cwd_file" || { rm -rf "$open_dir"; return 1; }
    expect_data "$open_id" "$open_command_length" "$command_file" || { rm -rf "$open_dir"; return 1; }
    record_test_command "$command_file"
    record_test_phase "$command_file"
    expect_data "$open_id" "$open_stdin_length" "$stdin_file" || { rm -rf "$open_dir"; return 1; }
    run_request "$open_id" "$open_shell" "$cwd_file" "$command_file" "$stdin_file" \
        "$open_login_shell" "$open_timeout_ms" "$open_stdout_limit" "$open_stderr_limit" &
}
missing_command=
for required_command in dd mkdir cat wc mkfifo setsid sleep kill mv rm rmdir tr; do
    if ! has_command "$required_command"; then missing_command=$required_command; break; fi
done
if [ -n "$missing_command" ]; then
    missing_file=$BASE/missing
    printf 'DISPATCHER_CAPABILITY_MISSING=%s\n' "$missing_command" >"$missing_file"
    send_file ERROR 0 "$missing_file"
    exit 78
fi
send_text HELLO_ACK 0 'protocol=codex-ssh-dispatcher/1;shell=sh;'
while read_frame; do
    case "$frame_kind" in
        HELLO) send_text HELLO_ACK "$frame_id" 'protocol=codex-ssh-dispatcher/1;shell=sh;' ;;
        OPEN) handle_open "$frame_id" "$frame_path" || exit 74; rm -f "$frame_path" ;;
        CANCEL)
            cancel_dir=$BASE/$frame_id
            if [ -f "$cancel_dir/pid" ]; then
                cancel_pid=$(cat "$cancel_dir/pid" 2>/dev/null || true)
                case "$cancel_pid" in
                    ''|*[!0-9]*) ;;
                    *)
                        kill -TERM -"$cancel_pid" 2>/dev/null || true
                        setsid sh -c 'sleep 0.05; kill -KILL -"$1" 2>/dev/null || true' codex-ssh-killer "$cancel_pid" &
                        ;;
                esac
            fi
            rm -f "$frame_path"
            ;;
        CLOSE) rm -f "$frame_path"; exit 0 ;;
        *) send_text ERROR "$frame_id" unexpected-frame; rm -f "$frame_path" ;;
    esac
done
exit 0
