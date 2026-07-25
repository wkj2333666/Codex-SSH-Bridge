use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::time::Duration;

use base64::Engine as _;
use globset::GlobSetBuilder;
use tokio_util::sync::CancellationToken;

use crate::error::{BridgeError, BridgeResult, ErrorCode};
use crate::output::{InternalSpoolOwner, StreamKind};
use crate::ssh::{FixedOperationKind, FixedRunRequest, RootedPathInputs};

use super::protocol::{SpoolCursor, context, encode_bytes, protocol_error, read_small_stream};
use super::{
    RemoteBridge, ResolvedSearch, SearchEngine, SearchMatch, SearchResult,
    attach_fixed_result_context, compile_glob,
};

// Search candidates are an intermediate, best-effort index rather than the
// user-visible result.  Do not let the general MCP frame budget turn a broad
// search into an unbounded grep of a remote data tree: on trees containing
// large binary artifacts, reading several thousand candidates can take much
// longer than enumerating them.  A capped candidate set is reported through
// SearchResult::truncated, so callers can narrow the path/glob and retry.
const MAX_SEARCH_CANDIDATE_BYTES: usize = 128 * 1024;
const MAX_SEARCH_OPERATION_TIMEOUT_MS: u64 = 30_000;

macro_rules! bounded_sentinel {
    () => {
        r#"
cb() (
 d=$(mktemp -d /tmp/codex-sentinel-bound.XXXXXX 2>/dev/null)||exit 90
 trap 'rm -rf -- "$d"' 0 1 2 15
 f=$d/codex-sentinel-bound;o=$d/o
 m=$(stat -c %a "$d" 2>/dev/null)||exit 90
 [ "$m" = 700 ]||exit 1;mkfifo "$f"||exit 90;[ -p "$f" ]||exit 1
 (printf abcdef>"$f")&p=$!;exec 3<"$f"
 CODEX_SSH_SENTINEL=bound head -c 3 <&3 >"$o" 2>/dev/null;h=$?
 cat <&3 >/dev/null;r=$?;exec 3<&-;wait "$p" 2>/dev/null;w=$?
 [ "$r:$w" = 0:0 ]||exit 90;v=$(cat "$o")||exit 90;[ "$h:$v" = 0:abc ]
)
cb;s=$?;case $s in 0);;1)printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=search_bound\000' >&2;exit 0;;*)exit 2;;esac
"#
    };
}

const CANDIDATE_SCRIPT: &str = concat!(
    r#"
root=$1
limit=$2
"#,
    bounded_sentinel!(),
    r#"
cf() (
 d=$(mktemp -d /tmp/codex-sentinel-search-find.XXXXXX 2>/dev/null)||exit 90
 trap 'rm -rf -- "$d"' 0 1 2 15
 mkdir "$d/a" "$d/z"&&printf x>"$d/a/.hidden"&&printf x>"$d/z/x"&&ln -s "$d/z" "$d/a/l"&&ln -s "$d/a" "$d/codex-sentinel-search-find"||exit 90
 find -H "$d/codex-sentinel-search-find" -type f -print0 >"$d/o" 2>/dev/null||exit 90
 printf '%s/.hidden\000' "$d/codex-sentinel-search-find">"$d/e"||exit 90;cmp -s "$d/e" "$d/o"
)
cf;s=$?;case $s in 0);;1)printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=find_nul\000' >&2;exit 0;;*)exit 2;;esac
if [ ! -e "$root" ] && [ ! -L "$root" ]; then printf 'NOT_FOUND\000' >&2; exit 0; fi
if [ ! -d "$root" ]; then printf 'NOT_DIRECTORY\000' >&2; exit 0; fi
if [ ! -r "$root" ]; then printf 'PERMISSION_DENIED\000' >&2; exit 0; fi
umask 077
scratch=$(mktemp -d /tmp/codex-ssh-search.XXXXXX) || exit 2
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT HUP INT TERM
fifo=$scratch/fifo
data=$scratch/data
mkfifo "$fifo" || exit 2
find -H "$root" -type f -print0 2>/dev/null >"$fifo" &
producer=$!
exec 3<"$fifo"
head -c "$limit" <&3 >"$data"
head_status=$?
bytes=$(wc -c <"$data")
capped=0
if [ "$bytes" -eq "$limit" ]; then capped=1; fi
if [ "$capped" -eq 1 ]; then
    cap_wait=0
    while [ "$cap_wait" -lt 100 ]; do
        sleep 0
        cap_wait=$((cap_wait + 1))
    done
    kill "$producer" 2>/dev/null || true
fi
exec 3<&-
wait "$producer" 2>/dev/null
wait_status=$?
if [ "$head_status" -ne 0 ]; then exit 2; fi
if [ "$capped" -eq 0 ]; then
    if [ "$wait_status" -ne 0 ]; then exit 2; fi
fi
cat "$data"
if [ "$capped" -eq 1 ]; then printf 'CAPPED\000' >&2; fi
"#,
);

const RG_SCRIPT: &str = concat!(
    r#"
query=$1
binary=$2
limit=$3
"#,
    bounded_sentinel!(),
    r#"
x=$(printf 'a\nb\000'|xargs -0 -r sh -c 'printf %s "$1"' codex-sentinel-rg-xargs 2>/dev/null);s=$?
printf x\000|xargs -0 -r sh -c 'exit 7' codex-sentinel-rg-xargs >/dev/null 2>&1;q=$?
if [ "$s" -ne 0 ]||[ "$q" -eq 0 ]||[ "$x" != 'a
b' ];then printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=xargs_nul\000' >&2;exit 0;fi
umask 077
scratch=$(mktemp -d /tmp/codex-ssh-search.XXXXXX) || exit 2
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT HUP INT TERM
codex_rg_file=$scratch/codex-sentinel-rg
if [ "$binary" = 1 ]; then
    printf '\377needle\n' >"$codex_rg_file" || exit 2
    codex_rg_json=$(rg --json --fixed-strings --hidden --no-ignore --text -- needle "$codex_rg_file" 2>/dev/null)
else
    printf 'before needle after\n' >"$codex_rg_file" || exit 2
    codex_rg_json=$(rg --json --fixed-strings --hidden --no-ignore -- needle "$codex_rg_file" 2>/dev/null)
fi
codex_rg_status=$?
if [ "$codex_rg_status" -gt 1 ]; then exit 2; fi
if [ "$binary" = 1 ]; then
    case "$codex_rg_json" in
        *'"type":"match"'*'"path":{"text":"'"$codex_rg_file"'"}'*'"lines":{"bytes":"/25lZWRsZQo="}'*'"line_number":1'*'"start":1,"end":7'*) codex_rg_ok=1 ;;
        *) codex_rg_ok=0 ;;
    esac
    rg --json --fixed-strings --hidden --no-ignore --text -- absent "$codex_rg_file" >/dev/null 2>&1
else
    case "$codex_rg_json" in
        *'"type":"match"'*'"path":{"text":"'"$codex_rg_file"'"}'*'"lines":{"text":"before needle after\n"}'*'"line_number":1'*'"start":7,"end":13'*) codex_rg_ok=1 ;;
        *) codex_rg_ok=0 ;;
    esac
    rg --json --fixed-strings --hidden --no-ignore -- absent "$codex_rg_file" >/dev/null 2>&1
fi
codex_rg_empty=$?
if [ "$codex_rg_empty" -gt 1 ]; then exit 2; fi
if [ "$codex_rg_status" -ne 0 ] || [ "$codex_rg_empty" -ne 1 ] || [ "$codex_rg_ok" -ne 1 ]; then
    printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=rg_json\000' >&2
    exit 0
fi
fifo=$scratch/fifo
data=$scratch/data
engine_error=$scratch/engine-error
input=$scratch/input
cat >"$input" || exit 2
mkfifo "$fifo" || exit 2
xargs -0 -r sh -c '
query=$1
binary=$2
engine_error=$3
shift 3
if [ "$binary" = 1 ]; then rg --json --fixed-strings --hidden --no-ignore --text -- "$query" "$@" 2>/dev/null; else rg --json --fixed-strings --hidden --no-ignore -- "$query" "$@" 2>/dev/null; fi
status=$?
if [ "$status" -eq 1 ]; then exit 0; fi
if [ "$status" -gt 1 ]; then printf "%s" "$status" >"$engine_error"; exit 255; fi
exit "$status"
' codex-ssh-bridge-rg "$query" "$binary" "$engine_error" <"$input" >"$fifo" 2>/dev/null &
producer=$!
exec 3<"$fifo"
head -c "$limit" <&3 >"$data"
head_status=$?
bytes=$(wc -c <"$data")
capped=0
if [ "$bytes" -eq "$limit" ]; then capped=1; fi
drain=
if [ "$capped" -eq 1 ]; then
    dd <&3 >/dev/null 2>&1 &
    drain=$!
    cap_wait=0
    while [ ! -e "$engine_error" ] && [ "$cap_wait" -lt 100 ]; do
        sleep 0
        cap_wait=$((cap_wait + 1))
    done
    kill "$producer" 2>/dev/null || true
    kill "$drain" 2>/dev/null || true
    wait "$drain" 2>/dev/null || true
fi
exec 3<&-
wait "$producer" 2>/dev/null
wait_status=$?
engine_status=$(cat "$engine_error" 2>/dev/null || :)
if [ "$head_status" -ne 0 ]; then exit 2; fi
if [ "$capped" -eq 0 ]; then
    if [ -n "$engine_status" ] || [ "$wait_status" -ne 0 ]; then exit 2; fi
else
    case "$engine_status" in ''|141|143) ;; *) exit 2 ;; esac
fi
cat "$data"
if [ "$capped" -eq 1 ]; then printf 'CAPPED\000' >&2; fi
"#,
);

const GREP_SCRIPT: &str = concat!(
    r#"
query=$1
limit=$2
"#,
    bounded_sentinel!(),
    r#"
x=$(printf 'a\nb\000'|xargs -0 -r sh -c 'printf %s "$1"' codex-sentinel-grep-xargs 2>/dev/null);s=$?
printf x\000|xargs -0 -r sh -c 'exit 7' codex-sentinel-grep-xargs >/dev/null 2>&1;q=$?
if [ "$s" -ne 0 ]||[ "$q" -eq 0 ]||[ "$x" != 'a
b' ];then printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=xargs_nul\000' >&2;exit 0;fi
umask 077
scratch=$(mktemp -d /tmp/codex-ssh-search.XXXXXX) || exit 2
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT HUP INT TERM
codex_grep_file=$scratch/codex-sentinel-grep
codex_grep_binary=$scratch/codex-sentinel-grep-binary
codex_grep_out=$scratch/codex-sentinel-grep-out
codex_grep_expected=$scratch/codex-sentinel-grep-expected
printf 'needle\n' >"$codex_grep_file" || exit 2
printf 'before\000needle\n' >"$codex_grep_binary" || exit 2
grep -IHnZ -F -- needle "$codex_grep_file" "$codex_grep_binary" >"$codex_grep_out" 2>/dev/null
codex_grep_status=$?
if [ "$codex_grep_status" -gt 1 ]; then exit 2; fi
{ printf '%s\000' "$codex_grep_file"; printf '1:needle\n'; } >"$codex_grep_expected" || exit 2
grep -IHnZ -F -- absent "$codex_grep_file" >/dev/null 2>&1
codex_grep_empty=$?
if [ "$codex_grep_empty" -gt 1 ]; then exit 2; fi
if [ "$codex_grep_status" -ne 0 ] || [ "$codex_grep_empty" -ne 1 ] ||
   ! cmp -s "$codex_grep_expected" "$codex_grep_out"; then
    printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=grep_nul\000' >&2
    exit 0
fi
fifo=$scratch/fifo
data=$scratch/data
engine_error=$scratch/engine-error
input=$scratch/input
cat >"$input" || exit 2
mkfifo "$fifo" || exit 2
xargs -0 -r sh -c '
query=$1
engine_error=$2
shift 2
grep -IHnZ -F -- "$query" "$@" 2>/dev/null
status=$?
if [ "$status" -eq 1 ]; then exit 0; fi
if [ "$status" -gt 1 ]; then printf "%s" "$status" >"$engine_error"; exit 255; fi
exit "$status"
' codex-ssh-bridge-grep "$query" "$engine_error" <"$input" >"$fifo" 2>/dev/null &
producer=$!
exec 3<"$fifo"
head -c "$limit" <&3 >"$data"
head_status=$?
bytes=$(wc -c <"$data")
capped=0
if [ "$bytes" -eq "$limit" ]; then capped=1; fi
drain=
if [ "$capped" -eq 1 ]; then
    dd <&3 >/dev/null 2>&1 &
    drain=$!
    cap_wait=0
    while [ ! -e "$engine_error" ] && [ "$cap_wait" -lt 100 ]; do
        sleep 0
        cap_wait=$((cap_wait + 1))
    done
    kill "$producer" 2>/dev/null || true
    kill "$drain" 2>/dev/null || true
    wait "$drain" 2>/dev/null || true
fi
exec 3<&-
wait "$producer" 2>/dev/null
wait_status=$?
engine_status=$(cat "$engine_error" 2>/dev/null || :)
if [ "$head_status" -ne 0 ]; then exit 2; fi
if [ "$capped" -eq 0 ]; then
    if [ -n "$engine_status" ] || [ "$wait_status" -ne 0 ]; then exit 2; fi
else
    case "$engine_status" in ''|141|143) ;; *) exit 2 ;; esac
fi
cat "$data"
if [ "$capped" -eq 1 ]; then printf 'CAPPED\000' >&2; fi
"#,
);

pub(super) async fn search(
    bridge: &RemoteBridge,
    request: ResolvedSearch,
    cancel: CancellationToken,
) -> BridgeResult<SearchResult> {
    let runner = &bridge.runner;
    let limits = runner.config().limits();
    let candidate_limit = (MAX_SEARCH_CANDIDATE_BYTES + 1).min(limits.max_frame_bytes + 1);
    let search_timeout = Duration::from_millis(
        limits
            .command_timeout_ms
            .min(MAX_SEARCH_OPERATION_TIMEOUT_MS),
    );
    let owner = InternalSpoolOwner::new();
    let candidates_result = bridge
        .execute_readonly_fixed(
            FixedRunRequest {
                kind: FixedOperationKind::ReadOnly,
                host: request.host.clone(),
                script: CANDIDATE_SCRIPT,
                args: vec![
                    request.path.as_str().to_owned(),
                    candidate_limit.to_string(),
                ],
                stdin: None,
                rooted_paths: RootedPathInputs {
                    argument_indices: &[0],
                    stdin_nul_paths: false,
                },
                required_capabilities: &["find_nul", "search_bound"],
                // The static script enforces the smaller candidate budget.
                // Keep the protocol capture bound at the normal frame limit
                // so a hostile or test remote that ignores the script cap is
                // still classified using the existing bounded-output path.
                stdout_limit: (limits.max_frame_bytes + 1) as u64,
                stderr_limit: 1024,
                timeout: search_timeout,
                cleanup: owner.registration(),
            },
            cancel.clone(),
        )
        .await?;
    let attach_candidates =
        |error| attach_fixed_result_context(error, &request.host, &candidates_result);
    let stderr = read_small_stream(&candidates_result.output, StreamKind::Stderr, 1024)
        .await
        .map_err(&attach_candidates)?;
    let candidate_capped = stderr == b"CAPPED\0";
    if !stderr.is_empty() && !candidate_capped {
        let error = match stderr.as_slice() {
            b"NOT_FOUND\0" => BridgeError::not_found(),
            b"PERMISSION_DENIED\0" => BridgeError::permission_denied(),
            b"NOT_DIRECTORY\0" => BridgeError::not_directory(),
            _ => protocol_error("search candidate control record is invalid"),
        };
        return Err(attach_candidates(error));
    }
    let mut cursor = SpoolCursor::new(
        &candidates_result.output,
        StreamKind::Stdout,
        limits.max_frame_bytes + 1,
    )
    .map_err(&attach_candidates)?;
    let mut builder = GlobSetBuilder::new();
    for glob in &request.globs {
        builder.add(compile_glob(glob).map_err(&attach_candidates)?);
    }
    let globs = builder
        .build()
        .map_err(|_| BridgeError::invalid_argument("search glob is invalid"))
        .map_err(&attach_candidates)?;
    let operation_root = crate::REMOTE_OPERATION_ROOT;
    let display_root = request.path.as_str().as_bytes();
    let mut candidates = Vec::with_capacity(10_001);
    let mut candidate_count = 0usize;
    loop {
        let path = if candidate_capped {
            cursor
                .next_field_capped(limits.max_frame_bytes)
                .await
                .map_err(&attach_candidates)?
        } else {
            cursor
                .next_field(limits.max_frame_bytes)
                .await
                .map_err(&attach_candidates)?
        };
        let Some(pinned_path) = path else { break };
        if pinned_path.is_empty() {
            return Err(attach_candidates(protocol_error(
                "search candidate path is empty",
            )));
        }
        let actual = logical_from_pinned(operation_root.as_bytes(), &pinned_path)
            .map_err(&attach_candidates)?;
        let relative = relative(display_root, &actual).map_err(&attach_candidates)?;
        candidate_count = candidate_count
            .checked_add(1)
            .ok_or_else(|| protocol_error("search candidate count overflowed"))
            .map_err(&attach_candidates)?;
        if candidates.len() < 10_001
            && (request.globs.is_empty()
                || globs.is_match(Path::new(&OsString::from_vec(relative.to_vec()))))
        {
            candidates.push(pinned_path);
        }
    }
    if candidate_capped && cursor.discarded_incomplete() && candidate_count == 0 {
        return Err(attach_candidates(protocol_error(
            "search candidate record is oversized",
        )));
    }
    candidates.sort();
    let mut truncated = candidate_capped || candidate_count > 10_000 || candidates.len() > 10_000;
    candidates.truncate(10_000);
    let rg = candidates_result.capability.tools.get("rg_json") == Some(&true);
    if request.binary && !rg {
        return Err(attach_candidates(BridgeError::new(
            ErrorCode::RemoteCapabilityMissing,
            "binary search requires remote rg JSON support",
            false,
        )));
    }
    let engine = if rg {
        SearchEngine::Rg
    } else {
        SearchEngine::Grep
    };
    let (script, args, required): (&'static str, Vec<String>, &'static [&'static str]) = if rg {
        (
            RG_SCRIPT,
            vec![
                request.query.clone(),
                if request.binary { "1" } else { "0" }.to_owned(),
                (limits.max_frame_bytes + 1).to_string(),
            ],
            &["rg_json", "xargs_nul", "search_bound"],
        )
    } else {
        (
            GREP_SCRIPT,
            vec![
                request.query.clone(),
                (limits.max_frame_bytes + 1).to_string(),
            ],
            &["grep_nul", "xargs_nul", "search_bound"],
        )
    };
    let command_reserve = runner
        .fixed_command_length(&request.host, script, &args)
        .map_err(&attach_candidates)?;
    if command_reserve >= limits.max_frame_bytes {
        return Err(attach_candidates(BridgeError::new(
            ErrorCode::RequestTooLarge,
            "fixed request exceeds the configured frame limit",
            false,
        )));
    }
    let mut stdin = Vec::new();
    for candidate in &candidates {
        // Keep absolute candidates on the wire.  The fixed-operation runner
        // pins them against `/` before changing cwd, so an explicit legacy
        // profile cannot accidentally reinterpret `/tmp/x` as
        // `<configured-root>/tmp/x` on the second search request.
        let candidate = candidate.clone();
        if stdin
            .len()
            .checked_add(candidate.len() + 1)
            .is_none_or(|next| next + command_reserve > limits.max_frame_bytes)
        {
            truncated = true;
            break;
        }
        stdin.extend_from_slice(&candidate);
        stdin.push(0);
    }
    if stdin.is_empty() {
        return Ok(SearchResult {
            context: context(
                request.host,
                candidates_result.capability.physical_root.clone(),
                &candidates_result.shell,
                candidates_result.helper_mode,
            ),
            engine,
            matches: Vec::new(),
            truncated,
        });
    }
    drop(owner);
    let owner = InternalSpoolOwner::new();
    let result = bridge
        .execute_readonly_fixed(
            FixedRunRequest {
                kind: FixedOperationKind::ReadOnly,
                host: request.host.clone(),
                script,
                args,
                stdin: Some(stdin),
                rooted_paths: RootedPathInputs {
                    argument_indices: &[],
                    // Candidate paths are already normalized relative to the
                    // session root by the first fixed operation.  They must
                    // not be pinned a second time.
                    stdin_nul_paths: false,
                },
                required_capabilities: required,
                stdout_limit: (limits.max_frame_bytes + 1) as u64,
                stderr_limit: 1024,
                timeout: search_timeout,
                cleanup: owner.registration(),
            },
            cancel,
        )
        .await
        .map_err(&attach_candidates)?;
    let attach_engine = |error| attach_fixed_result_context(error, &request.host, &result);
    let stderr = read_small_stream(&result.output, StreamKind::Stderr, 1024)
        .await
        .map_err(&attach_engine)?;
    let content_capped = stderr == b"CAPPED\0";
    if !stderr.is_empty() && !content_capped {
        return Err(attach_engine(protocol_error(
            "search engine control record is invalid",
        )));
    }
    let mut cursor = SpoolCursor::new(
        &result.output,
        StreamKind::Stdout,
        limits.max_frame_bytes + 1,
    )
    .map_err(&attach_engine)?;
    let (mut matches, result_lookahead) = if rg {
        parse_rg(
            &mut cursor,
            operation_root.as_bytes(),
            display_root,
            content_capped,
            request.max_results.saturating_add(1),
            limits.max_frame_bytes,
        )
        .await
        .map_err(&attach_engine)?
    } else {
        parse_grep(
            &mut cursor,
            operation_root.as_bytes(),
            display_root,
            request.query.as_bytes(),
            content_capped,
            request.max_results.saturating_add(1),
            limits.max_frame_bytes,
        )
        .await
        .map_err(&attach_engine)?
    };
    matches.sort_by(|left, right| {
        decoded_path(&left.relative_path)
            .cmp(&decoded_path(&right.relative_path))
            .then(left.line.cmp(&right.line))
            .then(left.column.cmp(&right.column))
    });
    if content_capped || result_lookahead || matches.len() > request.max_results {
        truncated = true;
        matches.truncate(request.max_results);
    }
    Ok(SearchResult {
        context: context(
            request.host,
            result.capability.physical_root.clone(),
            &result.shell,
            result.helper_mode,
        ),
        engine,
        matches,
        truncated,
    })
}

async fn parse_rg(
    cursor: &mut SpoolCursor<'_>,
    operation_root: &[u8],
    display_root: &[u8],
    capped: bool,
    retain: usize,
    record_limit: usize,
) -> BridgeResult<(Vec<SearchMatch>, bool)> {
    let mut matches = Vec::with_capacity(retain.min(1024));
    let mut lookahead = false;
    let mut match_records = 0usize;
    loop {
        let line = if capped {
            cursor.next_line_capped(record_limit).await?
        } else {
            cursor.next_line(record_limit).await?
        };
        let Some(line) = line else { break };
        let value: serde_json::Value = serde_json::from_slice(&line)
            .map_err(|_| protocol_error("rg JSON event is invalid"))?;
        let event = value
            .get("type")
            .and_then(|value| value.as_str())
            .ok_or_else(|| protocol_error("rg JSON event has no type"))?;
        match event {
            "begin" | "end" | "summary" => continue,
            "match" => {}
            _ => return Err(protocol_error("rg JSON event type is unknown")),
        }
        match_records += 1;
        let data = value
            .get("data")
            .ok_or_else(|| protocol_error("rg match has no data"))?;
        let pinned_path = json_bytes(
            data.get("path")
                .ok_or_else(|| protocol_error("rg match has no path"))?,
        )?;
        let actual = logical_from_pinned(operation_root, &pinned_path)?;
        let relative = relative(display_root, &actual)?;
        let mut content = json_bytes(
            data.get("lines")
                .ok_or_else(|| protocol_error("rg match has no lines"))?,
        )?;
        if content.last() == Some(&b'\n') {
            content.pop();
        }
        let line_number = data
            .get("line_number")
            .and_then(|value| value.as_u64())
            .ok_or_else(|| protocol_error("rg match line is invalid"))?;
        let column = data
            .get("submatches")
            .and_then(|value| value.as_array())
            .and_then(|values| values.first())
            .and_then(|value| value.get("start"))
            .and_then(|value| value.as_u64())
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| protocol_error("rg match column is invalid"))?;
        if matches.len() < retain {
            matches.push(SearchMatch {
                actual_path: encode_bytes(&actual),
                relative_path: encode_bytes(relative),
                line: line_number,
                column,
                content: encode_bytes(&content),
            });
        } else {
            lookahead = true;
        }
    }
    if capped && cursor.discarded_incomplete() && match_records == 0 {
        return Err(protocol_error("search event is oversized"));
    }
    Ok((matches, lookahead))
}

fn json_bytes(value: &serde_json::Value) -> BridgeResult<Vec<u8>> {
    if let Some(text) = value.get("text").and_then(|value| value.as_str()) {
        return Ok(text.as_bytes().to_vec());
    }
    if let Some(bytes) = value.get("bytes").and_then(|value| value.as_str()) {
        return base64::engine::general_purpose::STANDARD
            .decode(bytes)
            .map_err(|_| protocol_error("rg byte field is invalid"));
    }
    Err(protocol_error("rg text/bytes field is missing"))
}

async fn parse_grep(
    cursor: &mut SpoolCursor<'_>,
    operation_root: &[u8],
    display_root: &[u8],
    query: &[u8],
    capped: bool,
    retain: usize,
    record_limit: usize,
) -> BridgeResult<(Vec<SearchMatch>, bool)> {
    let mut matches = Vec::with_capacity(retain.min(1024));
    let mut lookahead = false;
    let mut completed_records = 0usize;
    loop {
        let actual = if capped {
            cursor.next_field_capped(record_limit).await?
        } else {
            cursor.next_field(record_limit).await?
        };
        let Some(pinned_path) = actual else { break };
        let actual = logical_from_pinned(operation_root, &pinned_path)?;
        let record = if capped {
            cursor.next_line_capped(record_limit).await?
        } else {
            cursor.next_line(record_limit).await?
        };
        let Some(record) = record else {
            if capped {
                break;
            }
            return Err(protocol_error("grep line is incomplete"));
        };
        let colon = record
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| protocol_error("grep line number is missing"))?;
        let line = std::str::from_utf8(&record[..colon])
            .ok()
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| protocol_error("grep line number is invalid"))?;
        let content = &record[colon + 1..];
        let column = find_bytes(content, query)
            .and_then(|value| u64::try_from(value + 1).ok())
            .ok_or_else(|| protocol_error("grep result does not contain the query"))?;
        completed_records += 1;
        if matches.len() < retain {
            matches.push(SearchMatch {
                actual_path: encode_bytes(&actual),
                relative_path: encode_bytes(relative(display_root, &actual)?),
                line,
                column,
                content: encode_bytes(content),
            });
        } else {
            lookahead = true;
        }
    }
    if capped && cursor.discarded_incomplete() && completed_records == 0 {
        return Err(protocol_error("search event is oversized"));
    }
    Ok((matches, lookahead))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn decoded_path(value: &super::EncodedValue) -> Vec<u8> {
    match value.encoding {
        super::ValueEncoding::Utf8 => value.value.as_bytes().to_vec(),
        super::ValueEncoding::Base64 => base64::engine::general_purpose::STANDARD
            .decode(&value.value)
            .unwrap_or_default(),
    }
}

fn relative<'a>(root: &[u8], actual: &'a [u8]) -> BridgeResult<&'a [u8]> {
    let relative = actual.strip_prefix(root).and_then(|rest| {
        if root.ends_with(b"/") {
            Some(rest)
        } else {
            rest.strip_prefix(b"/")
        }
    });
    relative.ok_or_else(|| protocol_error("search path escaped the configured root"))
}

fn logical_from_pinned(root: &[u8], pinned: &[u8]) -> BridgeResult<Vec<u8>> {
    if pinned == b"." {
        return Ok(root.to_vec());
    }
    let relative = pinned_relative(pinned)?;
    let needs_separator = !root.ends_with(b"/");
    let mut actual = Vec::with_capacity(root.len() + usize::from(needs_separator) + relative.len());
    actual.extend_from_slice(root);
    if needs_separator {
        actual.push(b'/');
    }
    actual.extend_from_slice(relative);
    Ok(actual)
}

fn pinned_relative(pinned: &[u8]) -> BridgeResult<&[u8]> {
    let relative = pinned
        .strip_prefix(b"./")
        .filter(|relative| !relative.is_empty())
        .ok_or_else(|| protocol_error("search path is not relative to the pinned root"))?;
    if relative
        .split(|byte| *byte == b'/')
        .any(|component| component.is_empty() || matches!(component, b"." | b".."))
    {
        return Err(protocol_error(
            "search path is not normalized beneath the pinned root",
        ));
    }
    Ok(relative)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{CANDIDATE_SCRIPT, GREP_SCRIPT, RG_SCRIPT};

    #[test]
    fn bounded_search_scripts_stop_producers_at_the_output_cap() {
        for script in [CANDIDATE_SCRIPT, RG_SCRIPT, GREP_SCRIPT] {
            assert!(
                script.matches("cat <&3 >/dev/null").count() <= 1,
                "bounded search script still drains the producer"
            );
            assert!(
                script.contains("kill \"$producer\""),
                "bounded search script does not terminate its producer"
            );
        }
    }

    #[test]
    fn candidate_script_returns_without_draining_an_endless_find() {
        let controls = tempfile::TempDir::new().unwrap();
        let root = controls.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let shim = controls.path().join("find");
        std::fs::write(
            &shim,
            "#!/bin/sh\ncase \"$2\" in *codex-sentinel-search-find) printf '%s/.hidden\\000' \"$2\" ;; *) exec yes \"$2/file\" ;; esac\n",
        )
        .unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o700)).unwrap();

        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(CANDIDATE_SCRIPT)
            .arg("codex-ssh-bridge-search")
            .arg(&root)
            .arg("64")
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", controls.path().display()),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let output = loop {
            if child.try_wait().unwrap().is_some() {
                break child.wait_with_output().unwrap();
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("candidate search did not stop at its byte cap");
            }
            thread::sleep(Duration::from_millis(10));
        };
        assert!(output.status.success());
        assert_eq!(output.stdout.len(), 64);
        assert!(
            output
                .stderr
                .windows(b"CAPPED\0".len())
                .any(|window| window == b"CAPPED\0")
        );
    }
}
