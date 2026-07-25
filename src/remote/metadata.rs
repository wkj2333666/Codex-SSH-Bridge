use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::error::{BridgeError, BridgeResult};
use crate::output::{InternalSpoolOwner, StreamKind};
use crate::ssh::{FixedOperationKind, FixedRunRequest, RootedPathInputs};

use super::protocol::{
    SpoolCursor, context, encode_bytes, entry_error, kind, parse_mode, parse_mtime, parse_u64,
    protocol_error, read_small_stream, utf8,
};
use super::{
    ListEntry, ListResult, RemoteBridge, RemoteFileKind, RemoteMetadata, ResolvedList,
    ResolvedStat, StatEntry, StatResult, attach_fixed_result_context,
};

const LIST_SCRIPT: &str = r#"
R=$1;D=$2;H=$3;M=$4;L=$5
lf(){
 if [ "$3" = 1 ];then find -H "$1" -mindepth 1 -maxdepth "$2" -printf '%P\000%y\000%s\000%m\000%T@\000'
 else find -H "$1" -mindepth 1 -maxdepth "$2" \( -path './.*' -o -path '*/.*' \) -prune -o -printf '%P\000%y\000%s\000%m\000%T@\000';fi
}
lx(){ xargs -0 -r -n 100 "$@"; }
cs() (
 d=$(mktemp -d /tmp/codex-sentinel-bound.XXXXXX 2>/dev/null)||exit 90
 trap 'rm -rf -- "$d"' 0 1 2 15
 f=$d/codex-sentinel-bound;o=$d/o
 m=$(stat -c %a "$d" 2>/dev/null)||exit 90
 [ "$m" = 700 ]||exit 11;mkfifo "$f"||exit 90;[ -p "$f" ]||exit 11
 (printf abcdef>"$f")&p=$!;exec 3<"$f"
 CODEX_SSH_SENTINEL=bound head -c 3 <&3 >"$o" 2>/dev/null;h=$?
 cat <&3 >/dev/null;r=$?;exec 3<&-;wait "$p" 2>/dev/null;w=$?
 [ "$r:$w" = 0:0 ]||exit 90;v=$(cat "$o")||exit 90;[ "$h:$v" = 0:abc ]||exit 11
 b=$d/codex-sentinel-list-production;z=$d/z;ft=$b/ft;fr=$b/fr;lr=$b/lr;hr=$b/hr
 mkdir -p "$ft" "$lr" "$hr" "$z"&&ln -s "$ft" "$fr"&&printf x>"$ft/f"&&ln -s "$z" "$lr/l"||exit 90
 if [ "$H" = 1 ];then n=.h;else n=v;printf x>"$hr/.x"||exit 90;fi
 printf x>"$hr/$n"&&chmod 640 "$ft/f"&&chmod 600 "$hr/$n"&&touch -d @7.25 "$ft/f"&&touch -h -d @8.5 "$lr/l"&&touch -d @9.25 "$hr/$n"||exit 90
 lf "$fr" "$D" "$H">"$o" 2>/dev/null&&lf "$lr" "$D" "$H">>"$o" 2>/dev/null&&lf "$hr" "$D" "$H">>"$o" 2>/dev/null||exit 90
 { printf 'f\000f\0001\000640\0007.2500000000\000';printf 'l\000l\000%s\000777\0008.5000000000\000' "${#z}";printf '%s\000f\0001\000600\0009.2500000000\000' "$n"; }>"$d/e"||exit 90
 cmp -s "$d/e" "$o"||exit 12
 x=$(printf 'a\nb\000'|lx sh -c 'printf %s "$1"' codex-sentinel-list-xargs 2>/dev/null);s=$?
 printf x\000|lx sh -c 'exit 7' codex-sentinel-list-xargs >/dev/null 2>&1;q=$?
 [ "$s" -eq 0 ]&&[ "$q" -ne 0 ]&&[ "$x" = 'a
b' ]||exit 13
)
cs;s=$?
case $s in 0);;11)printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=search_bound\000' >&2;exit 0;;12)printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=find_nul\000' >&2;exit 0;;13)printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=xargs_nul\000' >&2;exit 0;;*)exit 2;;esac
if [ ! -e "$R" ]&&[ ! -L "$R" ];then printf 'NOT_FOUND\000' >&2;exit 0;fi
if [ ! -d "$R" ];then printf 'NOT_DIRECTORY\000' >&2;exit 0;fi
if [ ! -r "$R" ];then printf 'PERMISSION_DENIED\000' >&2;exit 0;fi
cd -P -- "$R" 2>/dev/null||{ printf 'PERMISSION_DENIED\000' >&2;exit 0;}
umask 077
t=$(mktemp -d /tmp/codex-ssh-list.XXXXXX)||exit 2
cleanup(){ rm -rf -- "$t"; }
trap cleanup 0 1 2 15
a=$t/a;b=$t/b;c=$t/c;d=$t/d;e=$t/e;f=$t/f
printf 0 >"$f"
mkfifo "$a" "$b"||exit 2
(
lf . "$D" "$H" 2>/dev/null >"$a"
printf %s "$?">"$d"
) &
p=$!
(
lx sh -c '
c=$1;m=$2;shift 2
n=$(cat "$c")||exit 65
while [ "$#" -ge 5 ];do
if [ "$n" -lt $((m+1)) ];then n=$((n+1));printf "%s\000%s\000%s\000%s\000%s\000" "$1" "$2" "$3" "$4" "$5";fi
shift 5
done
[ "$#" -eq 0 ]||exit 65
printf %s "$n">"$c"
' codex-ssh-list "$f" "$M" <"$a" >"$b" 2>/dev/null
printf %s "$?">"$e"
) &
q=$!
exec 3<"$b"
head -c "$L" <&3 >"$c";h=$?
cat <&3 >/dev/null
r=$?;exec 3<&-
wait "$q" 2>/dev/null;s=$?
wait "$p" 2>/dev/null;u=$?
n=$(wc -c <"$c")
x=$(cat "$e" 2>/dev/null||printf 2)
y=$(cat "$d" 2>/dev/null||printf 2)
[ "$h:$r:$s:$u:$x:$y" = 0:0:0:0:0:0 ]||exit 2
cat "$c"
if [ "$n" -eq "$L" ];then printf 'CAPPED\000' >&2;fi
"#;

const STAT_SCRIPT: &str = r#"
codex_check_stat() (
    codex_stat_dir=$(mktemp -d /tmp/codex-sentinel-stat.XXXXXX 2>/dev/null) || exit 2
    cleanup_codex_stat() { rm -rf -- "$codex_stat_dir"; }
    trap cleanup_codex_stat EXIT HUP INT TERM
    codex_stat_file=$codex_stat_dir/file
    printf x >"$codex_stat_file" || exit 2
    chmod 640 "$codex_stat_file" || exit 2
    touch -d '@-1.123456789' -- "$codex_stat_file" || exit 2
    codex_stat_mode=$(stat --printf='%f' -- "$codex_stat_file" 2>/dev/null) || exit 1
    codex_stat_size=$(stat --printf='%s' -- "$codex_stat_file" 2>/dev/null) || exit 1
    codex_stat_seconds=$(stat --printf='%Y' -- "$codex_stat_file" 2>/dev/null) || exit 1
    codex_stat_human=$(stat --printf='%y' -- "$codex_stat_file" 2>/dev/null) || exit 1
    codex_stat_fraction=$(printf '%s' "$codex_stat_human" | cut -d. -f2 | cut -d' ' -f1)
    [ "$codex_stat_mode:$codex_stat_size:$codex_stat_seconds:$codex_stat_fraction" = \
      '81a0:1:-2:876543211' ]
)
codex_stat_status=0
codex_check_stat || codex_stat_status=$?
if [ "$codex_stat_status" -eq 1 ]; then
    printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=stat_printf\000' >&2
    exit 0
fi
if [ "$codex_stat_status" -ne 0 ]; then exit 2; fi
codex_xargs_newline='line
name'
codex_xargs_out=$(printf 'line\nname\000' |
    xargs -0 -r sh -c 'printf %s "$1"' codex-sentinel-stat-xargs 2>/dev/null)
codex_xargs_ok=$?
printf 'x\000' |
    xargs -0 -r sh -c 'exit 7' codex-sentinel-stat-xargs >/dev/null 2>&1
codex_xargs_failure=$?
if [ "$codex_xargs_ok" -ne 0 ] || [ "$codex_xargs_failure" -eq 0 ] ||
   [ "$codex_xargs_out" != "$codex_xargs_newline" ]; then
    printf 'CODE=CAPABILITY_MISMATCH\000CAPABILITY=xargs_nul\000' >&2
    exit 0
fi
exec xargs -0 -r sh -c '
for path do
    printf "%s\000" "$path"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then printf "NOT_FOUND\000"; continue; fi
    mode=$(stat --printf="%f" -- "$path" 2>/dev/null) || { printf "PERMISSION_DENIED\000"; continue; }
    size=$(stat --printf="%s" -- "$path" 2>/dev/null) || { printf "PERMISSION_DENIED\000"; continue; }
    seconds=$(stat --printf="%Y" -- "$path" 2>/dev/null) || { printf "PERMISSION_DENIED\000"; continue; }
    human=$(stat --printf="%y" -- "$path" 2>/dev/null) || { printf "PERMISSION_DENIED\000"; continue; }
    fraction=$(printf "%s" "$human" | cut -d. -f2 | cut -d" " -f1)
    printf "OK\000%s\000%s\000%s.%s\000" "$mode" "$size" "$seconds" "$fraction"
done
' codex-ssh-bridge-stat
"#;

pub(super) async fn list(
    bridge: &RemoteBridge,
    request: ResolvedList,
    cancel: CancellationToken,
) -> BridgeResult<ListResult> {
    let runner = &bridge.runner;
    let limits = runner.config().host(&request.host)?.limits;
    let owner = InternalSpoolOwner::new();
    let result = bridge
        .execute_readonly_fixed(
            FixedRunRequest {
                kind: FixedOperationKind::ReadOnly,
                host: request.host.clone(),
                script: LIST_SCRIPT,
                args: vec![
                    request.path.as_str().to_owned(),
                    request.depth.to_string(),
                    if request.include_hidden { "1" } else { "0" }.to_owned(),
                    request.max_entries.to_string(),
                    (limits.max_frame_bytes + 1).to_string(),
                ],
                stdin: None,
                rooted_paths: RootedPathInputs {
                    argument_indices: &[0],
                    stdin_nul_paths: false,
                },
                required_capabilities: &["find_nul", "xargs_nul", "search_bound"],
                stdout_limit: (limits.max_frame_bytes + 1) as u64,
                stderr_limit: 1024,
                timeout: Duration::from_millis(limits.command_timeout_ms),
                cleanup: owner.registration(),
            },
            cancel,
        )
        .await?;
    let attach = |error| attach_fixed_result_context(error, &request.host, &result);
    let stderr = read_small_stream(&result.output, StreamKind::Stderr, 1024)
        .await
        .map_err(&attach)?;
    let capped = stderr == b"CAPPED\0";
    if !stderr.is_empty() && !capped {
        let error = match stderr.as_slice() {
            b"NOT_FOUND\0" => BridgeError::not_found(),
            b"PERMISSION_DENIED\0" => BridgeError::permission_denied(),
            b"NOT_DIRECTORY\0" => BridgeError::not_directory(),
            _ => protocol_error("list control record is invalid"),
        };
        return Err(attach(error));
    }
    let root = request.path.as_str().as_bytes();
    let mut cursor = SpoolCursor::new(
        &result.output,
        StreamKind::Stdout,
        limits.max_frame_bytes + 1,
    )
    .map_err(&attach)?;
    let mut entries = Vec::with_capacity(request.max_entries.saturating_add(1));
    let mut qualifying = 0usize;
    let mut completed_records = 0usize;
    'records: loop {
        let first = if capped {
            cursor
                .next_field_capped(limits.max_frame_bytes)
                .await
                .map_err(&attach)?
        } else {
            cursor
                .next_field(limits.max_frame_bytes)
                .await
                .map_err(&attach)?
        };
        let Some(actual) = first else { break };
        let mut record = Vec::with_capacity(5);
        record.push(actual);
        for _ in 1..5 {
            let field = if capped {
                cursor
                    .next_field_capped(limits.max_frame_bytes)
                    .await
                    .map_err(&attach)?
            } else {
                cursor
                    .next_field(limits.max_frame_bytes)
                    .await
                    .map_err(&attach)?
            };
            let Some(field) = field else {
                if capped {
                    break 'records;
                }
                return Err(attach(protocol_error("list field count is invalid")));
            };
            record.push(field);
        }
        let discovered = record[0].as_slice();
        if discovered.is_empty() || discovered.starts_with(b"/") {
            return Err(attach(protocol_error("list relative path is invalid")));
        }
        let actual = join_raw(root, discovered);
        let relative = join_raw(request.path.relative().as_bytes(), discovered);
        completed_records += 1;
        if !request.include_hidden
            && relative
                .split(|byte| *byte == b'/')
                .any(|part| part.first() == Some(&b'.'))
        {
            return Err(attach(protocol_error(
                "list returned a hidden path after pruning",
            )));
        }
        qualifying = qualifying
            .checked_add(1)
            .ok_or_else(|| protocol_error("list entry count overflowed"))
            .map_err(&attach)?;
        let (mtime_seconds, mtime_nanoseconds) = parse_mtime(&record[4]).map_err(&attach)?;
        if entries.len() < request.max_entries.saturating_add(1) {
            entries.push(ListEntry {
                actual_path: encode_bytes(&actual),
                relative_path: encode_bytes(&relative),
                metadata: RemoteMetadata {
                    kind: kind(&record[1]).map_err(&attach)?,
                    size: parse_u64(&record[2]).map_err(&attach)?,
                    mode: parse_mode(&record[3]).map_err(&attach)?,
                    mtime_seconds,
                    mtime_nanoseconds,
                },
            });
        }
    }
    if capped && cursor.discarded_incomplete() && completed_records == 0 {
        return Err(attach(protocol_error("list record is oversized")));
    }
    entries.sort_by(|left, right| {
        decoded_sort_key(&left.relative_path).cmp(&decoded_sort_key(&right.relative_path))
    });
    let truncated = capped || qualifying > request.max_entries;
    entries.truncate(request.max_entries);
    Ok(ListResult {
        context: context(
            request.host,
            result.capability.physical_root.clone(),
            &result.shell,
            result.helper_mode,
        ),
        actual_path: encode_bytes(root),
        relative_path: encode_bytes(request.path.relative().as_bytes()),
        entries,
        truncated,
    })
}

pub(super) async fn stat(
    bridge: &RemoteBridge,
    request: ResolvedStat,
    cancel: CancellationToken,
) -> BridgeResult<StatResult> {
    let runner = &bridge.runner;
    let limits = runner.config().host(&request.host)?.limits;
    let mut stdin = Vec::new();
    for path in &request.paths {
        stdin.extend_from_slice(path.as_str().as_bytes());
        stdin.push(0);
    }
    let owner = InternalSpoolOwner::new();
    let result = bridge
        .execute_readonly_fixed(
            FixedRunRequest {
                kind: FixedOperationKind::ReadOnly,
                host: request.host.clone(),
                script: STAT_SCRIPT,
                args: Vec::new(),
                stdin: Some(stdin),
                rooted_paths: RootedPathInputs {
                    argument_indices: &[],
                    stdin_nul_paths: true,
                },
                required_capabilities: &["stat_printf", "xargs_nul"],
                stdout_limit: limits.max_frame_bytes as u64,
                stderr_limit: 1024,
                timeout: Duration::from_millis(limits.command_timeout_ms),
                cleanup: owner.registration(),
            },
            cancel,
        )
        .await?;
    let attach = |error| attach_fixed_result_context(error, &request.host, &result);
    let stderr = read_small_stream(&result.output, StreamKind::Stderr, 1024)
        .await
        .map_err(&attach)?;
    if !stderr.is_empty() {
        return Err(attach(protocol_error("stat control record is invalid")));
    }
    let mut cursor = SpoolCursor::new(&result.output, StreamKind::Stdout, limits.max_frame_bytes)
        .map_err(&attach)?;
    let mut entries = Vec::with_capacity(request.paths.len());
    for requested in &request.paths {
        let actual = cursor
            .next_field(limits.max_frame_bytes)
            .await
            .map_err(&attach)?
            .ok_or_else(|| protocol_error("stat response is incomplete"))
            .map_err(&attach)?;
        let status = cursor
            .next_field(64)
            .await
            .map_err(&attach)?
            .ok_or_else(|| protocol_error("stat response is incomplete"))
            .map_err(&attach)?;
        let observed_actual = pinned_path(requested.relative().as_bytes());
        if actual != observed_actual {
            return Err(attach(protocol_error("stat response order is invalid")));
        }
        let actual_path = encode_bytes(requested.as_str().as_bytes());
        let relative_path = encode_bytes(requested.relative().as_bytes());
        if status == b"OK" {
            let mode = cursor
                .next_field(64)
                .await
                .map_err(&attach)?
                .ok_or_else(|| protocol_error("stat response is incomplete"))
                .map_err(&attach)?;
            let size = cursor
                .next_field(64)
                .await
                .map_err(&attach)?
                .ok_or_else(|| protocol_error("stat response is incomplete"))
                .map_err(&attach)?;
            let mtime = cursor
                .next_field(128)
                .await
                .map_err(&attach)?
                .ok_or_else(|| protocol_error("stat response is incomplete"))
                .map_err(&attach)?;
            let raw_mode = u32::from_str_radix(utf8(&mode).map_err(&attach)?, 16)
                .map_err(|_| protocol_error("stat mode is invalid"))
                .map_err(&attach)?;
            let (mtime_seconds, mtime_nanoseconds) = parse_mtime(&mtime).map_err(&attach)?;
            entries.push(StatEntry::Success {
                actual_path,
                relative_path,
                metadata: RemoteMetadata {
                    kind: kind_from_mode(raw_mode),
                    size: parse_u64(&size).map_err(&attach)?,
                    mode: raw_mode & 0o7777,
                    mtime_seconds,
                    mtime_nanoseconds,
                },
            });
        } else {
            entries.push(StatEntry::Error {
                actual_path,
                relative_path,
                error: entry_error(&status).map_err(&attach)?,
            });
        }
    }
    if cursor
        .next_field(limits.max_frame_bytes)
        .await
        .map_err(&attach)?
        .is_some()
    {
        return Err(attach(protocol_error("stat response has trailing fields")));
    }
    Ok(StatResult {
        context: context(
            request.host,
            result.capability.physical_root.clone(),
            &result.shell,
            result.helper_mode,
        ),
        entries,
    })
}

fn join_raw(base: &[u8], relative: &[u8]) -> Vec<u8> {
    if relative.is_empty() {
        return base.to_vec();
    }
    let needs_separator = !base.is_empty() && !base.ends_with(b"/");
    let mut joined = Vec::with_capacity(base.len() + usize::from(needs_separator) + relative.len());
    joined.extend_from_slice(base);
    if needs_separator {
        joined.push(b'/');
    }
    joined.extend_from_slice(relative);
    joined
}

fn pinned_path(relative: &[u8]) -> Vec<u8> {
    if relative.is_empty() {
        return b".".to_vec();
    }
    let mut pinned = Vec::with_capacity(relative.len() + 2);
    pinned.extend_from_slice(b"./");
    pinned.extend_from_slice(relative);
    pinned
}

fn decoded_sort_key(value: &super::EncodedValue) -> Vec<u8> {
    match value.encoding {
        super::ValueEncoding::Utf8 => value.value.as_bytes().to_vec(),
        super::ValueEncoding::Base64 => {
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &value.value)
                .unwrap_or_default()
        }
    }
}

fn kind_from_mode(mode: u32) -> RemoteFileKind {
    match mode & libc::S_IFMT {
        libc::S_IFREG => RemoteFileKind::File,
        libc::S_IFDIR => RemoteFileKind::Directory,
        libc::S_IFLNK => RemoteFileKind::Symlink,
        libc::S_IFBLK => RemoteFileKind::BlockDevice,
        libc::S_IFCHR => RemoteFileKind::CharacterDevice,
        libc::S_IFIFO => RemoteFileKind::Fifo,
        libc::S_IFSOCK => RemoteFileKind::Socket,
        _ => RemoteFileKind::Other,
    }
}
