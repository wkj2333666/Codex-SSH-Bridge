# Transparent MCP Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make timeout, search, discovery, output retention, and diagnostics behave predictably through both raw MCP and the Codex tool adapter.

**Architecture:** The helper/dispatcher EXIT protocol reports timeout as an explicit fact, while the local Rust deadline remains authoritative. Search globs are compiled against paths relative to the requested search directory. MCP renderers retain presentation bytes rather than serializing internal result structs, and essential alias discovery is duplicated only in a small structured field for adapter compatibility.

**Tech Stack:** Rust 1.91.1, Tokio, POSIX sh dispatcher fallback, Rust remote helper, serde_json, existing output spool, GitHub Actions.

## Global Constraints

- This plan starts only after the transparent-host-runtime plan has a green GitHub CI checkpoint.
- Target release is `0.4.0`.
- Do not run Cargo build, test, Clippy, benchmark, or release commands locally.
- Local verification is limited to `cargo fmt`, `sh -n`, source inspection, and Git operations.
- No Python implementation or dependency.
- Default `remote_run` shell remains Bash; explicit `sh` and `login` remain.
- Exit status 124 is ordinary unless an explicit timeout fact is present.
- Errors contain facts only; never add `action` or `suggested_action`.
- Model-visible inline output remains capped at 32 KiB.
- Large business payload appears once; `remote_hosts` aliases are the sole intentional small duplication.
- Preserve output quotas, frame bounds, mutation uncertainty, and binary-safe paging.

---

## File map

- `src/ssh/session.rs`: five-field EXIT parsing, timeout result propagation, request deadline cancellation.
- `src/ssh/dispatcher.sh`: fallback timeout watchdog fact and five-line EXIT payload.
- `src/remote_helper.rs`: helper watchdog distinguishes timeout from client cancellation.
- `src/ssh/frame.rs`: unchanged framing; tests verify payload compatibility.
- `src/ssh/process.rs`: maps `SessionResult.timed_out` to `COMMAND_TIMEOUT`.
- `src/remote/search.rs`: requested-path-relative glob matching and bounded producer cancellation.
- `src/mcp/render.rs`: adapter-safe hosts result and byte retention.
- `src/remote/mod.rs`: presentation-byte retention API.
- `src/output.rs`: retain bounded bytes without serde serialization.
- `src/profile.rs`: compile-time request phase records.
- `tests/{dispatcher,remote_helper,session,ssh_transport,remote_ops,mcp_tools,mcp_protocol,performance_acceptance}.rs`: deterministic contract tests.

### Interfaces fixed by this plan

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionResult {
    pub(crate) request_id: u64,
    pub(crate) status: i32,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) stdout_truncated: bool,
    pub(crate) stderr_truncated: bool,
    pub(crate) elapsed_ms: u64,
    pub(crate) remote_process_may_continue: bool,
    pub(crate) timed_out: bool,
}

// Private to src/ssh/session.rs. Its parser cases live in that file's
// #[cfg(test)] module; integration tests exercise it through SessionResult.
fn parse_exit(payload: &[u8]) -> Result<ExitRecord, String>;

struct ExitRecord {
    status: i32,
    stdout_truncated: bool,
    stderr_truncated: bool,
    remote_process_may_continue: bool,
    timed_out: bool,
}

impl OutputStore {
    pub(crate) async fn retain_bytes(
        &self,
        provenance: StoredProvenance,
        bytes: Vec<u8>,
        cancel: CancellationToken,
    ) -> BridgeResult<OutputReference>;
}

impl RemoteBridge {
    pub async fn retain_presentation(
        &self,
        provenance: RetentionProvenance,
        bytes: Vec<u8>,
        cancel: CancellationToken,
    ) -> BridgeResult<OutputReference>;
}
```

## Task 1: Establish explicit timeout protocol failures

**Files:**
- Modify: `tests/dispatcher.rs`
- Modify: `tests/remote_helper.rs`
- Modify: `tests/session.rs`
- Modify: `tests/ssh_transport.rs`
- Modify: `tests/remote_ops.rs`
- Modify: `src/ssh/session.rs` (`#[cfg(test)]` parser cases only)

**Interfaces:**
- Consumes: current four-field EXIT payload.
- Produces: failing tests for five-field `ExitRecord` and exact exit-124 versus timeout behavior.

- [ ] **Step 1: Add parser tests for explicit timeout**

Add these exact cases inside `src/ssh/session.rs`'s private `#[cfg(test)]`
module so the production parser does not become public solely for testing:

```rust
#[test]
fn exit_payload_requires_explicit_timeout_bit() {
    assert_eq!(
        parse_exit(b"124\n0\n0\n0\n0\n").unwrap(),
        ExitRecord {
            status: 124,
            stdout_truncated: false,
            stderr_truncated: false,
            remote_process_may_continue: false,
            timed_out: false,
        }
    );
    assert!(parse_exit(b"124\n0\n0\n0\n").is_err());
    assert!(parse_exit(b"124\n0\n0\n0\n2\n").is_err());
    assert!(parse_exit(b"124\n0\n0\n0\n1\nextra\n").is_err());
}
```

- [ ] **Step 2: Add helper and dispatcher behavioral tests**

For both backends:

```rust
run("exit 124", timeout_ms = 2_000)
    => ExitRecord { status: 124, timed_out: false, .. };

run("sleep 5", timeout_ms = 100)
    => ExitRecord { timed_out: true, .. };
```

Measure only a generous upper bound that includes kill/drain framing:
completion under two seconds. Do not require fallback sh to provide a
sub-millisecond remote watchdog.

- [ ] **Step 3: Add remote API timeout mapping and recovery tests**

Assert an explicit status 124 produces `isError=false` and
`structuredContent.exit_code=124`. Assert explicit `timed_out=true` produces
`COMMAND_TIMEOUT`, contains `remote_process_may_continue` only when true, and
the immediately following no-op succeeds on the same or freshly recovered
session.

- [ ] **Step 4: Commit, push, and capture the intended CI failure**

```bash
cargo fmt --all
sh -n src/ssh/dispatcher.sh
git add src/ssh/session.rs tests/dispatcher.rs tests/remote_helper.rs tests/session.rs tests/ssh_transport.rs tests/remote_ops.rs
git commit -m "test: distinguish remote timeout from exit 124"
git push origin main
gh run watch "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: compile or assertions fail because the explicit timeout field does
not exist.

## Task 2: Implement explicit timeout facts end to end

**Files:**
- Modify: `src/ssh/session.rs`
- Modify: `src/ssh/dispatcher.sh`
- Modify: `src/remote_helper.rs`
- Modify: `src/ssh/process.rs`

**Interfaces:**
- Consumes: Task 1 tests.
- Produces: `ExitRecord`, `SessionResult.timed_out`, and factual
  `COMMAND_TIMEOUT`.

- [ ] **Step 1: Parse exactly five EXIT fields**

Replace tuple parsing with `ExitRecord`. `parse_bool` accepts only `0` and `1`
and receives a field name so malformed errors identify `stdout_truncated`,
`stderr_truncated`, `remote_process_may_continue`, or `timed_out`.

- [ ] **Step 2: Mark helper watchdog timeout separately**

Add `timed_out: AtomicBool` to `RequestControl`. Only the request's watchdog
sets it before calling `cancel()`:

```rust
if !*done {
    watchdog_control.timed_out.store(true, Ordering::Release);
    watchdog_control.cancel();
}
```

Client CANCEL sets only `cancelled`. Append the fifth payload line:

```rust
u8::from(control.timed_out.load(Ordering::Acquire))
```

- [ ] **Step 3: Mark shell dispatcher watchdog timeout separately**

Initialize `run_timed_out=0`. The timeout watchdog writes an atomic
request-private marker before terminating the process group. After `wait`, read
that marker and emit:

```sh
printf '%s\n%s\n%s\n%s\n%s\n' \
  "$run_status" "$run_stdout_truncated" "$run_stderr_truncated" \
  "$run_process_may_continue" "$run_timed_out" >"$run_exit_file"
```

The local Rust deadline still sends CANCEL at millisecond precision; the
remote watchdog is only a backstop.

- [ ] **Step 4: Map timeout before ordinary status handling**

In `SshRunner`, after session/capture cleanup:

```rust
if session_result.timed_out {
    let mut error =
        BridgeError::new(ErrorCode::CommandTimeout, "remote command timed out", false);
    error.details.remote_process_may_continue =
        session_result.remote_process_may_continue.then_some(true);
    return Err(error);
}
```

Do not infer from status 124.

- [ ] **Step 5: Format, syntax-check, commit, push, and require green**

```bash
cargo fmt --all
sh -n src/ssh/dispatcher.sh
git diff --check
git add src/ssh/session.rs src/ssh/dispatcher.sh src/remote_helper.rs src/ssh/process.rs
git commit -m "fix: report command timeouts explicitly"
git push origin main
gh run watch "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: Task 1 timeout tests pass and no existing cancellation or background
descendant test regresses.

## Task 3: Establish requested-path-relative search failures

**Files:**
- Modify: `tests/remote_ops.rs`
- Modify: `tests/mcp_tools.rs`
- Modify: `tests/fixtures/fake-ssh.sh`

**Interfaces:**
- Consumes: absolute remote path runtime.
- Produces: failing `*.txt` requested-directory semantics and cancellation tests.

- [ ] **Step 1: Add direct and nested glob cases**

Create:

```text
/srv/project/a.txt
/srv/project/sub/b.txt
/srv/project/sub/c.rs
```

Assert:

```rust
search("/srv/project", ["*.txt"]) == ["/srv/project/a.txt"];
search("/srv/project", ["**/*.txt"]) ==
    ["/srv/project/a.txt", "/srv/project/sub/b.txt"];
```

Keep absolute rendered result paths.

- [ ] **Step 2: Add bounded-producer cancellation**

Gate candidate production after at least one record, cancel the tool token,
and assert both candidate and content-search fake processes exit. Then run a
second search and assert it starts without waiting for stale producers.

- [ ] **Step 3: Add capability fallback parity**

Run the same glob cases with `rg_json=true` and `rg_json=false`; assert identical
paths and truncation. Preserve the rule that binary search requires rg JSON.

- [ ] **Step 4: Commit, push, and observe the intended failure**

```bash
cargo fmt --all
sh -n tests/fixtures/fake-ssh.sh
git add tests/remote_ops.rs tests/mcp_tools.rs tests/fixtures/fake-ssh.sh
git commit -m "test: define search-root glob semantics"
git push origin main
gh run watch "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: `*.txt` misses the direct requested-directory file under the old
configured-root-relative matching.

## Task 4: Implement search-root globs and producer teardown

**Files:**
- Modify: `src/remote/search.rs`
- Modify: `src/remote/mod.rs`

**Interfaces:**
- Consumes: Task 3 tests.
- Produces: requested-path-relative `GlobSet` matching and complete cancellation.

- [ ] **Step 1: Set the display/match root to the request path**

Delete configured-root branching. For each actual candidate:

```rust
let relative = relative(request.path.absolute().as_bytes(), &actual)?;
if request.globs.is_empty()
    || globs.is_match(Path::new(&OsString::from_vec(relative.to_vec())))
{
    candidates.push(pinned_path);
}
```

The renderer still uses `actual`, not `relative`.

- [ ] **Step 2: Couple all search stages to one cancellation token**

Candidate fixed command, cursor reader, rg/grep command, stream parser, and
retention use children of one operation token. On any error, bound, timeout, or
client cancellation, cancel the operation token before returning and await the
existing process/session cleanup path.

- [ ] **Step 3: Preserve bounds as truncation**

Candidate count, match count, per-record bytes, and output bytes keep existing
limits. A producer reaching a cap stops, drains/discards the incomplete record
as already defined, sets `truncated=true`, and does not remain active.

- [ ] **Step 4: Format, commit, push, and require green**

```bash
cargo fmt --all
git add src/remote/search.rs src/remote/mod.rs
git commit -m "fix: resolve search globs from requested paths"
git push origin main
gh run watch "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: both search engines pass direct/nested glob and cancellation tests.

## Task 5: Establish adapter-safe discovery and presentation-retention failures

**Files:**
- Modify: `tests/mcp_tools.rs`
- Modify: `tests/mcp_protocol.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- Consumes: compact 0.3.x renderer and output store.
- Produces: failing host structured data and exact retained-byte reconstruction tests.

- [ ] **Step 1: Change the hosts golden result**

For aliases `jnyxy`, `nkai`, and `weibo`, assert:

```rust
assert_eq!(text_content(&result), "jnyxy\nnkai\nweibo");
assert_eq!(
    result["structuredContent"],
    json!({"hosts":["jnyxy","nkai","weibo"]})
);
```

Assert no profile, root, description, shell, capability, count, or timing field.

- [ ] **Step 2: Add exact renderer-overflow reconstruction**

Create UTF-8 content beyond 32 KiB that includes quotes, backslashes, control
characters normalized by the renderer, and multibyte characters. Concatenate
the initial inline prefix with all `remote_output_read` pages and assert it
equals the full expected presentation byte-for-byte.

- [ ] **Step 3: Reject internal serialization leakage**

For read, list, search, stat, and run renderer overflow, page every result and
assert retained bytes do not contain internal keys:

```rust
for forbidden in [
    "\"context\"",
    "\"physical_root\"",
    "\"helper_mode\"",
    "\"raw_bytes\"",
    "\"aggregate_bytes\"",
    "\"detail\"",
] {
    assert!(!retained.contains(forbidden), "{forbidden}");
}
```

Keep separate coverage proving source-captured run stdout/stderr remains
pageable by its existing stream selector.

- [ ] **Step 4: Add retention saturation behavior**

When retention slots or quota are unavailable, the inline bounded result still
returns safely with `truncated=true` and no invalid `output_ref`. It must not
block a host session or convert the remote operation into failure.

- [ ] **Step 5: Commit, push, and observe intended failures**

```bash
cargo fmt --all
git add tests/mcp_tools.rs tests/mcp_protocol.rs tests/remote_ops.rs
git commit -m "test: define adapter-safe retained MCP output"
git push origin main
gh run watch "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: hosts structured content is empty and renderer-overflow pages expose
serialized detail under the old implementation.

## Task 6: Retain presentation bytes and expose essential aliases

**Files:**
- Modify: `src/mcp/render.rs`
- Modify: `src/remote/mod.rs`
- Modify: `src/output.rs`

**Interfaces:**
- Consumes: Task 5 tests.
- Produces: `retain_bytes`, `retain_presentation`, and hosts structured aliases.

- [ ] **Step 1: Add a byte-retention path without serde**

Implement `OutputStore::retain_bytes` using the existing entry-slot, quota,
private spool file, accounting, expiry, and cancellation mechanisms. Write
bytes through the capped writer directly; store them as the stdout stream with
no stderr path. Do not spawn the serde serializer worker.

- [ ] **Step 2: Validate remote or aggregate provenance once**

Extract the current provenance conversion from
`RemoteBridge::retain_serialized_detail` into:

```rust
async fn stored_provenance(
    &self,
    provenance: RetentionProvenance,
) -> BridgeResult<StoredProvenance>
```

`retain_presentation` calls it and then `runner.retain_bytes`. Existing
source-captured output references remain unchanged.

- [ ] **Step 3: Change `RetainedPresentation` to own bytes, not internal detail**

Remove generic `T: Serialize` and `detail`. Retain
`presentation.text.as_bytes().to_vec()` only when renderer-level truncation
needs a new reference. If the remote operation already supplied a valid
source-output reference, preserve it.

- [ ] **Step 4: Add minimal hosts structured content**

Build the alias vector once:

```rust
let aliases = result.hosts.iter().map(|host| host.host.clone()).collect::<Vec<_>>();
let text = aliases.join("\n");
let structured_content = json!({"hosts": aliases});
```

No other renderer duplicates payload.

- [ ] **Step 5: Format, commit, push, and require green**

```bash
cargo fmt --all
git diff --check
git add src/mcp/render.rs src/remote/mod.rs src/output.rs
git commit -m "fix: retain model-visible MCP presentation"
git push origin main
gh run watch "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: exact reconstruction, forbidden-field, quota, RSS, and 32 KiB
boundary tests pass.

## Task 7: Complete profile evidence without release overhead

**Files:**
- Modify: `src/profile.rs`
- Modify: `src/mcp/mod.rs`
- Modify: `src/ssh/process.rs`
- Modify: `src/ssh/session.rs`
- Modify: `src/output.rs`
- Modify: `tests/performance_acceptance.rs`

**Interfaces:**
- Consumes: runtime phase events from the first plan.
- Produces: a stable compile-time profile event set and zero ordinary release logging.

- [ ] **Step 1: Add a deterministic profile-event test**

Under `--features profile`, execute one cold and two warm fake-SSH calls. Parse
stderr JSONL and assert each request has ordered accepted/send/exit/render
events; only cold has generation start/ready; cancellation has
cancellation-start/confirmed or escalated. Assert serialized records do not
contain the fixture command, cwd, stdin, output, SSH identity path, or secret
environment value.

- [ ] **Step 2: Emit the missing events with existing macros**

Use `bridge_profile_span!` or a new zero-sized no-profile macro branch. Event
fields remain:

```rust
ProfileEvent {
    phase: &'static str,
    host: Option<&str>,
    request_id: Option<u64>,
    class: Option<&'static str>,
    elapsed_us: u64,
    bytes: Option<u64>,
}
```

Do not allocate a command/path copy to populate profile records.

- [ ] **Step 3: Prove non-profile compilation has no logging calls**

Add source/static or symbol assertions already used by the project so ordinary
release behavior cannot be enabled by an environment variable alone. The
`CODEX_SSH_BRIDGE_PROFILE` variable has an effect only in a binary compiled
with the `profile` feature.

- [ ] **Step 4: Commit, push, and require both CI jobs green**

```bash
cargo fmt --all
git add src/profile.rs src/mcp/mod.rs src/ssh/process.rs src/ssh/session.rs src/output.rs tests/performance_acceptance.rs
git commit -m "perf: expose bounded request phase profiles"
git push origin main
gh run watch "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: quality and diagnostics pass; profile artifact shows cold/warm phase
separation and no sensitive values.

## Task 8: MCP-contract verification checkpoint

**Files:**
- Modify only when evidence from CI identifies a contract defect.
- Inspect: all files in this plan.

**Interfaces:**
- Consumes: Tasks 1-7.
- Produces: green timeout/search/output/profile checkpoint.

- [ ] **Step 1: Audit every spec contract against test names**

Create a temporary checklist mapping:

```text
exit 124 ordinary -> timeout test name
explicit timeout -> timeout test name
search root globs -> rg and grep test names
producer cancellation -> recovery test name
hosts structured aliases -> golden test name
retained bytes -> reconstruction test names
profile redaction -> profile test name
```

Every row must point to a passing CI test, not merely source inspection.

- [ ] **Step 2: Inspect failed logs and fix evidenced gaps**

```bash
gh run view "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --json jobs,conclusion,url
gh run view "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --log-failed
```

Add a focused assertion before each correction. Do not relax output bounds,
timeout distinction, or cancellation recovery.

- [ ] **Step 3: Commit any final corrections and require green**

```bash
cargo fmt --all
sh -n src/ssh/dispatcher.sh
git diff --check
git add src tests
git commit -m "test: close transparent MCP contract regressions"
git push origin main
gh run watch "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: quality and diagnostics succeed, and the repository contains no
ordinary success `action`, verbose profile metadata, or serialized-detail
retention path used by MCP renderers.
