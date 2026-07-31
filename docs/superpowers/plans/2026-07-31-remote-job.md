# Remote Job Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add durable Remote Job MCP tools whose remote processes survive SSH, Bridge, Desktop, and Codex task interruption without changing synchronous `remote_run` behavior.

**Architecture:** The existing precompiled Rust helper gains a closed Job control operation and a detached per-job runner mode. Durable records and bounded logs live under the remote account's private state directory; the local Bridge performs edit barriers, transports compact requests, and exposes six separate MCP tools. No active job owns an SSH session or local output-spool entry.

**Tech Stack:** Rust 2024, Tokio on the local bridge, synchronous Rust and Unix `libc` primitives in the remote helper, serde JSON records, existing CXSB1 framed helper protocol, MCP 2025-06-18 tool schemas, GitHub Actions CI/cross release builds.

---

## File Structure

- Create `src/job_protocol.rs`: shared closed request/state/response records, opaque job IDs, state transitions, and size validation.
- Create `src/remote_job_runner.rs`: remote secure storage, lock/process identity checks, detached runner, log capture, cancellation, deletion, listing, and retention.
- Create `src/remote/job.rs`: local Bridge Job request validation, edit barrier, helper transport mapping, and public results.
- Modify `src/lib.rs`: export shared helper modules to the helper binary.
- Modify `src/bin/codex-ssh-bridge-helper.rs`: select persistent dispatcher mode or internal `job-runner` mode.
- Modify `src/remote_helper.rs`: parse and execute bounded `operation=job` requests without routing them through a user shell.
- Modify `src/ssh/session.rs`, `src/ssh/helper.rs`, `src/ssh/mod.rs`: encode Job frames and expose `execute_job` only for verified binary-helper sessions.
- Modify `src/remote/mod.rs`: expose Job request/result types and six `RemoteBridge` methods.
- Modify `src/error.rs`: add factual Job capability, state-integrity, start-uncertainty, cancel-uncertainty, and expiry codes/details.
- Modify `src/mcp/tools.rs`: add six closed MCP schemas and dispatchers.
- Modify `src/mcp/render.rs`: return compact Job metadata and bounded incremental log text.
- Modify `tests/remote_helper.rs`: remote store, runner, output, cancellation, identity, and retention tests.
- Modify `tests/ssh_transport.rs`: Job framing, helper-only capability, disconnect, and session-independence tests.
- Modify `tests/remote_ops.rs`: Bridge validation, edit barrier, uncertainty, and concurrent Job operations.
- Modify `tests/mcp_tools.rs`: exact schemas, argument validation, output shapes, cancellation, and RSS tests.
- Modify `tests/real_ssh.rs`: real SSH launch/disconnect/reconnect/log/cancel/delete lifecycle.
- Modify `tests/performance_acceptance.rs`: prove normal warm paths do not regress and Job requests release local resources.
- Modify `skills/remote-ssh-ops/SKILL.md` and `skills/remote-ssh-ops/references/operations.md`: teach Codex when and how to use Remote Job.
- Modify `README.md`, `docs/security.md`, and `docs/performance.md`: public behavior, threat boundary, and measured acceptance.
- Modify `Cargo.toml`, `Cargo.lock`, and release metadata: release the compatible feature as `0.7.0`; no new runtime dependency is required because `libc` already exists.

### Task 1: Shared Job Contract and RED Tests

**Files:**
- Create: `src/job_protocol.rs`
- Modify: `src/lib.rs`
- Test: `tests/remote_helper.rs`
- Test: `tests/remote_ops.rs`
- Test: `tests/mcp_tools.rs`

- [ ] **Step 1: Add failing contract tests**

Add tests named `task15_job_id_and_closed_records_are_bounded`,
`task15_job_state_transition_matrix_is_closed`,
`task15_remote_job_requests_validate_exact_boundaries`, and
`task15_mcp_job_schema_matrix_is_exact`. They must assert:

```rust
assert!(JobId::parse("0123456789abcdef0123456789abcdef").is_ok());
assert!(JobId::parse("../0123456789abcdef0123456789abcd").is_err());
assert!(JobId::parse("ABCDEF0123456789ABCDEF0123456789").is_err());
assert!(JobState::Starting.can_transition_to(JobState::Running));
assert!(!JobState::Succeeded.can_transition_to(JobState::Running));
assert_invalid("remote_job_start", json!({"host":"dev","command":"x","cwd":"/tmp","unknown":1}));
assert_invalid("remote_job_logs", json!({"host":"dev","job_id":VALID_ID,"max_bytes":1_048_577}));
```

The schema matrix must require the six approved tool names and reject an
action-field `remote_job` tool.

- [ ] **Step 2: Commit and prove RED in GitHub Actions**

```bash
git add tests/remote_helper.rs tests/remote_ops.rs tests/mcp_tools.rs
git commit -m "test: specify durable remote jobs"
git push origin main
gh run list --workflow CI --branch main --limit 1
run_id=$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$run_id" --exit-status
```

Expected: CI fails to compile because `JobId`, `JobState`, and the six schemas
do not exist. Record the failing run URL before implementing.

- [ ] **Step 3: Implement the shared closed records**

Create these core types in `src/job_protocol.rs`; every serde record uses
`#[serde(deny_unknown_fields)]` and an explicit `version: u32`:

```rust
pub const JOB_RECORD_VERSION: u32 = 1;
pub const JOB_ID_HEX_BYTES: usize = 32;
pub const MAX_JOB_LABEL_BYTES: usize = 256;
pub const DEFAULT_JOB_LOG_PAGE_BYTES: usize = 256 * 1024;
pub const MAX_JOB_LOG_PAGE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JobId(String);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState { Starting, Running, Succeeded, Failed, Cancelled, TimedOut, Lost }

impl JobState {
    pub fn is_terminal(self) -> bool;
    pub fn can_transition_to(self, next: Self) -> bool;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum JobShell {
    Bash,
    Sh,
    Login { path: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: i32,
    pub start_ticks: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRequestRecord {
    pub version: u32,
    pub job_id: JobId,
    pub shell: JobShell,
    pub cwd: String,
    pub command: String,
    pub stdin_base64: String,
    pub timeout_ms: Option<u64>,
    pub label: Option<String>,
    pub max_output_bytes: u64,
    pub created_unix_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobStateRecord {
    pub version: u32,
    pub job_id: JobId,
    pub state: JobState,
    pub boot_id: String,
    pub runner: Option<ProcessIdentity>,
    pub command_group: Option<ProcessIdentity>,
    pub created_unix_ms: u64,
    pub started_unix_ms: Option<u64>,
    pub finished_unix_ms: Option<u64>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout_retained_bytes: u64,
    pub stdout_observed_bytes: u64,
    pub stderr_retained_bytes: u64,
    pub stderr_observed_bytes: u64,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobLogsRequest {
    pub job_id: JobId,
    pub stdout_offset: u64,
    pub stderr_offset: u64,
    pub max_bytes: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobLogEncoding { Utf8, Base64 }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobLogPage {
    pub encoding: JobLogEncoding,
    pub value: String,
    pub next_offset: u64,
    pub eof: bool,
    pub retained_bytes: u64,
    pub observed_bytes: u64,
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobLogsResponse {
    pub job_id: JobId,
    pub state: JobState,
    pub stdout: JobLogPage,
    pub stderr: JobLogPage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSummary {
    pub job_id: JobId,
    pub label: Option<String>,
    pub state: JobState,
    pub cwd: String,
    pub created_unix_ms: u64,
    pub started_unix_ms: Option<u64>,
    pub finished_unix_ms: Option<u64>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case", deny_unknown_fields)]
pub enum JobControlResponse {
    Started(JobStateRecord),
    Status(JobStateRecord),
    Logs(JobLogsResponse),
    Cancelled(JobStateRecord),
    Listed(Vec<JobSummary>),
    Deleted { job_id: JobId },
}
```

Generate IDs with `rand::rng().fill_bytes(&mut [u8; 16])`; parse only exact
lowercase hexadecimal. Validate UTF-8 byte lengths, NUL exclusion, positive
optional timeout, canonical Base64 stdin, log offsets, page limits, and checked
integer conversions. The Job request stores stdin once as canonical Base64;
never serialize it as a JSON integer array.

- [ ] **Step 4: Push the contract implementation and require GREEN**

```bash
git add src/job_protocol.rs src/lib.rs
git commit -m "feat: define remote job contract"
git push origin main
run_id=$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$run_id" --exit-status
```

Expected: the Task 1 contract tests pass; later Job behavior tests may remain
absent, not ignored.

### Task 2: Secure Remote Store and Detached Runner

**Files:**
- Create: `src/remote_job_runner.rs`
- Modify: `src/bin/codex-ssh-bridge-helper.rs`
- Test: `tests/remote_helper.rs`

- [ ] **Step 1: Add failing filesystem and lifecycle tests**

Use a private temporary `HOME` and the current test binary as controlled child
commands. Cover exact modes, atomic state replacement, no-follow rejection,
wrong owner/type rejection where supported, immutable request, append-only
logs, normal/nonzero/signal exit, optional timeout, runner loss, boot mismatch,
and restart-independent status.

```rust
assert_eq!(mode(job_dir), 0o700);
assert_eq!(mode(job_dir.join("request")), 0o600);
assert_eq!(status.state, JobState::Running);
drop(initiating_control_connection);
assert_eq!(fresh_store.status(&job_id)?.state, JobState::Running);
```

- [ ] **Step 2: Implement descriptor-safe storage**

Implement a `JobStore` rooted at
`$HOME/.local/state/codex-ssh-bridge/jobs`. It must:

```rust
pub struct JobStore { root: OwnedFd, uid: libc::uid_t }

impl JobStore {
    pub fn open() -> io::Result<Self>;
    pub fn create(&self, request: &JobRequestRecord) -> io::Result<()>;
    pub fn read_state(&self, id: &JobId) -> io::Result<JobStateRecord>;
    pub fn replace_state(&self, id: &JobId, state: &JobStateRecord) -> io::Result<()>;
    pub fn read_logs(&self, request: &JobLogsRequest) -> io::Result<JobLogsResponse>;
    pub fn list(&self, max_jobs: usize) -> io::Result<Vec<JobSummary>>;
    pub fn delete_terminal(&self, id: &JobId) -> io::Result<()>;
    pub fn collect_expired(&self, now_ms: u64, budget: usize) -> io::Result<()>;
}
```

Use `openat`, `mkdirat`, `renameat`, `unlinkat`, `O_NOFOLLOW`, `O_CLOEXEC`,
owner/mode/type checks, same-directory temporary files, `fsync` before rename,
and `flock` through the existing `libc` dependency. Never concatenate an
unvalidated caller string into a path.

- [ ] **Step 3: Implement internal runner mode**

Make helper startup accept only either no arguments or exactly:

```text
codex-ssh-bridge-helper job-runner <32-lowercase-hex-job-id>
```

The dispatcher starts a runner with `current_exe`, null stdio, `setsid`, and a
private readiness pipe. The runner locks `runner.lock`, reads the immutable
request, records boot ID and `/proc/<pid>/stat` start token, starts the selected
shell in its own process group, drains stdout and stderr on separate threads,
and updates state atomically. It retains a shared aggregate log budget while
continuing to drain discarded bytes.

Timeout sends `TERM`, waits five seconds, verifies the same process identity,
then sends `KILL`. The runner records a terminal state only after `waitpid`
observes termination.

- [ ] **Step 4: Prove lifecycle GREEN in GitHub Actions**

```bash
git add src/remote_job_runner.rs src/bin/codex-ssh-bridge-helper.rs tests/remote_helper.rs
git commit -m "feat: run durable jobs in remote helper"
git push origin main
run_id=$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$run_id" --exit-status
```

Expected: all remote-store and runner tests pass under the normal and release
test jobs, with no leaked child processes.

### Task 3: Job Control Through the Persistent Helper

**Files:**
- Modify: `src/remote_helper.rs`
- Modify: `src/ssh/session.rs`
- Modify: `src/ssh/helper.rs`
- Modify: `src/ssh/mod.rs`
- Test: `tests/remote_helper.rs`
- Test: `tests/ssh_transport.rs`

- [ ] **Step 1: Add failing closed-wire tests**

Add an `operation=job` matrix for `start`, `status`, `logs`, `cancel`, `list`,
and `delete`. Require exactly one JSON DATA frame, reject unknown fields and
actions, reject Job operations on temporary-helper/POSIX fallback, and prove a
started Job returns READY/EXIT while continuing after the initiating session
is closed.

- [ ] **Step 2: Add typed helper transport**

Extend helper request dispatch without running Job control through a shell:

```rust
enum RequestSpec {
    Command(CommandSpec),
    Search(SearchSpec),
    Job(JobControlSpec),
}

pub enum JobControlRequest {
    Start(JobRequestRecord),
    Status { job_id: JobId },
    Logs(JobLogsRequest),
    Cancel { job_id: JobId },
    List { max_jobs: usize },
    Delete { job_id: JobId },
}
```

Encode responses as one bounded JSON stdout frame followed by EXIT. Run lazy
retention before each action. A canceled MCP request stops only that short
control operation; it never cancels a successfully acknowledged Job.

- [ ] **Step 3: Expose helper-only `SshRunner::execute_job`**

Add a session request kind that serializes the closed Job metadata and JSON
body over CXSB1. Require `HelperMode::Persistent`; otherwise return
`REMOTE_CAPABILITY_MISSING` with capability `remote_job`. Use the one shared
connect/admission deadline, but do not apply `command_timeout_ms` to the Job's
lifetime.

```rust
pub async fn execute_job(
    &self,
    host: String,
    request: JobControlRequest,
    cancel: CancellationToken,
) -> BridgeResult<JobControlResponse>;
```

- [ ] **Step 4: Push and require transport GREEN**

```bash
git add src/remote_helper.rs src/ssh/session.rs src/ssh/helper.rs src/ssh/mod.rs tests/remote_helper.rs tests/ssh_transport.rs
git commit -m "feat: transport remote job controls"
git push origin main
run_id=$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$run_id" --exit-status
```

Expected: malformed-wire, fallback capability, disconnect, and unrelated
request-concurrency tests pass.

### Task 4: Bridge API, Identity-Safe Cancel, and Uncertainty

**Files:**
- Create: `src/remote/job.rs`
- Modify: `src/remote/mod.rs`
- Modify: `src/error.rs`
- Test: `tests/remote_ops.rs`

- [ ] **Step 1: Add failing Bridge behavior tests**

Cover input bounds, absolute cwd/root resolution, Bash default and explicit
shells, stdin limits, edit-barrier failure, generated ID before mutation,
dropped launch acknowledgement, status/list recovery, idempotent cancel,
TERM-to-KILL escalation, PID reuse, delete refusal, concurrent log/status,
seven-day expiry, and host independence.

- [ ] **Step 2: Add public Job request/result types and methods**

Expose:

```rust
pub struct RemoteJobStartRequest {
    pub host: String,
    pub command: String,
    pub cwd: String,
    pub shell: RunShell,
    pub stdin: Option<RunStdin>,
    pub timeout_ms: Option<u64>,
    pub label: Option<String>,
}

pub struct RemoteJobIdRequest { pub host: String, pub job_id: JobId }

pub struct RemoteJobLogsRequest {
    pub host: String,
    pub job_id: JobId,
    pub stdout_offset: u64,
    pub stderr_offset: u64,
    pub max_bytes: usize,
}

pub struct RemoteJobListRequest { pub host: String, pub max_jobs: usize }

pub struct RemoteJobStartResult { pub host: String, pub job_id: JobId, pub state: JobState }
pub struct RemoteJobStatusResult { pub host: String, pub record: JobStateRecord }
pub struct RemoteJobLogsResult { pub host: String, pub logs: JobLogsResponse }
pub struct RemoteJobListResult { pub host: String, pub jobs: Vec<JobSummary> }
pub struct RemoteJobDeleteResult { pub host: String, pub job_id: JobId }

impl RemoteBridge {
    pub async fn job_start(&self, request: RemoteJobStartRequest, cancel: CancellationToken) -> BridgeResult<RemoteJobStartResult>;
    pub async fn job_status(&self, request: RemoteJobIdRequest, cancel: CancellationToken) -> BridgeResult<RemoteJobStatusResult>;
    pub async fn job_logs(&self, request: RemoteJobLogsRequest, cancel: CancellationToken) -> BridgeResult<RemoteJobLogsResult>;
    pub async fn job_cancel(&self, request: RemoteJobIdRequest, cancel: CancellationToken) -> BridgeResult<RemoteJobStatusResult>;
    pub async fn job_list(&self, request: RemoteJobListRequest, cancel: CancellationToken) -> BridgeResult<RemoteJobListResult>;
    pub async fn job_delete(&self, request: RemoteJobIdRequest, cancel: CancellationToken) -> BridgeResult<RemoteJobDeleteResult>;
}
```

`job_start` performs `edit_barrier` before sending Start. Map shell selection
through existing capability logic, map requested cwd through `RemotePath`, and
reuse run stdin decoding limits. All other actions require a discovered alias
and exact Job ID.

- [ ] **Step 3: Implement factual uncertainty and identity errors**

Add error codes `JOB_START_OUTCOME_UNKNOWN`, `JOB_CANCEL_OUTCOME_UNKNOWN`,
`JOB_STATE_INVALID`, and `JOB_EXPIRED`; extend `ErrorDetails` with optional
`job_id`. A lost response after the Start frame may have reached the helper
returns the generated ID and start uncertainty. Known pre-admission failure
does not. Cancel never claims `cancelled` unless the verified process group is
observed dead.

- [ ] **Step 4: Push and require Bridge GREEN**

```bash
git add src/remote/job.rs src/remote/mod.rs src/error.rs tests/remote_ops.rs
git commit -m "feat: expose durable remote job operations"
git push origin main
run_id=$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$run_id" --exit-status
```

Expected: all Bridge state, uncertainty, process-identity, and edit-barrier
tests pass.

### Task 5: Six Compact MCP Tools

**Files:**
- Modify: `src/mcp/tools.rs`
- Modify: `src/mcp/render.rs`
- Test: `tests/mcp_tools.rs`
- Test: `tests/mcp_protocol.rs`

- [ ] **Step 1: Add failing exact-schema and output tests**

Require six separate tools with closed objects, correct read-only/destructive
annotations, exact defaults, and no `action` field. Test compact output:

```rust
assert_eq!(
    job_tool_names,
    [
        "remote_job_start",
        "remote_job_status",
        "remote_job_logs",
        "remote_job_cancel",
        "remote_job_list",
        "remote_job_delete",
    ]
);
assert_eq!(serialized_error_code(JobStartOutcomeUnknown), "JOB_START_OUTCOME_UNKNOWN");
assert_eq!(serialized_error_code(JobCancelOutcomeUnknown), "JOB_CANCEL_OUTCOME_UNKNOWN");
```

Test each schema independently; do not rely on a count-only assertion.

```json
{"job_id":"0123456789abcdef0123456789abcdef","state":"running"}
```

Status/list must omit command and stdin. Logs must expose bounded labeled text
as `content.text` and `structuredContent.output`, plus independent offsets and
truncation metadata. Error output must include `job_id` only when known.

- [ ] **Step 2: Implement schemas and dispatch**

Add `JobStartArguments`, `JobIdArguments`, `JobLogsArguments`, and
`JobListArguments` with `deny_unknown_fields`. Use the existing host, path,
encoding, stdin, and shell schema builders. Define annotations as:

```text
start:  readOnly=false, destructive=false, idempotent=false
status: readOnly=true,  destructive=false, idempotent=true
logs:   readOnly=true,  destructive=false, idempotent=true
cancel: readOnly=false, destructive=true,  idempotent=true
list:   readOnly=true,  destructive=false, idempotent=true
delete: readOnly=false, destructive=true,  idempotent=true
```

- [ ] **Step 3: Implement compact renderers**

Use `compact_result` for start, status, cancel, and delete. Render list as one
JSON summary per line, with the same bounded text in structured `output`.
Render logs as optional `stdout:` and `stderr:` sections and metadata:

```rust
json!({
    "job_id": result.job_id,
    "state": result.state,
    "stdout_next_offset": result.stdout.next_offset,
    "stderr_next_offset": result.stderr.next_offset,
    "stdout_eof": result.stdout.eof,
    "stderr_eof": result.stderr.eof,
    "stdout_truncated": result.stdout.truncated,
    "stderr_truncated": result.stderr.truncated,
})
```

Do not copy Job logs into local `output_ref` retention.

- [ ] **Step 4: Push and require MCP GREEN plus RSS checks**

```bash
git add src/mcp/tools.rs src/mcp/render.rs tests/mcp_tools.rs tests/mcp_protocol.rs
git commit -m "feat: add remote job MCP tools"
git push origin main
run_id=$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$run_id" --exit-status
```

Expected: schema, rendering, wire-budget, cancellation, and fresh-child RSS
tests pass.

### Task 6: Real SSH, Performance, and Regression Gates

**Files:**
- Modify: `tests/real_ssh.rs`
- Modify: `tests/performance_acceptance.rs`
- Modify: `.github/workflows/ci.yml` only if the existing release diagnostic test selection omits the new named tests.

- [ ] **Step 1: Add real lifecycle acceptance**

The real-sshd test must start a command that prints, sleeps, and spawns a child;
drop the initiating runner and SSH session; create a fresh runner; list/status;
page both logs; cancel the process tree; verify no matching process remains;
delete; and verify the directory is gone.

- [ ] **Step 2: Add non-regression pressure acceptance**

Measure existing warm `remote_run true` before and while at least 16 Jobs are
active. Require its current latency ceiling and verify Bridge RSS/FD count
returns to the established ceiling after 1,000 status/log calls. Verify active
Jobs create no local spool entries and no additional persistent SSH child per
Job.

- [ ] **Step 3: Push and require full CI GREEN**

```bash
git add tests/real_ssh.rs tests/performance_acceptance.rs .github/workflows/ci.yml
git commit -m "test: pressure durable remote jobs"
git push origin main
run_id=$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$run_id" --exit-status
```

Expected: formatting, Clippy, debug tests, release tests, real SSH, RSS, and
performance jobs all pass. Diagnose failures from uploaded release diagnostics;
do not build or test locally.

### Task 7: Skill, Public Documentation, and Packaging

**Files:**
- Modify: `skills/remote-ssh-ops/SKILL.md`
- Modify: `skills/remote-ssh-ops/references/operations.md`
- Modify: `README.md`
- Modify: `docs/security.md`
- Modify: `docs/performance.md`
- Modify: `tests/packaging.rs`

- [ ] **Step 1: Add documentation/packaging assertions**

Require the installed Skill and operations reference to list all six tools,
state that `remote_run` remains synchronous, prefer Remote Job for long work,
warn that a Job survives a Codex task/Bridge disconnect, and forbid blind
retry after `start_outcome_unknown`. Require public docs to describe seven-day
retention, bounded logs, helper-only capability, and no reboot restart.

- [ ] **Step 2: Update the Skill contract**

Replace the existing instruction to hand-roll detached `remote_run` commands
with the following behavior:

```text
Use remote_run for bounded commands whose result is needed now. Use
remote_job_start for servers, downloads, training, or other work that must
survive this MCP call. Keep the returned job_id. If start outcome is unknown,
query that exact ID or list jobs; never submit the command again blindly.
```

Document exact schemas and incremental offsets. Keep errors factual; do not add
an `action` field or prescribe shell fallback.

- [ ] **Step 3: Update public security and performance docs**

Document the private remote path, modes, no-follow traversal, process identity,
bounded 64 MiB default diagnostic logs, seven-day lazy retention, independent
SSH lifetime, and measured start/status/log overhead from CI.

- [ ] **Step 4: Push and require documentation GREEN**

```bash
git add skills/remote-ssh-ops README.md docs/security.md docs/performance.md tests/packaging.rs
git commit -m "docs: document remote job lifecycle"
git push origin main
run_id=$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$run_id" --exit-status
```

Expected: packaging and full CI pass; release archives still contain the
updated Skill and public docs but exclude `docs/superpowers`.

### Task 8: Release 0.7.0, Install, and Production Pressure

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- No version assertion file currently contains `0.6.3`; verify that remains
  true before editing.

- [ ] **Step 1: Bump the backward-compatible feature release**

Change package version to `0.7.0`, update the lockfile version entry without a
local Cargo invocation, and update exact version assertions. Commit and push:

```bash
rg -n '0\.6\.3' --glob '!docs/superpowers/**' .
git add Cargo.toml Cargo.lock
git commit -m "chore: release 0.7.0"
git push origin main
run_id=$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$run_id" --exit-status
```

- [ ] **Step 2: Tag only the verified main commit**

```bash
git tag -a v0.7.0 -m "codex-ssh-bridge 0.7.0"
git push origin v0.7.0
gh run list --workflow Release --limit 1
release_run_id=$(gh run list --workflow Release --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$release_run_id" --exit-status
gh release view v0.7.0
```

Expected: all common bridge and helper architectures are attached with
checksums, and the packaged aarch64 archive contains bridge, all remote helper
targets, Skill, docs, manifest, and examples.

- [ ] **Step 3: Install the release without local build artifacts**

Download the aarch64 main archive and all helper artifacts through the
packaged installer, replacing the prior managed installation. Verify:

```bash
readlink -f ~/.local/bin/codex-ssh-bridge
codex mcp get ssh-bridge
codex-ssh-bridge --version
```

Expected: the symlink and MCP registration resolve to
`~/.local/share/codex-ssh-bridge/0.7.0+release/bin/codex-ssh-bridge`, and the
managed package includes the updated Skill plus every common helper target.

- [ ] **Step 4: Run manual `nkai` and `weibo` acceptance with the installed binary**

For each host: start a short success Job, a nonzero Job, a log-producing Job,
and a long process tree; page logs; restart only the test Bridge process;
recover with list/status; cancel the tree; delete terminal Jobs; then issue
bounded concurrent `remote_search` and `remote_run true` pressure while Jobs
remain active.

Record cold start, warm start, status, log-page, cancel, normal warm run, RSS,
FD count, SSH child count, and leaked remote process/file count. Acceptance is:

```text
0 lost acknowledged jobs
0 unrelated killed processes
0 blocked follow-up run/search requests
0 leaked local SSH children or spool entries per job
0 leaked remote process groups after verified cancel
existing warm run/search latency gates unchanged
```

- [ ] **Step 5: Verify repository and release state**

```bash
git status --short --branch
git log -8 --oneline
gh run list --branch main --limit 8
gh release view v0.7.0
```

Expected: clean `main`, synchronized with `origin/main`, all required workflows
green, v0.7.0 published, installed, and manually verified.
