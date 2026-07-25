# Transparent Host Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace bridge-owned host profiles and fixed concurrency admission with OpenSSH alias discovery, absolute remote paths, cancellation-safe session generations, and request-wide deadlines.

**Architecture:** Configuration version 2 stores only global integrity/time limits. `SshRunner` resolves any concrete alias discovered from the user's OpenSSH config, uses `/` only as the transport capability boundary, and allows Codex annotations to own ordinary scheduling. Per-alias generation state makes creation, eviction, cancellation, and recovery explicit without holding a lock across a business request.

**Tech Stack:** Rust 1.91.1, Tokio, OpenSSH, existing framed SSH session/helper, TOML/serde, GitHub Actions.

## Global Constraints

- Target release is `0.4.0`; configuration version is `2`.
- Do not run Cargo build, test, Clippy, benchmark, or release commands locally.
- Local verification is limited to `cargo fmt`, shell syntax, source inspection, and Git operations.
- All executable verification runs in GitHub Actions.
- Do not add Python code or a Python runtime dependency.
- OpenSSH config is authoritative for aliases and connection details.
- Every remote operation takes absolute remote paths; no configured root or task workspace is inferred.
- Remove bridge host count, global concurrency, per-host concurrency, and read-only-host policy.
- Preserve frame, byte, spool, retention, path-shape, host-key, expected-hash, atomic-write, and mutation-uncertainty safeguards.
- Work on `main`; each test-first gate is pushed and observed before its implementation commit.

---

## File map

- `src/config.rs`: version-2 limit schema, OpenSSH alias discovery, version-1 migration parser.
- `src/path.rs`: normalized absolute-path value; no configured-root relative representation.
- `src/ssh/mod.rs`: alias-only `SshPolicy`, shared `/` transport capability boundary.
- `src/ssh/argv.rs`: SSHFS argv no longer consumes a host profile or forces profile read-only.
- `src/ssh/process.rs`: remove admission semaphores and introduce per-alias session-generation state and request deadlines.
- `src/remote/mod.rs`: alias-only host discovery and absolute request resolution.
- `src/remote/{run,read,write,patch,metadata,search}.rs`: remove profile root/read-only consumers.
- `src/cli.rs`: retain discovery-only `hosts list`; remove add/show/remove and host-policy output.
- `src/cli/install.rs`: transactional version-1 to version-2 config migration.
- `src/main.rs`: construct MCP without a concurrency-derived pending bound.
- `src/mcp/mod.rs`: remove MCP task-window admission and `Server busy`.
- `src/error.rs`: remove reachable read-only-host error behavior.
- `config.example.toml`: version-2 limits only.
- `tests/{core,cli,remote_ops,ssh_transport,mcp_protocol,mcp_tools,packaging}.rs`: deterministic contract and migration coverage.

### Runtime interfaces fixed by this plan

```rust
pub const CONFIG_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub version: u32,
    pub limits: Limits,
    #[serde(skip)]
    discovered_aliases: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveLimits {
    pub connect_timeout_ms: u64,
    pub command_timeout_ms: u64,
    pub max_frame_bytes: usize,
    pub read_chunk_bytes: usize,
    pub max_read_bytes: usize,
    pub max_write_bytes: usize,
    pub preview_bytes: usize,
    pub max_output_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredHost {
    pub alias: String,
}

impl Config {
    pub fn limits(&self) -> EffectiveLimits;
    pub fn discover_hosts(&self) -> Vec<DiscoveredHost>;
    pub fn require_discovered_alias(&self, alias: &str) -> BridgeResult<DiscoveredHost>;
    pub fn load_with_discovery(path: &Path, ssh_config: &Path) -> BridgeResult<Self>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePath {
    absolute: String,
}

impl RemotePath {
    pub fn absolute(requested: &str) -> BridgeResult<Self>;
    pub fn as_str(&self) -> &str;
}

impl McpServer<S> {
    pub fn new(service: Arc<S>, max_frame_bytes: usize) -> BridgeResult<Self>;
}
```

## Task 1: Establish the version-2 configuration and migration failures

**Files:**
- Modify: `tests/core.rs`
- Modify: `tests/cli.rs`
- Modify: `tests/packaging.rs`
- Test: `tests/core.rs`
- Test: `tests/cli.rs`

**Interfaces:**
- Consumes: current `Config::load`, `Config::save_atomic`, and packaged installer test seams.
- Produces: failing tests for `ConfigV1::migrate`, version-2 serialization, and transactional install migration.

- [ ] **Step 1: Replace old host-profile assertions with exact version-2 schema tests**

Add tests equivalent to:

```rust
#[test]
fn v2_config_contains_only_global_non_admission_limits() {
    let config: Config = toml::from_str(
        r#"
version = 2
[limits]
connect_timeout_ms = 10000
command_timeout_ms = 300000
max_frame_bytes = 8388608
read_chunk_bytes = 262144
max_read_bytes = 1048576
max_write_bytes = 4194304
preview_bytes = 262144
max_output_bytes = 67108864
global_spool_quota_bytes = 536870912
retention_serialization_jobs = 2
"#,
    )
    .unwrap();
    let rendered = toml::to_string(&config).unwrap();
    for forbidden in [
        "[hosts",
        "root",
        "description",
        "read_only",
        "global_concurrency",
        "per_host_concurrency",
    ] {
        assert!(!rendered.contains(forbidden), "{forbidden}");
    }
}

#[test]
fn v1_migration_preserves_limits_and_returns_explicit_aliases() {
    const V1: &str = r#"
version = 1
[limits]
command_timeout_ms = 300000
retention_serialization_jobs = 2
global_concurrency = 8
per_host_concurrency = 2
[hosts.nkai]
root = "/home/wkj"
[hosts.weibo]
root = "/"
"#;
    let migrated = migrate_v1_text(V1).unwrap();
    assert_eq!(migrated.config.version, 2);
    assert_eq!(migrated.explicit_aliases, ["nkai", "weibo"]);
    assert_eq!(migrated.config.limits.command_timeout_ms, 300_000);
    assert_eq!(migrated.config.limits.retention_serialization_jobs, 2);
}
```

Delete tests whose only contract is host root validation, host override limits,
read-only policy, or fixed concurrency bounds. Keep file ownership, symlink,
unknown-field, byte-limit, timeout, and spool validation coverage.

- [ ] **Step 2: Add installer migration rollback tests**

Extend the install module's test support with:

```rust
struct InstallMigrationFixture {
    _temp: tempfile::TempDir,
    layout: InstallLayout,
    config_path: PathBuf,
    ssh_config_path: PathBuf,
    original: Vec<u8>,
    fail_after_config_migration: bool,
}

impl InstallMigrationFixture {
    fn with_v1_config_and_ssh_aliases(
        explicit: &[&str],
        discovered: &[&str],
    ) -> Self;
    async fn install(&self) -> BridgeResult<InstallReport>;
    fn config_bytes(&self) -> Vec<u8>;
    fn config_mode(&self) -> u32;
}
```

The constructor uses the existing fake Codex executable and canonical packaged
layout helpers, writes an exact private version-1 config, and writes one
concrete `Host <alias>` stanza per `discovered` alias. Add:

```rust
#[tokio::test]
async fn packaged_install_migrates_v1_config_atomically() {
    let fixture =
        InstallMigrationFixture::with_v1_config_and_ssh_aliases(
            &["nkai", "weibo"],
            &["nkai", "weibo"],
        );
    fixture.install().await.unwrap();
    let config = Config::load(&fixture.config_path).unwrap();
    assert_eq!(config.version, 2);
    assert!(!fixture.config_text().contains("[hosts."));
    assert_eq!(fixture.config_mode(), 0o600);
}

#[tokio::test]
async fn later_install_failure_restores_exact_v1_config_bytes() {
    let mut fixture =
        InstallMigrationFixture::with_v1_config_and_ssh_aliases(&["nkai"], &["nkai"]);
    let original = fixture.config_bytes();
    fixture.fail_after_config_migration = true;
    assert!(fixture.install().await.is_err());
    assert_eq!(fixture.config_bytes(), original);
}

#[tokio::test]
async fn migration_rejects_v1_alias_missing_from_openssh_config_without_writes() {
    let fixture =
        InstallMigrationFixture::with_v1_config_and_ssh_aliases(&["missing"], &[]);
    let original = fixture.config_bytes();
    let error = fixture.install().await.unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidConfig);
    assert_eq!(fixture.config_bytes(), original);
}
```

- [ ] **Step 3: Format and perform local static verification**

Run:

```bash
cargo fmt --all
git diff --check
rg -n "global_concurrency|per_host_concurrency|read_only|\\[hosts" tests/core.rs tests/cli.rs
```

Expected: formatting succeeds; remaining matches are migration fixtures or
explicit forbidden-field assertions only.

- [ ] **Step 4: Commit and push the failing configuration tests**

```bash
git add tests/core.rs tests/cli.rs tests/packaging.rs
git commit -m "test: define transparent v2 configuration"
git push origin main
```

- [ ] **Step 5: Observe the intended GitHub failure**

Run:

```bash
gh run watch "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: CI fails in compilation/tests because `migrate_v1_text`,
version-2 config shape, and install migration do not exist. Preserve the run URL
as TDD evidence before implementation.

## Task 2: Implement version-2 config and transactional installation migration

**Files:**
- Modify: `src/config.rs`
- Modify: `src/cli/install.rs`
- Modify: `config.example.toml`
- Modify: `tests/core.rs`
- Modify: `tests/cli.rs`

**Interfaces:**
- Consumes: failing Task 1 tests.
- Produces:

```rust
pub(crate) struct MigratedV1 {
    pub config: Config,
    pub explicit_aliases: Vec<String>,
}

pub(crate) fn migrate_v1_text(input: &str) -> BridgeResult<MigratedV1>;
```

- [ ] **Step 1: Split strict version-2 parsing from a private version-1 migration schema**

Define private serde-only `ConfigV1`, `LimitsV1`, `HostProfileV1`, and
`HostLimitOverridesV1` with `deny_unknown_fields`. `migrate_v1_text` must:

```rust
let old: ConfigV1 = toml::from_str(input).map_err(|error| {
    BridgeError::invalid_config(format!("invalid version-1 configuration: {error}"))
})?;
if old.version != 1 {
    return Err(BridgeError::invalid_config("configuration is not version 1"));
}
let explicit_aliases = old.hosts.into_keys().collect::<Vec<_>>();
let config = Config {
    version: 2,
    limits: Limits {
        connect_timeout_ms: old.limits.connect_timeout_ms,
        command_timeout_ms: old.limits.command_timeout_ms,
        max_frame_bytes: old.limits.max_frame_bytes,
        read_chunk_bytes: old.limits.read_chunk_bytes,
        max_read_bytes: old.limits.max_read_bytes,
        max_write_bytes: old.limits.max_write_bytes,
        preview_bytes: old.limits.preview_bytes,
        max_output_bytes: old.limits.max_output_bytes,
        global_spool_quota_bytes: old.limits.global_spool_quota_bytes,
        retention_serialization_jobs: old.limits.retention_serialization_jobs,
    },
};
config.validate()?;
Ok(MigratedV1 { config, explicit_aliases })
```

Remove host maps and concurrency fields from active types, defaults,
validation, `EffectiveLimits`, and serialization. The private
`discovered_aliases` field is skipped by serde, populated exactly once by
`load_with_discovery`, and reused for every warm request.

- [ ] **Step 2: Add an injected OpenSSH-config path seam for deterministic discovery**

Keep production discovery rooted at `$HOME/.ssh/config`; add a private
`discover_ssh_aliases_from(path: &Path) -> Vec<String>` used by tests and
migration preflight. Reuse include cycle/depth protection and exact alias
validation. Return sorted deduplicated aliases.

- [ ] **Step 3: Journal configuration migration in the packaged installer**

Extend `InstallLayout` with the resolved config and SSH config paths. Add:

```rust
struct ConfigMigration {
    original: Vec<u8>,
    replacement: Vec<u8>,
    path: PathBuf,
}

#[derive(Default)]
struct InstallJournal {
    // existing fields
    config_quarantine: Option<QuarantinedPath>,
    config_replacement_created: bool,
}
```

Preflight computes migration without writing. Apply quarantines the original,
writes the private replacement with `create_new`, fsyncs it, and records the
journal. Rollback removes the replacement and renames the quarantine back.
Cleanup deletes the quarantine only after MCP, Skill, marker, and bundle steps
all succeed.

- [ ] **Step 4: Replace `config.example.toml` with the exact version-2 keys**

The example must contain `version = 2`, one `[limits]` table, and none of:

```text
[hosts
root =
description =
read_only =
global_concurrency =
per_host_concurrency =
```

- [ ] **Step 5: Format, commit, push, and verify Task 1 green**

```bash
cargo fmt --all
git diff --check
git add src/config.rs src/cli/install.rs config.example.toml tests/core.rs tests/cli.rs
git commit -m "feat: migrate to alias-only v2 configuration"
git push origin main
gh run watch "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: configuration/migration tests pass. Other suites may still fail
because remote callers have not yet migrated; record their exact failures for
Task 4 rather than weakening the Task 1 contract.

## Task 3: Establish absolute-path and alias-only operation failures

**Files:**
- Modify: `tests/core.rs`
- Modify: `tests/remote_ops.rs`
- Modify: `tests/ssh_transport.rs`
- Modify: `tests/cli.rs`
- Modify: `tests/mcp_tools.rs`

**Interfaces:**
- Consumes: version-2 `Config` and discovery seam.
- Produces: failing tests for `RemotePath::absolute`, alias-only host results,
  SSHFS behavior, and `/` transport setup.

- [ ] **Step 1: Replace configured-root path tests with normalized absolute-path tests**

Add:

```rust
#[test]
fn remote_path_requires_and_normalizes_absolute_input() {
    assert_eq!(RemotePath::absolute("/a/./b/../c").unwrap().as_str(), "/a/c");
    for invalid in ["", ".", "relative/path", "../escape"] {
        assert_eq!(
            RemotePath::absolute(invalid).unwrap_err().code,
            ErrorCode::RemoteAbsolutePathRequired
        );
    }
    assert_eq!(
        RemotePath::absolute("/ok\0bad").unwrap_err().code,
        ErrorCode::InvalidArgument
    );
}
```

Delete `relative()` and configured-root escape expectations.

- [ ] **Step 2: Add end-to-end absolute-operation tests**

Build version-2 fixtures with a discovered fake alias and assert list, stat,
read, search, write, patch, and run pass their exact absolute operand to fake
SSH. Include a cwd outside the old `/home/wkj` root to prove no hidden profile
boundary remains.

```rust
assert_eq!(run_request.cwd, "/srv/other-project");
assert_eq!(read_result.files[0].actual_path.value, "/srv/other-project/a.txt");
```

- [ ] **Step 3: Add alias-only discovery and SSHFS tests**

Assert `remote_hosts` contains only aliases, `hosts list` uses the same sorted
set, and `build_sshfs_argv` never adds `-o ro` from bridge policy. Keep explicit
mountpoint identity, reconnect, strict SSH, no-forwarding, and nonempty checks.
Generate 257 concrete `Host test-000` through `Host test-256` stanzas and
assert all 257 sorted aliases are discovered and accepted. This is a regression
test for removal of the previous host-count limit; do not replace it with
truncation, paging, or an arbitrary new count.

- [ ] **Step 4: Commit, push, and observe the intended failure**

```bash
cargo fmt --all
git add tests/core.rs tests/remote_ops.rs tests/ssh_transport.rs tests/cli.rs tests/mcp_tools.rs
git commit -m "test: require absolute alias-only remote operations"
git push origin main
gh run watch "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: failures cite `RemotePath::absolute`, removed host fields, and old
configured-root operands.

## Task 4: Implement alias-only hosts and absolute operations

**Files:**
- Modify: `src/path.rs`
- Modify: `src/ssh/mod.rs`
- Modify: `src/ssh/argv.rs`
- Modify: `src/ssh/process.rs`
- Modify: `src/remote/mod.rs`
- Modify: `src/remote/run.rs`
- Modify: `src/remote/read.rs`
- Modify: `src/remote/write.rs`
- Modify: `src/remote/patch.rs`
- Modify: `src/remote/metadata.rs`
- Modify: `src/remote/search.rs`
- Modify: `src/cli.rs`
- Modify: `src/error.rs`

**Interfaces:**
- Consumes: Task 3 failing tests and version-2 config.
- Produces: normalized absolute paths, alias-only policy resolution, and
  transport capability root `/`.

- [ ] **Step 1: Replace `RemotePath::resolve` with `RemotePath::absolute`**

Normalize `.` and `..` lexically from `/`; reject non-absolute input with
`RemoteAbsolutePathRequired`; reject NUL. Remove stored `relative`.

- [ ] **Step 2: Make `SshPolicy::for_host` alias-only**

Use:

```rust
pub fn for_host(
    alias: &str,
    limits: EffectiveLimits,
    runtime_paths: &RuntimePaths,
    resolved_connection_identity: &str,
) -> BridgeResult<Self>
```

Validate with `Config::require_discovered_alias(alias)`. Generate the same
strict OpenSSH options and control filename. Remove `ResolvedHost`.

- [ ] **Step 3: Convert runner setup to `/` transport scope**

Capability probing and persistent session startup use `/`; the actual request
passes its normalized absolute cwd directly. Remove
`operation_root_for_path`, `root_relative_one`, and root-rewriting helpers.
Fixed file scripts receive absolute paths and keep their existing quoting and
NUL defenses.

- [ ] **Step 4: Remove host-profile behavior from remote operations**

Each resolver calls:

```rust
let _host = bridge.runner.config().require_discovered_alias(&request.host)?;
let path = RemotePath::absolute(&requested)?;
let limits = bridge.runner.config().limits();
```

Remove all `profile.root`, `profile.read_only`, description, and host override
branches. Remove `ReadOnlyHost` construction and stale model-visible fields.

- [ ] **Step 5: Reduce host info and CLI surface**

Use:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostInfo {
    pub host: String,
}
```

`hosts list` prints discovered aliases. Remove `AddHostArgs`, `HostName`,
`HostsCommand::{Add,Remove,Show}`, config writes, and `--read-only`.
`build_sshfs_argv` takes `host: &str`; mount result omits configured path,
physical root, and read-only policy metadata.

- [ ] **Step 6: Format, commit, push, and verify absolute-path suites**

```bash
cargo fmt --all
git diff --check
git add src tests
git commit -m "refactor: make remote paths and aliases explicit"
git push origin main
gh run watch "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: Task 3 tests pass; remaining failures should be fixed concurrency or
MCP-constructor references handled next.

## Task 5: Establish no-admission-limit and poisoned-generation failures

**Files:**
- Modify: `tests/mcp_protocol.rs`
- Modify: `tests/ssh_transport.rs`
- Modify: `tests/performance_acceptance.rs`
- Modify: `tests/fixtures/fake-ssh.sh`

**Interfaces:**
- Consumes: alias-only runner.
- Produces: deterministic failures for unlimited MCP task acceptance,
  cancellation at initialization phases, and generation eviction/recovery.

- [ ] **Step 1: Replace MCP queue-full tests with acceptance/cancellation tests**

Construct `McpServer::new(service, frame_bytes)` and send at least 64 valid
read-only calls held on a test gate. Assert every call enters the service,
`remote_hosts` remains responsive, cancellation of each ID completes cleanup,
and no response contains JSON-RPC code `-32000`.

- [ ] **Step 2: Add runner tests for cancellation at each pre-spawn phase**

Extend fake SSH gates for resolve, probe, helper handshake, and session-open.
For each gate:

```rust
let first_request = request(
    "dev",
    ShellRequest::Bash,
    Duration::from_secs(5),
);
let first = tokio::spawn(runner.execute(first_request, first_cancel.clone()));
wait_until_gate_is_held().await;
first_cancel.cancel();
assert_eq!(first.await.unwrap().unwrap_err().code, ErrorCode::Cancelled);
release_gate();
let recovery_request = request(
    "dev",
    ShellRequest::Bash,
    Duration::from_secs(5),
);
assert_eq!(
    runner
        .execute(recovery_request, CancellationToken::new())
        .await
        .unwrap()
        .status,
    0
);
```

Assert the recovery request creates at most one new generation and no stale
initializer remains.

- [ ] **Step 3: Add poisoned-session and inherited-pipe recovery tests**

Kill the fake dispatcher after OPEN and before EXIT; assert all current waiters
receive a transport error, the next call starts exactly one SSH child, and a
background descendant retaining stdout does not prevent the next request.

- [ ] **Step 4: Commit, push, and observe intended failures**

```bash
cargo fmt --all
git add tests/mcp_protocol.rs tests/ssh_transport.rs tests/performance_acceptance.rs tests/fixtures/fake-ssh.sh
git commit -m "test: define cancellation-safe unlimited scheduling"
git push origin main
gh run watch "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: old `McpServer::new` arity, queue-full behavior, runner semaphores, or
initializer/session state fail these tests.

## Task 6: Remove duplicate admission and implement session generations

**Files:**
- Modify: `src/main.rs`
- Modify: `src/mcp/mod.rs`
- Modify: `src/mcp/protocol.rs`
- Modify: `src/ssh/process.rs`
- Modify: `src/ssh/session.rs`
- Modify: `src/profile.rs`

**Interfaces:**
- Consumes: Task 5 tests.
- Produces:

```rust
struct HostGeneration {
    number: u64,
    session: Arc<HostSession>,
}

struct HostSlot {
    current: Mutex<Option<HostGeneration>>,
    next_number: AtomicU64,
}
```

- [ ] **Step 1: Remove MCP admission capacity**

Change `McpServer::new` to two arguments, remove `max_pending`,
`MCP_PENDING_WINDOW_EXTRA`, `is_control_tool`, and `server_busy_response`.
Use an unbounded writer channel so completion bookkeeping never blocks the
owner loop that must continue reading cancellation notifications:

```rust
let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
```

Keep frame/JSON/result-size bounds. Every syntactically valid call is registered
in `active` and spawned. Transport EOF still cancels and drains all active
tasks.

- [ ] **Step 2: Remove runner semaphores and initializer maps**

Delete `global_limit`, `host_limits`, `OperationReservation`,
`acquire_operation`, `wait_for_permit`, and concurrency validation. Replace
`initializers`, `sessions`, and `session_initializers` with:

```rust
host_slots: Mutex<HashMap<String, Arc<HostSlot>>>
```

- [ ] **Step 3: Implement cancellation-safe generation creation**

`session_for_host` obtains `HostSlot.current` with `tokio::select!` over lock
acquisition, request cancellation, and the remaining absolute deadline. The
mutex itself is the per-alias single-flight primitive:

1. return a cloned current session when it is not closed;
2. remove and close a dead current generation;
3. allocate the next generation number;
4. resolve/probe/connect while holding only this alias's creation lock and
   selecting cancellation/deadline at every await;
5. publish the new generation and release the lock;
6. on cancellation, timeout, or initialization error, drop the partially
   created child/session, leave `current=None`, and release the lock.

Waiters block only on this creation mutex and can independently cancel or time
out. No lock spans `session.execute`, output capture, rendering, or retention.

- [ ] **Step 4: Add one request-entry deadline**

Compute:

```rust
let deadline = Instant::now()
    .checked_add(request.timeout)
    .ok_or_else(|| BridgeError::invalid_argument("command timeout is too large"))?;
```

Pass `deadline` through policy resolution, capability probing, generation wait,
request send, execution, output drain, and cancel cleanup. Replace phase-local
full-duration sleeps with `remaining_timeout(deadline)`. Keep the separately
bounded connection timeout as:

```rust
min(remaining_timeout(deadline)?, Duration::from_millis(limits.connect_timeout_ms))
```

- [ ] **Step 5: Make generation eviction atomic**

`drop_session(alias, expected_generation)` removes only the exact generation
number and `Arc` currently stored. Fatal session errors call shutdown after
removal and notify waiters. Ordinary nonzero exit does not evict.

- [ ] **Step 6: Add profile phase events behind the existing feature**

Emit only IDs, phase, elapsed microseconds, and byte counts for:
`request_accepted`, `policy_resolved`, `generation_wait`,
`generation_start`, `generation_ready`, `generation_evicted`,
`session_sent`, `session_exit`, and `cancellation_cleanup`. Never log command,
path, stdin, environment, credentials, or output.

- [ ] **Step 7: Format, commit, push, and run full CI**

```bash
cargo fmt --all
sh -n src/ssh/dispatcher.sh
sh -n tests/fixtures/fake-ssh.sh
git diff --check
git add src tests
git commit -m "fix: align SSH lifecycle with Codex scheduling"
git push origin main
gh run watch "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: all Task 5 lifecycle tests pass, no source reference to
`global_concurrency`, `per_host_concurrency`, `MCP task queue full`, or
`SSH concurrency limiter` remains outside historical design documents.

## Task 7: Runtime-plan verification checkpoint

**Files:**
- Modify only if CI exposes a defect in this plan's scope.
- Inspect: all files listed above.

**Interfaces:**
- Consumes: Tasks 1-6.
- Produces: one green runtime checkpoint commit on `main`.

- [ ] **Step 1: Inspect CI failures without weakening the contract**

Use:

```bash
gh run view "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --json jobs,conclusion,url
gh run view "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --log-failed
```

Classify every failure as compile migration, deterministic test regression,
resource regression, or workflow issue. Do not restore removed fields or
semaphores to satisfy stale tests.

- [ ] **Step 2: Fix only evidenced runtime defects**

For each failure, add or tighten a focused assertion before the source fix.
Keep all old safety tests that do not depend on configured roots/read-only
policy/concurrency admission.

- [ ] **Step 3: Preserve protocol-shape, latency, and memory gates**

Require the existing release-mode performance suite to prove:

```text
bridge-only dispatch p95 < 2 ms
warm direct persistent-helper p95 < 10 ms
warm complete fake-SSH request p95 < 250 ms
one warm request sends exactly one business frame
warm requests run no ssh -G, capability probe, or helper-install round trip
all existing idle, output, retention, and cancellation RSS ceilings pass
```

Cold helper installation is reported separately and is not mixed into the
warm distribution. If CI runner noise violates a latency threshold, first use
the profile phases to identify the work; do not widen a gate without evidence
that the measured interval is outside bridge control.

- [ ] **Step 4: Commit only evidenced corrections and require green**

For every correction, add or preserve the focused failing assertion, then:

```bash
cargo fmt --all
git diff --check
git add src tests
git commit -m "test: close transparent runtime regressions"
git push origin main
gh run watch "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: all runtime, protocol-shape, latency, RSS, and diagnostics jobs pass
on the same `main` commit. Record the run URL for the next plan.
