# Transparent Runtime Reliability Design

Date: 2026-07-25
Target release: 0.4.0

## Goal

Make `codex-ssh-bridge` behave like Codex's local execution surface while
retaining SSH-specific transport optimizations. A Codex task should be able to
replace a local file or command operation with the corresponding `remote_*`
tool without learning bridge queues, helper deployment, configured roots, or
SSH session recovery.

This design fixes the production failures found after installing 0.3.2 and
manually exercising `nkai`:

- a request can become stuck before an SSH child is spawned and leave later
  requests waiting behind bridge-owned admission state;
- Codex can lose the actual aliases from `remote_hosts` even though raw MCP
  contains them;
- a command timeout can look like an ordinary exit status 124;
- renderer overflow retention can expose serialized internal result structures
  instead of the original model-visible stream;
- search globs are unexpectedly relative to a configured host root instead of
  the requested search path;
- fixed bridge concurrency limits duplicate Codex's own tool scheduler;
- release target caches are scoped to individual tags, duplicated between the
  bridge and helper matrices, and have brought repository cache use to roughly
  9.06 GB.

The design also completes previously approved configuration behavior that the
current implementation has not fully migrated: SSH aliases come from the
user's OpenSSH configuration, every operation supplies absolute remote paths,
and there is no host allowlist, configured host root, or host read-only mode.

## Evidence and model

The relevant execution stack is:

```text
LLM
  -> Codex task tool runtime
  -> long-lived local stdio MCP child
  -> codex-ssh-bridge request
  -> persistent SSH session for one alias
  -> persistent remote helper or shell dispatcher
  -> remote process/filesystem
```

Codex 0.144.5 treats MCP tools with `readOnlyHint=true` as parallel-capable.
Tools without that property use the same exclusive tool gate as local
side-effecting operations. Codex also owns the MCP tool-call timeout and
cancellation token. The bridge must honor that lifecycle, not add a second
fixed-capacity policy visible to the model.

Independent raw stdio MCP and direct CLI tests prove that 0.3.2 can execute on
`nkai` with a healthy persistent helper. A hung Codex-task call showed no SSH
child under the bridge process, which places the wait before remote process
spawn. The solution therefore covers every local wait phase and session
generation transition rather than patching only the HTTP-server symptom.

## Versioning

This is a pre-1.0 minor release because it intentionally removes obsolete
configuration and CLI behavior and changes search and timeout semantics.
Version 0.4.0 has no compatibility mode that restores fixed bridge scheduling,
configured roots, or the old result-retention format.

The installer performs a one-time configuration migration so an existing
0.3.x installation can upgrade without manual editing.

## Host and workspace contract

### Alias discovery

`remote_hosts` discovers concrete aliases from the user's local OpenSSH
configuration, including its user-config includes. It does not use a
bridge-owned allowlist and does not impose a host-count limit.

Discovery keeps these rules:

- wildcard-only patterns are not exposed as callable aliases;
- negated patterns are not exposed;
- `Include` files are followed with cycle and depth protection;
- invalid MCP alias strings are omitted;
- discovery is local-only and does not connect to any host;
- OpenSSH remains authoritative for hostname, user, port, identity, proxy, host
  key, and authentication behavior.

The bridge does not invent an alias or guess a hostname when the requested
alias is absent.

### Absolute remote paths

There is no configured host root and no task-ID-to-workspace mapping.

- `remote_run.cwd` is an absolute remote directory.
- All file tool paths are absolute remote paths.
- `remote_search.path` is an absolute remote directory.
- SSHFS remains an explicit human-only operation with an explicit absolute
  remote source and local mountpoint.

The bridge normalizes and validates the supplied absolute path but does not
pretend it is a local workspace path. Remote symlinks, bind mounts, and mount
changes follow ordinary remote filesystem semantics.

### Removed host policy

The following are removed from the active configuration and CLI:

- `[hosts.*]`;
- host `root`;
- host `description`;
- host `read_only`;
- per-host limit overrides;
- `hosts add`, `hosts remove`, and `hosts show`;
- `READ_ONLY_HOST` as a reachable runtime outcome.

`hosts list` may remain as a human-readable alias-discovery command and must
use the same discovery source as `remote_hosts`.

Read-only MCP annotations remain. They describe a tool's side effects to Codex;
they are unrelated to the removed host read-only policy.

### Configuration migration

Configuration version advances to 2.

During `install --user --apply`, the new packaged binary:

1. reads and securely validates an existing version-1 configuration;
2. verifies that every explicitly stored host alias is discoverable through
   the effective OpenSSH config;
3. preserves the remaining global byte, timeout, spool, and retention limits;
4. removes the host table and concurrency fields;
5. writes version 2 atomically with private permissions;
6. records enough state in the install journal to restore the exact old file if
   a later installation step fails.

If an old explicit alias is not discoverable, installation fails factually
without changing the configuration. The user can add it to OpenSSH config and
retry.

The version-2 active limits are:

- `connect_timeout_ms`;
- `command_timeout_ms`;
- `max_frame_bytes`;
- `read_chunk_bytes`;
- `max_read_bytes`;
- `max_write_bytes`;
- `preview_bytes`;
- `max_output_bytes`;
- `global_spool_quota_bytes`;
- `retention_serialization_jobs`.

## Scheduling and lifecycle

### Codex owns ordinary tool scheduling

The bridge removes `global_concurrency` and `per_host_concurrency` from
configuration, effective limits, runner semaphores, and MCP pending-window
derivation.

Observable behavior:

- ordinary concurrency never returns `Server busy`;
- there is no host-count or per-host request-count limit;
- read-only tools remain annotated read-only and may run concurrently when
  Codex permits;
- mutations and `remote_run` remain side-effecting and Codex may serialize
  them exactly as it does local side-effecting tools;
- separate Codex tasks behave like separate local Codex processes and are not
  globally serialized by the bridge.

The MCP reader still enforces the wire-frame bound. The output store still
enforces entry and byte quotas. OS allocation failures remain factual I/O
failures. These are integrity bounds, not an ordinary admission scheduler.

### Request deadline

Every host-scoped request computes one absolute deadline at request entry. The
deadline covers:

1. SSH policy resolution;
2. capability and helper initialization;
3. single-flight session creation;
4. session acquisition;
5. request-frame send;
6. remote execution;
7. output drain;
8. cancellation cleanup.

Every await in these phases selects among completion, the request cancellation
token, and the remaining deadline. A phase cannot reset the full timeout or
wait forever after an earlier phase has consumed part of it.

Local serialization needed for output retention uses its own small bounded
worker pool and cannot hold a host session or delay completion of the remote
request.

### Session generations

Each alias has at most one current session generation per bridge process.
Initialization is cancellation-safe single-flight state:

- only generation creation is protected by the initializer;
- no business request holds the initializer while executing remotely;
- waiters observe the same success or factual initialization failure;
- a cancelled waiter leaves generation creation running only while another
  live waiter or owner still needs it;
- an abandoned initializer cannot leave a permanently pending state.

Fatal transport, framing, helper handshake, or cancellation-cleanup failure
atomically marks the generation dead, removes it from the alias slot, closes
the local SSH child, and wakes every waiter. A later request creates a fresh
generation. No request is automatically replayed after it may have begun a
mutation.

### Request isolation and cancellation

Every request has an independent request ID, cancellation token, output
collectors, and remote process group.

- Cancelling a request before send performs no remote work.
- Cancelling a running read or command sends the request cancel frame.
- If termination is not confirmed within the bounded cleanup grace, the whole
  session generation is closed.
- Mutation uncertainty is preserved whenever the remote side may have applied
  a change.
- Completing or cancelling one request releases all request-local state even
  if a descendant inherited stdout or stderr.
- A late frame for a completed request is discarded by generation and request
  ID and cannot complete a newer request.

`remote_hosts` remains a local control operation and never waits for a host
session.

### Background descendants

When a shell exits but a descendant such as an HTTP server retains inherited
stdout or stderr:

- the request gets only a short bounded drain window;
- the result sets `remote_process_may_continue=true`;
- collectors detach safely without retaining an admission slot or initializer;
- the next request may use the same healthy session immediately.

This behavior remains covered by a real `python3 -m http.server` workload on
`nkai`; Python is test workload only and is not a bridge dependency.

## Timeout protocol

Exit status 124 is not sufficient evidence of a timeout because a user command
may deliberately return 124.

The helper/dispatcher EXIT frame gains an explicit `timed_out` field:

```text
EXIT <request-id> <exit-status> <process-may-continue> <timed-out>
```

Both implementations set it only when their own deadline watchdog terminates
the request. The local session parser validates the field.

- `timed_out=false`, status 124: ordinary successful tool result with
  `exit_code=124`.
- `timed_out=true`: `COMMAND_TIMEOUT` tool error.
- If descendants may remain, the timeout error also contains
  `remote_process_may_continue=true`.
- Timeout errors contain facts only and never an `action` field.

The local Rust request deadline is authoritative and sends a cancel frame at
millisecond precision. The binary helper also uses a Tokio deadline. The shell
dispatcher watchdog is only a remote safety backstop and may use the best
timing primitive available on that server; correctness does not depend on
fractional `sleep` support. Measured completion may include bounded
process-termination and framing time, but the timeout decision must not be
rounded up to the next whole second.

## Search contract

`remote_search.globs` are relative to the requested `remote_search.path`.

For a request with:

```json
{
  "path": "/work/project/src",
  "globs": ["*.rs"]
}
```

`*.rs` matches files directly inside `/work/project/src`; `**/*.rs` matches
nested files according to the existing separator-aware glob behavior.

Rendered match paths remain absolute so the model cannot mistake them for local
files. Search candidate production, search execution, stream parsing, and
output retention all obey cancellation and the request deadline. Reaching a
configured match/candidate/output bound returns truncation, not a stuck
producer.

## MCP result contract

### Essential discovery data

`remote_hosts` returns aliases in both representations:

```text
content.text:
jnyxy
nkai
weibo
```

```json
structuredContent:
{"hosts":["jnyxy","nkai","weibo"]}
```

This intentional small duplication makes aliases survive Codex app/tool
adapter presentation. It does not restore verbose host profiles, roots,
descriptions, capabilities, or shell metadata.

All other successful tools keep the 0.3.x compact contract: large business
payload appears only in `content`; `structuredContent` contains only small
state such as exit code, truncation, paging cursor, or uncertainty.

### Retained output

The renderer retains the complete model-visible presentation bytes, not a
serialized internal Rust result.

- `remote_output_read` returns the next raw page of those presentation bytes.
- Page metadata contains only `next_offset`, `eof`, and, when the page itself
  is shortened, `truncated` plus the same `output_ref`.
- Retained pages never expose `RemoteRunResult`, `ReadResult`, provenance,
  helper mode, raw byte counters, or other internal fields.
- Source-level output truncation and renderer-level 32 KiB truncation converge
  on the same presentation-stream contract.

The output store may retain stream bytes in binary-safe form internally.
UTF-8 pages are cut only at valid character boundaries; binary data remains
encoded according to the existing value encoding contract.

### Errors

Errors remain factual:

```json
{
  "error": {
    "code": "COMMAND_TIMEOUT",
    "message": "remote command timed out"
  }
}
```

Only outcome-relevant fields are added. `action` and `suggested_action` remain
forbidden.

## Diagnostics

The release binary has no ordinary per-request logging and adds no model-visible
diagnostic fields.

The existing compile-time profile feature gains request-phase events:

- MCP request accepted;
- host policy resolved;
- generation wait/start/ready/evicted;
- session request sent;
- first/last output frame;
- remote exit received;
- cancellation started/confirmed/escalated;
- rendering and retention completed.

Events contain opaque request/generation IDs, phase name, elapsed microseconds,
and byte counts. They never contain commands, paths, credentials, environment,
stdin, or remote output.

This instrumentation is used by CI profile tests and optional manual diagnosis
but is compiled out of the normal release path so hot-request cost remains
effectively zero.

## CI and cache design

### Cache policy

The repository currently stores roughly 9.06 GB of caches because debug target
caches are keyed by commit SHA and release target caches are saved separately
for every tag and for bridge/helper jobs.

The new policy uses:

1. one fixed quality target cache per runner architecture, Rust toolchain,
   cache-schema version, and dependency-graph hash;
2. one fixed diagnostics target cache under the same stable dimensions;
3. one main-branch cross target cache per target triple, shared by bridge and
   helper builds;
4. one shared Cargo registry/Git cache per toolchain and dependency-graph hash;
5. one minimal Rust toolchain cache per component profile;
6. one `cross` binary cache per runner architecture, Rust version, and pinned
   cross version.

The dependency-graph hash covers both `Cargo.toml` and `Cargo.lock`. Commit SHA
and release tag are not target-cache key components. Project source is cheap to
rebuild; dependency artifacts are the reusable payload. A manually advanced
cache-schema component invalidates caches when compiler flags or workflow build
semantics change without a manifest change.

### Main-branch prewarm

A `cross-cache` workflow runs on:

- changes to `Cargo.toml` or `Cargo.lock` on `main`;
- changes to the pinned Rust/cross configuration;
- changes to the cross-cache workflow;
- manual dispatch.

Its eight-target matrix builds the main bridge for all release targets and the
helper for the six supported helper targets in the same target directory. It
saves caches in default-branch scope, which later tag workflows may restore.

### Release workflow

Release uses one eight-target build matrix instead of separate eight-job bridge
and six-job helper matrices.

- Every target builds the bridge.
- The six helper targets also build and verify the helper in the same job.
- Jobs restore main-scoped caches but do not save tag-scoped target caches.
- Packaging still emits eight archives.
- Every archive contains its target's bridge plus all six helpers, Skill,
  plugin manifest, examples, license, README, and required docs.
- Publish remains gated on every build and package job.

### CI workflow

- Formatting, Clippy, ordinary tests, packaging metadata, release profile, RSS,
  cancellation, and protocol tests remain mandatory.
- Quality and diagnostics continue in parallel.
- Ordinary tests may use Cargo's normal parallelism.
- RSS/profile tests remain explicitly isolated where measurement requires it.
- Stable cache keys eliminate one multi-gigabyte cache per commit.
- `ripgrep` is installed only when absent.

After the new main-scoped caches are proven usable, obsolete SHA- and tag-scoped
target caches are deleted. The shared Cargo, toolchain, and cross caches are
kept. Cache inventory must remain comfortably below GitHub's repository limit.

## Test-first implementation

No production behavior changes before failing tests establish each contract.
Tests run in GitHub Actions, not on the local Raspberry Pi. Local work is
limited to source editing, `cargo fmt`, shell syntax checks, YAML/static
inspection, and Git operations.

Required deterministic tests include:

1. version-1 config migration removes hosts, roots, read-only policy, and
   concurrency fields while preserving all remaining limits;
2. aliases are discovered from OpenSSH config with includes and no host-count
   cap;
3. every remote operation accepts absolute paths without configured roots;
4. concurrent requests are not rejected or gated by bridge concurrency
   semaphores;
5. cancellation during each initialization/session phase releases waiters and
   permits a fresh request;
6. a poisoned session generation is evicted and rebuilt once;
7. a timed-out request cannot block a later request;
8. explicit exit 124 is not a timeout;
9. helper and shell timeouts produce the explicit timeout flag;
10. `*.txt` is relative to the requested search path;
11. a cancelled/bounded search stops every producer;
12. aliases survive both MCP content and structured result paths;
13. renderer overflow pages reconstruct exactly the original presentation and
    contain no internal serialization;
14. inherited-pipe HTTP-server completion does not block the session;
15. existing mutation uncertainty, path validation, atomic write, expected
    hash, hostile-output, frame, spool, RSS, and shell-fallback tests remain
    green.

## Production acceptance loop

Static tests are necessary but not sufficient. Every candidate release follows
this loop:

1. push `main`;
2. wait for all GitHub CI jobs and inspect failures/logs;
3. trigger or verify main-scoped cross caches;
4. tag and publish the immutable release;
5. download the aarch64 main archive and verify its checksum;
6. install the packaged bridge, Skill, plugin metadata, and all six helpers;
7. verify the Codex MCP registration points at the new managed version;
8. start an independent raw stdio MCP client and assert
   `serverInfo.version`;
9. start a fresh real Codex client so MCP lifecycle and result adaptation are
   exercised, then operate `nkai`;
10. run read, stat, list, write, patch, search, Bash-default, explicit-sh,
    large-output paging, exit-124, timeout, cancellation, background HTTP
    server, concurrent reads, and session-break/recovery scenarios;
11. measure cold setup, at least 30 warm no-op calls, and bounded concurrency;
12. verify cleanup leaves no test files, HTTP servers, or stale test helpers;
13. inspect cache hit logs and total cache size.

The failure-injection scenarios deliberately include:

- a broad search cancelled or timed out while producing candidates;
- a descendant retaining inherited stdout/stderr;
- an SSH/session generation terminated during a request;
- a cancelled request during session initialization;
- large output crossing the 32 KiB renderer boundary.

Any newly exposed defect returns to the test-first implementation step. A
release is not complete merely because CI is green or direct SSH works.

## Completion criteria

Version 0.4.0 is complete only when:

- source, config examples, README, security/performance docs, Skill, and package
  contents describe the same behavior;
- all GitHub CI and release jobs pass;
- all release architectures and helpers exist with verified checksums;
- the installed binary and active Codex registration both report 0.4.0;
- a fresh Codex client visibly receives the actual host aliases;
- repeated `nkai` production tests recover after every injected failure without
  `Server busy`, indefinite queueing, or manual bridge restart;
- timeout, paging, and glob behavior match this contract;
- warm bridge/SSH/helper latency remains network-dominated with no new remote
  round trip;
- cache use is materially below the current 9.06 GB and subsequent main/tag
  runs show reusable cache hits;
- the repository is clean and local `main` equals `origin/main`.

## Rejected alternatives

### Patch individual symptoms

Adding another timeout around search, increasing the semaphore limits, or
special-casing HTTP servers leaves duplicate scheduling and poisoned session
state intact.

### Retry automatically

Automatic retry can duplicate remote mutations. Recovery creates a fresh
session for the next explicit request; it does not replay an uncertain request.

### Global bridge daemon

A machine-wide HTTP/Unix-socket daemon could share SSH sessions between Codex
tasks, but adds authentication, multi-task isolation, daemon upgrade, stale
workspace, and crash-recovery complexity. The persistent per-task helper
already removes remote bootstrap cost. A long-lived stdio MCP child matches
Codex's supported local model more closely.

### SSHFS agent workspace

SSHFS makes remote files look local and can cause the model to apply local path
assumptions, local watchers, or destructive commands to a remote tree. It
remains an explicit human-only convenience and is not part of Agent operation.
