# Write-Back Edit Cache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make repeated remote code reads and edits local-memory operations while preserving guarded remote commits, forcing same-host synchronization before commands and filesystem observations, and bounding unsynchronized time and memory.

**Architecture:** Add one in-memory, per-MCP-process edit cache behind `RemoteBridge`. A pure Rust state machine owns complete file generations, dirty-age and payload thresholds, LRU accounting, retries, and conflicts. A production backend fetches guarded snapshots and commits each host's final desired states through one existing persistent-helper session request, partitioning only when the configured frame limit requires it. `RemoteBridge` keeps the public nine-tool surface unchanged and inserts cache reads, buffered mutations, same-host barriers, post-command invalidation, and bounded shutdown synchronization.

**Tech Stack:** Rust 1.91.1, Tokio, SHA-256, existing CXSB1 persistent SSH helper transport, POSIX safe-write scripts, MCP JSON-RPC, GitHub Actions.

## Global Constraints

- Do not run `cargo build`, `cargo test`, `cargo clippy`, release builds, or performance benchmarks on the local Raspberry Pi.
- Local checks are limited to source inspection, `git diff --check`, YAML/JSON/TOML parsing with already-installed non-Cargo tools, and `cargo fmt --all`.
- Push test commits to GitHub Actions to obtain RED/GREEN evidence. Use `gh run watch` and `gh run view --log-failed` through an approved network path when the sandbox blocks GitHub.
- Do not create a daemon, disk journal, SSHFS workspace, task-ID dependency, systemd service, watchdog, cache-control MCP tool, or model-visible synchronization protocol.
- Keep the MCP tool names, input schemas, text-first output shape, and factual error policy unchanged. Do not add an `action` field.
- Keep Bash as the default command shell. The edit cache must not introduce a shell-selection fallback.
- Preserve all existing safe-write, no-follow, root-path, cancellation, mutation-ambiguity, and output-bound guarantees.
- Use a minor release, `0.5.0`, because successful mutation calls acquire an intentionally different durability boundary.

---

## File Structure

### New files

- `src/remote/edit_cache.rs`: cache key/value types, generations, host state, LRU, timer scheduling, retry/conflict state, barrier coordination, and the testable backend trait.
- `src/remote/edit_sync.rs`: production snapshot/commit backend and bounded batch command/protocol.
- `tests/edit_cache.rs`: fake-backend state-machine and concurrency integration tests.

### Existing files with focused changes

- `src/config.rs`: three global edit-cache limits and validation.
- `src/remote/mod.rs`: cache ownership and tool-level routing.
- `src/remote/read.rs`: reusable byte slicing/rendering plus cache-aware reads.
- `src/remote/patch.rs`: expose guarded snapshot metadata and local patch preparation without immediate commit.
- `src/remote/write.rs`: expose safe mutation primitives and share their validation logic with the batch synchronizer.
- `src/mcp/protocol.rs`, `src/mcp/mod.rs`, `src/mcp/tools.rs`: a default no-op service shutdown hook and bounded bridge shutdown.
- `tests/core.rs`, `tests/remote_ops.rs`, `tests/mcp_tools.rs`, `tests/mcp_protocol.rs`, `tests/real_ssh.rs`, `tests/performance_acceptance.rs`, `tests/packaging.rs`: contract, integration, protocol, production-like, performance, RSS, and packaging coverage.
- `skills/remote-ssh-ops/SKILL.md`, `skills/remote-ssh-ops/references/operations.md`, `README.md`, `docs/security.md`, `docs/performance.md`: durability and performance contract.
- `.github/workflows/ci.yml`: run the new release diagnostics without adding another release compilation.

---

## Task 1: Freeze configuration and compatibility contracts

**Files:**

- Modify: `tests/core.rs`
- Modify: `src/config.rs`

**Steps:**

- [ ] Add RED tests asserting these `Limits::default()` values:
  `edit_flush_delay_ms = 30_000`,
  `edit_flush_threshold_bytes = 16 * 1024`, and
  `edit_cache_max_bytes = 16 * 1024 * 1024`.
- [ ] Add parsing/round-trip tests proving an existing version-2 config that omits the fields receives the defaults and a version-2 config may override them.
- [ ] Add boundary tests: all three values reject zero; delay rejects values above 300,000 ms; threshold rejects values above 4 MiB; cache size rejects values above 64 MiB; threshold may not exceed cache size.
- [ ] Assert the fields are global only and remain absent from `HostLimitOverrides`.
- [ ] Push the tests and confirm GitHub quality fails because the fields do not exist:
  `gh run watch "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status`.
- [ ] Add the three fields and public default/maximum constants to `src/config.rs`; retain `CONFIG_VERSION = 2` because serde defaults make the file format backward compatible.
- [ ] Extend `validate_limits`, `LimitsV1::default`, and `migrate_v1_text` so migration receives current defaults without changing old explicit limits.
- [ ] Run only `cargo fmt --all` and `git diff --check` locally.
- [ ] Commit with message `feat: configure write-back edit cache`.
- [ ] Push and verify the quality job is GREEN before proceeding.

---

## Task 2: Build the deterministic cache state machine

**Files:**

- Create: `src/remote/edit_cache.rs`
- Create: `tests/edit_cache.rs`
- Modify: `src/remote/mod.rs`

**Steps:**

- [ ] Write paused-time RED tests for a first fetch followed by cache hits, and for a partial read that does not create a complete entry.
- [ ] Write RED tests proving a second edit does not move the first generation's 30-second deadline and the cumulative payload flushes at exactly 16 KiB.
- [ ] Write RED tests for generation rollover while a flush future is held, rebasing a newer generation on the committed hash, and a barrier waiting through both generations.
- [ ] Write RED tests for independent hosts: a blocked host must not block cache hits, mutations, timers, or flushes on another host.
- [ ] Write RED tests for transient retry delays of 1, 2, 4, 8, 16, then 30 seconds without busy looping; a forced barrier bypasses the sleep once.
- [ ] Write RED tests for sticky `WRITE_CONFLICT`: retain local bytes, do not retry automatically, and return the same factual conflict to a relevant barrier.
- [ ] Write RED tests for clean-entry LRU eviction, dirty entries never being silently evicted, the 16 MiB accounting ceiling, and an oversize-operation result that selects immediate-write fallback without entering the cache.
- [ ] Push the tests and record the RED CI run.
- [ ] Define `CacheKey { host, path }`, `RemoteBase` (`Missing` or regular-file hash/mode), `DesiredState` (`Present(Arc<[u8]>)` or `Deleted`), and monotonic `Generation`.
- [ ] Define one `HostState` with an entry map, dirty payload counter, first-dirty deadline, clean-LRU sequence, optional in-flight generation, last transient error, sticky conflicts, and a `Notify` for barriers.
- [ ] Define an object-safe internal `EditBackend` whose boxed futures provide `fetch_complete` and `commit_batch`. Keep it crate-private and inject a fake backend in tests; do not add `async-trait`.
- [ ] Implement the state transitions using short `tokio::sync::Mutex` critical sections. Clone only `Arc<[u8]>`, batch descriptors, hashes, and small metadata before network I/O.
- [ ] Start at most one weak-reference timer worker per dirty host. Recompute its next deadline after every state transition; do not spawn one sleeper per edit.
- [ ] Serialize local mutation preparation per host, but release that gate before remote synchronization. Reads on cached entries and other hosts remain concurrent.
- [ ] Make cache shutdown idempotent and return after one caller-supplied bounded attempt.
- [ ] Run only `cargo fmt --all` and `git diff --check` locally.
- [ ] Commit with message `feat: add edit cache state machine`.
- [ ] Push and make the new deterministic suite GREEN.

---

## Task 3: Add one-request guarded batch synchronization

**Files:**

- Create: `src/remote/edit_sync.rs`
- Modify: `src/remote/write.rs`
- Modify: `src/remote/patch.rs`
- Modify: `src/remote/mod.rs`
- Modify: `tests/remote_ops.rs`
- Modify: `tests/fixtures/fake-ssh.sh` only if request accounting cannot distinguish mutation batches today

**Steps:**

- [ ] Add RED fake-SSH tests proving three buffered edits of one file produce one mutation request, a multi-file batch below the frame bound produces one mutation request, and a forced partition reports correct cumulative progress.
- [ ] Add hostile-path and binary-content tests, including spaces, quotes, dollar signs, newlines, leading dashes, NUL bytes in content, zero-length files, create, replace, delete, unchanged final content, and conflict.
- [ ] Add cancellation and broken-transport tests proving an ambiguous current path is never marked clean.
- [ ] Push the tests and record the expected missing-batch RED failures.
- [ ] Refactor the existing safe-write and guarded-delete shell definitions into reusable private fragments without changing their single-file behavior.
- [ ] Add `BatchMutation` descriptors containing the canonical host/path, base existence/hash, desired existence/hash/content length, and preserved mode.
- [ ] Encode descriptors as bridge-generated, safely quoted fixed arguments and concatenate only present-file bytes on stdin. The fixed batch script must consume each exact byte count with `dd`; arbitrary binary content and path whitespace/newlines must not become shell syntax.
- [ ] Execute the entire transport batch as one `FixedOperationKind::Mutation` through the existing persistent helper. Do not add a second helper process or a new CXSB1 connection.
- [ ] Make the remote script validate every entry's base immediately before that entry, then perform the existing same-directory temporary-file and atomic-rename or guarded-delete operation sequentially.
- [ ] Return a bounded NUL protocol with ordered per-path `CHANGED`, `UNCHANGED`, `CONFLICT`, or `UNKNOWN` records and the resulting hash/mode needed to rebase newer local generations.
- [ ] Preserve current multi-file partial progress: confirmed earlier paths are changed, the current ambiguous path is outcome-unknown, and later paths are not changed.
- [ ] Partition only when `command bytes + stdin bytes` would exceed `max_frame_bytes` or an existing write bound. Treat the partitions as one logical flush and carry confirmed progress forward.
- [ ] Implement `SshEditBackend` using the refactored guarded snapshot and batch commit functions.
- [ ] Keep the old immediate single-file write/delete path intact for cache-pressure fallback and for regression comparison.
- [ ] Run only `cargo fmt --all` and `git diff --check` locally.
- [ ] Commit with message `feat: batch guarded edit synchronization`.
- [ ] Push and make fake-SSH, remote-operation, and existing mutation safety tests GREEN.

---

## Task 4: Route reads, writes, and patches through the cache

**Files:**

- Modify: `src/remote/mod.rs`
- Modify: `src/remote/read.rs`
- Modify: `src/remote/write.rs`
- Modify: `src/remote/patch.rs`
- Modify: `tests/edit_cache.rs`
- Modify: `tests/remote_ops.rs`
- Modify: `tests/mcp_tools.rs`

**Steps:**

- [ ] Add RED tests for cached full read, uncached partial read, two local patches observing each other, create/read/delete tombstone behavior, multi-file all-or-none local preparation, SHA mismatch, binary write, immediate fallback, and unchanged compact MCP output.
- [ ] Push the tests and record the cache-routing RED failures.
- [ ] Construct `RemoteBridge` with an `Arc<EditCache>` configured from global `Limits` and an `SshEditBackend` sharing the same `SshRunner`.
- [ ] Extract read slicing into a pure helper that exactly preserves `start_line`, `max_lines`, `max_bytes`, UTF-8/base64 encoding, hashes, and truncation flags.
- [ ] Serve dirty and clean complete entries from memory. For a mixed multi-path read, combine cached entries with normal remote entries in request order and preserve one same-host `RemoteContext`.
- [ ] Populate a clean cache entry only when a normal remote read returns the complete file. A truncated or ranged miss remains uncached.
- [ ] Make the first mutation fetch a complete guarded snapshot, including missing state, hash, mode, and context. Deduplicate concurrent first fetches for the same path.
- [ ] Split patch handling into parse/resolve, obtain all current generations, pure local apply, and atomic local commit. If any file preparation fails, commit none of that tool call's local generations.
- [ ] Buffer `remote_write` create/replace after validating its requested base against the current cached or fetched generation. Preserve explicit SHA checks.
- [ ] Count mutation payload from the incoming patch or write content, not full cached file size.
- [ ] Return the existing compact MCP success text (`Done!` / `Wrote …`) with empty structured content. Do not add cache fields, durability advice, generations, or an action.
- [ ] For the internal `WriteResult`, use the fetched mode for replacement and `0600` for create, and set `temporary_cleanup_confirmed = false` until the batch commit; rendering remains unchanged.
- [ ] Exercise immediate-write fallback when the new complete generation cannot fit after clean eviction and a pressure flush.
- [ ] Run only `cargo fmt --all` and `git diff --check` locally.
- [ ] Commit with message `feat: buffer remote reads and mutations`.
- [ ] Push and make core, MCP-tool, and remote-operation jobs GREEN.

---

## Task 5: Install barriers, timers, retries, and command invalidation

**Files:**

- Modify: `src/remote/edit_cache.rs`
- Modify: `src/remote/mod.rs`
- Modify: `tests/edit_cache.rs`
- Modify: `tests/remote_ops.rs`

**Steps:**

- [ ] Add RED tests for all four barrier tools, all three non-barriers, post-command invalidation, barrier suppression on failure, timer flush, threshold flush, reconnect, and no cross-host head-of-line blocking.
- [ ] Add a RED stress test with concurrent cached reads, patches during an in-flight sync, barriers, and two hosts; assert final bytes and generations, not task scheduling order.
- [ ] Push the tests and record the barrier/timer RED failures.
- [ ] Before `remote_run`, `remote_stat`, `remote_list`, or `remote_search`, resolve the canonical alias and call `flush_host_barrier`.
- [ ] Do not start the requested operation when synchronization returns an error. Return that original factual error with existing host/shell/root context.
- [ ] Keep `remote_read`, `remote_hosts`, and `remote_output_read` non-barriers.
- [ ] After a successful `remote_run`, invalidate every clean entry for that host. Do not invalidate dirty or conflicted state.
- [ ] Ensure a same-host barrier waits for an in-flight generation and every newer generation created before the barrier can proceed.
- [ ] Make timer and threshold flushes use the same state transition and batch path as barriers; no duplicated synchronization implementation.
- [ ] Retain dirty state after connect timeout, helper startup failure, remote timeout, or other retryable transport failure. Retry in the background with the capped schedule from Task 2.
- [ ] Run only `cargo fmt --all` and `git diff --check` locally.
- [ ] Commit with message `feat: synchronize edits at remote barriers`.
- [ ] Push and make the deterministic and fake-SSH concurrency suites GREEN.

---

## Task 6: Flush once on normal MCP shutdown

**Files:**

- Modify: `src/mcp/protocol.rs`
- Modify: `src/mcp/mod.rs`
- Modify: `src/mcp/tools.rs`
- Modify: `src/remote/mod.rs`
- Modify: `tests/mcp_protocol.rs`
- Modify: `tests/mcp_tools.rs`

**Steps:**

- [ ] Add RED protocol tests for default no-op shutdown, exactly-once clean shutdown, bounded hanging shutdown, and no deadlock when a tool call is being cancelled.
- [ ] Add RED MCP-tool integration tests proving clean EOF flushes buffered bytes and a simulated process loss leaves the remote unchanged.
- [ ] Push the tests and record the shutdown-hook RED failures.
- [ ] Add an object-safe `ToolService::shutdown()` boxed future with a default no-op implementation so existing stub services need no behavioral change.
- [ ] On clean MCP EOF, first stop accepting new calls, cancel/drain active calls under the existing cleanup bounds, then invoke service shutdown once.
- [ ] Give bridge shutdown one final all-host flush attempt bounded by the configured connect/command deadlines and an MCP-level cap. Do not loop through background retry delays.
- [ ] On broken input/output transport, process abort, panic, or forced task cancellation, preserve current prompt termination behavior; do not claim dirty data was synchronized.
- [ ] Do not let final sync write MCP responses after the client has closed stdin.
- [ ] Run only `cargo fmt --all` and `git diff --check` locally.
- [ ] Commit with message `feat: flush buffered edits on mcp shutdown`.
- [ ] Push and make MCP protocol tests GREEN.

---

## Task 7: Publish the durability contract without burdening Codex

**Files:**

- Modify: `skills/remote-ssh-ops/SKILL.md`
- Modify: `skills/remote-ssh-ops/references/operations.md`
- Modify: `README.md`
- Modify: `docs/security.md`
- Modify: `docs/performance.md`
- Modify: `tests/packaging.rs`
- Modify: `tests/mcp_tools.rs`

**Steps:**

- [ ] Add RED packaging and MCP-output assertions for the exact warning, unchanged nine-tool schema, compact buffered success, factual sync errors, and absence of `action`.
- [ ] Push the tests and record the missing-documentation RED failures.
- [ ] Add this exact warning once in the installed skill:
  `写操作可能先进入本地缓冲区。Bridge 会在 30 秒内或执行观察/命令操作前尝试同步；如果连接中断或 Bridge 异常退出，写入可能失败。同步失败时，后续远端命令不会执行。`
- [ ] Keep the normal workflow unchanged: discover alias, use absolute paths, read narrowly, patch, then verify with `remote_run`. Do not tell the model to track cache state or call a flush operation.
- [ ] Document that success means accepted into the task-owned bridge buffer, while barriers and healthy timers establish remote durability.
- [ ] Document conflict, crash-loss, cache isolation, memory ceiling, command invalidation, and why this is not SSHFS.
- [ ] Keep the nine tool definitions and their input schemas unchanged; no new `remote_flush` tool.
- [ ] Keep buffered success and sync errors within existing MCP output budgets and free of duplicated host/root/shell blocks or `action`.
- [ ] Package the updated skill/reference files in every release archive.
- [ ] Run only `cargo fmt --all`, `git diff --check`, and source-format inspection locally.
- [ ] Commit with message `docs: explain buffered remote edit durability`.
- [ ] Push and make packaging and MCP-output tests GREEN.

---

## Task 8: Add production-like latency, RSS, and real-SSH gates

**Files:**

- Modify: `tests/performance_acceptance.rs`
- Modify: `tests/real_ssh.rs`
- Modify: `.github/workflows/ci.yml`
- Modify: `docs/performance.md`

**Steps:**

- [ ] Add release-only profile cases that report first-miss edit, warm buffered edit, timer flush, threshold flush, barrier flush, and two-host independent flush percentiles separately.
- [ ] Assert a warm buffered edit creates zero SSH session requests and that several logical edits below the frame bound create one helper mutation request at flush.
- [ ] Add a fresh-child RSS case that fills the cache to 16 MiB, synchronizes, evicts clean entries, and reports baseline, steady, peak, and retained RSS.
- [ ] Gate steady cache-owned content at 16 MiB and additional peak RSS below 32 MiB. Keep existing output/session RSS gates unchanged.
- [ ] Extend the real-sshd fixture with create/replace/delete batching, a same-host command barrier, two independent bridge processes producing `WRITE_CONFLICT`, disconnect/reconnect with retained dirty data, and cleanup verification.
- [ ] In `.github/workflows/ci.yml`, add these cases to the existing release diagnostics job rather than a new compilation job.
- [ ] Compile all required release test binaries in the existing `Prepare release diagnostic binaries` step once. Invoke the new filtered cases afterward so Cargo reports a cache hit and does not rebuild.
- [ ] Keep the pinned toolchain, Cargo registry/git, quality target, diagnostics target, ripgrep, cross binary, and per-target release caches. Do not merge them into one oversized cache or weaken Clippy/tests/RSS coverage.
- [ ] Upload edit-cache profile and RSS logs with `release-diagnostics`.
- [ ] Run only `cargo fmt --all`, YAML inspection, and `git diff --check` locally.
- [ ] Commit with message `test: gate edit cache latency and rss`.
- [ ] Push and require both `Rust quality and tests` and `Release profile and RSS diagnostics` to pass.
- [ ] Compare Actions step timings and cache-hit annotations with the last pre-feature run; if the diagnostics job recompiles, correct only the feature/profile mismatch or target list causing it.

---

## Task 9: Complete CI review and harden only evidenced failures

**Files:**

- Modify: only files implicated by failing tests, Clippy, formatting, or diagnostic evidence

**Steps:**

- [ ] Inspect the latest run:
  `gh run list --workflow CI --branch main --limit 5`.
- [ ] Watch it to terminal state:
  `gh run watch RUN_ID --exit-status`.
- [ ] For failure, fetch only failed logs:
  `gh run view RUN_ID --log-failed`.
- [ ] Fix the smallest demonstrated defect. Do not add a queue limit, watchdog, daemon, root-observation round trip, or model-visible recovery advice.
- [ ] Run only `cargo fmt --all` and `git diff --check` locally; commit and push each focused correction.
- [ ] Repeat until formatting, Clippy, all debug tests, real sshd, release profiles, RSS gates, and packaging pass in the same commit.
- [ ] Review the final diff against the design document and explicitly verify every non-goal remains absent.

---

## Task 10: Release, install, and manually pressure-test 0.5.0

**Files:**

- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `.codex-plugin/plugin.json`
- Modify: version-specific packaging expectations if present

**Steps:**

- [ ] Set package, lockfile, and plugin versions to `0.5.0` without building locally.
- [ ] Commit `chore: release 0.5.0`, push `main`, and wait for the authoritative CI commit to pass.
- [ ] Create and push annotated tag `v0.5.0`.
- [ ] Watch Release until every supported main-program architecture, every supported remote-helper architecture, archive assembly, checksum, and publication job succeeds.
- [ ] Inspect the aarch64 archive contents before installation: bridge binary, all helper architectures, plugin manifest, skill and references, README/docs, license, and `.mcp.json.example`.
- [ ] Download the aarch64 release, verify its published SHA-256, and run the packaged installer with `install --user --apply`.
- [ ] Remove superseded managed release directories through the installer so only `0.5.0+release` remains; confirm the stable `~/.local/bin/codex-ssh-bridge` symlink and Codex MCP registration resolve through that stable link.
- [ ] Start a fresh Codex task or Desktop MCP client instance so it launches the newly installed bridge. Do not expect an already-running task-owned MCP process to hot-upgrade.
- [ ] Start a separate raw 0.5.0 MCP process for reproducible measurements and use configured aliases only.
- [ ] Against `nkai`, create a unique temporary directory and measure: first full read/edit, at least 20 warm buffered patches, cached reads, 30-second timer flush, exact 16-KiB threshold flush, `stat/list/search/run` barriers, post-run invalidation, and final file contents.
- [ ] Against a second configured host, run concurrent buffered edits and barriers to prove there is no cross-host head-of-line blocking.
- [ ] Interrupt connectivity, accept another buffered edit, restore connectivity, and prove the retained generation synchronizes. Separately terminate a disposable raw MCP process with dirty state and confirm the documented loss boundary.
- [ ] Use two raw MCP processes on the same remote file and prove the later guarded flush returns `WRITE_CONFLICT` rather than overwriting.
- [ ] Record bridge-reported latency plus end-to-end wall time, helper request counts, RSS baseline/steady/peak, file descriptors, local bridge/helper processes, and remote helper processes.
- [ ] Remove all temporary remote files and confirm no temporary mutation files or test processes remain.
- [ ] If manual testing exposes a defect, return to Task 1-style RED CI coverage before changing production code; publish a patch release only after CI and the same manual scenario pass.

---

## Completion Evidence

- [ ] One approved design document and this implementation plan are committed on `main`.
- [ ] GitHub CI is GREEN for the exact release commit.
- [ ] Release `v0.5.0` contains every main and helper architecture and the updated skill.
- [ ] The local installation resolves to `0.5.0+release`; old managed versions are removed.
- [ ] A fresh bridge process passes real-host timer, threshold, barrier, conflict, reconnect, concurrency, latency, and RSS checks.
- [ ] Warm buffered edits produce no SSH request, and a below-frame batch produces one helper mutation request.
- [ ] The user-facing warning accurately states that a connection interruption or abnormal bridge exit can lose buffered writes.
