# Write-Back Edit Cache Design

## Context

The current `remote_apply_patch` path preserves strong remote-write semantics,
but it is expensive over a high-latency connection:

1. the bridge reads the complete remote file and its hash;
2. the bridge applies the patch locally; and
3. the bridge sends the complete replacement file back for guarded atomic
   installation.

A production benchmark against a configured Linux host measured the following
median warm edit latency:

| File size | Local filesystem | SSHFS | SSH bridge |
| --- | ---: | ---: | ---: |
| 8 KiB | 0.27 ms | 1,361 ms | 699 ms |
| 512 KiB | 1.47 ms | 5,942 ms | 4,538 ms |

The warm empty-command bridge baseline was 195 ms. MCP initialization took
1.47 ms, showing that local Rust and MCP dispatch are not the material cost.
The expensive part is repeated network round trips and complete-file transfer.

An analysis of local Codex tool-call order found 22 real remote mutations
grouped into eight edit batches before the next same-host `remote_run`. Those
22 mutations could therefore have required eight remote synchronization
operations instead of 22. All eight batches eventually reached a command
barrier, but only three did so within 30 seconds and one remained dirty for
about 20 hours. A command barrier alone is therefore useful but insufficient.

The mutation-size distribution was:

| Metric | Mutation payload |
| --- | ---: |
| Median | 1.6 KiB |
| 75th percentile | 4.5 KiB |
| 90th percentile | 13.3 KiB |
| Maximum | 27.3 KiB |

No observed edit batch reached 64 KiB. The active flush threshold is therefore
16 KiB, complemented by a 30-second maximum dirty age.

## Goals

- Make consecutive remote reads and code edits operate at local memory speed
  after the first complete-file fetch.
- Reduce multiple logical mutations to one remote synchronization request.
- Never leave dirty content buffered for more than 30 seconds under healthy
  connectivity.
- Ensure commands and filesystem-wide observations never run against known
  stale remote content.
- Preserve guarded writes, atomic replacement, conflict detection, mutation
  progress, and bounded failure behavior.
- Keep MCP output compact and close to the local Codex tool experience.
- Bound steady-state cache memory and transient RSS growth.
- Add no SSHFS workspace, global daemon, task-ID dependency, disk journal,
  systemd service, or watchdog.

## Non-goals

- Buffered mutation success will not mean that the remote file is already
  durable. The skill must describe this semantic explicitly.
- The bridge will not recover in-memory dirty data after its process is killed
  or crashes.
- Caches will not be shared across Codex tasks or MCP processes.
- The bridge will not hide a remote conflict by overwriting the newer remote
  file.
- The bridge will not implement a complete local overlay filesystem for
  directory listing, metadata, or search.
- The design does not change Codex's MCP-process upgrade lifecycle.

## Cache Scope and Identity

Each MCP bridge process owns one edit cache. It does not need a Codex task ID.
Entries are keyed by:

```text
(canonical SSH alias, validated absolute remote path)
```

The cache is not persisted to disk and is not shared with another MCP process.
Independent tasks remain independent. Concurrent tasks that modify the same
remote path are detected through the existing remote-state and SHA-256 guards.
Project worktrees remain the recommended way to isolate independent tasks.

Each complete entry records:

- the remote base state: missing or regular file with SHA-256 and relevant
  metadata;
- the current local state: present bytes or a deletion tombstone;
- a monotonically increasing local generation;
- the first-dirty timestamp;
- accumulated mutation payload bytes since the last synchronization;
- clean, dirty, syncing, transient-failure, or conflict state; and
- LRU accounting for clean entries.

File content uses shared immutable byte storage so a sync generation can hold
a stable snapshot without copying unchanged buffers. Applying a new mutation
creates only the next required content generation.

## Read and Mutation Data Flow

### Reads

`remote_read` serves a requested range from local content when a complete
cache entry exists. A partial remote read on a cache miss remains a normal
bounded remote read and does not pretend to populate the complete-file cache.

The first mutation of an uncached regular file fetches its complete content and
SHA-256 under existing size and consistency limits. This first edit still pays
network latency. Later reads and mutations use the cached generation.

### Patches

`remote_apply_patch` parses and validates the patch locally as it does today.
It resolves each absolute path, obtains a complete base when required, applies
the patch to the current cached generation, and records the resulting present
content or deletion tombstone.

All files in one tool call are prepared before the cache commits that local
generation. Invalid patches do not leave partial local cache changes.

### Writes

`remote_write` stores the supplied content as a local generation. Create and
guarded-replace modes still establish the required remote base state before
accepting a buffered mutation. Content hashes and sizes can be computed
locally, but the result is not described as remotely durable.

### Compact MCP output

Successful buffered mutations keep the approved compact, local-like output
shape. They do not add repeated context, synchronization advice, or an action
field. The durable behavioral warning belongs in the installed skill.

Errors remain factual. The model chooses the recovery operation.

## Synchronization Triggers

Dirty state is synchronized by the earliest of:

1. 30 seconds after the host first became dirty;
2. 16 KiB of cumulative mutation payload for that host;
3. a same-host synchronization barrier;
4. cache pressure that cannot be relieved by evicting clean entries; or
5. bounded best-effort MCP shutdown.

The 30-second timer measures maximum dirty age. Later mutations do not reset
it. Continuous editing therefore cannot postpone synchronization forever.

The 16 KiB counter measures patch and write input bytes accumulated since the
last successful synchronization. It does not measure the complete size of
files held in the cache; changing one line in a large file must not trigger a
flush merely because the file itself is large.

## Synchronization Barriers

The following same-host operations first wait for any in-flight generation and
then flush all remaining dirty generations:

- `remote_run`;
- `remote_stat`;
- `remote_list`; and
- `remote_search`.

If synchronization fails, the requested command or observation is not
executed. This prevents a test, search, or metadata query from observing a
known stale remote tree.

`remote_read` is not a barrier because it can serve the latest cached file
generation directly. `remote_hosts` and `remote_output_read` do not observe the
current remote filesystem and do not flush edits.

After a successful `remote_run`, the bridge invalidates all clean entries for
that host because an arbitrary command may have changed any file. A later read
or mutation obtains a fresh base.

## Batched Remote Commit

A host flush sends one bounded mutation batch through the persistent helper.
The batch contains each path's base state and final desired state, not every
intermediate local patch.

The helper validates rooted absolute paths and base guards, then performs the
existing safe-write or guarded-delete protocol sequentially. Each write uses a
same-directory temporary file and atomic rename. The batch reports:

- paths changed;
- paths not changed;
- the failed path, if any; and
- paths whose outcome is unknown.

The design does not claim multi-file transactional atomicity. Its partial
progress semantics match the current sequential multi-file patch boundary.

## Concurrent Edits During Synchronization

When a flush starts, it snapshots the current dirty generation under a short
local lock and releases the lock before network I/O. Later mutations create a
new generation and remain local-speed.

On successful synchronization:

- the synchronized generation becomes the new remote base;
- any newer dirty generation is rebased onto the returned final hash; and
- any newer dirty generation keeps the first-dirty timestamp recorded when
  that generation was created.

Each unsynchronized generation is therefore bounded by 30 seconds from its own
first mutation. Later mutations in the same generation do not reset its timer.

A same-host barrier waits until both the in-flight generation and every newer
generation are synchronized. It cannot run between two local generations.

## Failure and Conflict Semantics

Transient SSH, timeout, or helper-startup failures retain dirty data in memory.
The bridge records the failure and retries in the background with bounded
exponential delays capped at 30 seconds. A later barrier also retries
immediately.

Local cached reads and additional mutations may continue during a transient
network failure. A barrier returns the underlying synchronization error if it
still cannot commit and does not execute its requested operation.

A remote base mismatch is a permanent `WRITE_CONFLICT`, not a transient
transport failure. The affected path becomes conflicted:

- the bridge retains its local generation;
- it does not automatically retry or overwrite the remote file; and
- the next relevant tool operation returns the existing factual conflict
  error without an action recommendation.

Failed or ambiguous paths are never silently marked clean.

Normal MCP shutdown makes one bounded final synchronization attempt within
existing connection and command deadlines. Abnormal termination can lose
unsynchronized in-memory changes.

## Resource Bounds

The defaults are:

| Setting | Default |
| --- | ---: |
| `edit_flush_delay_ms` | 30,000 |
| `edit_flush_threshold_bytes` | 16 KiB |
| `edit_cache_max_bytes` | 16 MiB |

The cache limit covers complete content retained by the MCP process. Clean
entries are evicted by LRU. Dirty and syncing generations are never silently
evicted.

When the cache approaches its limit, it:

1. evicts clean LRU entries;
2. flushes dirty entries when necessary; and
3. falls back to the existing immediate remote mutation path when one
   operation still cannot fit safely.

The target is at most 16 MiB of steady cache-owned resident content and less
than 32 MiB additional peak RSS in the release pressure test. Existing
per-file read, write, frame, and output limits continue to apply.

## Skill Contract

The packaged remote-operation skill must state:

> 写操作可能先进入本地缓冲区。Bridge 会在 30 秒内或执行观察/命令操作前尝试同步；如果连接中断或 Bridge 异常退出，写入可能失败。同步失败时，后续远端命令不会执行。

The skill must not instruct Codex to manage cache state, call a flush tool, or
track generations. Synchronization remains bridge-owned and transparent.

## Tests

### Deterministic state-machine tests

Tests with paused time and a fake remote writer will cover:

- first complete-file fetch and subsequent local cache hits;
- partial reads not incorrectly creating complete entries;
- the 30-second timer not resetting after later edits;
- the exact 16 KiB payload threshold;
- clean LRU eviction and the 16 MiB aggregate limit;
- generation rollover while a flush is in flight;
- no lost edit across two or more generations;
- same-host barrier waiting for all generations;
- host independence;
- transient retry without busy looping;
- sticky SHA conflict without overwrite;
- bounded shutdown; and
- immediate-write fallback under cache pressure.

### Protocol and integration tests

Fake-SSH and real-sshd fixtures will cover:

- one remote batch for multiple buffered edits;
- safe create, replace, delete, and patch;
- multi-file partial progress;
- mutation-outcome-unknown propagation;
- `remote_run`, `remote_stat`, `remote_list`, and `remote_search` barriers;
- no barrier for cached `remote_read`;
- cache invalidation after `remote_run`;
- disconnect, reconnect, and retained dirty content; and
- two MCP processes producing a guarded conflict rather than lost updates.

### Performance and RSS acceptance

Release-profile diagnostics will separately measure:

- first-miss edit latency;
- warm buffered edit latency;
- timer and threshold batch-flush latency;
- same-host barrier latency;
- multiple hosts flushing independently;
- steady and peak RSS at the cache limit; and
- retained RSS after synchronized clean entries are evicted.

A warm buffered edit must not create an SSH session request. One batch must
produce one helper mutation request rather than one request per logical patch.

## CI, Release, and Manual Validation

The local Raspberry Pi remains source-editing and installation only. It does
not run Cargo build, test, Clippy, benchmark, or release commands.

GitHub Actions remains authoritative and will:

- run the deterministic, fake-SSH, real-sshd, protocol, performance, and RSS
  suites;
- retain the existing pinned toolchain, Cargo dependency, target, command-line
  tool, and cross-target caches;
- build the bridge for every supported main-program architecture;
- build every supported remote-helper architecture; and
- package the current plugin metadata, skill, and example configuration.

After CI and Release succeed, the installed release will be tested manually
against a configured Linux SSH host with:

- first-miss and repeated buffered patches;
- timer, threshold, and observation barriers;
- a command that validates the synchronized content;
- transient disconnect and reconnect;
- guarded conflict from a second MCP process;
- concurrent edit pressure; and
- MCP RSS, file-descriptor, process, and latency observations.

All temporary remote test files and processes are removed after validation.
