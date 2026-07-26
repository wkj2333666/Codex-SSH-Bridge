# Session Liveness, Compact MCP Output, RSS, and CI Design

## Context

`codex-ssh-bridge` 0.4.4 can enter a state where `remote_hosts` remains
responsive but remote operations for an SSH alias never reach the remote
helper. A fresh 0.4.4 MCP process can use the same alias successfully, so the
failure is not explained by an outdated installation or an unavailable host.

Live inspection established four relevant facts:

1. The affected MCP process and registered executable were both 0.4.4.
2. The remote persistent helper was alive and waiting for request input.
3. A fresh raw MCP process completed the same `nkai` command successfully.
4. Session acquisition and its per-host single-flight lock are outside the
   command response deadline, while every MCP process currently derives the
   same OpenSSH `ControlPath` for a given alias and resolved identity.

The fourth point permits an internal session acquisition failure to outlive the
tool timeout and also couples independent Codex tasks through a detached
OpenSSH master. A separate production measurement also showed retained RSS
growth caused by eagerly allocating both output preview buffers for every
request, including zero-output requests.

## Goals

- Make every pre-dispatch stage bounded and cancellation-safe.
- Prevent one failed session initializer from blocking later requests forever.
- Isolate OpenSSH connection reuse to one MCP process while preserving reuse
  inside that process.
- Add no heartbeat, watchdog, daemon, systemd unit, or hot-path network round
  trip.
- Never retry a mutation after its request frames may have reached the helper.
- Reduce empty-request RSS retention without weakening output bounds.
- Make `remote_hosts` as compact and predictable as the analogous local host
  discovery result.
- Reduce GitHub CI latency without moving builds or tests onto the local
  Raspberry Pi.

## Non-goals

- The bridge will not make an already running Codex task hot-load a newly
  installed MCP executable.
- The bridge will not retain old release installations for stale tasks.
- The bridge will not add task IDs or infer Codex workspace identity.
- The bridge will not add background health polling.
- The bridge will not automatically replay a command whose delivery is
  ambiguous.
- Other remote tool result shapes will not be broadly redesigned in this
  release.

## Session and Connection Boundary

### One bounded setup budget

The configured `connect_timeout_ms` is the upper bound for a single session
connection attempt. It covers:

- waiting to become the per-host session initializer;
- spawning SSH;
- reading the persistent-helper install status;
- uploading helper bytes when required;
- reading the helper handshake; and
- bounded child termination and drain after a setup failure.

Cancellation remains independently active throughout those stages. Cleanup is
best effort and bounded; returning an error must not wait forever for a child
process.

The user command timeout continues to describe remote command execution. It is
not consumed by capability discovery before the command exists, but callers
will no longer wait indefinitely in that discovery or session-acquisition
phase.

### Cancellation-safe single flight

Only one task may establish a session for an alias at a time. Followers wait
under the same bounded setup budget. When the leader succeeds, followers reuse
the resulting session. When it fails or is cancelled, it publishes failure,
removes the in-flight generation, and permits a later request to start a new
attempt.

No follower remains attached to an abandoned mutex owner or an unresolved
generation.

### Retry boundary

The bridge may retry connection establishment only before any request frame
has been accepted by a session writer. Once request delivery may have started,
the bridge returns the transport, cancellation, or timeout result and preserves
the existing `remote_process_may_continue` ambiguity semantics. It does not
replay the command.

### Per-MCP-instance OpenSSH reuse

The hashed `ControlPath` gains a runner-instance nonce generated when the MCP
service constructs its `SshRunner`. All connections made by one MCP process to
the same resolved host may reuse its private master, but another MCP process
cannot attach to it. This preserves capability-probe to persistent-session
cold-start reuse without coupling Codex tasks and does not require Codex to
provide a task ID.

The private master has a five-second `ControlPersist` grace sufficient for cold
initialization. It is not a service and is not shared globally. Warm remote
commands continue to use the already established persistent helper session and
therefore gain no additional SSH handshake or probe.

## MCP Result Shape

`remote_hosts` remains text-first for Codex readability:

```text
jnyxy
nkai
tkserver
weibo
```

Its structured content becomes:

```json
{"hosts":["jnyxy","nkai","tkserver","weibo"]}
```

It will no longer return an empty object or repeat cached shell, root,
description, and read-only metadata. Alias discovery is the only behavior of
this tool. Detailed per-host state belongs to the operation that actually
needs it.

All other remote tools retain their approved text-first shapes in this release.
Errors remain factual and do not include a suggested `action`; Codex decides
the next operation.

## Output Memory

`PreviewSink` will allocate its head and tail storage lazily. Empty output keeps
zero-capacity buffers. A stream allocates only when bytes actually arrive, and
never beyond the existing preview and aggregate limits.

The change does not alter truncation, UTF-8 rendering, output references,
spooling, or byte accounting.

The release RSS acceptance test will:

1. start and warm one release MCP process;
2. issue 1,000 zero-output requests with concurrency 20;
3. require post-warm RSS growth of at most 8 MiB; and
4. require growth across the final five observation rounds of at most 2 MiB.

File descriptors and thread counts remain bounded and are recorded with the RSS
evidence.

## CI and Release

The Raspberry Pi remains source-editing and installation only. No local Cargo
build, test, Clippy, benchmark, or release build is part of this work.

GitHub Actions will:

- cache the pinned Rust toolchain and command-line test tools;
- add a target cache to the quality job so dependency and test artifacts are
  not rebuilt from zero on every push;
- retain the separate release-profile diagnostics cache;
- avoid duplicate package-manager work on cache hits;
- keep cross-target caches in the default-branch scope so later tags can
  restore them; and
- continue building every supported bridge and helper target in Release.

CI remains authoritative. A temporary pushed commit first demonstrates the new
regression tests failing, then the implementation commit makes them pass.

## Tests

The regression suite will cover:

- helper status received followed by a handshake that never completes;
- helper upload backpressure where the remote side stops reading;
- bounded cleanup when an SSH child refuses to exit promptly;
- a follower waiting behind a failed or cancelled session initializer;
- a second request successfully starting after the failed generation is
  removed;
- distinct `ControlPath` values for separate runner/MCP process instances;
- identical `ControlPath` reuse within one instance;
- no retry after request-frame delivery becomes ambiguous;
- compact `remote_hosts` text and structured output;
- lazy zero-output preview allocation and the release RSS gate.

After CI and Release succeed, the installed release will be exercised manually
against both `nkai` and `weibo` with:

- cold and warm minimal commands;
- same-host concurrency;
- mixed-host concurrency;
- bounded timeout and recovery;
- file read/write/patch cleanup;
- several independent raw MCP processes; and
- RSS, file-descriptor, and child-process observations.

## Release and Installation

The release version will advance from 0.4.4 to 0.4.5. GitHub Release produces
all bridge and helper architectures. Installation removes the previous managed
release and leaves only the new managed package, with:

- the local architecture bridge under `bin/`;
- every packaged remote helper beside it under `remote-helpers/`;
- plugin resources and the current skill included in the package; and
- both `~/.local/bin/codex-ssh-bridge` and Codex MCP registration resolving
  through the stable symlink.

A running Codex task still owns its already-started MCP child. The documented
upgrade procedure is to install, fully quit Codex, reopen it, and start or
resume a task. That lifecycle behavior is not emulated inside the bridge.
