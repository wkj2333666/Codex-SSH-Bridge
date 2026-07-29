# Single Connect Deadline Design

## Context

`codex-ssh-bridge` 0.5.6 intends `connect_timeout_ms` to bound one complete
host/session setup attempt, but the implementation starts independent timeout
budgets for capability initialization, session creation, request-queue send,
and remote READY admission. With the default 10-second connect timeout, one
minimal request can therefore remain in pre-command setup for roughly 30
seconds. A transient network failure can make every cold or stale host session
appear wedged at once even though `remote_hosts` remains responsive.

Production measurements on one MCP process reproduced the issue:

- `nkai` completed in 2.9 seconds;
- `whhpc` completed in 4.8 seconds;
- `weibo` completed in 32.0 seconds;
- `jnyxy` returned `CONNECT_TIMEOUT` after 17.9 seconds; and
- `tkserver` returned `REMOTE_EXIT` after 25.5 seconds.

All requests used the same bounded command and an eight-second command timeout.
The command timeout correctly applies only after remote READY, so it cannot
bound the duplicated setup budgets.

## Goal

Make one configured `connect_timeout_ms` value the upper bound for all
pre-command work in one bridge execution attempt, without changing warm-command
behavior or remote command timeout semantics.

## Design

Create one absolute Tokio `Instant` at the start of each runner execution.
Use that same deadline for:

1. waiting for the per-host capability initializer;
2. SSH identity and capability discovery;
3. waiting for the per-host session initializer;
4. persistent, temporary-helper, or POSIX session establishment;
5. sending the framed request to the session writer; and
6. waiting for the remote READY admission frame.

No phase may derive a fresh full-duration timeout. Functions that need a
duration for OpenSSH or child setup receive only the time remaining before the
shared deadline.

`SessionRequest` carries the absolute admission deadline rather than a
duration. The writer-queue send and READY wait both consume that same budget.
The remote command timeout still starts at READY and remains independent.

When setup fails or is cancelled, the existing initializer guards unwind
normally. A non-reusable session is removed before returning. No command is
retried after request-frame delivery may have begun.

## Scope

The change covers both execution paths:

- `SshRunner::execute`, used by `remote_run`; and
- `SshRunner::execute_fixed_once`, used by remote file, search, metadata,
  patch, write, and edit-cache synchronization operations.

It adds no daemon, watchdog, circuit breaker, heartbeat, background probe,
retry loop, configuration field, or MCP schema change.

## Tests

Fake SSH will support a bounded delay immediately before session startup.
Regression tests will spend part of the connect budget in capability probing
and the remainder in session startup, then require:

- `CONNECT_TIMEOUT`;
- total wall time bounded by one configured connect timeout plus CI scheduling
  tolerance;
- no command frame after the setup deadline; and
- a later request can establish a fresh session.

Both normal and fixed-request execution paths receive regression coverage.
Existing cancellation, mutation-ambiguity, concurrency, and real-SSH tests
remain authoritative.

## Delivery

The Raspberry Pi remains source-editing only. A test-only commit demonstrates
RED in GitHub Actions, the implementation commit produces GREEN, and the
release workflow builds all bridge/helper architectures. After installing the
new release, manual mixed-host probes verify cold, warm, timeout, cancellation,
and recovery behavior.
