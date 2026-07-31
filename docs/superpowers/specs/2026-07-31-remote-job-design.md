# Remote Job Design

## Context

`remote_run` is intentionally synchronous. It owns one request until the
remote command exits, a configured timeout expires, or the MCP caller cancels
the request. That contract works well for bounded commands, builds, and tests,
but it is the wrong lifetime boundary for training, downloads, servers, and
other work that must survive an SSH connection, Codex task, Desktop process,
or bridge restart.

Increasing `remote_run` timeouts would keep the command tied to an MCP call and
an SSH session. Shell detachment such as `nohup ... &` would make process
identity, status, logs, cancellation, and uncertain launch outcomes the
model's responsibility. Both approaches reduce transparency and recreate the
session-blocking failures that the bridge is meant to prevent.

## Goals

- Add durable remote jobs without changing `remote_run` behavior.
- Let a new Codex task discover and manage jobs started by an earlier task.
- Let jobs survive local MCP, Desktop, and SSH disconnection.
- Keep launch, status, log, cancellation, and deletion semantics factual and
  compact enough for Codex.
- Prevent long jobs from occupying a bridge request, SSH session, or local
  output spool entry.
- Preserve the existing absolute-path, shell, edit-synchronization, output,
  and untrusted-remote-data boundaries.
- Add no systemd unit, daemon, resident supervisor, watchdog, restart policy,
  fixed job-count limit, or fixed concurrency limit.

## Non-goals

- Jobs do not automatically restart or resume after the remote machine
  reboots.
- The bridge does not provide distributed scheduling, dependency graphs,
  resource allocation, interactive terminals, or service health management.
- A Job is not a replacement for a workload manager such as Slurm or for an
  application-owned durable checkpoint.
- Job logs are bounded diagnostics, not an unlimited business-data store.
- This design does not change Codex's MCP-process upgrade lifecycle.

## Tool Surface

Remote Job is a separate tool family. `remote_run` remains synchronous and
retains its current schema, cancellation, timeout, and output behavior.

| Tool | Required input | Optional input | Compact success result |
| --- | --- | --- | --- |
| `remote_job_start` | `host`, `command`, absolute `cwd` | `shell`, `stdin`, `timeout_ms`, `label` | `job_id`, `state` |
| `remote_job_status` | `host`, `job_id` | none | state, exit status, timestamps, retained and observed log lengths |
| `remote_job_logs` | `host`, `job_id` | `stdout_offset`, `stderr_offset`, `max_bytes` | bounded stdout/stderr pages and independent next offsets |
| `remote_job_cancel` | `host`, `job_id` | none | `job_id`, resulting state |
| `remote_job_list` | `host` | `max_jobs` | newest-first job summaries |
| `remote_job_delete` | `host`, `job_id` | none | deleted `job_id` |

`remote_job_start` uses the same command, absolute working-directory, stdin,
and shell shapes as `remote_run`. Bash remains the default. An explicit `sh`
or login shell is honored, and an unavailable explicitly requested shell is an
error rather than a silent fallback. Remote output remains untrusted.

`timeout_ms` is a positive job-lifetime timeout. It is optional; absence means
no bridge-enforced job timeout. It is not capped by the synchronous
`command_timeout_ms`, because doing so would prevent the intended long-running
use case. The MCP tool-call deadline bounds only launch acknowledgement.

`label` is optional UTF-8 text of at most 256 bytes with no NUL, for human and
model recognition. It does not participate in identity or authorization.
`remote_job_list` defaults to the newest 100 summaries and permits at most
1,000. Summaries contain the job ID, label, state, working directory,
timestamps, and exit status, but not the full command or stdin.

`remote_job_logs` uses zero-based byte offsets independently for stdout and
stderr. `max_bytes` bounds their combined returned payload, defaults to 256
KiB, and is capped at 1 MiB like existing bounded reads. The result reports
each stream's next offset, end-of-file state, retained length, observed length,
and truncation state. Already retained bytes and their offsets never change
while the job is running.

## Remote Storage and Runner

Each host stores jobs below:

```text
~/.local/state/codex-ssh-bridge/jobs/<job_id>/
```

The bridge generates `job_id` locally before any remote mutation as 128 random
bits encoded as lowercase hexadecimal. The exact opaque ID is the only legal
directory name. The job root and per-job directories use mode `0700`; regular
files use `0600`.

One directory contains:

```text
request
state
stdout.log
stderr.log
runner.lock
```

`request` is immutable and records the admitted command parameters without
placing them in the process command line. `state` is an atomically replaced,
versioned record. The logs are append-only until the runner exits.
`runner.lock` is held exclusively for the runner lifetime.

The packaged Rust helper supplies a short-lived internal job-runner mode. One
runner exists per active job and exits when that job reaches a terminal state.
It is not a persistent bridge daemon or supervisor.

Job tools are advertised only when the installed binary helper can guarantee
independent process groups, reliable detachment, advisory file locking,
atomic same-directory replacement, and process identity verification. A host
using the POSIX shell fallback returns a factual capability-missing error
instead of emulating unsafe detachment.

## Start Data Flow

`remote_job_start` performs these steps:

1. Validate the discovered alias, absolute working directory, shell, stdin,
   timeout, label, and request-size limits.
2. Flush the host's buffered edits using the same synchronization barrier as
   `remote_run`. A failed or ambiguous flush prevents launch.
3. Generate the job ID before the first remote mutation.
4. Securely create the job directory and atomically install the immutable
   request and initial `starting` state.
5. Ask the helper to spawn its own executable in internal job-runner mode with
   a fresh session and no inherited SSH stdin, stdout, or stderr.
6. The runner acquires `runner.lock`, opens the persistent logs, creates a
   separate process group for the requested command, records verified process
   identity, and atomically changes the state to `running`.
7. The launch helper returns success only after receiving that readiness
   handshake. The SSH request may then end without affecting the job.

The runner continuously drains both output streams. It waits for the command,
enforces the optional lifetime timeout, and atomically writes exactly one
terminal state before releasing its lock and exiting.

Job creation is independent of the bridge's persistent command-session pool.
An active job therefore consumes no bridge request slot or SSH session and
cannot serialize normal run, search, read, or mutation operations.

## State and Identity

The state machine is:

```text
starting -> running -> succeeded
                    -> failed
                    -> cancelled
                    -> timed_out
starting/running    -> lost
```

`succeeded` means exit code zero. `failed` records a nonzero exit code or
signal-derived status. `cancelled` and `timed_out` mean the verified process
group was observed terminated for that reason. All five are terminal states.

PID alone is never process identity. The state record includes the remote boot
identity and a kernel process-start token for the runner and command-group
leader. Status and cancellation compare those tokens with the current process
before treating a PID or process group as belonging to the job. This prevents
PID reuse from targeting an unrelated process.

Status reconciles the durable state with `runner.lock`:

- a held lock plus matching process identity means the job is active;
- a released lock plus a valid terminal record returns that terminal state;
- a nonterminal record with a released lock is atomically classified as
  `lost` only when both the recorded runner and command process group are
  verified absent, or when the recorded boot identity differs from the current
  boot; and
- contradictory or unverifiable evidence returns a factual integrity error
  rather than guessing.

A reboot changes boot identity. A previously nonterminal job is consequently
reported as `lost`; it is not restarted.

## Cancellation and Deletion

Cancellation is idempotent. A terminal job returns its existing state. For an
active job, the bridge first verifies boot and process-start identity, then
sends `TERM` to the job's process group, waits a five-second grace period, and
uses `KILL` only if the same verified group remains alive. The runner records
`cancelled` after observing termination.

If the bridge cannot prove which process it terminated or cannot prove that it
terminated, it returns `cancel_outcome_unknown`. It must not report
`cancelled`. No signal is sent when identity verification fails.

Deletion is serialized with status and cancellation. It accepts only a
verified terminal job, refuses active or uncertain jobs, closes all open files,
and removes exactly the validated opaque-ID directory. It never follows a
symbolic link.

## Launch Uncertainty and Errors

The job ID makes an interrupted launch recoverable without duplicate work.

- If launch is known not to have started, the helper removes the incomplete
  directory and returns the underlying deterministic error.
- If the remote mutation or runner launch may have happened but the
  acknowledgement is lost, the error contains `job_id` and
  `start_outcome_unknown`.
- The caller resolves an unknown result with `remote_job_status` or
  `remote_job_list`. It must not retry `remote_job_start` blindly.

All other errors remain factual and contain no suggested action. Transport
failure, missing capability, invalid state, identity mismatch, log truncation,
and retention expiry remain distinguishable error or result fields.

## Logs and Retention

The runner captures at most the host's effective `max_output_bytes` across the
two log files, 64 MiB by default. Both streams are always drained so a verbose
child cannot block after the retention budget is exhausted. A shared byte
budget retains bytes in arrival order; later bytes are discarded while the
runner continues counting per-stream `observed_bytes` and records truncation.

This remote log storage is independent of the bridge's local `output_ref`
spool and its ten-minute lifetime. Applications that require complete logs
must write their own project log as part of the submitted command.

Terminal jobs are retained for seven days from their terminal timestamp. Each
Job tool performs bounded lazy garbage collection before its requested
operation. Garbage collection removes only securely validated terminal job
directories older than seven days. It does not scan outside the fixed job root
and never delays one call with an unbounded directory walk. Explicit deletion
remains available.

## Security Boundaries

- Every job operation validates an exact 32-character lowercase hexadecimal
  job ID before resolving a path.
- Directory traversal uses descriptor-relative, no-follow operations. Any
  symbolic link, wrong owner, group/world-writable component, unexpected file
  type, or incompatible record version is rejected.
- Request and state records have bounded lengths and closed schemas. Commands,
  labels, logs, exit messages, and all other remote bytes are untrusted.
- Command text and stdin are stored only in the protected request file and are
  omitted from list output. MCP responses remain bounded and compact.
- Job tools honor the same host discovery and configured-root execution
  authority as existing tools. The job metadata root itself is bridge-owned
  state, not a caller-selected path.
- No job operation invokes an interactive shell profile unless the caller
  explicitly requests login-shell semantics.

## Concurrency and Resource Bounds

Jobs on one or many hosts run independently. The bridge adds no arbitrary
host-count, active-job, or global concurrency limit. Remote operating-system
limits remain authoritative and launch failures are returned directly.

Metadata operations use short per-job locks only while reading or replacing
records. Log reads do not block the writer. Starting, inspecting, or cancelling
one job cannot hold the normal SSH dispatcher queue while the job itself runs.

The local MCP process retains no command, stdin, log body, join handle, or
session ownership after launch acknowledgement. Completed jobs consume only
bounded remote files until deletion or retention expiry.

## Tests

### Deterministic tests

State-machine and filesystem tests cover:

- every legal and illegal state transition;
- atomic request and state installation;
- job-ID, path, owner, mode, symlink, record-version, and size validation;
- shell selection, command quoting, stdin admission, labels, and optional
  timeout semantics;
- independent log offsets during concurrent append;
- shared output-budget exhaustion while both streams continue draining;
- seven-day retention and bounded lazy garbage collection; and
- idempotent status, cancellation, and deletion behavior.

### Fake transport and helper tests

Integration fixtures cover:

- SSH or MCP disconnection before and after the runner readiness handshake;
- a dropped successful launch response returning a recoverable job ID;
- a new bridge process discovering, inspecting, reading logs from, cancelling,
  and deleting an earlier process's job;
- normal exit, nonzero exit, signal exit, timeout, cancellation escalation, and
  runner loss;
- PID reuse, boot-identity change, stale locks, contradictory records, and
  refusal to signal an unverified process group;
- concurrent status, log, cancel, list, and delete calls;
- large-output truncation without child-process blockage; and
- failure of Job tools on incapable shell-fallback hosts.

### Real SSH and release acceptance

The real-SSH workflow starts a job, tears down its initiating SSH and bridge
processes, starts a new bridge, and verifies discovery, incremental logs,
terminal status, cancellation, and deletion. It also verifies that the job
leaves no SSH child or bridge-owned local spool entry after acknowledgement.

Performance acceptance requires no material regression in existing cold and
warm `remote_run`, read, search, and cancellation tests. Job start, status, and
log reads must release request memory after each MCP response, and a pressure
run with many terminal jobs must remain within existing bridge RSS and file
descriptor ceilings.

After CI and release workflows pass, the release is installed and manually
tested against `nkai` and `weibo`: start bounded and long jobs, disconnect and
restart the bridge, recover them from a new session, page logs, cancel a process
tree, verify terminal states, delete jobs, and pressure normal searches while
jobs run.

## Delivery

The Raspberry Pi remains source-editing only. No local Cargo build, test,
Clippy, release build, or performance benchmark is run. A test-only commit
demonstrates RED in GitHub Actions, implementation commits produce GREEN, and
the release workflow builds the bridge and all helper architectures. Manual
production pressure testing begins only after installing the resulting GitHub
release.
