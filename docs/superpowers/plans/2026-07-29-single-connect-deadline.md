# Single Connect Deadline Implementation Plan

> **Execution rule:** Do not run Cargo build, test, Clippy, benchmark, or
> release commands on the local Raspberry Pi. GitHub Actions is the
> authoritative build and test host. Local validation is limited to source
> inspection, diffs, and rustfmt.

**Goal:** Bound all pre-command SSH work by one configured connect deadline for
both `remote_run` and fixed remote operations.

**Architecture:** Create one absolute setup deadline at each runner entry and
pass it through capability initialization, session creation, writer admission,
and the remote READY wait. Preserve the independent command timeout that begins
at READY.

**Tech stack:** Rust 1.91.1, Tokio, OpenSSH, MCP JSON-RPC, GitHub Actions.

## Global Constraints

- Add no daemon, watchdog, circuit breaker, heartbeat, background probe,
  retry loop, configuration field, or MCP schema change.
- Do not replay a command after request-frame delivery may have begun.
- Do not run Rust builds or tests locally.
- Require test-only RED evidence in GitHub Actions before implementation.

---

### Task 1: Add RED setup-budget regressions

**Files:**

- Modify: `tests/fixtures/fake-ssh.sh`
- Modify: `tests/ssh_transport.rs`

**Interfaces:**

- Consumes: `Limits.connect_timeout_ms`, `SshRunner::execute`, and
  `SshRunner::execute_fixed_once`.
- Produces: fake session-start delay control and behavior tests for one shared
  setup budget.

- [ ] Add `FAKE_SSH_SESSION_START_SLEEP_SECONDS` immediately before fake
  dispatcher/helper startup.
- [ ] Add a normal-run test that consumes one budget across probe and session
  startup, returns `CONNECT_TIMEOUT`, stays below a hand-derived wall-time
  ceiling, and emits no command marker.
- [ ] Add the equivalent fixed-request test.
- [ ] Run `cargo fmt --all` locally; do not compile.
- [ ] Commit and push the test-only change.
- [ ] Confirm GitHub CI fails because the old implementation resets the setup
  deadline after capability initialization.

### Task 2: Thread one absolute deadline through setup

**Files:**

- Modify: `src/ssh/process.rs`
- Modify: `src/ssh/session.rs`
- Update: any test constructors that create `SessionRequest` directly.

**Interfaces:**

- Consumes: one `tokio::time::Instant` created at runner entry.
- Produces: `SessionRequest.admission_deadline: Instant` and session setup that
  only receives the remaining shared budget.

- [ ] Create the setup deadline before capability-initializer acquisition in
  `execute` and `execute_fixed_once`.
- [ ] Pass the exact deadline into `session_for_host`; remove its fresh
  deadline.
- [ ] Derive the HostSession connect duration only from the remaining shared
  budget.
- [ ] Replace `SessionRequest.admission_timeout` with
  `admission_deadline`.
- [ ] Use the same admission deadline for writer send and READY wait.
- [ ] Preserve the separate response deadline that starts after READY.
- [ ] Run `cargo fmt --all` locally; do not compile.
- [ ] Commit and push.
- [ ] Require all GitHub CI jobs, release diagnostics, and architecture checks
  to pass.

### Task 3: Release, install, and manually verify

**Files:**

- Modify version metadata required by the existing release workflow.

**Interfaces:**

- Consumes: GitHub release artifacts.
- Produces: one installed release with the local bridge architecture and all
  packaged helper architectures.

- [ ] Bump the patch release version.
- [ ] Push the release tag and wait for GitHub Release success.
- [ ] Install the release through the packaged installer, leaving only the new
  managed version.
- [ ] Verify the stable binary symlink and Codex MCP registration.
- [ ] Start a fresh MCP process and pressure-test all discovered aliases in
  parallel.
- [ ] Verify a failing host consumes no more than one connect budget plus
  transport/CI tolerance while healthy hosts complete independently.
- [ ] Verify warm commands, same-host concurrency, cancellation, and a
  post-timeout recovery request.
