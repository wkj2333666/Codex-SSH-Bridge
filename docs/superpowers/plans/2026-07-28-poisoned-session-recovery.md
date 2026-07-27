# Poisoned Session Recovery Implementation Plan

> **Execution rule:** Do not run Cargo build, test, Clippy, benchmark, or release
> commands on the local Raspberry Pi. GitHub Actions is the authoritative build
> and test host.

**Goal:** Retire an SSH session after cancellation or timeout cannot be
confirmed, so later calls never reuse a possibly poisoned transport.

**Architecture:** Add one atomic retirement bit to `HostSession`. Set it only
when request cancellation does not receive a bounded completion. Make
`SshRunner` cache lookup admit only reusable sessions and remove retired
instances by identity.

**Tech stack:** Rust 1.91.1, Tokio, OpenSSH, MCP JSON-RPC, GitHub Actions.

## Task 1: RED regression

- [ ] Extend `tests/ssh_transport.rs` so an unconfirmed cancellation is followed
      by a same-host request.
- [ ] Assert that the follow-up starts a second SSH session instead of entering
      the first session.
- [ ] Push the test-only commit and retain the failing CI evidence.

## Task 2: Minimal implementation

- [ ] Add atomic retirement state to `HostSession`.
- [ ] Retire only when cancellation delivery or completion is unconfirmed.
- [ ] Replace `is_closed` cache checks with a reusable-session check.
- [ ] Remove a retired cached session after the originating call returns.
- [ ] Push and require the complete GitHub CI suite to pass.

## Task 3: Release pressure test

- [ ] Build all artifacts through the GitHub Release workflow.
- [ ] Install the new aarch64 bridge and all helper architectures.
- [ ] Verify parallel search cancellation and immediate same-host recovery.
- [ ] Verify an affected host does not block a second alias.
- [ ] Repeat the RED→GREEN→Release loop for every newly reproduced defect.
