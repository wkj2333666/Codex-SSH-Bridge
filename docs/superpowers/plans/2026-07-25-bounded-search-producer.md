# Bounded Remote Search Producer Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (recommended) to implement this plan task-by-task.

**Goal:** Make remote search return as soon as its bounded output frame is full, instead of draining an unbounded remote `find`, `rg`, or `grep` producer.

**Architecture:** Keep the existing FIFO framing, output limits, capability probes, cancellation, and error protocol. After `head -c` reaches the configured byte limit, close the reader and terminate the producer; only wait for normal producer completion when the stream ended below the limit. Apply the same bounded-consumer rule to candidate, ripgrep, and grep scripts.

**Tech Stack:** Rust 2024, POSIX shell scripts embedded in Rust, existing GitHub Actions CI. No new dependency and no Python.

## Global Constraints

- Do not run local Cargo build, test, clippy, release, or benchmark commands; GitHub Actions is authoritative.
- Preserve `CAPPED\0`, capability mismatch, engine-error, output-limit, cancellation, and timeout semantics.
- Never expose an unbounded remote stream to the local bridge after the configured frame limit is reached.
- Keep Bash/default-shell and helper transport behavior unchanged.

## File Map

- Modify `src/remote/search.rs`: terminate bounded producers instead of draining their complete output.
- Test `src/remote/search.rs`: add a regression assertion covering all three embedded scripts.
- Update `docs/performance.md` or `docs/security.md` only if the existing documentation describes search as fully traversing a tree after a byte cap.

### Task 1: Define the no-drain regression

- [ ] Add a unit regression that checks candidate, rg, and grep scripts do not contain the old `cat <&3 >/dev/null` drain and do contain bounded producer termination.
- [ ] Do not run the test locally; record that it is intentionally RED until the script change is made.

### Task 2: Stop producers at the byte cap

- [ ] Remove the unconditional drain from all three scripts.
- [ ] Close fd 3 after `head`, detect `bytes = limit`, terminate the producer, and tolerate producer termination caused by the cap.
- [ ] For an uncapped stream, retain strict producer/status/engine-error checks.
- [ ] Keep `CAPPED\0` on stderr when the exact byte limit is reached.

### Task 3: CI verification

- [ ] Run `git diff --check` locally only.
- [ ] Commit and push to `main`.
- [ ] Use GitHub Actions to run formatting, clippy, tests, and release compilation; do not substitute local Cargo commands.
- [ ] If CI exposes shell portability or cancellation regressions, fix them in a follow-up commit and repeat CI.
