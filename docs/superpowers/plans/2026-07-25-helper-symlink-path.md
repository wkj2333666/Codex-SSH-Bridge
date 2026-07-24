# Helper Symlink Path Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make the packaged bridge find the sibling `remote-helpers/` directory when launched through the stable symlink in `~/.local/bin`.

**Architecture:** Keep `CODEX_SSH_BRIDGE_HELPERS_DIR` as the explicit override. For the default path, canonicalize the executable, walk from `bin/` to the bundle root, and append the sibling `remote-helpers/` directory so versioned package assets remain discoverable through a symlink. Add a focused unit regression test for a symlinked executable path and the packaged layout.

**Tech Stack:** Rust 2024, standard library filesystem APIs, existing GitHub CI.

## Global Constraints

- Do not use Python or add runtime dependencies.
- Do not run local Cargo builds or tests; GitHub Actions is authoritative.
- Preserve the explicit helper-directory environment override and existing private-path validation.

### Task 1: Lock the symlink behavior with a regression test

**Files:**
- Modify: `src/ssh/helper.rs:366-415`

- [ ] **Step 1: Add a pure path-resolution test**

Create a temporary versioned executable path and a stable symlink, then assert the helper directory is resolved beside the versioned executable.

- [ ] **Step 2: Commit the test with the implementation change pending**

The local test run is intentionally omitted per the project constraint; CI must execute the test.

### Task 2: Resolve the sibling helper directory

**Files:**
- Modify: `src/ssh/helper.rs:327-339`

- [x] **Step 1: Extract `helper_directory_from_executable`**

Canonicalize the executable path, walk through its `bin/` parent to the bundle root, and append `remote-helpers`, preserving the explicit environment override unchanged.

- [x] **Step 2: Route `helper_directory` through the extracted function**

Return the same error class for missing or invalid executable paths.

### Task 3: CI verification and release handoff

**Files:**
- No additional source files.

- [ ] **Step 1: Push the source and test changes to `main`**

- [ ] **Step 2: Confirm GitHub CI passes the helper and packaging tests**

- [ ] **Step 3: Publish the next release and reinstall without the temporary MCP environment override**
