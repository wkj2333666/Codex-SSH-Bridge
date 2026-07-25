# Local Codex Output Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. This project policy forbids local Cargo builds and tests; every Cargo verification step below runs in GitHub Actions.

**Goal:** Release 0.3.0 with remote MCP results that are as compact and local-Codex-like as possible while retaining the existing specialized remote tools and SSH behavior.

**Architecture:** Keep `RemoteBridge`, SSH sessions, dispatcher/helper, retention, and internal result types unchanged for ordinary synchronous requests. Modify the existing MCP renderer to select concise text and structured fields, cap model-visible output at 32 KiB, and retain complete details only through the existing opaque reference mechanism. Fix the dispatcher lifecycle so a completed shell parent cannot hold a host request slot hostage through inherited output pipes; report that a child may continue. A full process-handle API is deliberately a separate follow-up design, not an implicit `remote_run` flag. Remove prescriptive error actions at the MCP boundary.

**Tech Stack:** Rust 1.91.1, serde/serde_json, existing Tokio MCP server, GitHub Actions with Cargo and target caches.

## Global Constraints

- Keep all nine existing synchronous tool names and input schemas unchanged.
- Keep explicit SSH aliases and absolute remote paths.
- Omitted `remote_run.shell` remains Bash; Bash is never silently changed to sh.
- Preserve path validation, capability checks, mutation uncertainty, cancellation, RSS, wire, and retention behavior.
- Do not add a projection framework, compatibility switch, second retention system, or extra SSH request.
- Model-visible inline result data is limited to 32 KiB, measured from `content.text` plus serialized `structuredContent`.
- Errors contain facts only; remove MCP `action` and `suggested_action` output.
- Do not run `cargo build`, `cargo test`, `cargo clippy`, release builds, or benchmarks locally. GitHub Actions is authoritative.
- The public package version becomes `0.3.0`; no legacy output mode is shipped.

---

### Task 0: Fix long-lived remote service lifecycle before output refactoring

**Files:**
- Modify: `src/ssh/session.rs`, `src/ssh/dispatcher.sh`.
- Add/modify: focused Rust lifecycle tests.
- Modify: `skills/remote-ssh-ops/SKILL.md`, `skills/remote-ssh-ops/references/operations.md`.

- [ ] **Step 1: Add a failing fixture case.**

  Reproduce a command whose parent exits while a child keeps the captured
  stdout/stderr descriptors open. Confirm that this is why an HTTP server
  started with synchronous `remote_run` blocks the dispatcher and the next
  request on that host.

- [ ] **Step 2: Decouple request completion from inherited pipes.**

  Keep `remote_run` synchronous for a foreground command. After the shell
  parent exits, wait only a bounded drain grace for normal stdout/stderr EOF;
  then send `EXIT` even when a descendant still owns a FIFO. Extend the EXIT
  payload with an optional continuation bit and let background collectors drain
  independently. This keeps later requests usable and does not change ordinary
  foreground command output.

- [ ] **Step 3: Document the lifecycle boundary.**

  Document that `remote_run` is still synchronous and that this bridge does not
  yet expose a persistent process handle. HTTP servers, viewers, and other
  long-lived processes must explicitly detach stdin/stdout/stderr and their
  process group; do not put ad-hoc `&` jobs through synchronous `remote_run`.
  State that an already stuck old request requires cancelling or restarting
  that SSH session once; the fix prevents new occurrences. A first-class
  process-start/handle API remains a separate follow-up aligned with local
  Codex behavior.

- [ ] **Step 4: Verify in GitHub Actions only.**

  Run the focused inherited-pipe lifecycle tests in CI. Do not run Cargo
  build/test locally.

---

### Task 1: Replace old MCP expectations with 0.3.0 contract tests

**Files:**
- Modify: `src/mcp/render.rs` test module around the existing renderer assertions.
- Modify: `tests/mcp_tools.rs` existing success, truncation, shell, write, patch, and error assertions.
- Modify: `tests/mcp_protocol.rs` invalid-argument and error-projection assertions.

**Interfaces:**
- Consumes: existing `CallToolResult`, `Remote*Result`, and renderer fixtures.
- Produces: failing tests that describe the exact 0.3.0 MCP result shape for all nine tools.

- [ ] **Step 1: Add forbidden-field and model-size helpers to the test fixtures.**

  Add a recursive JSON assertion that rejects normal `structuredContent` fields
  named `remote`, `physical_root`, `helper_mode`, `shell`, `elapsed_ms`,
  `entry_count`, `match_count`, `raw_bytes`, `aggregate_bytes`,
  `detail_retained`, `action`, and `suggested_action`. Add a helper that sums
  UTF-8 lengths of `content[*].text` and the serialized `structuredContent`.

- [ ] **Step 2: Replace success assertions with the compact contract.**

  Update tests so that they expect aliases, `kind<TAB>path` list lines,
  compact stat JSON lines, `path:line:text` search lines, raw read content,
  labeled run stdout/stderr, `exit_code`, `Done!`, and `Wrote /path` as
  specified by the design document. Keep the existing nonzero-exit and
  mutation-uncertainty scenarios.

- [ ] **Step 3: Add the 32 KiB boundary cases.**

  Cover exact-fit output, one byte over the limit, UTF-8 boundary handling,
  `truncated: true`, an opaque `output_ref`, and a subsequent
  `remote_output_read` page. Assert that business output does not appear a
  second time in `structuredContent`.

- [ ] **Step 4: Add the no-action error cases.**

  Assert that invalid arguments and remote failures contain `code` and
  `message`, never `action` or `suggested_action`, while preserving
  `mutation_may_have_applied`, changed/unknown path facts, and process
  continuation facts when the scenario supplies them.

- [ ] **Step 5: Commit the contract test migration.**

  ```bash
  git add src/mcp/render.rs tests/mcp_tools.rs tests/mcp_protocol.rs
  git commit -m "test: define compact MCP output contract"
  ```

  Do not run the tests locally. The expected failing state is checked by the
  GitHub Actions run after the implementation commits are added.

### Task 2: Implement concise successful renderers and the 32 KiB bound

**Files:**
- Modify: `src/mcp/render.rs` functions `hosts`, `list`, `stat`, `search`,
  `read`, `output_read`, `write`, `apply_patch`, `run`, and the existing
  `render_retained`/`complete_result` helpers.
- Modify: `src/remote/mod.rs` only if a small existing result field is needed
  to preserve a non-UTF-8 path or content marker; do not change transport.

**Interfaces:**
- Consumes: complete internal remote results and existing retention provenance.
- Produces: concise `CallToolResult` values; retention receives the complete
  internal result while the model receives only the selected projection.

- [ ] **Step 1: Add one renderer constant and one UTF-8-safe text cap helper.**

  Define `MODEL_INLINE_RESULT_BYTES: usize = 32 * 1024` in `render.rs`. Add a
  helper that truncates a `String` only at a UTF-8 boundary and reports whether
  truncation occurred. Make the existing result-budget check use the smaller
  of the MCP response budget and this model budget; retain the existing wire
  budget and compact fallback checks unchanged.

- [ ] **Step 2: Add small text builders beside the existing presentation types.**

  Build strings directly from existing result fields:

  - hosts: one `host` alias per line;
  - list: `kind<TAB>actual absolute path` per entry;
  - stat: one JSON object per line with `path`, `kind`, `size`, `mtime`, and
    `mode`;
  - search: `path:line:text` per match;
  - read: one file body, or `==> absolute path <==` separators for multiple
    files;
  - run: one labeled section for each non-empty stdout/stderr stream;
  - write: `Wrote /absolute/path`;
  - patch: `Done!`.

  Preserve existing encoded-value behavior. UTF-8 values are rendered as text;
  binary values retain an explicit `base64:` marker so the projection never
  silently corrupts remote data.

- [ ] **Step 3: Separate the model presentation from the retained detail.**

  Update the existing retention helper so it receives a concise presentation
  for `complete_result` and the original complete result for
  `retain_serialized_detail`. Do not serialize the complete `ListResult`,
  `ReadResult`, `SearchResult`, or `RemoteRunResult` as normal MCP content.
  When the 32 KiB cap is crossed, return the safe text prefix plus only
  `truncated` and `output_ref` metadata.

- [ ] **Step 4: Minimize structured success metadata.**

  Emit `{}` for hosts, list, stat, read, write, and patch unless truncation
  requires `truncated` and `output_ref`. Emit `next_offset` and `eof` for
  `remote_output_read`. Emit only `exit_code` for a normal run, adding
  truncation metadata when needed. Keep the existing output reference and
  paging store.

- [ ] **Step 5: Preserve the explicit POSIX-sh information without diagnostics.**

  Keep the existing factual POSIX-sh warning when an explicit sh result needs
  to warn about syntax differences. Do not expose helper mode, physical root,
  shell version, timing, raw byte counts, or duplicated context on success.

- [ ] **Step 6: Commit the renderer implementation.**

  ```bash
  git add src/mcp/render.rs src/remote/mod.rs
  git commit -m "feat: compact remote MCP success results"
  ```

### Task 3: Remove prescriptive error output

**Files:**
- Modify: `src/error.rs` `ErrorDetails` and shell-capability error construction.
- Modify: `src/mcp/protocol.rs` `CallToolResult::invalid_argument` and the
  invalid-argument size constant.
- Modify: `src/mcp/tools.rs` `invalid_arguments`.
- Modify: `src/mcp/render.rs` error renderers and error presentation structs.
- Modify: `tests/mcp_protocol.rs`, `tests/mcp_tools.rs`, and renderer tests.

**Interfaces:**
- Consumes: internal `BridgeError` facts and capability-selection failures.
- Produces: factual MCP errors with no action recommendation.

- [ ] **Step 1: Add factual shell fields at capability-selection failure.**

  Extend internal error details with optional `requested_shell` and
  `available_shells`. When a Bash request fails against a POSIX-only
  capability, record `requested_shell: "bash"` and `available_shells: ["sh"]`.
  Keep physical root and shell version internal for retention/debugging only.

- [ ] **Step 2: Remove the MCP action API.**

  Change `CallToolResult::invalid_argument(actionable_safe_text)` to
  `CallToolResult::invalid_argument()`. Delete
  `MAX_INVALID_ARGUMENT_ACTION_BYTES` and the per-tool action match in
  `src/mcp/tools.rs`. Keep the existing static invalid-argument message.

- [ ] **Step 3: Simplify rendered error fields.**

  Remove `action`, `action_truncated`, retryability, timing, byte-count, root,
  helper, and shell-version fields from the model-visible error projection.
  Keep `error.code`, `error.message`, and only relevant factual fields:
  `path`, changed/not-changed/unknown paths or their retained reference,
  `mutation_may_have_applied`, `remote_process_may_continue`,
  `requested_shell`, and `available_shells`. Preserve control-character
  normalization and existing retention of oversized mutation details.

- [ ] **Step 4: Make invalid arguments and remote errors non-prescriptive.**

  Render a concise factual text message and a structured error object without
  any action field. The model must decide whether to retry, change a path,
  choose sh, or stop.

- [ ] **Step 5: Commit the error implementation.**

  ```bash
  git add src/error.rs src/mcp/protocol.rs src/mcp/tools.rs src/mcp/render.rs tests/mcp_protocol.rs tests/mcp_tools.rs
  git commit -m "feat: remove prescriptive MCP error actions"
  ```

### Task 4: Optimize GitHub CI without reducing coverage

**Files:**
- Modify: `.github/workflows/ci.yml` quality and diagnostics jobs.
- Modify: any affected CI-only test selection if a real shared-state failure
  is observed in GitHub Actions.

**Interfaces:**
- Consumes: existing Cargo test, RSS, profile, and artifact steps.
- Produces: parallel quality/diagnostics jobs and reusable debug/release target
  caches.

- [ ] **Step 1: Split the target cache keys by job and commit.**

  Use separate prefixes for `quality` and `diagnostics`, append
  `${{ github.sha }}` to each primary key, and restore using the same
  toolchain/lockfile prefix. Keep the toolchain and Cargo registry/Git caches.

- [ ] **Step 2: Remove avoidable serialization and duplicate compilation.**

  Remove `--test-threads=1` from the ordinary all-target test command, remove
  the quality job's redundant release binary build, and remove
  `needs: quality` from diagnostics. Keep the existing RSS/profile commands
  serial within diagnostics.

- [ ] **Step 3: Avoid unnecessary package installation.**

  Change the ripgrep setup to use the preinstalled runner binary when present
  and run `apt-get` only when `command -v rg` fails.

- [ ] **Step 4: Keep output-contract tests in the quality job.**

  Do not create a new CI job. The existing quality command covers the new MCP
  renderer tests; diagnostics remains responsible for release-only profile,
  RSS, and memory evidence.

- [ ] **Step 5: Commit the workflow changes.**

  ```bash
  git add .github/workflows/ci.yml
  git commit -m "ci: parallelize quality and diagnostics"
  ```

  Push the branch and inspect the GitHub Actions run. If parallel ordinary
  tests expose a real shared-state failure, isolate only that test target in a
  serial command; do not restore global serialization without evidence.

### Task 5: Bump the public version and update documentation

**Files:**
- Modify: `Cargo.toml` package version.
- Modify: `Cargo.lock` package version entry.
- Modify: `.codex-plugin/plugin.json` version.
- Modify: `README.md` MCP output and shell-fallback descriptions.
- Modify: `docs/security.md` only where it promises that full transport
  metadata is returned to the Agent.

**Interfaces:**
- Consumes: the completed 0.3.0 output behavior.
- Produces: consistent package metadata and public documentation.

- [ ] **Step 1: Set all package version fields to `0.3.0`.**

  Update the Cargo package, lockfile package record, and plugin manifest. Do
  not add binaries, `.mcp.json`, or private development resources to the
  package.

- [ ] **Step 2: Document the concise result contract.**

  Explain that specialized remote tools remain, normal results are compact,
  large output is paged through `output_ref`, and errors contain facts rather
  than suggested actions. State that Bash remains the default and that a Bash
  capability failure exposes the available shell fact without silently
  switching shells.

- [ ] **Step 3: Commit metadata and documentation.**

  ```bash
  git add Cargo.toml Cargo.lock .codex-plugin/plugin.json README.md docs/security.md
  git commit -m "chore: release compact MCP contract as 0.3.0"
  ```

### Task 6: GitHub-only verification and handoff

**Files:**
- No source changes unless a GitHub failure identifies a concrete regression.
- Inspect: `.github/workflows/ci.yml`, release workflow artifacts, and the
  generated Actions summaries.

**Interfaces:**
- Consumes: all commits from Tasks 1–5.
- Produces: verified main branch ready for an explicitly requested v0.3.0 tag.

- [ ] **Step 1: Push the implementation commits to the working branch.**

  Do not run Cargo locally. Use the configured GitHub workflow path and wait
  for both `quality` and `diagnostics` jobs.

- [ ] **Step 2: Confirm contract and safety evidence in Actions.**

  Require formatting, Clippy, all tests, MCP contract tests, RSS bounds,
  release profile, cancellation, mutation uncertainty, and performance
  profile artifacts to pass. Confirm quality and diagnostics overlap in time
  and that the target cache reports a hit or a successful save on the next
  run.

- [ ] **Step 3: Confirm package metadata without local builds.**

  Use the CI metadata validation and release package checks to confirm that
  Cargo, plugin, archive resources, and `.mcp.json.example` all describe
  version 0.3.0. Do not create or publish a release tag until the user
  explicitly requests publication.

- [ ] **Step 4: Commit any evidence-only workflow correction.**

  If a workflow-only correction is required, commit it separately with a
  focused message and rerun the same GitHub checks. Do not substitute a local
  Cargo build or test.
