# Dual Patch Syntax Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `remote_apply_patch` accept both Codex's native `*** Begin Patch` syntax and standard unified diff without changing its MCP request shape or remote mutation semantics.

**Architecture:** Add a focused local Codex patch parser and context applicator beside the existing unified parser. A deterministic prefix dispatcher produces one bounded per-file edit stream; both formats converge to the existing `DesiredState` and edit-cache synchronization path before any remote mutation. Keep absolute paths mandatory and reject native move directives in the first release.

**Tech Stack:** Rust 2024, existing bridge patch/edit-cache modules, MCP JSON Schema, GitHub Actions, packaged Skill documentation

## Global Constraints

- Keep one `remote_apply_patch` tool with required fields `host` and `patch`; add no `format`, `cwd`, or second patch tool.
- Select Codex syntax only when the first non-empty line is exactly `*** Begin Patch`; select unified diff only when it starts with `--- `.
- Accept Codex Add, Update, and Delete operations with absolute paths; reject `*** Move to` before remote access.
- Preserve all existing unified-diff behavior and tests.
- Parse and apply locally; never invoke remote `patch`, `git apply`, or shell parsing.
- Both formats must converge to the existing guarded snapshot, edit-cache, conflict, output-limit, and synchronization path.
- Errors remain factual and must not echo full patch or file content.
- Do not run local Cargo build, test, Clippy, benchmark, or release commands. GitHub Actions is authoritative.
- Use one RED branch push and one GREEN branch push so CI validates TDD without repeatedly rebuilding the matrix.

---

### Task 1: Freeze The Dual-Format Contract In RED Tests

**Files:**
- Modify: `src/remote/patch.rs` test module
- Modify: `tests/mcp_tools.rs`
- Modify: `tests/packaging.rs`

**Interfaces:**
- Consumes: existing `remote::patch::parse_patch`, `RemoteBridge::apply_patch`, and MCP tool registry.
- Produces: failing tests for `parse_request_patch(input: &str) -> BridgeResult<Vec<ParsedFilePatch>>`, native Add/Update/Delete application, schema wording, and packaged Skill wording.

- [ ] **Step 1: Create an isolated project-local worktree**

```bash
mkdir -p .worktrees
git worktree add .worktrees/dual-patch-syntax -b feat/dual-patch-syntax main
cd .worktrees/dual-patch-syntax
```

Expected: the worktree is inside the project, branch is `feat/dual-patch-syntax`, and `git status --short` is empty.

- [ ] **Step 2: Add parser and application contract tests**

Add tests in `src/remote/patch.rs` that call the not-yet-implemented request parser and the shared application entry point:

```rust
#[test]
fn codex_and_unified_create_produce_identical_bytes() {
    let codex = concat!(
        "*** Begin Patch\n",
        "*** Add File: /srv/repo/new.txt\n",
        "+alpha\n",
        "+beta\n",
        "*** End Patch\n",
    );
    let unified = concat!(
        "--- /dev/null\n",
        "+++ /srv/repo/new.txt\n",
        "@@ -0,0 +1,2 @@\n",
        "+alpha\n",
        "+beta\n",
    );
    assert_eq!(
        apply_request(None, codex).unwrap(),
        apply_request(None, unified).unwrap(),
    );
}

#[test]
fn codex_update_uses_ordered_context_matching() {
    let patch = concat!(
        "*** Begin Patch\n",
        "*** Update File: /srv/repo/a.txt\n",
        "@@ section two\n",
        "-old\n",
        "+new\n",
        "*** End Patch\n",
    );
    assert_eq!(
        apply_request(Some(b"old\nsection two\nold\n"), patch).unwrap(),
        PatchedFile::Write(b"old\nsection two\nnew\n".to_vec()),
    );
}

#[test]
fn codex_delete_matches_unified_delete() {
    let codex = concat!(
        "*** Begin Patch\n",
        "*** Delete File: /srv/repo/old.txt\n",
        "*** End Patch\n",
    );
    let unified = concat!(
        "--- /srv/repo/old.txt\n",
        "+++ /dev/null\n",
        "@@ -1 +0,0 @@\n",
        "-old\n",
    );
    assert_eq!(
        apply_request(Some(b"old\n"), codex).unwrap(),
        apply_request(Some(b"old\n"), unified).unwrap(),
    );
}
```

Define the test helper against the intended production interfaces so the RED failure is structural:

```rust
fn apply_request(base: Option<&[u8]>, input: &str) -> crate::BridgeResult<super::PatchedFile> {
    let parsed = super::parse_request_patch(input)?;
    assert_eq!(parsed.len(), 1);
    let sha256 = base.map(|bytes| format!("{:x}", Sha256::digest(bytes)));
    super::apply_parsed_file(
        base.zip(sha256.as_deref()),
        &parsed[0],
        super::MAX_PATCH_BYTES,
    )
}
```

- [ ] **Step 3: Add rejection and no-remote-access tests**

Cover these exact inputs and expected error classes:

```rust
for input in [
    "*** Begin Patch\n*** Move to: /srv/repo/b\n*** End Patch\n",
    "*** Begin Patch\n*** Add File: relative.txt\n+x\n*** End Patch\n",
    "*** Begin Patch\n*** Add File: /srv/repo/a\n+x\n*** End Patch\ntrailing\n",
    "*** Begin Patch\n--- /dev/null\n+++ /srv/repo/a\n@@ -0,0 +1 @@\n+x\n*** End Patch\n",
] {
    assert_eq!(
        super::parse_request_patch(input).unwrap_err().code,
        ErrorCode::InvalidArgument,
    );
}
```

Add a fake-SSH integration assertion in `tests/remote_ops.rs` or the existing patch preflight test group proving malformed Codex syntax creates no fake SSH call-log entry.

- [ ] **Step 4: Add MCP and packaging contract tests**

In `tests/mcp_tools.rs`, require both the tool description and the `patch` property description to contain `Codex apply_patch`, `unified diff`, and `absolute` while retaining `maxLength = 4_194_304` and the same required fields.

In `tests/packaging.rs`, require the installed Skill and operations reference to contain:

```text
*** Begin Patch
standard unified diff
absolute paths
*** Move to
unsupported
```

- [ ] **Step 5: Commit and push the RED contract**

```bash
git add src/remote/patch.rs tests/remote_ops.rs tests/mcp_tools.rs tests/packaging.rs
git commit -m "test: define dual remote patch syntax"
git push -u origin feat/dual-patch-syntax
```

- [ ] **Step 6: Verify RED in GitHub Actions**

Run through the approved network path:

```bash
gh workflow run CI --ref feat/dual-patch-syntax
gh run list --branch feat/dual-patch-syntax --workflow CI --limit 1
gh run watch <run-id> --exit-status
```

The explicit dispatch is required because ordinary feature-branch pushes do
not trigger `.github/workflows/ci.yml`.

Expected: CI fails because `parse_request_patch` and `apply_parsed_file` do not exist and the live MCP/Skill descriptions do not yet advertise both formats. Record the run URL in the implementation notes.

### Task 2: Parse And Apply Native Codex Patches Locally

**Files:**
- Create: `src/remote/codex_patch.rs`
- Modify: `src/remote/mod.rs`
- Modify: `src/remote/patch.rs`

**Interfaces:**
- Consumes: `FilePatchOperation`, `PatchedFile`, existing patch byte/file/hunk/body/path limits, `BridgeError`, and `ErrorCode`.
- Produces: `CodexFilePatch`, `CodexUpdateChunk`, `parse_codex_patch`, and `apply_codex_file`.

- [ ] **Step 1: Add the focused native parser module**

Declare `mod codex_patch;` in `src/remote/mod.rs`. Create these bounded types in `src/remote/codex_patch.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CodexFilePatch {
    pub path: String,
    pub operation: FilePatchOperation,
    pub add_bytes: Option<Vec<u8>>,
    pub chunks: Vec<CodexUpdateChunk>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CodexUpdateChunk {
    pub context: Option<String>,
    pub old_lines: Vec<String>,
    pub new_lines: Vec<String>,
    pub end_of_file: bool,
}

pub(super) fn parse_codex_patch(input: &str) -> BridgeResult<Vec<CodexFilePatch>>;

pub(super) fn apply_codex_file(
    base: Option<&[u8]>,
    patch: &CodexFilePatch,
    maximum_output_bytes: usize,
) -> BridgeResult<PatchedFile>;
```

Reuse the existing constants by changing only their visibility to `pub(super)`: `MAX_PATCH_BYTES`, `MAX_PATCH_FILES`, `MAX_PATCH_HUNKS`, `MAX_PATCH_BODY_LINES`, and `MAX_PATCH_PATH_BYTES`. Reuse `validate_absolute_patch_path`, `invalid_patch`, `patch_too_large`, and `write_conflict` with the same visibility adjustment rather than duplicating security rules.

- [ ] **Step 2: Implement strict envelope and file-directive parsing**

The parser must:

1. enforce the existing byte/NUL limits before allocation;
2. require the first record `*** Begin Patch` and final record `*** End Patch`;
3. accept only `*** Add File:`, `*** Update File:`, and `*** Delete File:` with canonical absolute paths;
4. reject `*** Move to:` with `InvalidArgument`;
5. reject duplicate paths, empty Add/Update sections, nested markers, unified headers, and trailing records;
6. count files, update chunks, and body lines against the existing limits; and
7. retain body text without echoing it in errors.

Use fixed factual messages such as `Codex patch move is unsupported`, `Codex patch path is not absolute`, and `Codex patch envelope has trailing data`.

- [ ] **Step 3: Implement ordered context application**

Implement an exact, allocation-bounded sequence search:

```rust
fn find_sequence(haystack: &[&str], needle: &[String], start: usize, eof: bool) -> Option<usize> {
    if needle.is_empty() {
        return Some(if eof { haystack.len() } else { start.min(haystack.len()) });
    }
    let last = haystack.len().checked_sub(needle.len())?;
    let range = start.min(last)..=last;
    if eof {
        let candidate = last;
        return haystack[candidate..]
            .iter()
            .zip(needle)
            .all(|(actual, expected)| *actual == expected)
            .then_some(candidate);
    }
    range.into_iter().find(|&candidate| {
        haystack[candidate..candidate + needle.len()]
            .iter()
            .zip(needle)
            .all(|(actual, expected)| *actual == expected)
    })
}
```

For each update chunk, advance the cursor past the first context-header match, locate `old_lines` from that cursor, record a replacement, and continue after the match. Apply replacements in reverse index order. Pure additions insert at the current cursor, or at EOF when `*** End of File` is set. Enforce `maximum_output_bytes` before extending output and reject unchanged updates with the existing write-conflict semantics.

Add and update results follow native Codex newline behavior: each parsed added line contributes `\n`; delete produces `PatchedFile::Delete`. Unified no-terminal-newline behavior remains untouched.

- [ ] **Step 4: Run source-only checks**

```bash
cargo fmt --all -- --check
git diff --check
```

Expected: both exit zero and no `target/` directory is created.

- [ ] **Step 5: Commit the native parser and applicator**

```bash
git add src/remote/codex_patch.rs src/remote/mod.rs src/remote/patch.rs
git commit -m "feat: parse native Codex patches"
```

### Task 3: Route Both Formats Through One Mutation Pipeline

**Files:**
- Modify: `src/remote/patch.rs`
- Test: `src/remote/patch.rs`
- Test: `tests/remote_ops.rs`

**Interfaces:**
- Consumes: `codex_patch::parse_codex_patch`, `codex_patch::apply_codex_file`, existing `FilePatch`, `apply_file_patch`, and all cached/immediate mutation helpers.
- Produces: `ParsedFilePatch`, `parse_request_patch`, `apply_parsed_file`, and unchanged `ApplyPatchResult` behavior.

- [ ] **Step 1: Add the input-neutral wrapper**

Add to `src/remote/patch.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParsedFilePatch {
    Unified(FilePatch),
    Codex(super::codex_patch::CodexFilePatch),
}

impl ParsedFilePatch {
    fn path(&self) -> &str;
    fn operation(&self) -> FilePatchOperation;
}

pub(crate) fn parse_request_patch(input: &str) -> BridgeResult<Vec<ParsedFilePatch>> {
    let first = input.lines().find(|line| !line.is_empty())
        .ok_or_else(|| invalid_patch("patch is empty"))?;
    if first == "*** Begin Patch" {
        return super::codex_patch::parse_codex_patch(input)
            .map(|items| items.into_iter().map(ParsedFilePatch::Codex).collect());
    }
    if first.starts_with("--- ") {
        return parse_patch(input)
            .map(|items| items.into_iter().map(ParsedFilePatch::Unified).collect());
    }
    Err(invalid_patch("patch syntax is not recognized"))
}

pub(crate) fn apply_parsed_file(
    base: Option<(&[u8], &str)>,
    patch: &ParsedFilePatch,
    maximum_output_bytes: usize,
) -> BridgeResult<PatchedFile>;
```

`apply_parsed_file` dispatches only local application. The Codex arm ignores the hash value after the shared base guard has selected the cached/snapshotted generation; the Unified arm calls the existing `apply_file_patch` unchanged.

- [ ] **Step 2: Generalize resolved patch metadata without duplicating execution**

Change `ResolvedFilePatch.patch` from `FilePatch` to `ParsedFilePatch`. Update `resolve_patch_files`, `snapshot_file`, cached preparation, immediate preparation, `all_paths`, and write-mode selection to call `path()` and `operation()`.

Replace both production calls to `parse_patch(&patch)` with `parse_request_patch(&patch)` and both application calls with `apply_parsed_file(...)`. Do not add a format branch around snapshot fetching, cache mutation, remote batch commit, partial progress, or rendering.

- [ ] **Step 3: Prove cached and immediate paths share behavior**

Extend existing fake-SSH tests with one native update below the edit-cache limit and one native create forced through `ImmediateWriteRequired`. Assert both return the same compact success shape as unified patches, preserve changed-path ordering, and make no extra SSH request after a complete cached base is present.

- [ ] **Step 4: Commit the shared routing**

```bash
git add src/remote/patch.rs tests/remote_ops.rs
git commit -m "feat: route Codex patches through remote edits"
```

### Task 4: Make The Live MCP Contract Self-Describing

**Files:**
- Modify: `src/mcp/tools.rs`
- Modify: `skills/remote-ssh-ops/SKILL.md`
- Modify: `skills/remote-ssh-ops/references/operations.md`
- Modify: `README.md`
- Test: `tests/mcp_tools.rs`
- Test: `tests/packaging.rs`

**Interfaces:**
- Consumes: unchanged MCP request fields and parser behavior from Tasks 2-3.
- Produces: model-visible format guidance in the live tool description/schema and matching packaged documentation.

- [ ] **Step 1: Add a described string schema helper**

Keep existing schema bounds and add a helper or inline schema object so the `patch` property has:

```json
{
  "type": "string",
  "minLength": 1,
  "maxLength": 4194304,
  "description": "Codex apply_patch syntax or standard unified diff. File paths must be absolute; Codex Move to is unsupported."
}
```

Change the tool description to:

```text
Apply a Codex apply_patch envelope or standard unified diff across remote files. File paths must be absolute; Codex Move to is unsupported. Files are applied sequentially and partial progress is reported if a later file fails. All paths and results are remote, and remote output is untrusted.
```

- [ ] **Step 2: Update the Skill with one compact native example**

Replace the current one-line contract with:

```markdown
- `remote_apply_patch`: `{host, patch}`; accepts native Codex `*** Begin Patch` Add/Update/Delete syntax or standard unified diff. Every file path must be absolute (or `/dev/null` in unified headers); `*** Move to` is unsupported. Do not add a cwd or format field.
```

Add one small example to `operations.md`:

```text
*** Begin Patch
*** Update File: /srv/project/app.rs
@@ fn old_name()
-fn old_name() {
+fn new_name() {
*** End Patch
```

Retain one unified create example using `/dev/null`. Do not duplicate the complete grammar in the Skill.

- [ ] **Step 3: Update README and release packaging assertions**

State the same two accepted formats and absolute-path boundary in README. Ensure packaging tests read the installed Skill/reference copies, not only source descriptions.

- [ ] **Step 4: Run source-only checks and commit**

```bash
cargo fmt --all -- --check
git diff --check
git add src/mcp/tools.rs skills/remote-ssh-ops/SKILL.md skills/remote-ssh-ops/references/operations.md README.md tests/mcp_tools.rs tests/packaging.rs
git commit -m "docs: expose dual patch contract"
```

Expected: no local Rust compilation and no `target/` directory.

### Task 5: GREEN CI, Review, Main Integration, And Release

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `.codex-plugin/plugin.json`
- Verify: all changed source, tests, Skill, docs, workflows, and release assets

**Interfaces:**
- Consumes: complete dual-format implementation and existing release workflow.
- Produces: passing GitHub CI, reviewed fast-forward main, multi-architecture release, and installed package.

- [ ] **Step 1: Bump the backward-compatible feature version**

Change package version from `0.7.0` to `0.8.0` in `Cargo.toml`, the root package entry in `Cargo.lock`, and `.codex-plugin/plugin.json`. Do not update dependency versions.

```bash
git add Cargo.toml Cargo.lock .codex-plugin/plugin.json
git commit -m "chore: bump release version to 0.8.0"
```

- [ ] **Step 2: Push the GREEN implementation**

```bash
git push origin feat/dual-patch-syntax
gh workflow run CI --ref feat/dual-patch-syntax
gh run list --branch feat/dual-patch-syntax --workflow CI --limit 1
gh run watch <run-id> --exit-status
```

Expected: the complete CI workflow passes. Confirm cache restore steps report hits where their keys are unchanged. Do not substitute local Cargo tests if CI fails.

- [ ] **Step 3: Review the final diff against the specification**

```bash
git diff main...feat/dual-patch-syntax --stat
git diff main...feat/dual-patch-syntax --check
git log --oneline main..feat/dual-patch-syntax
```

Verify explicitly: one public tool; deterministic prefix dispatch; absolute paths; unsupported Move; no remote shell patching; shared cache/immediate mutation path; unchanged unified behavior; bounded parser counts; factual errors; compact output.

- [ ] **Step 4: Fast-forward and push main**

From the primary worktree:

```bash
git merge --ff-only feat/dual-patch-syntax
git push origin main
```

Wait for main CI to pass before tagging.

- [ ] **Step 5: Tag and run the release workflow**

```bash
git tag -a v0.8.0 -m "v0.8.0"
git push origin v0.8.0
gh run list --workflow Release --limit 1
gh run watch <release-run-id> --exit-status
gh release view v0.8.0
```

Expected: the Release workflow succeeds and publishes the main bridge for all configured architectures plus the complete helper set and checksums.

- [ ] **Step 6: Install only the new release package**

Download the release archive for the local architecture, verify its published
checksum, extract it, and run its packaged binary with
`install --user --apply`. The archive is the complete source of the binary,
all helper architectures, plugin, Skill, docs, and examples. Verify the
installer created `/home/wkj/.local/share/codex-ssh-bridge/0.8.0+release`,
updated the stable binary and Skill links plus MCP registration, and retained
only the newly installed release after validation. Do not manually splice
resources from the source checkout into the installed package.

- [ ] **Step 7: Manually verify the installed release against a real alias**

Start a fresh 0.8.0 MCP process and use a temporary directory under one discovered test alias. Through MCP, verify:

1. native Codex Add creates a file;
2. native Codex Update changes it using `@@` context;
3. standard unified diff changes the same file;
4. native Codex Delete removes it;
5. native `*** Move to` fails before a remote request;
6. `remote_run` after edits sees synchronized content; and
7. warm `remote_run` and `remote_search` medians do not regress beyond normal network variation because parsing is local-only.

Delete only the temporary remote test directory after recording results.

- [ ] **Step 8: Remove the feature worktree and branch after verification**

```bash
git worktree remove .worktrees/dual-patch-syntax
git branch -d feat/dual-patch-syntax
git push origin --delete feat/dual-patch-syntax
```

Expected: local and origin `main` point to the v0.8.0 release commit, no stale feature worktree/branch remains, and the primary worktree is clean.
