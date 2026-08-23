# Codex-Only Remote Patch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `remote_apply_patch` accept the complete native Codex patch language, require absolute remote paths, and remove unified diff support in the `0.9.0` breaking release.

**Architecture:** Keep the MCP request as `{host, patch}` and replace the dual-format dispatcher with one bounded Codex parser and matcher in `src/remote/codex_patch.rs`. Feed its `CodexFilePatch` values directly into the existing guarded snapshot, edit-cache, immediate mutation, cancellation, and partial-progress pipeline in `src/remote/patch.rs`; expand moves into a destination write plus guarded source delete without adding cwd or session state.

**Tech Stack:** Rust 2024, Tokio, existing bridge edit cache and guarded SSH mutation helpers, MCP JSON Schema, GitHub Actions, packaged Codex Skill

**Spec:** `docs/superpowers/specs/2026-08-23-codex-only-remote-patch-design.md`

## Global Constraints

- Keep one `remote_apply_patch` tool with required fields `host` and `patch`; add no `format`, `cwd`, session, or second patch tool.
- Accept only Codex `*** Begin Patch` syntax and reject unified diff before SSH or edit-cache mutation.
- Match native Codex grammar and normal LF update results, including optional environment id, Add, Delete, Update, repeated `@@`, `*** End of File`, and `*** Move to:`.
- Require absolute remote paths for every source and move destination; this is the deliberate difference from local Codex.
- A present `*** Environment ID:` must be nonempty and equal the MCP `host`.
- Treat a self-move as an in-place update; do not reproduce upstream deletion behavior.
- Parse and apply locally; never invoke remote `patch`, `git apply`, or shell parsing.
- Preserve guarded snapshots, aggregate limits, buffered edit durability, cancellation, partial progress, and successful MCP response shape.
- Errors remain factual and must not echo full patch or file content.
- Bump `Cargo.toml`, `Cargo.lock`, and `.codex-plugin/plugin.json` together from `0.8.1` to `0.9.0`.
- Do not run local Cargo build, test, Clippy, benchmark, or release commands. GitHub Actions is authoritative.
- Use one RED branch push and one GREEN branch push so CI validates TDD without repeatedly rebuilding the full matrix.

## File Map

- `src/remote/codex_patch.rs`: sole patch AST, parser, native context matcher, and content derivation.
- `src/remote/patch.rs`: shared limits/errors plus remote path resolution, snapshots, cache staging, immediate commits, moves, and progress details; all unified parser/application code is removed.
- `tests/remote_ops.rs`: end-to-end fake-SSH/cache/move/limits/progress behavior using absolute Codex envelopes.
- `tests/real_ssh.rs`: real-SSH patch fixture migrated from unified to Codex syntax.
- `tests/mcp_tools.rs`: MCP contract and live tool-call fixtures migrated to Codex-only wording/input.
- `tests/packaging.rs`: packaged README/Skill/reference contract and version assertions.
- `src/mcp/tools.rs`, `README.md`, `skills/remote-ssh-ops/SKILL.md`, `skills/remote-ssh-ops/references/operations.md`: one public grammar and examples.
- `Cargo.toml`, `Cargo.lock`, `.codex-plugin/plugin.json`: coordinated `0.9.0` version.

---

### Task 1: Freeze The Codex-Only Contract In RED Tests

**Files:**
- Modify: `src/remote/codex_patch.rs`
- Modify: `src/remote/patch.rs`
- Modify: `tests/remote_ops.rs`
- Modify: `tests/mcp_tools.rs`
- Modify: `tests/packaging.rs`

**Interfaces:**
- Consumes: current `parse_codex_patch`, `apply_codex_file`, `RemoteBridge::apply_patch`, MCP tool registry, and fake SSH fixture.
- Produces: failing contract tests for `parse_codex_patch(input, expected_environment_id)`, native matching, moves, unified rejection, schema wording, and packaged documentation.

- [ ] **Step 1: Create the execution branch/worktree through the required execution skill**

Use branch `codex/codex-only-remote-patch` from the current main commit that
contains both approved planning documents. Confirm:

```bash
git status --short
git rev-parse --short HEAD
```

Expected: status is empty and HEAD contains the approved design commit.

- [ ] **Step 2: Record the upstream parity baseline**

Through the approved GitHub network path, run:

```bash
git ls-remote https://github.com/openai/codex.git refs/heads/main
```

Copy the returned 40-character SHA into a test comment named
`UPSTREAM_APPLY_PATCH_BASELINE` beside the parity cases. The comment must also
name `parser.rs`, `streaming_parser.rs`, and `seek_sequence.rs`; this makes the
fixture reviewable without adding an upstream runtime dependency.

- [ ] **Step 3: Add parser and matcher RED cases**

In `src/remote/codex_patch.rs`, add tests against the intended signature:

```rust
fn parse(input: &str) -> crate::BridgeResult<Vec<super::CodexFilePatch>> {
    super::parse_codex_patch(input, "dev")
}

#[test]
fn repeated_context_selectors_are_valid_before_one_change() {
    let patch = concat!(
        "*** Begin Patch\n",
        "*** Update File: /srv/repo/src/lib.rs\n",
        "@@ impl Server\n",
        "@@ fn dispatch\n",
        "-old();\n",
        "+new();\n",
        "*** End Patch\n",
    );
    let parsed = parse(patch).unwrap();
    assert_eq!(parsed[0].chunks.len(), 2);
    assert!(parsed[0].chunks[0].old_lines.is_empty());
    assert!(parsed[0].chunks[1].old_lines.is_empty());
}

#[test]
fn environment_id_must_match_host() {
    let matching = concat!(
        "*** Begin Patch\n",
        "*** Environment ID: dev\n",
        "*** Add File: /srv/repo/a\n",
        "+x\n",
        "*** End Patch\n",
    );
    assert!(super::parse_codex_patch(matching, "dev").is_ok());
    assert_eq!(
        super::parse_codex_patch(matching, "prod").unwrap_err().code,
        ErrorCode::InvalidArgument,
    );
}

#[test]
fn move_and_move_only_updates_parse() {
    for body in [
        "",
        "@@\n-old\n+new\n",
    ] {
        let patch = format!(
            "*** Begin Patch\n*** Update File: /srv/repo/a\n*** Move to: /srv/repo/b\n{body}*** End Patch\n"
        );
        let parsed = parse(&patch).unwrap();
        assert_eq!(parsed[0].move_path.as_deref(), Some("/srv/repo/b"));
    }
}
```

Add application fixtures proving exact, `trim_end`, `trim`, Unicode punctuation,
EOF, first-chunk-without-`@@`, and context-anchored pure-addition matching. Each
fixture calls `apply_codex_file` with a byte base and asserts the exact LF-ended
result. Include this regression shape:

```rust
assert_eq!(
    apply(
        b"impl Server\nfn other() {}\nfn dispatch\nold();\n",
        concat!(
            "*** Begin Patch\n",
            "*** Update File: /srv/repo/src/lib.rs\n",
            "@@ impl Server\n",
            "@@ fn dispatch\n",
            "-old();\n",
            "+new();\n",
            "*** End Patch\n",
        ),
    )
    .unwrap(),
    super::PatchedFile::Write(
        b"impl Server\nfn other() {}\nfn dispatch\nnew();\n".to_vec()
    ),
);
```

- [ ] **Step 4: Add public-contract RED cases**

In `tests/remote_ops.rs`, add a preflight test that passes a valid standard
unified diff, expects `InvalidArgument`, and asserts zero fake SSH `G`, `P`, `S`,
and `C` records. Add update-and-move and self-move integration tests using
absolute paths under the fixture's temporary remote root. For a normal move,
assert destination bytes, source absence, and `changed_paths == [destination,
source]` in commit order. For a self-move, assert the source remains and occurs
once in `changed_paths`.

In `tests/mcp_tools.rs`, replace the dual-format assertions with:

```rust
for required in ["Codex apply_patch", "absolute", "Move to"] {
    assert!(patch_description.contains(required));
    assert!(patch_schema_description.contains(required));
}
for forbidden in ["unified diff", "unsupported"] {
    assert!(!patch_description.contains(forbidden));
    assert!(!patch_schema_description.contains(forbidden));
}
```

In `tests/packaging.rs`, require `*** Begin Patch`, `*** Move to`, and `absolute
paths`, and reject `standard unified diff`, `/dev/null`, and `Move to is
unsupported` across the Skill and operations reference.

- [ ] **Step 5: Run source-only checks**

```bash
cargo fmt --all -- --check
git diff --check
```

Expected: both exit zero and no `target/` directory is created.

- [ ] **Step 6: Commit and push the RED contract**

```bash
git add src/remote/codex_patch.rs src/remote/patch.rs tests/remote_ops.rs tests/mcp_tools.rs tests/packaging.rs
git commit -m "test: define Codex-only remote patch contract"
git push -u origin codex/codex-only-remote-patch
gh workflow run CI --ref codex/codex-only-remote-patch
PATCH_RED_RUN_ID=$(gh run list --branch codex/codex-only-remote-patch --workflow CI --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$PATCH_RED_RUN_ID" --exit-status
```

Expected: CI is RED because move remains unsupported, repeated context-only
selectors fail, unified diff is still accepted, and public descriptions still
advertise both formats. Record the run URL in the implementation handoff.

### Task 2: Implement Native Parser And Matching Parity

**Files:**
- Modify: `src/remote/codex_patch.rs`
- Modify: `src/remote/patch.rs`

**Interfaces:**
- Consumes: `host: &str`, existing patch limits, `validate_absolute_patch_path`, `FilePatchOperation`, `PatchedFile`, and error constructors.
- Produces: `parse_codex_patch(input: &str, expected_environment_id: &str) -> BridgeResult<Vec<CodexFilePatch>>`, `CodexFilePatch.move_path`, context-aware `CodexUpdateChunk`, and native ordered matching.

- [ ] **Step 1: Extend the AST without adding a second representation**

Use these production shapes in `src/remote/codex_patch.rs`:

```rust
pub(crate) struct CodexFilePatch {
    pub path: String,
    pub move_path: Option<String>,
    pub operation: FilePatchOperation,
    pub add_bytes: Option<Vec<u8>>,
    pub chunks: Vec<CodexUpdateChunk>,
}

pub(crate) struct CodexUpdateChunk {
    pub context: Option<String>,
    pub old_lines: Vec<String>,
    pub new_lines: Vec<String>,
    pub context_line_indices: Vec<(usize, usize)>,
    pub end_of_file: bool,
}

pub(super) fn parse_codex_patch(
    input: &str,
    expected_environment_id: &str,
) -> BridgeResult<Vec<CodexFilePatch>>;
```

Initialize `move_path: None` for Add/Delete and parse it only immediately after
an Update directive. Validate source and destination with the same absolute
path function. Track all sources and destinations in one `BTreeSet`; reject an
overlap before returning the AST, except source-equals-destination within the
same update.

- [ ] **Step 2: Implement the complete envelope and update grammar**

Add `const ENVIRONMENT_ID: &str = "*** Environment ID: ";`. After the begin
marker, consume at most one environment record. Reject empty/mismatched values
with fixed messages `Codex patch environment id is empty` and `Codex patch
environment id does not match host`.

Change update parsing so an `@@` record may finish a context-only chunk and
start another chunk. Accept the grammar's empty Update body; application later
classifies an unchanged non-move as `WriteConflict`. Preserve leading context
markers and populate `context_line_indices` when a line prefixed by one space
is copied to both sides. Allow the first chunk to begin directly with change
lines. Keep all existing byte/file/chunk/body/path limits and reject nested
envelopes or a unified header as malformed Codex content.

- [ ] **Step 3: Replace exact-only lookup with native ordered lookup**

Implement one bounded `seek_sequence` that searches from `start` in this order:

```rust
enum MatchMode {
    Exact,
    TrimEnd,
    Trim,
    UnicodeNormalized,
}
```

For `UnicodeNormalized`, map Codex's dash code points to `-`, curly single
quotes to `'`, curly double quotes to `"`, and non-breaking/typographic spaces
to ASCII space after trimming. When `end_of_file` is true, try the tail offset
first and then the normal cursor search. Empty context-only chunks advance the
cursor but schedule no replacement. A pure addition with a context inserts at
that cursor; an anchorless pure addition inserts before the terminal empty line
or at EOF.

Apply replacements in source order and reconstruct LF-normalized output. Keep
the existing output ceiling and unchanged-update `WriteConflict` behavior.

- [ ] **Step 4: Route the host into parsing**

In both buffered and immediate branches of `src/remote/patch.rs`, call:

```rust
let patches = super::codex_patch::parse_codex_patch(&patch, &host)?;
```

Do not yet delete the unified types in this task; replace only production
`parse_request_patch` calls so the new native parser is exercised by the public
path. Keep unified helpers temporarily test-only until Task 4 removes their
tests and code together.

- [ ] **Step 5: Run source-only checks and commit**

```bash
cargo fmt --all -- --check
git diff --check
git add src/remote/codex_patch.rs src/remote/patch.rs
git commit -m "feat: match native Codex patch grammar"
```

Expected: formatting checks pass without compiling locally.

### Task 3: Add Guarded Move Execution To Both Mutation Paths

**Files:**
- Modify: `src/remote/patch.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- Consumes: `CodexFilePatch { path, move_path, operation, .. }`, `PreparedMutationPath`, `FileSnapshot`, `PreparedEdit`, `DesiredState`, guarded write/delete preflight helpers.
- Produces: moves represented as destination write then source delete, with stable actual-path progress ordering in buffered and immediate modes.

- [ ] **Step 1: Resolve and enumerate every actual mutation path**

Replace the single-path wrapper with:

```rust
struct ResolvedFilePatch {
    patch: super::codex_patch::CodexFilePatch,
    source: super::write::PreparedMutationPath,
    destination: Option<super::write::PreparedMutationPath>,
}

impl ResolvedFilePatch {
    fn mutation_paths(&self) -> Vec<String> {
        match self.patch.move_path.as_deref() {
            Some(destination) if destination != self.patch.path => {
                vec![destination.to_owned(), self.patch.path.clone()]
            }
            _ => vec![self.patch.path.clone()],
        }
    }
}
```

Resolve both paths before SSH. Flatten `mutation_paths()` into `all_paths` for
success and progress details. Treat source-equals-destination as no destination
path. Preserve parser order between file sections.

- [ ] **Step 2: Snapshot source and destination before preparing output**

Generalize `snapshot_file` to consume a `PreparedMutationPath` plus the display
path used for errors. For a move, snapshot the source and then destination while
decrementing the same aggregate base-byte budget. Store:

```rust
struct PatchSnapshots {
    source: FileSnapshot,
    destination: Option<FileSnapshot>,
}
```

Apply textual chunks only to `source.base()`. A move-only update returns the
original source bytes rather than the unchanged-update conflict. A destination
directory, unsafe mode, oversized file, or path conflict fails during
preparation with every `changed_paths` entry still empty.

- [ ] **Step 3: Expand buffered moves into one prepared batch**

Load complete edit-cache entries for both source and destination. Derive the
new bytes from the source desired state. Push destination `PreparedEdit` first,
using `DesiredState::Present`, then source `PreparedEdit` with
`DesiredState::Deleted`. Charge the request `payload_bytes` exactly once on the
first emitted edit and charge output bytes exactly once for the moved content.
For self-move, emit only the ordinary source update.

Pass the expanded vector to the existing `mutate_prepared_batch`; do not add a
new cache transaction type. Return the flattened actual paths.

- [ ] **Step 4: Expand immediate moves into guarded write then delete**

For destination `Missing`, preflight `WriteMode::Create`; for destination
`Regular`, preflight `WriteMode::Replace { expected_sha256 }`. Then preflight a
source delete with the source hash. Append `PreparedMutation::Write(destination)`
before `PreparedMutation::Delete(source)`, so existing sequential execution and
`attach_mutation_progress_context` classify partial progress correctly.

If destination write succeeds and source deletion has an uncertain outcome,
the error must report destination in `changed_paths`, source in
`outcome_unknown_paths`, and no source in `not_changed_paths`. If deletion fails
definitively, report destination changed and source not changed.

- [ ] **Step 5: Complete move integration coverage**

Extend the Task 1 tests with:

- move-only to a missing destination;
- update-and-move over an existing destination;
- self-move preserving the source;
- destination path outside the configured root rejected before SSH;
- destination snapshot conflict before mutation;
- buffered move followed by `remote_sync_edits`;
- cancellation before destination write; and
- definite and uncertain source-delete failure after destination write.

Use absolute paths produced from `remote.path().join(...)` in every patch
header. Assert bytes, existence, fake SSH call counts, and the exact progress
arrays described in Step 4.

- [ ] **Step 6: Run source-only checks and commit**

```bash
cargo fmt --all -- --check
git diff --check
git add src/remote/patch.rs tests/remote_ops.rs
git commit -m "feat: apply guarded remote patch moves"
```

### Task 4: Delete Unified Diff And Migrate Existing Coverage

**Files:**
- Modify: `src/remote/patch.rs`
- Modify: `src/remote/codex_patch.rs`
- Modify: `tests/remote_ops.rs`
- Modify: `tests/real_ssh.rs`
- Modify: `tests/mcp_tools.rs`

**Interfaces:**
- Consumes: `Vec<CodexFilePatch>` and the move-aware mutation pipeline from Tasks 2-3.
- Produces: no unified parser, AST, applicator, dispatcher, or unified test input remains in production or generic integration coverage.

- [ ] **Step 1: Delete unified-only production code**

Remove these types and helpers from `src/remote/patch.rs`:

```text
FilePatch
ParsedFilePatch
Hunk
HunkRange
HunkLine
HunkLineKind
HeaderPath
RecordCursor
LogicalLine
LogicalLineCursor
OutputBuilder
parse_patch
parse_request_patch
parse_header_path
classify_headers
parse_hunk_header
parse_range
parse_usize
parse_body_record
increment_hunk_count
mark_previous_no_newline
validate_operation_hunks
validate_no_newline_positions
apply_file_patch
apply_parsed_file
range_anchor
```

Delete `NO_NEWLINE_MARKER` and unified-only imports. Change every pipeline field
and parameter from `ParsedFilePatch` to `CodexFilePatch`; call `path`,
`move_path`, and `operation` directly. The non-envelope error must be exactly
`patch must use Codex apply_patch syntax` and must occur before path resolution,
cache access, or SSH.

- [ ] **Step 2: Migrate generic patch unit tests**

Move surviving parser/application limit tests into `src/remote/codex_patch.rs`.
Keep coverage for byte, file, chunk, body-line, path, output, base-UTF-8, NUL,
duplicate/overlapping path, unchanged update, and conflict limits using Codex
envelopes. Delete tests whose subject is numerical unified ranges, `---`/`+++`
headers, `a/`/`b/` stripping, `/dev/null`, or `\\ No newline at end of file`.

After the migration, this source search must return no result:

```bash
rg -n 'parse_patch\(|apply_file_patch\(|ParsedFilePatch|HunkRange|NO_NEWLINE_MARKER' src
```

- [ ] **Step 3: Convert mutation-pipeline integration fixtures**

Add exact helpers near the `tests/remote_ops.rs` fixture utilities:

```rust
fn codex_update(path: &std::path::Path, old: &str, new: &str) -> String {
    format!(
        "*** Begin Patch\n*** Update File: {}\n-{old}\n+{new}\n*** End Patch\n",
        path.display(),
    )
}

fn codex_add(path: &std::path::Path, content: &str) -> String {
    let body = content.lines().map(|line| format!("+{line}\n")).collect::<String>();
    format!(
        "*** Begin Patch\n*** Add File: {}\n{body}*** End Patch\n",
        path.display(),
    )
}

fn codex_delete(path: &std::path::Path) -> String {
    format!(
        "*** Begin Patch\n*** Delete File: {}\n*** End Patch\n",
        path.display(),
    )
}
```

Convert every non-parser-specific unified patch in `tests/remote_ops.rs`,
`tests/real_ssh.rs`, and live calls in `tests/mcp_tools.rs` to these absolute
Codex forms. Multi-file tests build one envelope containing multiple file
directives, not concatenated envelopes. Preserve the original assertions for
cache hits, SSH call counts, cancellation, races, aggregate byte limits,
partial progress, and mutation uncertainty.

Replace `FixtureBridge::absolute_patch`'s unified-header rewrite with the four
Codex path directives so any deliberately concise relative fixture is still
converted before it reaches production:

```rust
for prefix in [
    "*** Add File: ",
    "*** Update File: ",
    "*** Delete File: ",
    "*** Move to: ",
] {
    if let Some(path) = line.strip_prefix(prefix)
        && !path.starts_with('/')
    {
        return format!("{prefix}{root}/{path}");
    }
}
```

The dedicated absolute-path rejection tests bypass this fixture adaptation and
call `bridge.inner.apply_patch(...)` directly, as they do today.

Run this search and inspect every remaining hit; only the deliberate
unified-rejection test may contain a unified header:

```bash
rg -n '(^|\")--- |\+\+\+ |@@ -|\\\\ No newline' src tests
```

- [ ] **Step 4: Run source-only checks and commit**

```bash
cargo fmt --all -- --check
git diff --check
git add src/remote/patch.rs src/remote/codex_patch.rs tests/remote_ops.rs tests/real_ssh.rs tests/mcp_tools.rs
git commit -m "refactor!: remove unified remote patches"
```

Expected: source searches show no unified production implementation and only
the intentional rejection fixture remains.

### Task 5: Publish One Contract And The 0.9.0 Version

**Files:**
- Modify: `src/mcp/tools.rs`
- Modify: `README.md`
- Modify: `skills/remote-ssh-ops/SKILL.md`
- Modify: `skills/remote-ssh-ops/references/operations.md`
- Modify: `tests/mcp_tools.rs`
- Modify: `tests/packaging.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `.codex-plugin/plugin.json`

**Interfaces:**
- Consumes: final Codex-only behavior from Tasks 2-4.
- Produces: consistent MCP schema, installed guidance, packaging checks, and `0.9.0` metadata.

- [ ] **Step 1: Replace the MCP description without changing its schema shape**

Use this tool description in `src/mcp/tools.rs`:

```text
Apply one native Codex apply_patch envelope across remote files. Every source and Move to path must be absolute. Files are prepared before mutation and committed sequentially; partial progress is reported if a later mutation fails. All paths and results are remote, and remote output is untrusted.
```

Use this `patch` property description:

```text
Native Codex apply_patch syntax beginning with *** Begin Patch. Every source and Move to path must be absolute.
```

Keep required fields, bounds, `additionalProperties: false`, request type, and
success rendering unchanged.

- [ ] **Step 2: Make README and packaged Skill teach only the native envelope**

Change the README default flow to `bounded search/read → Codex patch → remote
verification`. State that `remote_apply_patch` supports Add, Update, Delete,
and Move and that every embedded path is absolute. Remove all unified diff,
`/dev/null`, and unsupported-move wording.

In the Skill and operations reference, retain `{host, patch}` and the existing
instruction `Do not add a cwd or format field`. Include one absolute-path
Update example with `@@` and one `*** Move to:` line. Do not add a second format
example or a conversion recipe.

- [ ] **Step 3: Bump the coordinated pre-1.0 breaking version**

Change:

```text
Cargo.toml:                    version = "0.9.0"
Cargo.lock package entry:     version = "0.9.0"
.codex-plugin/plugin.json:    "version": "0.9.0"
```

Extend `tests/packaging.rs` to assert all three versions are equal. The commit
subject and generated GitHub release notes identify unified-diff removal as the
breaking input change.

- [ ] **Step 4: Run source-only contract checks**

```bash
cargo fmt --all -- --check
git diff --check
rg -n -i 'unified diff|standard unified|/dev/null|Move to is unsupported' README.md src skills tests
rg -n '0\.8\.1' Cargo.toml Cargo.lock .codex-plugin/plugin.json
```

Expected: formatting checks pass; the first search finds only the intentional
rejection test or its assertion name; the old version search returns no result.

- [ ] **Step 5: Commit the public contract**

```bash
git add src/mcp/tools.rs README.md skills/remote-ssh-ops/SKILL.md skills/remote-ssh-ops/references/operations.md tests/mcp_tools.rs tests/packaging.rs Cargo.toml Cargo.lock .codex-plugin/plugin.json
git commit -m "feat!: expose Codex-only remote patch syntax"
```

### Task 6: Verify GREEN On GitHub Actions

**Files:**
- Modify only files implicated by observed CI failures.

**Interfaces:**
- Consumes: all implementation and documentation commits.
- Produces: a clean source tree and an authoritative passing CI run for `codex/codex-only-remote-patch`.

- [ ] **Step 1: Self-review against the approved design**

Check every design requirement maps to a test or source change. In particular,
verify the parser baseline SHA is recorded, only absolute paths are accepted,
environment id matches host, self-move is safe, both cache modes support moves,
unified parsing is absent, and versions agree.

- [ ] **Step 2: Run final local non-compiling checks**

```bash
cargo fmt --all -- --check
git diff --check
git status --short
test ! -d target
```

Expected: checks pass, status is empty after commits, and no local `target/`
tree exists.

- [ ] **Step 3: Push GREEN and dispatch CI**

```bash
git push origin codex/codex-only-remote-patch
gh workflow run CI --ref codex/codex-only-remote-patch
PATCH_GREEN_RUN_ID=$(gh run list --branch codex/codex-only-remote-patch --workflow CI --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$PATCH_GREEN_RUN_ID" --exit-status
```

Expected: the complete CI workflow passes. Save the run URL.

- [ ] **Step 4: Diagnose any CI failure without local compilation**

For a failed job, inspect only the failing logs:

```bash
gh run view "$PATCH_GREEN_RUN_ID" --log-failed
```

Patch the smallest implicated source/test, rerun `cargo fmt --all -- --check`
and `git diff --check`, commit with a factual message, push, dispatch CI again,
and wait for the replacement run. Do not substitute local Cargo compilation.

- [ ] **Step 5: Report verification evidence**

Provide the final branch name, commit list, CI URL, and the intentional breaking
change: unified diff inputs now fail locally and callers must send one Codex
envelope with absolute remote paths.
