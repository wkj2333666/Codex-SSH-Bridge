# Codex-Only Remote Patch Design

## Context

`remote_apply_patch` currently accepts two unrelated patch languages: Codex's
`*** Begin Patch` envelope and standard unified diff. The Codex parser is only a
subset of the native grammar: it rejects repeated `@@` context selectors that
do not themselves contain changes, rejects `*** Move to:`, and uses stricter
matching than Codex. This makes a native-looking patch fail before SSH even
starts and leaves the model to infer which of two grammars the MCP tool expects.

The bridge already has a coherent long-term request boundary: file operations
carry `host` plus absolute remote paths, while commands carry `host` plus an
explicit absolute `cwd`. This change does not add a session, remembered cwd,
format selector, or second patch tool. It only makes the existing patch body a
single, predictable language.

## Decision

`remote_apply_patch` becomes Codex-only in version `0.9.0`. Its JSON request
shape remains:

```json
{"host":"alias","patch":"*** Begin Patch\n...\n*** End Patch\n"}
```

Unified diff is removed rather than deprecated or retained as an undocumented
fallback. An input that does not contain a Codex envelope fails locally with
`InvalidArgument` and the factual message `patch must use Codex apply_patch
syntax`. The parser never retries another grammar.

This is an intentional breaking input-contract change. It is published as a
minor pre-1.0 release and called out in the `0.9.0` release notes, MCP schema,
README, packaged Skill, and operations reference.

## Compatibility Target

The compatibility target is the grammar and normal file-update behavior of
OpenAI Codex's native apply-patch implementation as inspected on 2026-08-23:

- <https://github.com/openai/codex/blob/main/codex-rs/apply-patch/src/parser.rs>
- <https://github.com/openai/codex/blob/main/codex-rs/apply-patch/src/streaming_parser.rs>
- <https://github.com/openai/codex/blob/main/codex-rs/apply-patch/src/seek_sequence.rs>

Implementation records the upstream commit SHA used to build parity fixtures,
so later upstream changes do not silently redefine a released bridge version.
The bridge copies no upstream source dependency at runtime; it implements the
small bounded grammar locally and carries focused parity fixtures.

The accepted grammar is:

```text
start: begin_patch environment_id? hunk+ end_patch
begin_patch: "*** Begin Patch" LF
environment_id: "*** Environment ID: " filename LF
end_patch: "*** End Patch" LF?
hunk: add_hunk | delete_hunk | update_hunk
add_hunk: "*** Add File: " filename LF add_line+
delete_hunk: "*** Delete File: " filename LF
update_hunk: "*** Update File: " filename LF change_move? change?
add_line: "+" /(.*)/ LF
change_move: "*** Move to: " filename LF
change: (change_context | change_line)+ eof_line?
change_context: ("@@" | "@@ " /(.+)/) LF
change_line: ("+" | "-" | " ") /(.*)/ LF
eof_line: "*** End of File" LF
```

The bridge deliberately differs from local Codex in path resolution: every
source and move destination must be an absolute remote path. Relative paths,
`/dev/null`, traversal aliases, repeated separators, control characters, and
paths outside the configured root remain invalid. This is the only patch-body
grammar deviation.

The optional `*** Environment ID:` preamble is accepted. Because MCP already
routes with the required `host` field, a present environment id must equal
`host`; an empty or mismatched value fails before remote access. Codex's
lenient heredoc wrappers are shell-invocation compatibility, not patch grammar,
and are not accepted inside the MCP `patch` string.

## Parsing And Matching

All syntax, path, duplicate-path, byte, file, chunk, and line limits are
validated before any SSH process or edit-cache mutation. The parser preserves
the distinction between context lines and identical remove/add text and allows:

- an update with `*** Move to:` and no textual chunks;
- the first update chunk without an explicit `@@` marker;
- multiple consecutive `@@` context selectors before the changed lines;
- pure additions with or without a context selector; and
- `*** End of File` on the final chunk.

Update matching follows native ordered search. Each context selector advances
the cursor, and the changed block is located after it. Search attempts exact,
trailing-whitespace-insensitive, fully-trimmed, then native Unicode-punctuation
normalization matches. Later chunks continue after earlier matches. Normal
output uses native LF normalization; create and updated text end in LF.

Parity means matching the native accepted grammar and intended file result for
normal operations. It does not mean deliberately reproducing an upstream data
loss defect: a move whose destination equals its source is treated as an
ordinary in-place update.

## Move Execution

`CodexFilePatch` gains `move_path: Option<String>`. A non-self move is prepared
as one logical patch operation with two guarded paths:

1. read and match the source generation;
2. snapshot the destination, which may be missing or an existing regular file;
3. write the updated bytes to the destination; and
4. delete the source using its guarded base hash.

This matches native overwrite behavior while preserving bridge safeguards.
Both paths are resolved and snapshotted before the first mutation. Immediate
execution reports the destination write before the source delete in partial
progress. Buffered execution stages the same destination write and source
delete in one edit-cache generation. `changed_paths` contains both actual paths
in commit order; a self-move contains the source once.

Overlapping source/destination paths across file sections are rejected before
remote access. This prevents one section from silently changing the base used
by another and preserves the bridge's all-input-preflight invariant.

## Internal Structure

`src/remote/codex_patch.rs` owns the only patch AST, parser, context matcher,
and byte derivation. `src/remote/patch.rs` retains remote path preparation,
snapshot acquisition, edit-cache integration, immediate commit, cancellation,
and partial-progress reporting.

The unified-only `FilePatch`, `Hunk`, `HunkRange`, `HunkLine`, `HeaderPath`,
`RecordCursor`, numerical range parser, unified applicator, `ParsedFilePatch`
enum, and format dispatcher are deleted. The mutation pipeline consumes
`Vec<CodexFilePatch>` directly. Shared limits and error constructors stay in
`patch.rs` unless moving one into `codex_patch.rs` materially simplifies their
ownership; no new runtime dependency is introduced.

## Errors

Errors remain bounded, factual, and do not echo patch contents. They
distinguish malformed envelopes or directives, environment mismatch,
non-absolute paths, overlapping paths, context mismatch, size limits, guarded
write conflict, and uncertain mutation outcome. A unified diff is classified
only as a non-Codex patch; there is no unified-specific parser error.

## Documentation And Versioning

The MCP tool and `patch` property descriptions state that only Codex
apply-patch syntax is accepted, every path is absolute, and moves are
supported. README and packaged Skill examples use only the Codex envelope.
References to unified diff, `/dev/null` patch headers, and unsupported moves are
removed.

`Cargo.toml`, `Cargo.lock`, and `.codex-plugin/plugin.json` move together from
`0.8.1` to `0.9.0`. The release note identifies unified-diff removal as the
breaking change and tells human callers to emit Codex envelopes instead.

## Testing

Tests are migrated rather than simply deleted. Existing mutation-pipeline,
cache, cancellation, conflict, limit, and partial-progress scenarios are
rewritten with absolute-path Codex envelopes. Unified-parser-specific range,
header, `/dev/null`, and no-newline-marker tests are removed.

Focused parity tests cover:

1. the multi-`@@` form that failed in task `01a0200a-6fa0-7043-a8fd-88359ee0d924`;
2. Add, Delete, Update, move-only, update-and-move, and self-move;
3. optional matching and mismatched environment ids;
4. first chunks without `@@`, pure additions, EOF anchoring, and LF output;
5. exact, `trim_end`, `trim`, and Unicode-normalized context search;
6. absolute source and destination enforcement;
7. unified diff rejection before SSH or cache mutation;
8. overlapping-path rejection before mutation;
9. move overwrite and partial-progress classification; and
10. MCP schema, README, Skill, packaging, and version consistency.

GitHub Actions remains the authoritative build and test host. Local validation
is limited to `cargo fmt --all -- --check`, `git diff --check`, source searches,
and other non-compiling checks required by the repository policy.

## Non-goals

- No cwd, remembered directory, session state, or one-process-per-task layer.
- No `format` request field or separate unified-diff MCP tool.
- No remote `patch`, `git apply`, or shell parsing.
- No silent conversion from unified diff to Codex syntax.
- No change to successful MCP response shape or edit-cache durability.
