# Dual Patch Syntax Design

## Context

`remote_apply_patch` currently accepts standard unified diffs, while Codex's
native local `apply_patch` tool uses an envelope beginning with
`*** Begin Patch` and file directives such as `*** Add File`. The remote tool's
name and generic schema description lead the model to reuse the native syntax,
but the bridge rejects it before any remote mutation.

This is an interface mismatch, not a remote execution failure. It conflicts
with the project's goal of making remote editing behave like local Codex work.

## Goals

- Accept the patch syntax Codex naturally emits for its local tool.
- Preserve standard unified diff support for existing callers, `git diff`, and
  other established patch producers.
- Keep one MCP tool and one patch execution path.
- Preserve absolute remote paths, guarded snapshots, conflict detection,
  bounded edit caching, and atomic synchronization.
- Add no format selector or extra decision for the model.

## Non-goals

- Do not accept relative paths or add a patch working directory.
- Do not execute `patch`, `git apply`, or another remote shell parser.
- Do not infer malformed or mixed syntax.
- Do not implement two independent mutation engines.
- Do not change successful output or edit-cache durability semantics.

## Input Contract

`remote_apply_patch` keeps its existing request shape:

```json
{"host":"alias","patch":"..."}
```

The first non-empty input line selects exactly one parser:

- `*** Begin Patch` selects Codex apply-patch syntax.
- `--- ` selects standard unified diff syntax.
- Any other prefix is an invalid patch.

Once selected, the whole input must use that syntax. Nested envelopes,
trailing content after `*** End Patch`, and mixtures of Codex directives with
unified file headers are invalid. Detection is deterministic and does not
retry one parser after the other fails.

The MCP tool description and `patch` property description state both accepted
formats and the absolute-path rule. The installed Skill gives one minimal
create example for each format and explicitly distinguishes the remote tool
from the local tool's transport while preserving the same familiar syntax.

## Codex Syntax Boundary

The compatibility parser accepts the native operations needed for file edits:

- `*** Add File: /absolute/path`
- `*** Update File: /absolute/path`
- `*** Delete File: /absolute/path`

All file paths must be absolute. `/dev/null` remains a unified-diff concept and
is not a Codex file directive. Add-file body lines retain their required `+`
prefix. Update hunks use Codex's ordered text-context semantics: an optional
`@@` header advances the search cursor past its first match, then context plus
removed lines select the first matching contiguous region at or after that
cursor. Later hunks continue after earlier matches. A missing match is a
conflict. This mirrors Codex's native application order instead of adding a
stricter ambiguity rule. The parser and matcher run locally and never delegate
interpretation to a shell command.

`*** Move to` is explicitly unsupported in the first release because it adds
cross-path rename and partial-progress semantics rather than mere syntax
compatibility. It is rejected before remote access. Add, update, and delete are
the required compatibility surface.

## Shared Internal Representation

Both parsers produce bounded per-file edit plans containing:

- canonical absolute path;
- create, update, or delete operation;
- syntax-specific, already validated hunk anchors and body lines; and
- terminal-newline state.

All files are parsed and structurally validated before snapshots are fetched
or cache generations are changed. Unified hunks apply with their numerical
ranges; Codex hunks apply with their textual context anchors. Both produce the
same final `DesiredState` values. From that boundary onward, both syntaxes use
the same output-size checks, local edit-cache transaction, remote batch
synchronization, and partial-progress reporting.

Syntax choice therefore affects parsing only. It does not create a new hot
path after parsing and does not change network or remote-helper performance.

## Errors

Errors remain factual and contain no prescribed action. They distinguish:

- unrecognized patch prefix;
- malformed Codex envelope or directive;
- malformed unified diff;
- mixed syntax;
- non-absolute path;
- unsupported Codex move directive; and
- existing size, conflict, and mutation-uncertainty failures.

No error echoes the complete patch or file content.

## Testing

Parser and integration tests prove:

1. equivalent Codex and unified patches produce identical create, update, and
   delete results;
2. the exact `*** Begin Patch` form emitted by local Codex is accepted;
3. both formats retain absolute-path and root-containment enforcement;
4. mixed syntax, trailing envelope data, duplicate files, malformed hunks,
   traversal attempts, and unsupported moves fail before remote access;
5. byte, file, hunk, line, output, and cache limits apply equally;
6. no-terminal-newline behavior remains byte-accurate;
7. ordered context matching selects the same first occurrence as native Codex;
8. existing unified-diff tests continue to pass unchanged; and
9. MCP schema, Skill, README, packaging, and release assets advertise the same
   contract.

GitHub Actions remains the authoritative build and test environment. Local
verification is limited to formatting and source-level checks under the
repository policy.

## Compatibility And Performance

Unified diff behavior is backward compatible. Codex syntax is additive. Format
selection is one bounded prefix scan before parsing and is negligible relative
to parsing, snapshot acquisition, and SSH transport. The MCP request schema and
successful response shape do not change, so existing clients need no update.

The compatibility grammar and ordered context behavior follow the official
Codex apply-patch implementation:
`https://github.com/openai/codex/tree/main/codex-rs/apply-patch`.
