# Local Codex Output Parity Design

Date: 2026-07-25  
Target release: 0.3.0

## Goal

Make remote SSH tools feel like the corresponding local Codex operations while
preserving the specialized remote calls that reduce Agent work.

The bridge continues to provide `remote_list`, `remote_read`,
`remote_search`, and the other existing tools. It remains responsible for
remote command construction, quoting, capability handling, bounded reads,
retention, and SSH lifecycle management.

Only the model-visible MCP result is simplified. This is an intentionally
breaking output-contract change and therefore advances the pre-1.0 minor
version from 0.2.x to 0.3.0. There is no legacy-output switch.

## Non-goals

- Do not collapse the tool surface into only `remote_run`.
- Do not change SSH transport, dispatcher, helper, or session behavior.
- Do not add a general projection framework or a parallel result type
  hierarchy.
- Do not weaken path validation, output bounds, mutation reporting, or
  cancellation safety.
- Do not add another paging or retention system.
- Do not run local Cargo builds or tests; GitHub Actions remains authoritative.

## Implementation boundary

The existing `src/mcp/render.rs` module remains the output boundary:

```text
existing complete remote result
    -> select model-relevant fields in the existing render function
    -> MCP content and structuredContent
```

Internal result types retain physical roots, helper mode, shell metadata,
byte counts, elapsed time, and full mutation state. Renderers omit these facts
from normal successful results unless a fact is required to interpret an
exceptional outcome.

This design adds no remote request and no additional SSH round trip.

## Input contract

Existing specialized tools and their input fields remain unchanged.

- Every host-scoped call still takes an explicit SSH alias.
- File operations still require absolute remote paths.
- `remote_run` still requires an absolute remote working directory.
- Omitted `remote_run.shell` still means Bash.
- `sh` and `login` remain explicit choices.
- Existing request size and collection bounds remain enforced.

The breaking change is limited to MCP results and the removal of prescriptive
error actions.

## Successful output contract

Large business data appears only once. `content` carries the model-readable
payload. `structuredContent` carries only small state that cannot be expressed
by the payload itself.

### Discovery and read tools

| Tool | `content` | `structuredContent` |
| --- | --- | --- |
| `remote_hosts` | One SSH alias per line | `{}` |
| `remote_list` | One `kind<TAB>absolute_path` record per line | Empty unless truncated |
| `remote_stat` | One compact JSON record per path containing `path`, `kind`, `size`, `mtime`, and `mode` | `{}` |
| `remote_search` | One `path:line:text` record per match, matching familiar `rg` output | Empty unless truncated |
| `remote_read` | Raw content for one file; `==> absolute_path <==` separators for multiple files | Empty unless truncated |
| `remote_output_read` | Raw retained page content | `next_offset` and `eof` |

When an operation is truncated, its structured result contains:

```json
{
  "truncated": true,
  "output_ref": "opaque-reference"
}
```

`remote_output_read` continues to use the existing retained-output store and
opaque references.

### Execution and mutation tools

| Tool | `content` | `structuredContent` |
| --- | --- | --- |
| `remote_run` | Non-empty stdout and stderr, each labeled with its stream name | `exit_code`, plus truncation fields when needed |
| `remote_apply_patch` | `Done!` on complete success | `{}` |
| `remote_write` | `Wrote /absolute/path` | `{}` |

A non-zero remote command exit code remains an ordinary completed command
result, not an MCP protocol error.

### Fields omitted from normal success

Normal successful output does not contain:

- `remote`
- repeated `host`
- `physical_root`
- `helper_mode`
- shell kind or version
- `actual_path` and `relative_path` duplicates
- aggregate names and entry counts
- raw byte counts
- elapsed milliseconds
- `detail_retained`
- false-valued truncation fields
- false-valued mutation or process-continuation fields

The tool invocation already identifies the host and requested paths. Repeating
them as provenance metadata does not help the model interpret a normal result.

## Inline output bound

The bridge returns at most 32 KiB of model-visible inline result data for one
tool call. The measured size is the sum of UTF-8 bytes in all `content.text`
values plus the serialized `structuredContent` value. MCP and JSON-RPC envelope
syntax is outside this model-output budget and remains governed by the existing
wire limit.

If the complete result exceeds that bound:

1. the renderer emits the bounded prefix that fits;
2. the existing retention store preserves the complete bounded bridge result;
3. `structuredContent` reports `truncated: true` and an `output_ref`;
4. the Agent may request more data with `remote_output_read`.

The 32 KiB limit is applied below the existing MCP wire limit. It limits model
context consumption, while the wire limit continues to protect protocol
framing. The renderer must not tokenize output or estimate language-model
tokens.

## Error contract

Errors report facts, not suggested behavior:

```json
{
  "code": "ERROR_CODE",
  "message": "concise factual description"
}
```

The bridge removes `action` and `suggested_action` from every error, including
invalid arguments. The Agent decides what to do next.

Only relevant factual fields are added:

- `path`
- `changed_paths`
- `not_changed_paths`
- `outcome_unknown_paths`
- `mutation_may_have_applied`
- `remote_process_may_continue`
- `requested_shell`
- `available_shells`

For example, an unavailable Bash reports that Bash was requested and lists
known available shells. It does not instruct the Agent to retry with `sh`.

Physical roots, helper mode, shell version, timing, and internal transport
diagnostics remain available to bridge debug/profile logging but are not
model-visible error fields.

Partial mutations and uncertain outcomes retain their existing conservative
semantics. This output cleanup does not convert an unknown outcome into success
or failure.

## Renderer constraints

The implementation stays within the existing renderer:

- Each `render_*` path explicitly selects its output fields.
- Large stdout, stderr, file bodies, listings, and matches occur in only one
  MCP representation.
- `structuredContent` never repeats large values already present in `content`.
- Existing escaping and control-character normalization remain active where
  structured metadata is rendered.
- Existing compact wire fallback remains available for failures below the MCP
  framing layer.
- Debug-only details go to profile/debug output, never the ordinary MCP result.

No generic model-projection trait, registry, compatibility mode, or runtime
format configuration is introduced.

## CI contract tests

Existing GitHub CI gains tests for the 0.3.0 contract:

1. Golden output tests cover every successful tool.
2. Error tests prove that `action` and `suggested_action` are absent.
3. Forbidden-field tests reject normal output containing root, helper, shell
   version, timing, duplicate path, or redundant count metadata.
4. A 32 KiB boundary test covers exact-fit, one-byte-over, and retained-page
   behavior.
5. Large-value tests prove that content is not duplicated in
   `structuredContent`.
6. Compact successful results have no more than 512 bytes of fixed wrapping
   overhead, excluding the business payload and mandatory JSON-RPC envelope.
7. Existing mutation-uncertainty, cancellation, wire-bound, RSS, and hostile
   output tests continue to pass.

No new CI job is needed for these contract tests; they run in the existing
quality suite.

## CI duration changes

The current workflow serializes more work than the correctness model requires.
The following changes reduce wall-clock time without reducing coverage:

1. Remove the global `--test-threads=1` from ordinary tests.
2. Keep RSS and performance acceptance tests explicitly serial.
3. Start `quality` and `diagnostics` independently instead of making
   diagnostics wait for quality.
4. Remove the redundant release-binary build from `quality`; the release
   workflow builds release artifacts, and diagnostics already compiles the
   release test profile.
5. Give debug quality builds and release diagnostics separate target caches.
6. Use a commit-specific target-cache primary key and restore the most recent
   cache sharing the same toolchain and `Cargo.lock` prefix. Successful CI runs
   can then save newly compiled project artifacts instead of repeatedly
   restoring an immutable first-run target cache.
7. Install `ripgrep` only when the hosted runner does not already provide it.

Toolchain, Cargo registry, Cargo Git, and cross-compiler caches remain. Release
architecture coverage remains unchanged.

If parallel ordinary tests expose a real shared-state dependency, only the
affected integration test target is moved to a serial invocation. The workflow
must not restore global serialization merely to mask an unidentified race.

## Acceptance criteria

The change is complete when:

- all nine tools keep their current input schemas;
- normal results follow the output tables above;
- no successful result exposes the forbidden diagnostic fields;
- no error contains an action recommendation;
- output over 32 KiB is retained and pageable;
- cancellation and uncertain-mutation facts remain visible when applicable;
- the renderer performs no additional remote operation;
- CI passes formatting, Clippy, tests, output-contract checks, release
  diagnostics, RSS bounds, and performance profiling;
- CI reports quality and diagnostics in parallel;
- the release version is 0.3.0;
- no local Cargo build, test, Clippy, or benchmark was used to validate the
  implementation.
