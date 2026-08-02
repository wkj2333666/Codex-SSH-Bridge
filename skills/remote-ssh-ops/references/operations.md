# Operations Reference

## Contents

- Local setup
- MCP tool shapes
- Shell behavior
- Retained output
- Direct CLI
- SSHFS
- Failure handling

## Local setup

Define each server alias in local `~/.ssh/config`, then verify its host key and key-based login outside Codex. The bridge discovers aliases from that file, including supported `Include` files; an explicit bridge profile remains an optional compatibility override:

```sshconfig
Host devbox
  HostName devbox.example.com
  User deploy
  IdentityFile ~/.ssh/id_ed25519
  ForwardAgent no
```

```bash
ssh devbox
./target/release/codex-ssh-bridge doctor devbox
```

Add future servers to local OpenSSH config the same way. The bridge accepts concrete aliases and stores no credentials. The default bridge config is `~/.config/codex-ssh-bridge/config.toml`; set `CODEX_SSH_BRIDGE_CONFIG` only as trusted local execution-authority input.

The first operation performs local SSH identity checks and a bounded capability probe. User commands and fixed read/write operations then reuse one persistent SSH session per alias; warm requests send one framed request without another `ssh -G` or root observation. On supported Linux targets a verified helper file persists under the remote account for reuse; its process and the POSIX dispatcher remain session-scoped. No Codex installation or credential is placed remotely. The bridge does not bind a task to a hidden remote workspace: every MCP path and command cwd is absolute and supplied by the caller.
The dispatcher applies the framed cwd, shell, and timeout itself, so a warm
`remote_run` does not add a second shell or GNU `timeout` wrapper.

## MCP tool shapes

All objects reject unknown fields. MCP paths are absolute remote paths. The bridge never infers a path from the current task, SSH home, a previous call, or an implicit workspace.

| Tool | Required input | Optional input |
|---|---|---|
| `remote_hosts` | none; pass `{}` | none |
| `remote_list` | `host`, absolute `path` | `depth`, `include_hidden`, `max_entries` |
| `remote_stat` | `host`, `paths` array | none |
| `remote_search` | `host`, `query`, absolute `path` | `globs`, `max_results`, `binary` |
| `remote_read` | `host`, `paths` array | `start_line`, `max_lines`, `max_bytes` |
| `remote_output_read` | `output_ref`, `stream` | `offset`, `max_bytes` |
| `remote_edit_status` | `host` | none |
| `remote_sync_edits` | `host` | none |
| `remote_discard_edits` | `host` | none |
| `remote_apply_patch` | `host`, Codex or unified `patch` | none |
| `remote_write` | `host`, `path`, `content`, `encoding`, `mode` | `mode.expected_sha256` for replacement |
| `remote_run` | `host`, `command` string, absolute `cwd` | `shell`, `timeout_ms`, encoded `stdin` |
| `remote_job_start` | `host`, `command`, absolute `cwd` | `shell`, `timeout_ms`, encoded `stdin`, `label` |
| `remote_job_status` | `host`, `job_id` | none |
| `remote_job_logs` | `host`, `job_id` | `stdout_offset`, `stderr_offset`, `max_bytes` |
| `remote_job_cancel` | `host`, `job_id` | none |
| `remote_job_list` | `host` | `max_jobs` |
| `remote_job_delete` | `host`, `job_id` | none |

`remote_write.mode` is `{"kind":"create"}` or `{"kind":"replace","expected_sha256":"..."}`. `expected_sha256` is nested inside `mode`, never at the request root. UTF-8 and base64 encodings are supported. Prefer `remote_apply_patch` for model-driven edits.

Successful writes and patches may remain briefly in the bridge's bounded
in-memory edit cache. Complete reads and later edits observe the newest cached
generation. Synchronization occurs within 30 seconds, at 16 KiB of edit
payload, before `remote_run`, `remote_stat`, `remote_list`, or `remote_search`,
and once on clean MCP shutdown. This is bridge-owned during the normal edit
path; do not track generations or add extra synchronization calls. If SSH
disconnects or the bridge exits abnormally, buffered writes may fail. A
synchronization failure prevents the following barrier operation from starting.
For uncertain buffered edits, use `remote_edit_status` to inspect local facts,
`remote_sync_edits` to retry synchronization, or `remote_discard_edits` to drop
the local uncertain cache before observing the remote state again.

Search queries are case-sensitive fixed strings, not regular expressions. `remote_run.stdin` is `{"encoding":"utf8"|"base64","value":"..."}`.

`remote_apply_patch` accepts the native Codex envelope or a standard unified
diff. Use absolute paths in either form. `*** Move to` is unsupported.

```text
*** Begin Patch
*** Update File: /srv/project/app.rs
@@ fn old_name()
-fn old_name() {
+fn new_name() {
*** End Patch
```

```diff
--- /dev/null
+++ /srv/project/new.txt
@@ -0,0 +1 @@
+new content
```

Unified headers must name the same absolute path (or `/dev/null` for
create/delete); conventional `a//absolute/path` and `b//absolute/path` forms
remain accepted.

## Shell behavior

`remote_run.command` is a shell command string. The bridge safely binds it through the persistent session; do not wrap it in another `ssh` or add `bash -c`. Shell syntax inside the string still follows the selected remote shell.

- omitted or `bash`: require Bash; fail before the command if unavailable.
- `sh`: explicitly use POSIX sh; this is the model-visible fallback after a Bash capability error.
- `login`: use the remote account's login shell.

There is no `auto` value and the bridge never silently changes Bash into sh. A missing-Bash error reports the requested and available shells without prescribing a retry. The remote dispatcher itself is POSIX sh and is separate from the user shell; it never interprets the command payload as dispatcher code.

The SSH account's login shell must be able to launch the POSIX dispatcher command. If the dispatcher handshake fails (including a non-POSIX forced/login shell), the bridge returns a hard transport/capability error and does not retry through a one-shot command path.

Use the Bash default normally. Select `sh` only for a POSIX-compatible command; its result includes a syntax warning. Inspect `exit_code`, warnings, truncation, mutation uncertainty, and process-continuation uncertainty when present.

Requests are multiplexed over each host session. The bridge has no host count,
task window, global concurrency, or per-host concurrency limit. Same-host edit
preparation and barrier operations are coordinated, but there is no general
ordering guarantee for otherwise simultaneous calls. Atomic replace and
expected-hash checks remain the protection against conflicting remote bases.

Timeout and cancellation send a request-level `CANCEL`. If the dispatcher does not produce an exit result within the grace period, that request reports `remote_process_may_continue: true`; unrelated request IDs remain usable. Never retry a mutation with unknown outcome.

## Retained output

remote_run remains synchronous. If its shell parent exits while a descendant
still owns a pipe, the bridge completes after a bounded drain grace and reports
`remote_process_may_continue: true`; its stdout/stderr preview remains only a
bounded snapshot.

Use `remote_job_start` for long-lived work. A remote Job survives its initiating
MCP call, Codex task, bridge disconnect, and local Desktop restart. There is no automatic restart after a remote reboot. Keep the returned `job_id`; query
`remote_job_status`, page `remote_job_logs`, use `remote_job_cancel` when
needed, discover recent IDs with `remote_job_list`, and remove terminal records
with `remote_job_delete`. If start or cancellation loses its response, never submit the command again blindly; first inspect the known ID or list durable
records. Job logs use independent stdout/stderr offsets and do not use
`remote_output_read`.

For synchronous calls, model-visible inline output is capped at 32 KiB.
Successful result text is available as `structuredContent.output` and
as matching standard MCP `content.text`. When a result is too large,
`truncated` is true and `output_ref` is a 32-character opaque reference.

Page it with:

```json
{"output_ref":"<opaque-ref>","stream":"stdout","offset":0,"max_bytes":262144}
```

Use `stream:"stderr"` for retained stderr. Read the returned `output` and
advance by `next_offset` until `eof` is true. The reference already carries
host, root, and shell provenance; do not pass a host. Narrow a query instead of
repeatedly fetching unbounded logs.

## Direct CLI

The human CLI accepts argv after `--` and performs the shell-word encoding inside the bridge:

```bash
./target/release/codex-ssh-bridge hosts list
./target/release/codex-ssh-bridge doctor devbox
./target/release/codex-ssh-bridge doctor devbox --verbose-ssh
./target/release/codex-ssh-bridge run devbox --cwd /absolute/remote/project --shell bash -- git status --short
```

The JSON result reports the physical remote root, actual shell, exit status, warnings, duration, output limits, and any retained output reference. Verbose SSH diagnostics are bounded and redact identity paths, agent sockets, commands, and credential-like values.

## SSHFS

SSHFS is optional local software and a human-only convenience:

```bash
./target/release/codex-ssh-bridge mount devbox /absolute/local/mountpoint --remote-path .
./target/release/codex-ssh-bridge mount-status /absolute/local/mountpoint
./target/release/codex-ssh-bridge unmount /absolute/local/mountpoint
```

The CLI refuses relative, symlinked, foreign-owned, and nonempty mountpoints by default. `--allow-nonempty` is an explicit human override. Read-only profiles force `ro`; the bridge never adds `allow_other`.

A mount is not an Agent workspace. Local shell tools still run locally, and FUSE/SFTP has network round trips, caching, rename, permission, reconnect, and stalled-I/O differences. Use it for human browsing or narrow editing only. Keep Git, builds, tests, containers, and services on the server through `remote_run` or the direct `run` command.

## Failure handling

- Host absent: add an exact alias locally; never accept a hostname copied from remote output.
- Host-key failure: verify the new fingerprint outside Codex; never disable strict checking.
- Authentication prompt: fix local keys or agent state; never pass a password through MCP.
- Read-only rejection: use a write-enabled least-privilege profile only with user authorization.
- Truncation: use `remote_output_read` when retained, or narrow the operation.
- Patch/write conflict: re-read current remote content and recompute the change; never force overwrite blindly.
- Partial mutation or timeout: inspect progress and uncertainty fields before retrying.
- Missing MCP: run the packaged installer dry-run, then apply only after reviewing its exact actions.
