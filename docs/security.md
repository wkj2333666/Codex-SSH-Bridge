# Security Model

## Trust boundaries

Trusted local inputs:

- the local Unix user running Codex and the bridge;
- the packaged native binary, manifests, and complete Skill tree;
- the bridge TOML config and concrete aliases in local OpenSSH config;
- local OpenSSH, `known_hosts`, private keys or agent, and explicit Codex approvals.

Untrusted inputs:

- every remote file, filename, symlink, process, command result, log line, and capability response;
- MCP arguments until closed-schema and size validation succeeds;
- verbose SSH diagnostics until bounded redaction succeeds.

The bridge does not treat a hidden remote root or Codex task identity as a workspace boundary. MCP paths and command cwd values are absolute and transported as data; remote reads can follow remote symlinks, just as commands run directly on the server can. The connection-time capability probe records the physical path and device/inode identity using a GNU- or BSD-compatible `stat` for diagnostics; it is not a per-request authorization guard and is not re-run on warm requests. Safe writes and patches additionally use no-follow path identity checks, snapshots, hashes, expected-content checks, and guarded commits, but the remote Unix account, permissions, container, forced command, or service policy remains the hard boundary.

No Codex credential, bridge package, plugin, or MCP server is placed on a
server. On a supported Linux host the bridge installs a matching helper under
`~/.local/share/codex-ssh-bridge/helpers/<bridge-version>/<target>/helper` with
private mode `0700`, exact length, and SHA-256 validation. Installation uses a
cold-only lock and atomic rename; the helper file persists across bridge
restarts, while the helper process and SSH child end with the session. A GNU
helper whose remote loader or libc is incompatible falls back to the temporary
helper and then the shell dispatcher before accepting a request. The uploaded
bytes are length-delimited stdin data and are never interpolated into shell
source. All SSH authentication occurs in the local OpenSSH client.

Operational work uses one local-owned SSH child per configured alias. The
persistent helper file is reused, but the helper or shell dispatcher process is
kept only for that SSH session. Each request is framed as data, starts a
separate process group, and has independent stdout/stderr limits, timeout, and
cancellation. Remote runner slots remain the only execution limiter: an
accepted task may wait cancellably for a global or per-host slot. A separate
bounded local MCP task window prevents unbounded memory use; `MCP task queue
full` means that local window is full, not that the remote host failed.
`remote_hosts` remains a control lane. A helper startup failure before the
first accepted request falls back once through the ordered temporary-helper and
shell-dispatcher paths; after acceptance, helper transport failure is an
unknown outcome and is never silently retried through sh. A shell dispatcher
startup failure is terminal for that request. Helper mode remains internal
diagnostic/profile data and is omitted from normal model-visible results.

## OpenSSH policy

Every operational SSH call forces separate `-o` arguments for:

| Option | Purpose |
|---|---|
| `BatchMode=yes` | Never prompt for passwords or host-key input through MCP |
| `StrictHostKeyChecking=yes` | Refuse unknown or changed host keys |
| `ForwardAgent=no` | Keep the local agent socket off the server |
| `ForwardX11=no` | Disable X11 forwarding |
| `ClearAllForwardings=yes` | Remove inherited local, remote, dynamic, and tunnel forwarding |
| `PermitLocalCommand=no` | Prevent local commands from SSH config |
| `RequestTTY=no` | Keep operations non-interactive |
| `ControlMaster=auto` | Reuse a private connection when safe |
| `ControlPersist=300` | Keep the private master for five minutes |
| `ServerAliveInterval=15` | Detect a silent encrypted-transport failure every 15 seconds |
| `ServerAliveCountMax=3` | Stop after three unanswered encrypted keepalives |
| `ControlPath=<private hashed path>` | Avoid public/predictable sockets and cross-profile masters |

Connection setup also applies the configured `ConnectTimeout`. Ordinary SSH and SSHFS both inherit the two server-alive options exactly once; SSHFS additionally applies `reconnect` and never enables `allow_other`.

The first operation for an alias runs bounded `ssh -G` with the security-critical options and hashes the resulting configuration. That digest and the derived policy are cached for the bridge process; warm requests do not repeat `ssh -G`. A mismatch discovered during initial setup is non-retryable `INVALID_CONFIG`; restart the bridge only after reviewing an intentional local alias change. Pattern-only aliases are not added to the bridge config. Host aliases are passed after `--`, and the MCP surface accepts no arbitrary SSH option.

The local Unix user and that user's OpenSSH configuration remain trusted execution authority. A same-UID process can change configuration after the `ssh -G` comparison and before the following OpenSSH invocation; that exact post-check race is inside the same-UID trust boundary, not a claimed hostile-local isolation boundary. Restart the bridge only after reviewing an intentional alias change.

## Command and shell handling

The public shell contract is explicit: omitted `remote_run.shell` means Bash, `sh` is an explicit retry choice, and `auto` is not accepted.

MCP paths, queries, globs, patch bodies, file content, stdin, and absolute command cwd values are transported as data. Fixed remote programs use static scripts plus positional parameters. The direct human CLI converts each argv word with the bridge's bounded shell encoder.

`remote_run` intentionally accepts a shell command string. The bridge safely binds the whole string into the selected remote shell, but syntax inside it still has that shell's meaning. Omitted shell and explicit `bash` both require Bash; an unavailable Bash is a capability error that records the requested and available shells without silently retrying or prescribing an action. Explicit `login` obtains the account shell from a strict, unique `getent passwd UID` record, or from one unique `/etc/passwd` record only when `getent` is absent. It rejects malformed, relative, oversized, non-regular, or non-executable paths, treats an empty passwd shell as `/bin/sh` like OpenSSH, and never trusts `$SHELL`. Absolute cwd values are bound as positional data before the resolved shell receives the command payload. Full shell and transport metadata remain internal diagnostics; ordinary MCP success output contains only model-relevant command results.

Local `LC_ALL=C` is forced only for bridge protocol and SSH-diagnostic phases. Raw `remote_run` does not add that override, so the bridge does not itself cause an `LC_*` `SendEnv` rule to change the user's command locale.

Session note: the dispatcher is always POSIX sh and never parses a user command as its own control language. A timeout or cancellation is request-scoped. If termination is not confirmed, that result reports that the remote process may continue; unrelated request IDs remain usable and mutations are not retried.

All command tools are treated as mutating. A detached or ambiguous remote child can survive cancellation, so results expose process-continuation and mutation uncertainty instead of claiming rollback.

## Files, output, and protocol limits

- The TOML config is a private current-user-owned regular file; load/save reject unsafe ancestors, symlinks, FIFOs, and group/other-writable modes.
- Runtime directories are real, current-user-owned mode `0700`; spools are mode `0600` and quota-accounted.
- Reads, searches, writes, patches, stdout, stderr, JSON frames, aggregate object members, nesting, and retained pages have compiled ceilings.
- Stdout and stderr drain concurrently. Large output spills to private files rather than becoming one resident allocation.
- Retained references are opaque, expiring, provenance-bound, page-limited, and safe under concurrent discard/read.
- Strict JSON rejects duplicate keys, excess depth/nodes/members/key bytes, malformed UTF-8, NUL floods, oversized frames, and trailing data before tool dispatch.
- Remote output is serialized once as JSON data. JSON-RPC-looking text or terminal controls cannot create another protocol frame.

## Mutation semantics

`remote_write` provides create or conditional replace. `remote_apply_patch` snapshots every base before the first mutation and executes files in patch order. Results separate confirmed changed paths, confirmed unchanged paths, and outcome-unknown paths. Never automatically retry an unknown outcome.

## Local installation transaction

Install and uninstall are dry-run unless `--apply` is present. Apply mode:

- validates the canonical package and complete deterministic Skill tree;
- rejects symlinks, special files, untrusted owners, and unsafe writable ancestors outside a sealed current-user boundary;
- structurally validates the plugin, MCP JSON, Skill frontmatter, and typed stdio MCP dependency;
- obtains a private `O_NOFOLLOW`, mode-`0600`, current-user-owned cross-bundle lock;
- repeats preflight under that lock;
- journals directories immediately as they are created;
- quarantines identity-matching local objects with same-directory no-replace renames;
- re-queries Codex after add/remove success, failure, or timeout and compensates observed partial mutation;
- removes only content matching the recorded installation identity.

The lock serializes this bridge's transactions. The local Unix user remains trusted: a separate process running as that same user can ignore the lock and directly edit Codex configuration, and the current Codex CLI has no compare-and-swap remove operation. Final rechecks detect many such races, but this is not a hostile-same-UID isolation mechanism.

The identity is content-hashed, so overwriting an active bundle in place is rejected rather than treated as an implicit upgrade. Preserve the old version long enough to run its identity-matching uninstall, then install the reviewed new version from a different durable directory.

Source validation remains component-by-component and no-follow. A real current-user-owned `0700` ancestor establishes a sealed boundary: below it, current-user-owned directories may retain group/other mode bits because other UIDs cannot traverse the seal and the same UID is already trusted. Sticky `/tmp` does not establish that boundary; foreign owners, writable root-owned descendants, package symlinks, and unsafe canonical Codex executable targets remain rejected. This accommodates the local Codex release layout under a private home without weakening a shared directory tree.

## SSHFS boundary

SSHFS is human-only and absent from MCP. A mount does not change where a shell command runs. Mount/unmount validate a stable current-user-owned directory identity and the current Linux mount table before calling local helpers. Same-UID processes remain inside the local trust boundary.

Even with transport hardening, FUSE/SFTP behavior differs from a native filesystem: reconnects, caching, rename, ownership, hardlinks, and stalled I/O can surprise local applications. Prefer structured remote tools.

## Verification commands

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --lib ssh::frame::tests
cargo test --lib ssh::session::tests
cargo test --test dispatcher --test session --test mcp_tools -- --nocapture
cargo test --test mcp_protocol --test packaging --test cli -- --nocapture
cargo build --release
cargo test --release --test mcp_protocol task7_adversarial_ -- --nocapture
cargo test --release --test mcp_tools task8_cancel_process_ -- --nocapture
cargo test --release --test mcp_tools task8_output_rss_ -- --nocapture
CODEX_SSH_BRIDGE_REQUIRE_REAL_SSH=1 cargo test --release --test real_ssh -- --nocapture
```

The `remote_ops` and `performance_acceptance` fixtures use the persistent
dispatcher protocol, including request cancellation, bounded output, cleanup,
and capability-mismatch cases. Final acceptance also runs the predictable-temp
symlink regression, 16 MiB stdout+stderr serialization case, oversized-frame
recovery, SSHFS policy/race tests, CRLF OpenSSH diagnostic classification, and
an isolated real-OpenSSH fixture.
