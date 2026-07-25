# Codex SSH Bridge

Use Codex on this local machine to inspect, edit, and run commands on SSH aliases from the local OpenSSH configuration without installing or signing in to Codex on those servers.

```text
local Codex
    │ local stdio MCP
    ▼
native Rust bridge
    │ local OpenSSH + local keys/agent/known_hosts
    ▼
remote sshd ── files, compilers, tests, services

optional, human-only: local SSHFS mount over SFTP
```

The bridge keeps one local-owned SSH session per alias. On supported Linux
architectures it installs a matching Rust helper under the remote account's
`~/.local/share/codex-ssh-bridge/helpers/<bridge-version>/<target>/helper`
with mode `0700`, then reuses that file for later bridge starts. The helper
process itself lives only as long as the SSH session; unsupported hosts and
startup-incompatible helpers fall back to the POSIX dispatcher. No Codex
binary, API key, plugin, daemon, or service is installed remotely.

## Why this design

| Approach | Strength | Problem for this use case | Role |
|---|---|---|---|
| Raw `ssh` | Universal and minimal | Leaves target selection, quoting, limits, shell detection, cancellation, and output handling to the Agent | Transport below the bridge |
| SSHFS | Convenient human browsing | Makes remote files look local while commands still run locally; adds FUSE/SFTP latency and reconnect semantics | Explicit optional CLI only |
| Native local MCP | Closed schemas, local SSH aliases, bounded I/O, shared policy, explicit Bash/sh choice | Non-interactive by design | Default Agent interface |

The bridge is Rust rather than a Bash program because strict MCP framing, bounded parsing, async concurrency, process-group cancellation, and spool quotas need one auditable state machine. Bash and POSIX sh remain supported as the *remote command shells*; Bash is the default and sh is always an explicit choice.

SSHFS is intentionally absent from the MCP tool list. This prevents an Agent from silently treating a FUSE path as a local workspace.

## Requirements

- Local Linux host with Rust 1.91.1 or newer to build the bridge.
- Local OpenSSH client at `/usr/bin/ssh`.
- Key-based or local-agent authentication and verified host keys.
- Remote `sshd`, a POSIX sh, a GNU- or BSD-compatible `stat`, and the ordinary utilities checked by `doctor`; Bash is optional. `shell=login` additionally needs an account shell that can be resolved through `getent passwd` or, when `getent` is absent, one unique readable `/etc/passwd` record.
- Optional local `sshfs` and `fusermount3` for the human mount commands.
- Common Linux remote architectures use the bundled helper; new or unsupported hosts remain usable through the shell fallback. The local bridge binary must match the local host.

## Build and package locally

```bash
cargo build --release
./target/release/codex-ssh-bridge --help
```

There is no Python runtime or remote build step.

## CI and release builds

GitHub Actions runs formatting, Clippy, the full test suite, release builds,
and source-package checks. Release archives are published from version tags.

The release tag must match the version in `Cargo.toml`; for example:

```bash
git tag v<version>
git push origin v<version>
```

The release workflow publishes Linux binaries and SHA-256 files for:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `armv7-unknown-linux-gnueabihf`
- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`
- `riscv64gc-unknown-linux-gnu`
- `powerpc64le-unknown-linux-gnu`
- `s390x-unknown-linux-gnu`

Each archive contains `bin/codex-ssh-bridge`, the Skill and configuration
templates, and `remote-helpers/` with helpers for all six supported Linux
architectures: static musl helpers for `x86_64`, `aarch64`, and `armv7l`, plus
GNU-target helpers for `riscv64`, `ppc64le`, and `s390x`.
When a GNU helper cannot run because the remote loader or libc is incompatible,
the bridge reports the startup fallback and uses the POSIX dispatcher.
Keep that directory beside the bridge binary. The bridge probes `uname -s` and
`uname -m`, verifies the local helper length and SHA-256, and installs the
matching helper once per bridge-version/target on each remote account. A later
cold connection reports a persistent cache hit and uploads zero helper bytes;
warm requests do not probe, hash, lock, or upload. If persistent startup fails,
the fallback order is temporary helper, then POSIX dispatcher. For local
development or a custom package, set `CODEX_SSH_BRIDGE_HELPERS_DIR` to a
private directory containing files named by their Rust target triple.

The selected transport remains available to bridge diagnostics and profiling,
but is omitted from normal model-visible MCP results. To remove all installed
helper versions for one verified SSH account, run this explicitly (it is not
an automatic operation):

```bash
ssh ALIAS -- 'find ~/.local/share/codex-ssh-bridge/helpers -mindepth 1 -maxdepth 1 -type d -exec rm -rf -- {} +'
```

This deletes every bridge helper version for that account. Verify `ALIAS`
before running it; do not paste an unverified host name into the command.

Download the archive matching the local Codex host, extract it to a private
path, and run `bin/codex-ssh-bridge install --user --apply`; the installer
registers the stable local MCP path and links the Skill. Windows and macOS assets are not produced
because the bridge currently requires Linux OpenSSH and Linux SSHFS tooling.

## Configure hosts

Define and manually verify aliases in local `~/.ssh/config`:

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

Future aliases are discovered automatically from `~/.ssh/config` and its
supported `Include` files. `hosts add` remains available for compatibility
profiles, but MCP operations do not use a configured root to infer paths. The default local config is
`~/.config/codex-ssh-bridge/config.toml`; [config.example.toml](config.example.toml)
documents limits. It accepts configuration `version = 2` and contains only
global transport and bounded-I/O limits—never credentials.

On first use, the bridge validates the local SSH configuration and probes the
remote shell and utility capabilities. It reuses the connection for later
requests without repeating transport diagnostics in ordinary MCP output.
Writes and patches use expected hashes, no-follow checks, atomic replacement,
and explicit conflict or unknown-outcome reporting.

## Install for local Codex

Release archives contain the native Rust bridge, its Skill, and only the public
documentation needed by users. Run the packaged binary from its extracted
directory; installation is a dry-run until `--apply` is supplied:

```bash
./bin/codex-ssh-bridge install --user
./bin/codex-ssh-bridge install --user --apply
codex mcp get ssh-bridge --json
```

The installer verifies the extracted bundle, copies it atomically into
`~/.local/share/codex-ssh-bridge/<version>+release`, updates the stable
executable at `~/.local/bin/codex-ssh-bridge`, registers Codex against that
stable path, and links the Skill at `~/.codex/skills/remote-ssh-ops`. It can
migrate an older bridge-managed MCP entry, Skill symlink, or Skill copy, but
refuses unrelated files. Older bridge-managed release directories are pruned
only after the new MCP entry and Skill have been verified.

Start a new Codex task after installing or updating so the MCP and Skill
surfaces are reloaded. `.mcp.json.example` is a template for integrations that
do not use the installer; it is not a machine-specific configuration.

For a direct MCP entry, Codex can prompt only for tools not marked read-only:

```toml
[mcp_servers.ssh-bridge]
default_tools_approval_mode = "writes"
```

## Agent workflow

Invoke the Skill explicitly when useful:

```text
Use $remote-ssh-ops to inspect the devbox repository, patch the timeout bug, and run its focused tests.
Use $remote-ssh-ops to search devbox logs without downloading unbounded output.
```

The nine MCP tools are:

| Read-oriented | Mutation/command |
|---|---|
| `remote_hosts`, `remote_list`, `remote_stat`, `remote_search`, `remote_read`, `remote_output_read` | `remote_apply_patch`, `remote_write`, `remote_run` |

The default flow is bounded search/read → unified patch → remote verification.
Calls are synchronous. Normal results mirror familiar local tools: listings,
search matches, file bodies, and stdout/stderr appear once as concise text,
while structured fields contain only state such as `exit_code`, truncation, or
uncertain outcomes. Model-visible inline data is capped at 32 KiB; oversized
detail is retained under an opaque `output_ref` and paged with
`remote_output_read`, so the Agent never needs to reconstruct transport logic.
Errors report factual codes and relevant state without prescribing an action.

All MCP file paths and `remote_run.cwd` are absolute remote paths. The bridge never derives them from a Codex task ID, SSH home, configured root, or previous request. `remote_apply_patch` headers must use absolute paths (or `/dev/null` for create/delete). `remote_run` accepts one command string plus `shell: bash|sh|login`; omission means `bash`. Bash is never silently changed to sh: if Bash is unavailable, the capability error records that Bash was requested and which shells are available, leaving the next decision to the model. `login` resolves the account shell from NSS or `/etc/passwd`, never from `$SHELL`, and fails closed when it cannot do so safely. Inspect `exit_code`, warnings, truncation, mutation uncertainty, and process-continuation uncertainty when present.

Operational requests use one persistent SSH session per alias and are
multiplexed without bridge-defined host or concurrency admission limits.
Requests remain bounded by frame, read, write, output, and spool limits and are cancellable;
mutations report conflicts or unknown outcomes and are never blindly retried.
The internally selected helper transport does not change command shell
selection (`bash` remains the default unless the caller explicitly requests
`sh` or `login`).

## Human direct CLI

The direct CLI accepts argv and handles shell-word encoding inside the bridge:

```bash
./target/release/codex-ssh-bridge hosts list
./target/release/codex-ssh-bridge run devbox --cwd /absolute/remote/project --shell bash -- git status --short
```

This is convenient for a person or a diagnostic. Model-driven work should use MCP so results remain structured and approvals follow tool annotations.

## Optional SSHFS

Mount only when a person explicitly wants local browsing:

```bash
mkdir -p /absolute/local/mountpoint
./target/release/codex-ssh-bridge mount devbox /absolute/local/mountpoint --remote-path .
./target/release/codex-ssh-bridge mount-status /absolute/local/mountpoint
./target/release/codex-ssh-bridge unmount /absolute/local/mountpoint
```

The CLI requires a real absolute current-user-owned mountpoint, refuses nonempty directories without `--allow-nonempty`, and never enables `allow_other`. It prints that the mount is remote and not a local workspace.

Use SSHFS for browsing or narrow human editing. Keep builds, Git, tests, containers, and services on the server through `remote_run`. SFTP/FUSE workloads add a round trip to many metadata operations; caching, permissions, hardlinks, rename behavior, and broken-connection recovery also differ from a native filesystem. See the [SSHFS documentation](https://github.com/libfuse/sshfs).

## Security and performance

The bridge forces non-interactive authentication, strict host keys, no agent/X11/port forwarding, no local command, no TTY, bounded connection time, `ServerAliveInterval=15`, `ServerAliveCountMax=3`, and a private hashed ControlMaster socket for ordinary SSH and SSHFS. It never accepts arbitrary SSH options from MCP. Remote output remains untrusted and remote Unix permissions are the hard isolation boundary.

Read [docs/security.md](docs/security.md) for the complete trust model and flags. Read [docs/performance.md](docs/performance.md) for performance notes.
