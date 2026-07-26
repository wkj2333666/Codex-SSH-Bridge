# Performance Evidence

## Measurement host

- Host: Raspberry Pi-class aarch64 Linux machine
- Kernel: Linux aarch64 (exact kernel release intentionally omitted)
- Rust: `rustc 1.91.1 (ed61e7d7 2025-11-07)`, LLVM 21.1.2
- OpenSSH: 10.0p2 Debian 7+deb13u4, OpenSSL 3.5.6
- Profile: Cargo `release`, thin LTO, one codegen unit, stripped symbols

These are acceptance measurements for the framed persistent-session transport,
not universal throughput claims. Network latency, SSH server load, cipher choice,
filesystem behavior, and CPU architecture dominate real-server results.

## Reproduce

```bash
cargo test --release --test mcp_tools task78_release_dispatch_ -- --nocapture
cargo test --test session -- --nocapture
cargo test --release --test mcp_tools task8_five_hosts_ -- --nocapture
cargo test --release --test mcp_tools task8_cancel_process_ -- --nocapture
cargo test --release --test mcp_tools task8_output_rss_ -- --nocapture
cargo test --release --test mcp_protocol task7_wide_json_rss_ -- --nocapture
cargo test --release --test performance_acceptance -- --nocapture
cargo test --release --test performance_acceptance task12_release_persistent_helper_cold_reuse_warm_profile -- --nocapture
env CODEX_SSH_BRIDGE_PROFILE=1 cargo test --release --features profile --test performance_acceptance task12_release_helper_and_shell_cold_warm_profile -- --nocapture
env CODEX_SSH_BRIDGE_PROFILE=1 cargo test --release --features profile --test performance_acceptance task12_release_persistent_helper_cold_reuse_warm_profile -- --nocapture 2>persistent-profile.jsonl
CODEX_SSH_BRIDGE_HELPER_INTEGRATION=1 cargo test --test session supported_linux_architecture_uses_uploaded_helper_once_per_session -- --nocapture
CODEX_SSH_BRIDGE_REQUIRE_REAL_SSH=1 cargo test --release --test real_ssh -- --nocapture
```

Latency tests warm the relevant path, collect at least 120 samples, sort raw durations, and enforce the compiled p95 thresholds. RSS tests run fresh child processes and report warmed baseline, observed peak, and delta from `/proc/self/status`.

To inspect bridge phases locally, opt into the profile feature and redirect
the JSONL events (emitted on stderr) to a file:

```bash
CODEX_SSH_BRIDGE_PROFILE=1 \
  cargo test --release --features profile --locked \
  --test performance_acceptance task11_release_cold_and_warm_ssh_profile \
  -- --nocapture 2>profile.jsonl
```

The normal release build does not include the profile feature or emit profile
events. Events contain only phase, host alias, request id, cold/warm class,
elapsed microseconds, and byte counts; credentials, commands, paths, and
remote output are never recorded. Persistent cold setup additionally emits
`helper_install_probe`, `helper_install_upload` (only for a first install), and
`helper_handshake`. A persistent-file cold reuse emits the probe and handshake
but no upload; warm requests emit none of the `helper_install_*` phases. The
cold sample includes local policy and capability setup plus the first SSH
session; the warm sample reuses the persistent session. Preparation, session,
and capture spans intentionally
overlap while the remote process and output drains run concurrently, so their
durations must not be added together. GitHub CI stores the profile and RSS
logs as a diagnostic artifact, but its timings are not a substitute for
measurements across the actual network to a target server.

## Recorded values

| Case | Samples / shape | Observed | Gate |
|---|---:|---:|---:|
| Bridge-only MCP dispatch | 200 | p50 4.685 µs, p95 5.889 µs, max 40.704 µs | p95 < 2 ms |
| Cold fake-SSH MCP call | 100 | p50 52.043 ms, p95 58.715 ms, max 66.317 ms | diagnostic baseline |
| Warm fake-SSH MCP call | 120 (after 16 warmups) | p50 32.975 ms, p95 43.829 ms, max 57.088 ms | p95 < 250 ms |
| Five hosts, one-second command each | 5 concurrent | 1.121394528 s wall time; resolve/probe/command calls each exactly 5, with no root-observe calls | < 1.5 s |
| Cancellation to whole process-group exit | one TERM-ignoring fixture | 71.637629 ms | < 250 ms |
| Bounded persistent-session output plus retained models | fresh child | RSS delta 2,480 KiB | < 32 MiB |
| MCP output at the 64 MiB quota plus retained models | three fresh children | RSS delta 7,248–7,280 KiB | < 16 MiB |
| Maximum-budget wide JSON array | fresh child | RSS delta 8,400 KiB | < 48 MiB |
| Maximum-budget wide JSON object | separate fresh child | RSS delta 17,088 KiB | < 48 MiB |
| Base64 admission at the maximum input budget | fresh child | RSS delta 14,176 KiB | < 32 MiB |
| Maximum MCP payload | complete framed case | payload 8,388,608 bytes; newline-delimited frame 8,388,609 bytes | exact compiled ceiling |
| Tool-list / required output page | complete MCP serialization | 6,947 / 1,048,576 bytes | within wire budget |

The release helper profile below was measured locally on 2026-07-23 (not on the
Raspberry Pi measurement host above) with eight cold process starts and 32
requests in one warm process. Values are p50 / p95:

| Direct remote executor | Observed |
|---|---:|
| Rust helper cold startup | 835 µs / 1.47 ms |
| POSIX shell dispatcher cold startup | 7.12 ms / 10.62 ms |
| Rust helper warm request | 1.57 ms / 2.25 ms |
| POSIX shell dispatcher warm request | 52.56 ms / 61.87 ms |

This isolates process and protocol overhead only; it excludes SSH handshake,
network latency, capability probing, and remote command work. Reproduce it with
`CODEX_SSH_BRIDGE_PROFILE=1 cargo test --release --features profile --test
performance_acceptance task12_release_helper_and_shell_cold_warm_profile --
--nocapture`.

The complete fake-SSH p95 includes the bounded remote command process and output capture. The first request for an alias pays local identity resolution, capability probing, and SSH session startup; warm commands reuse one persistent dispatcher session and send one request frame, so they do not pay another SSH handshake, `ssh -G`, or root observation. Capability root metadata is connection-time diagnostic context, not a warm authorization round trip. The five-host test demonstrates absence of cross-host head-of-line blocking at the stated concurrency, not capacity beyond configured limits.

MCP dispatch and remote execution are separate measurements. The bridge does not impose a task window or global/per-host runner slots; independent request IDs are multiplexed over persistent host sessions. Warm latency measurements should report MCP dispatch, persistent-session transport, and remote command time separately.

## Why memory stays bounded

- Input framing rejects the first byte past the configured limit and then recovers at the next newline.
- Strict JSON applies aggregate depth, node, object-member, and key-byte budgets during parsing.
- Commands stream stdin and drain stdout/stderr concurrently; persistent
  sessions stream frame payloads directly into the bounded capture sink rather
  than retaining a second full stdout/stderr copy in `SessionResult`.
- Large output spills to private files under shared byte, entry, and serialization-job quotas.
- MCP rendering retains oversized details once and returns a compact provenance-bound reference.
- Paging opens independent cursors rather than cloning a shared resident output buffer.
- Array and object RSS gates run in different fresh children so allocator retention cannot hide amplification.

The five-host 40 MiB streaming test also checks the file-backed spool quota;
the number of simultaneously observed spool files is timing-dependent and is
bounded by the configured quota rather than treated as an exact count.

## Rust, Bash, and SSHFS

The native Rust bridge removes interpreter startup from every MCP frame and keeps validation, scheduling, cancellation, quotas, and serialization in one process. On supported Linux hosts, the Rust helper additionally removes per-request remote shell setup, request temp files, FIFOs, and `dd`/`wc` output staging; the helper upload is paid once during cold session startup. GNU helper startup can fall back to the persistent shell dispatcher when the remote loader or libc is incompatible. Replacing the bridge with Bash would move JSON correctness, frame bounds, and concurrent process ownership into shell text without improving the dominant SSH/network latency.

The bridge still uses the remote Bash or POSIX sh selected by capability probing because commands must execute where the server's tools and data live. Omitted `remote_run.shell` means Bash; `sh` is an explicit retry choice after a Bash capability error. There is no hidden fallback.

The persistent session adds a fixed startup cost once per alias. Acceptance measurements must therefore report `helper_cold`/`helper_warm` separately from `shell_cold`/`shell_warm` on the same fixture. A long command does not block another request until the configured per-host capacity is exhausted; a session transport failure invalidates all pending requests and is not automatically retried.

OpenSSH connection reuse is private to one MCP runner. A runner uses a
five-second `ControlPersist` grace to bridge capability probing and persistent
helper startup, while warm commands use the already-open framed helper session.
This keeps the warm path unchanged and prevents a detached master from coupling
separate Codex tasks.

Session acquisition, helper status, helper upload, and helper handshake share a
bounded connection deadline. Waiting behind another initializer is also
bounded. These setup deadlines apply before any command frame is submitted, so
they can safely release a failed generation without replaying a mutation.

The zero-output release RSS gate warms one MCP process, executes 1,000 requests
at concurrency 20, limits post-warm RSS growth to 8 MiB, and limits growth
across the last five observation rounds to 2 MiB. Empty preview streams allocate
no head or tail storage; the existing bounded buffers grow only after output
arrives.

SSHFS is optional because repository walks and builds can turn many small filesystem calls into network round trips. The structured tools batch list/stat/read/search work remotely and return bounded results, which reduces both latency and Agent-side context pressure.

The persistent-session gates should be rerun on the target host; the following
localhost fixture records real-SSH behavior separately from fake-transport timing.

## Isolated real OpenSSH

`tests/real_ssh.rs` generated temporary Ed25519 host, client, and wrong-host keys; launched an unprivileged OpenSSH 10.0p2 `sshd` on a localhost high port; and completed in 2.80 seconds with one pass, zero failures, and no skip. It verified strict known-host rejection, public-key login, ControlMaster inode reuse, connection-time root diagnostics, trusted account-login-shell resolution, explicit Bash, explicit sh, strict shell selection, hostile quoting, list/stat/read/fixed-string search, guarded write/patch, timeout, cancellation uncertainty, and cleanup of the master sockets, remote test processes, and daemon.

The managed sandbox denies local `bind(2)`, so the final fixture was run with approved local-network execution. Developer runs without `CODEX_SSH_BRIDGE_REQUIRE_REAL_SSH=1` retain one visible skip reason when facilities are unavailable. Release acceptance uses the required-mode command above: setup failure is fatal, so a required run cannot report a skip as a pass. The recorded real-SSH run completed without a skip.

The real-SSH wording above predates the persistent dispatcher path; current MCP accepts `bash`, `sh`, and `login`, with omitted shell meaning `bash`. There is no silent Bash-to-sh fallback.
