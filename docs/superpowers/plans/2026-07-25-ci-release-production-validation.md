# CI, Release, and Production Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build, test, publish, install, and repeatedly exercise version 0.4.0 with reusable GitHub caches and real Codex-to-`nkai` production scenarios.

**Architecture:** GitHub `main` owns reusable dependency/toolchain/cross-target caches; tag workflows restore but never save target caches. One nine-target union matrix builds eight bridge targets and six helper targets, followed by eight packages. Static workflow contract tests, raw stdio MCP smoke, a fresh Codex client, and fault injection together form the release gate.

**Tech Stack:** GitHub Actions, Rust 1.91.1, cross 0.2.5, Bash, jq, gh CLI, OpenSSH, Codex CLI 0.144.5 or newer.

## Global Constraints

- Begin only after both prior plans have green GitHub CI checkpoints.
- Target release and tag are exactly `0.4.0` and `v0.4.0`.
- Do not run local Cargo build, test, Clippy, benchmark, or release commands.
- GitHub Actions is authoritative for compilation and tests.
- The local machine installs the aarch64 bridge package and all six helpers from the GitHub release.
- Release archives exist for eight main targets.
- The union build/cache matrix contains nine unique target triples because ARMv7 GNU main and ARMv7 musl helper differ.
- Release jobs restore main-scoped target caches and never save tag-scoped target caches.
- Do not put local aliases, usernames, home paths, tokens, machine descriptions, or production test results in README/package metadata.
- Live-test paths are explicit arguments and remote temporary artifacts are cleaned.
- Do not use Python to implement the bridge or smoke harness; a remote Python HTTP server is allowed only as an injected workload.
- Do not declare the goal complete solely from green CI, a published release, or direct SSH success.

---

## File map

- `.github/workflows/ci.yml`: stable quality/diagnostics caches.
- `.github/workflows/cross-cache.yml`: main-scoped nine-target prewarm.
- `.github/workflows/release.yml`: restore-only union build, eight packages, publish.
- `tests/packaging.rs`: workflow/cache/package/version contract tests.
- `tools/live-mcp-smoke.sh`: Bash+jq raw stdio MCP and remote workload harness.
- `README.md`: community-facing build/install/use contract only.
- `docs/security.md`: OpenSSH alias, absolute path, trust, and cancellation boundaries.
- `docs/performance.md`: cold/warm profile and production measurement method.
- `skills/remote-ssh-ops/SKILL.md`: concise Agent workflow using absolute paths and factual fallbacks.
- `skills/remote-ssh-ops/references/operations.md`: exact tool contract and recovery facts.
- `Cargo.toml`, `Cargo.lock`, `.codex-plugin/plugin.json`: version 0.4.0.
- `config.example.toml`, `.mcp.json.example`: packaged examples.

### Workflow matrix fixed by this plan

```yaml
matrix:
  include:
    - { target: x86_64-unknown-linux-gnu, build_main: true, build_helper: false }
    - { target: aarch64-unknown-linux-gnu, build_main: true, build_helper: false }
    - { target: armv7-unknown-linux-gnueabihf, build_main: true, build_helper: false }
    - { target: x86_64-unknown-linux-musl, build_main: true, build_helper: true }
    - { target: aarch64-unknown-linux-musl, build_main: true, build_helper: true }
    - { target: armv7-unknown-linux-musleabihf, build_main: false, build_helper: true }
    - { target: riscv64gc-unknown-linux-gnu, build_main: true, build_helper: true }
    - { target: powerpc64le-unknown-linux-gnu, build_main: true, build_helper: true }
    - { target: s390x-unknown-linux-gnu, build_main: true, build_helper: true }
```

The dependency hash used in keys is:

```yaml
${{ hashFiles('Cargo.toml', 'Cargo.lock') }}
```

## Task 1: Establish CI/cache/release workflow failures

**Files:**
- Modify: `tests/packaging.rs`
- Test: `tests/packaging.rs`

**Interfaces:**
- Consumes: current split CI/release workflows and cache inventory.
- Produces: failing static workflow tests for stable keys, main prewarm, union build, and restore-only tags.

- [ ] **Step 1: Replace old cache-count assertions with semantic assertions**

Add this exact helper, then parse workflow text and assert:

```rust
fn union_targets(workflow: &str) -> BTreeSet<&'static str> {
    [
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "armv7-unknown-linux-gnueabihf",
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-musl",
        "armv7-unknown-linux-musleabihf",
        "riscv64gc-unknown-linux-gnu",
        "powerpc64le-unknown-linux-gnu",
        "s390x-unknown-linux-gnu",
    ]
    .into_iter()
    .filter(|target| workflow.contains(target))
    .collect()
}

assert!(!ci.contains("${{ github.sha }}"));
assert!(ci.contains("hashFiles('Cargo.toml', 'Cargo.lock')"));
assert!(ci.contains("rust-target-quality-v2-"));
assert!(ci.contains("rust-target-diagnostics-v2-"));

assert!(cross_cache.contains("branches:\n      - main"));
assert!(cross_cache.contains("workflow_dispatch:"));
assert_eq!(union_targets(&cross_cache).len(), 9);

assert_eq!(union_targets(&release).len(), 9);
assert!(release.contains("uses: actions/cache/restore@"));
assert!(!release.contains("uses: actions/cache@"));
assert!(!release.contains("${{ github.ref }}"));
assert!(!release.contains("${{ github.ref_name }}"));
```

Allow `GITHUB_REF_NAME` only in tag/version/package naming shell steps, never in
a cache key.

- [ ] **Step 2: Assert exact build and package coverage**

Add target-set helpers and assert eight `build_main=true`, six
`build_helper=true`, one helper-only ARMv7 musl entry, eight package outputs,
and every package copies all six helpers. Assert publish depends on all package
jobs.

- [ ] **Step 3: Assert cache paths and scopes**

Require:

```text
~/.rustup/toolchains/${{ env.RUST_TOOLCHAIN }}-*
~/.cargo/registry
~/.cargo/git
~/.cargo/bin/cross
target
```

Require cache-schema `v2`, Rust version, target triple where relevant, and the
manifest+lock hash. Reject commit SHA and tag in target keys.

- [ ] **Step 4: Commit, push, and observe intended failure**

```bash
cargo fmt --all
git add tests/packaging.rs
git commit -m "test: define reusable CI and release caches"
git push origin main
gh run watch "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: packaging tests fail because `cross-cache.yml` is absent and current
keys/matrices violate the new contract.

## Task 2: Implement stable CI and main-scoped cross caches

**Files:**
- Modify: `.github/workflows/ci.yml`
- Create: `.github/workflows/cross-cache.yml`
- Modify: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: Task 1 workflow tests.
- Produces: stable main caches and a nine-target restore-only release build.

- [ ] **Step 1: Stabilize CI target keys**

Use full `actions/cache` in `ci.yml` because `main` owns cache saves:

```yaml
key: ${{ runner.os }}-${{ runner.arch }}-rust-target-quality-v2-${{ env.RUST_TOOLCHAIN }}-${{ hashFiles('Cargo.toml', 'Cargo.lock') }}
```

Use the analogous diagnostics key. Remove SHA restore chains. Keep separate
quality and diagnostics target directories/keys.

- [ ] **Step 2: Add the main `cross-cache` workflow**

Trigger only on workflow dispatch and relevant `main` changes:

```yaml
on:
  push:
    branches: [main]
    paths:
      - Cargo.toml
      - Cargo.lock
      - .github/workflows/cross-cache.yml
      - .github/workflows/release.yml
  workflow_dispatch:
```

Use the exact nine-entry matrix from this plan. Restore/save toolchain,
dependency, cross binary, and per-target `target` cache. Build main/helper only
when their booleans are true. Verify artifacts with `file`.

- [ ] **Step 3: Merge release build jobs**

Replace `build-main` and `build-helper` with `build` using the nine-entry
matrix. Use `actions/cache/restore` for per-target target cache so tag scope
cannot save a duplicate. Upload one artifact per matrix target containing
`bin/codex-ssh-bridge` when present and `remote-helpers/<target>` when present.

- [ ] **Step 4: Package eight main targets from union artifacts**

The package matrix remains eight main targets. Download all union artifacts,
copy the selected main binary, copy all six helper files, and verify every
required resource before archive/checksum creation.

- [ ] **Step 5: Static-check, commit, push, and wait for CI plus prewarm**

```bash
git diff --check
git add .github/workflows/ci.yml .github/workflows/cross-cache.yml .github/workflows/release.yml
git commit -m "ci: share main-scoped cross build caches"
git push origin main
gh run watch "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
gh run watch "$(gh run list --workflow cross-cache --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: packaging tests, quality, diagnostics, and all nine prewarm jobs pass.

## Task 3: Prove cache reuse and clean obsolete cache entries

**Files:**
- No source edits unless evidence reveals a key/scope defect.
- Inspect: GitHub cache inventory and Actions logs.

**Interfaces:**
- Consumes: successful Task 2 workflows.
- Produces: cache-hit evidence and repository cache use materially below 9.06 GB.

- [ ] **Step 1: Re-run cross-cache and inspect exact hits**

Trigger:

```bash
gh workflow run cross-cache.yml --ref main
gh run watch "$(gh run list --workflow cross-cache --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Inspect all nine logs. Every per-target target cache, Rust toolchain, Cargo
dependency cache, and cross binary cache must show an exact hit or a documented
first-save followed by a hit on this second run.

- [ ] **Step 2: Inventory cache IDs before deletion**

```bash
gh cache list --repo wkj2333666/Codex-SSH-Bridge --limit 100 --json id,key,ref,sizeInBytes,lastAccessedAt
```

Classify as keep only:

- current `main` quality-v2;
- current `main` diagnostics-v2;
- current `main` nine cross target-v2 entries;
- current shared dependency/toolchain/cross entries.

Everything with old commit SHA keys, old `bridge-`/`helper-` tag target keys, or
the malformed tag ref scope is obsolete.

- [ ] **Step 3: Delete only resolved obsolete cache IDs**

For each numeric ID in the reviewed deletion list from Step 2, invoke
`gh cache delete` once with that exact numeric argument. Do not delete by a
prefix and do not delete any current v2 main cache.

- [ ] **Step 4: Re-inventory and record total bytes**

Sum `sizeInBytes`; require the total to be materially below 9.06 GB and below
the repository limit with space for one future dependency-graph generation.

## Task 4: Establish documentation, Skill, package, and smoke-harness failures

**Files:**
- Modify: `tests/packaging.rs`
- Create: `tools/live-mcp-smoke.sh`
- Modify: `README.md`
- Modify: `docs/security.md`
- Modify: `docs/performance.md`
- Modify: `skills/remote-ssh-ops/SKILL.md`
- Modify: `skills/remote-ssh-ops/references/operations.md`

**Interfaces:**
- Consumes: final runtime/MCP behavior.
- Produces: failing package/document consistency assertions and a no-Python raw MCP smoke contract.

- [ ] **Step 1: Add forbidden stale-language assertions**

Scan community/package docs and reject:

```text
allowlist
configured root
read-only host
global_concurrency
per_host_concurrency
MCP task queue full
retry with sh
```

Permit historical design documents under `docs/superpowers`; exclude them from
package-facing scans.

- [ ] **Step 2: Assert the Skill's exact operational boundary**

Require the Skill to state:

- paths are remote and absolute;
- aliases come from local OpenSSH config;
- omitted shell means Bash;
- explicit sh fallback is reported to the Agent;
- cancellation/transport failure may leave mutation uncertainty;
- no automatic retry of uncertain mutations;
- SSHFS is human-only and never an Agent workspace;
- no fixed host or concurrency limit.

- [ ] **Step 3: Add a Bash+jq raw MCP smoke harness**

`tools/live-mcp-smoke.sh` takes:

```text
tools/live-mcp-smoke.sh /absolute/path/to/codex-ssh-bridge HOST /absolute/remote/base
```

It must:

1. start `<binary> mcp` as a Bash coprocess;
2. initialize MCP and verify `serverInfo.version`;
3. call `remote_hosts` and assert HOST exists in both text and
   `structuredContent.hosts`;
4. create a unique remote directory beneath the explicit base;
5. write/stat/read/search/patch/list a small file;
6. run Bash-default and explicit sh commands;
7. verify ordinary exit 124 and a true timeout;
8. generate more than 32 KiB and page its output reference;
9. launch an inherited-pipe HTTP-server workload and run the next probe;
10. clean the exact remote test directory and process;
11. terminate MCP and verify no local child remains.

Use `jq`, Bash builtins, `mktemp`, and bridge MCP calls; do not use Python as
the local harness.

- [ ] **Step 4: Commit tests/harness/docs and observe intended CI failures**

```bash
sh -n tools/live-mcp-smoke.sh
cargo fmt --all
git add tests/packaging.rs tools/live-mcp-smoke.sh README.md docs/security.md docs/performance.md skills/remote-ssh-ops
git commit -m "test: define packaged production validation"
git push origin main
gh run watch "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: stale docs/package assertions fail until the next task completes the
content and version migration.

## Task 5: Align package-facing docs and bump version 0.4.0

**Files:**
- Modify: `README.md`
- Modify: `docs/security.md`
- Modify: `docs/performance.md`
- Modify: `skills/remote-ssh-ops/SKILL.md`
- Modify: `skills/remote-ssh-ops/references/operations.md`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `.codex-plugin/plugin.json`
- Modify: `config.example.toml`
- Modify: `.mcp.json.example`

**Interfaces:**
- Consumes: Task 4 package assertions.
- Produces: one consistent 0.4.0 source/package contract.

- [ ] **Step 1: Rewrite package-facing host/path/lifecycle wording**

Describe only current behavior: local OpenSSH aliases, absolute remote paths,
persistent invisible session/helper, Codex-owned tool scheduling, request
deadlines, generation eviction, factual timeout/cancellation, and output
paging. Keep security warnings concise and community-safe.

- [ ] **Step 2: Keep the Skill small and model-oriented**

Do not put internal phase names, cache policy, benchmark history, local aliases,
or installation debug paths in `SKILL.md`. Put exact schemas and error facts in
`references/operations.md`. Keep the first Skill instructions sufficient for
normal discovery/read/write/run/recovery.

- [ ] **Step 3: Bump all source/package versions exactly**

Set:

```toml
version = "0.4.0"
```

in `Cargo.toml`, the root package entry in `Cargo.lock`, and plugin manifest.
Verify no active package file still claims 0.3.2.

- [ ] **Step 4: Format, static-check, commit, push, and require green CI**

```bash
cargo fmt --all
sh -n tools/live-mcp-smoke.sh
git diff --check
rg -n "0\\.3\\.2|global_concurrency|per_host_concurrency|configured root|read-only host" README.md docs/security.md docs/performance.md skills config.example.toml .codex-plugin Cargo.toml Cargo.lock
git add README.md docs skills Cargo.toml Cargo.lock .codex-plugin/plugin.json config.example.toml .mcp.json.example tools/live-mcp-smoke.sh tests/packaging.rs
git commit -m "chore: prepare transparent runtime release 0.4.0"
git push origin main
gh run watch "$(gh run list --workflow CI --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Expected: quality and diagnostics green; no forbidden active wording; package
metadata versions agree.

## Task 6: Publish immutable v0.4.0 release

**Files:**
- No source edits after the green release commit.
- Inspect: GitHub tag, workflow, release, and assets.

**Interfaces:**
- Consumes: exact green `main` commit from Task 5 and proven main caches.
- Produces: immutable `v0.4.0` and eight verified archives/checksums.

- [ ] **Step 1: Verify local and origin main are identical and clean**

```bash
git status --short --branch
git rev-parse HEAD
git rev-parse origin/main
git tag --list v0.4.0
```

Expected: clean; HEAD equals origin/main; tag absent.

- [ ] **Step 2: Create and push the annotated release tag**

```bash
git tag -a v0.4.0 -m "codex-ssh-bridge 0.4.0"
git push origin v0.4.0
```

- [ ] **Step 3: Watch release workflow and inspect cache restoration**

```bash
gh run watch "$(gh run list --workflow Release --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

Require nine build jobs, eight package jobs, publish success, and main target
cache hits. No log may report saving a tag-scoped target cache.

- [ ] **Step 4: Verify release metadata and assets**

```bash
gh release view v0.4.0 --json isDraft,isPrerelease,tagName,targetCommitish,assets,url
```

Require non-draft/non-prerelease, tag `v0.4.0`, eight `.tar.gz` files, eight
adjacent `.sha256` files, and no source-built `bin` artifact outside archives.

## Task 7: Download, verify, and install the aarch64 release

**Files:**
- Writes outside repository only to `/tmp` and managed user installation paths.
- Inspect: release archive, checksums, managed install, MCP registration, Skill.

**Interfaces:**
- Consumes: published v0.4.0 assets.
- Produces: active installed v0.4.0 aarch64 bridge with all six helper binaries.

- [ ] **Step 1: Download the exact aarch64 GNU archive and checksum to a fresh temp directory**

Use `mktemp -d`, then:

```bash
gh release download v0.4.0 --repo wkj2333666/Codex-SSH-Bridge \
  --pattern 'codex-ssh-bridge-0.4.0-aarch64-unknown-linux-gnu.tar.gz*'
sha256sum -c codex-ssh-bridge-0.4.0-aarch64-unknown-linux-gnu.tar.gz.sha256
```

- [ ] **Step 2: Inspect archive before extraction**

Reject absolute paths, `..`, symlinks, device nodes, unexpected binaries, or a
missing plugin/Skill/docs/example/helper. Require exactly one bridge and all six
helper filenames.

- [ ] **Step 3: Extract and run packaged transactional installer**

Run the packaged binary:

```bash
./codex-ssh-bridge-0.4.0-aarch64-unknown-linux-gnu/bin/codex-ssh-bridge install --user --apply
```

Verify the v1 config migrated to v2, MCP registration points to:

```text
~/.local/share/codex-ssh-bridge/0.4.0+release/bin/codex-ssh-bridge
```

and the stable `~/.local/bin/codex-ssh-bridge` plus Skill symlink target that
managed release.

- [ ] **Step 4: Verify all six local helpers and installed metadata**

Check executable mode and `file` output for:

```text
x86_64-unknown-linux-musl
aarch64-unknown-linux-musl
armv7-unknown-linux-musleabihf
riscv64gc-unknown-linux-gnu
powerpc64le-unknown-linux-gnu
s390x-unknown-linux-gnu
```

Run `codex mcp get ssh-bridge` and require the 0.4.0 managed path.

## Task 8: Run raw MCP production smoke and pressure on nkai

**Files:**
- No repository edits unless a defect is found.
- Temporary local and remote artifacts only.

**Interfaces:**
- Consumes: installed v0.4.0 and `tools/live-mcp-smoke.sh`.
- Produces: protocol, behavior, cleanup, cold/warm, and fault-injection evidence.

- [ ] **Step 1: Run the committed smoke harness against the installed binary**

Invoke with explicit arguments:

```bash
tools/live-mcp-smoke.sh \
  /home/wkj/.local/share/codex-ssh-bridge/0.4.0+release/bin/codex-ssh-bridge \
  nkai /home/wkj
```

Require every operation and final cleanup check to pass.

- [ ] **Step 2: Measure cold and warm latency through raw MCP**

Start a fresh MCP process for cold measurement. In one warm process execute at
least 30 `remote_run ":"` calls. Report cold, p50, p95, and max bridge-reported
wall time separately from Codex UI/tool wall time. Do not attribute UI time to
SSH without evidence.

- [ ] **Step 3: Exercise read concurrency without bridge admission**

Issue at least 64 independent read/stat calls over raw MCP, cancel a subset,
and assert all uncancelled calls complete, no `Server busy` appears, and RSS
returns near baseline after results and retained pages expire/discard.

- [ ] **Step 4: Inject and recover from failures**

Run each separately:

- cancel a broad bounded search during candidate production;
- start a descendant retaining stdout/stderr;
- time out `sleep 5` at 100 ms;
- run `exit 124`;
- kill the SSH/session generation mid-request;
- cancel during a cold generation start;
- cross the 32 KiB renderer boundary.

After every case, immediately run a no-op and stat. No case may require bridge
restart or leave later requests queued indefinitely.

- [ ] **Step 5: Verify remote helper persistence and cleanup**

Confirm the installed persistent helper on `nkai` is version 0.4.0-compatible,
executable, and reused on warm calls. Confirm no test directories, matching HTTP
server, or test process remains.

## Task 9: Exercise a fresh real Codex client

**Files:**
- No repository edits unless a defect is found.
- Inspect: Codex JSON events and MCP tool results.

**Interfaces:**
- Consumes: installed/registered v0.4.0.
- Produces: evidence that Codex, not only a custom raw client, receives aliases
  and completes/recoveries correctly.

- [ ] **Step 1: Start a fresh Codex client process**

Use the existing user MCP registration and a bounded `codex exec --json`
prompt that requests:

1. `remote_hosts`;
2. a Bash-default no-op on `nkai` with absolute cwd;
3. stat/read of a known harmless path;
4. a timeout followed by a recovery no-op.

Do not ask it to mutate production project files.

- [ ] **Step 2: Inspect Codex events**

Require MCP server version 0.4.0, actual aliases visible to the model/tool event,
successful tool completion, factual timeout, and successful recovery. Record
Codex tool wall time separately from bridge result timing.

- [ ] **Step 3: Test the active task tool surface after a new task is available**

Because stdio MCP processes are task-lived and do not hot reload, verify in a
new Codex task that `remote_hosts`, `remote_run`, and `remote_stat` use the new
server. Do not claim the already-running old task process changed in place.

## Task 10: Defect loop and final completion audit

**Files:**
- Modify tests before source for every defect.
- Update version/tag only by a new patch release if v0.4.0 is already immutable.

**Interfaces:**
- Consumes: Tasks 1-9 evidence.
- Produces: fixed release, clean repository, and requirement-by-requirement proof.

- [ ] **Step 1: For every production defect, reproduce deterministically**

Add the narrowest fake-SSH, raw-MCP, packaging, or real-SSH test that fails for
the observed reason. Push and capture the failing GitHub run before source
repair.

- [ ] **Step 2: Implement the root fix and rerun all gates**

Do not special-case `nkai` or a test command. Fix the lifecycle/protocol/cache
boundary, push, require green CI, publish the next unused patch tag, install,
and repeat Tasks 7-9.

- [ ] **Step 3: Audit every explicit requirement**

Build an evidence table covering:

- config v2 migration and rollback;
- OpenSSH alias discovery;
- absolute remote paths;
- no fixed host/concurrency admission;
- cancellation and generation recovery;
- timeout versus exit 124;
- search glob/cancellation;
- compact adapter-visible output;
- retained output reconstruction;
- CI coverage and cache hits/size;
- nine build targets, eight archives, six helpers;
- installed binary/MCP/Skill version;
- raw MCP production operations;
- fresh Codex client behavior;
- remote/local cleanup;
- clean `main == origin/main`.

Mark any indirect or missing evidence incomplete and continue the loop.

- [ ] **Step 4: Complete only when no required work remains**

Run final read-only checks:

```bash
git status --short --branch
git rev-parse HEAD
git rev-parse origin/main
gh run list --workflow CI --branch main --limit 3
gh release view v0.4.0
gh cache list --repo wkj2333666/Codex-SSH-Bridge --limit 100
codex mcp get ssh-bridge
```

Only after the evidence table is complete, production recovery is repeatable,
and cleanup is proven may the active goal be marked complete.
