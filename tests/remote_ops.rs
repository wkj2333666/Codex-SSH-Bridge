mod support;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::ops::Deref;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use codex_ssh_bridge::capability::ShellRequest;
use codex_ssh_bridge::output::OutputStore;
use codex_ssh_bridge::output::StreamKind;
use codex_ssh_bridge::remote::{
    AggregateKind, ApplyPatchRequest, ApplyPatchResult, EncodedValue, EntryError, EntryErrorCode,
    HostInfo, HostsResult, ListEntry, ListRequest, ListResult, OutputReadResult, ReadEntry,
    ReadRequest, ReadResult, RemoteBridge, RemoteContext, RemoteFileKind, RemoteJobStartRequest,
    RemoteMetadata, RemoteRunRequest, RetentionProvenance, RunShell, RunStdin, SearchEngine,
    SearchMatch, SearchRequest, SearchResult, ShellMetadata, ShellName, StatEntry, StatRequest,
    StatResult, ValueEncoding, WriteEncoding, WriteMode, WriteOperation, WriteRequest, WriteResult,
};
use codex_ssh_bridge::ssh::{RunRequest, RuntimePaths, SshRunner};
use codex_ssh_bridge::{BridgeError, ErrorCode};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use serde::Serialize;
use serde::ser::{SerializeSeq, Serializer};

struct FixtureBridge {
    inner: RemoteBridge,
    root: PathBuf,
}

impl FixtureBridge {
    fn new(inner: RemoteBridge, root: &Path) -> Self {
        Self {
            inner,
            root: root.to_owned(),
        }
    }

    fn absolute(&self, path: String) -> String {
        if path.is_empty() || path.starts_with('/') {
            path
        } else {
            self.root.join(path).to_string_lossy().into_owned()
        }
    }

    fn absolute_optional(&self, path: Option<String>) -> Option<String> {
        Some(match path {
            Some(path) => self.absolute(path),
            None => self.root.to_string_lossy().into_owned(),
        })
    }

    fn relative(&self, path: String) -> String {
        let root = self.root.to_string_lossy();
        path.strip_prefix(root.as_ref())
            .and_then(|path| path.strip_prefix('/'))
            .unwrap_or(&path)
            .to_owned()
    }

    fn relative_error(&self, mut error: BridgeError) -> BridgeError {
        error.details.failed_path = error
            .details
            .failed_path
            .take()
            .map(|path| self.relative(path));
        for paths in [
            &mut error.details.changed_paths,
            &mut error.details.not_changed_paths,
            &mut error.details.outcome_unknown_paths,
        ]
        .into_iter()
        .flatten()
        {
            *paths = std::mem::take(paths)
                .into_iter()
                .map(|path| self.relative(path))
                .collect();
        }
        error
    }

    fn absolute_patch(&self, patch: String) -> String {
        let root = self.root.to_string_lossy();
        patch
            .split_inclusive('\n')
            .map(|line| {
                for prefix in ["--- a/", "+++ b/"] {
                    if let Some(remainder) = line.strip_prefix(prefix)
                        && !remainder.starts_with('/')
                    {
                        return format!("{prefix}{root}/{remainder}");
                    }
                }
                line.to_owned()
            })
            .collect()
    }

    async fn list(
        &self,
        mut request: ListRequest,
        cancel: CancellationToken,
    ) -> Result<ListResult, BridgeError> {
        request.path = self.absolute_optional(request.path);
        self.inner.list(request, cancel).await
    }

    async fn stat(
        &self,
        mut request: StatRequest,
        cancel: CancellationToken,
    ) -> Result<StatResult, BridgeError> {
        request.paths = request
            .paths
            .into_iter()
            .map(|path| self.absolute(path))
            .collect();
        self.inner.stat(request, cancel).await
    }

    async fn read(
        &self,
        mut request: ReadRequest,
        cancel: CancellationToken,
    ) -> Result<ReadResult, BridgeError> {
        request.paths = request
            .paths
            .into_iter()
            .map(|path| self.absolute(path))
            .collect();
        self.inner.read(request, cancel).await
    }

    async fn search(
        &self,
        mut request: SearchRequest,
        cancel: CancellationToken,
    ) -> Result<SearchResult, BridgeError> {
        request.path = self.absolute_optional(request.path);
        self.inner.search(request, cancel).await
    }

    async fn run(
        &self,
        mut request: RemoteRunRequest,
        cancel: CancellationToken,
    ) -> Result<codex_ssh_bridge::remote::RemoteRunResult, BridgeError> {
        request.cwd = self.absolute_optional(request.cwd);
        self.inner.run(request, cancel).await
    }

    async fn write(
        &self,
        mut request: WriteRequest,
        cancel: CancellationToken,
    ) -> Result<WriteResult, BridgeError> {
        request.path = self.absolute(request.path);
        self.inner.write(request, cancel).await
    }

    async fn apply_patch(
        &self,
        mut request: ApplyPatchRequest,
        cancel: CancellationToken,
    ) -> Result<ApplyPatchResult, BridgeError> {
        request.patch = self.absolute_patch(request.patch);
        match self.inner.apply_patch(request, cancel).await {
            Ok(mut result) => {
                result.changed_paths = result
                    .changed_paths
                    .into_iter()
                    .map(|path| self.relative(path))
                    .collect();
                Ok(result)
            }
            Err(error) => Err(self.relative_error(error)),
        }
    }
}

impl Deref for FixtureBridge {
    type Target = RemoteBridge;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

fn fixture(root: &std::path::Path, rg: bool) -> (tempfile::TempDir, Arc<SshRunner>, FixtureBridge) {
    fixture_with_options(root, rg, None, &[])
}

fn executable_on_path(name: &str) -> PathBuf {
    let path = std::env::var_os("PATH").expect("test PATH must be set");
    std::env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("{name} must be installed for this test"))
}

fn fixture_with_options(
    root: &std::path::Path,
    rg: bool,
    max_frame: Option<usize>,
    extra: &[(&str, OsString)],
) -> (tempfile::TempDir, Arc<SshRunner>, FixtureBridge) {
    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let mut config = support::config_with_host("dev", root.to_str().unwrap());
    if let Some(max_frame) = max_frame {
        config.limits.max_frame_bytes = max_frame;
    }
    let mut environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (OsString::from("FAKE_SSH_ROOT"), OsString::from("/")),
        (
            OsString::from("FAKE_SSH_CANDIDATE_ROOT"),
            OsString::from(format!(".{}", root.display())),
        ),
    ]);
    for (key, value) in extra {
        environment.insert(OsString::from(key), value.clone());
    }
    if !rg {
        let bin = runtime_base.path().join("no-rg-bin");
        std::fs::create_dir(&bin).unwrap();
        let rg = bin.join("rg");
        std::fs::write(&rg, b"#!/bin/sh\nexit 64\n").unwrap();
        std::fs::set_permissions(&rg, std::fs::Permissions::from_mode(0o755)).unwrap();
        let inherited = environment
            .get(&OsString::from("PATH"))
            .cloned()
            .unwrap_or_else(|| OsString::from("/usr/local/bin:/usr/bin:/bin"));
        environment.insert(
            OsString::from("PATH"),
            OsString::from(format!("{}:{}", bin.display(), inherited.to_string_lossy())),
        );
    }
    let runner = Arc::new(
        SshRunner::with_executable(
            Arc::new(config),
            runtime,
            store,
            support::fake_ssh_path(),
            environment,
        )
        .unwrap(),
    );
    let bridge = FixtureBridge::new(
        RemoteBridge::new_immediate_for_transport_tests(Arc::clone(&runner)),
        root,
    );
    (runtime_base, runner, bridge)
}

fn fixture_with_probed_login_shell(
    root: &std::path::Path,
    login_shell: &std::path::Path,
) -> (
    tempfile::TempDir,
    Arc<SshRunner>,
    FixtureBridge,
    tempfile::TempDir,
) {
    use std::os::unix::fs::MetadataExt;

    let controls = tempfile::TempDir::new().unwrap();
    let uid = std::fs::metadata(root).unwrap().uid();
    write_executable(
        &controls.path().join("getent"),
        format!(
            "#!/bin/sh\n[ \"$1:$2\" = passwd:{uid} ] || exit 2\nprintf '%s\\n' {}\n",
            codex_ssh_bridge::quote::shell_word(&format!(
                "fixture:x:{uid}:{uid}::/tmp:{}",
                login_shell.display()
            ))
            .unwrap(),
        ),
    );
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        controls.path().display()
    ));
    let (runtime, runner, bridge) = fixture_with_options(
        root,
        false,
        None,
        &[
            ("PATH", path),
            ("FAKE_SSH_ACCOUNT_SHELL", login_shell.as_os_str().to_owned()),
        ],
    );
    (runtime, runner, bridge, controls)
}

fn fixture_with_patch_policy(
    root: &std::path::Path,
    max_write_bytes: Option<usize>,
    max_output_bytes: Option<u64>,
    read_only: bool,
    extra: &[(&str, OsString)],
) -> (tempfile::TempDir, Arc<SshRunner>, FixtureBridge) {
    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let mut config = support::config_with_host("dev", root.to_str().unwrap());
    if let Some(max_write_bytes) = max_write_bytes {
        config.limits.max_write_bytes = max_write_bytes;
    }
    if let Some(max_output_bytes) = max_output_bytes {
        config.limits.max_output_bytes = max_output_bytes;
    }
    config.hosts.get_mut("dev").unwrap().read_only = read_only;
    let mut environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (OsString::from("FAKE_SSH_ROOT"), OsString::from("/")),
    ]);
    for (key, value) in extra {
        environment.insert(OsString::from(key), value.clone());
    }
    let runner = Arc::new(
        SshRunner::with_executable(
            Arc::new(config),
            runtime,
            store,
            support::fake_ssh_path(),
            environment,
        )
        .unwrap(),
    );
    let bridge = FixtureBridge::new(
        RemoteBridge::new_immediate_for_transport_tests(Arc::clone(&runner)),
        root,
    );
    (runtime_base, runner, bridge)
}

fn context() -> RemoteContext {
    RemoteContext {
        remote: true,
        host: "dev".to_owned(),
        physical_root: "/physical/root".to_owned(),
        shell: ShellMetadata {
            kind: ShellName::Sh,
            version: None,
            fallback: false,
        },
        helper_mode: None,
    }
}

async fn cached_context(bridge: &FixtureBridge) -> RemoteContext {
    bridge
        .stat(
            StatRequest {
                host: "dev".to_owned(),
                paths: vec![".".to_owned()],
            },
            CancellationToken::new(),
        )
        .await
        .unwrap()
        .context
}

struct CountingDetail {
    serializations: Arc<AtomicUsize>,
}

impl Serialize for CountingDetail {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.serializations.fetch_add(1, Ordering::Release);
        serializer.serialize_str("must not be serialized")
    }
}

#[tokio::test]
async fn retention_rejects_uncached_or_forged_remote_provenance_before_serializing() {
    let root = tempfile::TempDir::new().unwrap();
    let (runtime, _runner, bridge) = fixture(root.path(), true);
    let serializations = Arc::new(AtomicUsize::new(0));

    let error = bridge
        .retain_serialized_detail(
            RetentionProvenance::Remote(context()),
            CountingDetail {
                serializations: Arc::clone(&serializations),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(serializations.load(Ordering::Acquire), 0);
    assert_eq!(spool_file_count(runtime.path()), 0);

    let valid = cached_context(&bridge).await;
    let cached_shell = valid.shell.clone();
    let mut invalid = Vec::new();
    let mut remote_false = valid.clone();
    remote_false.remote = false;
    invalid.push(remote_false);
    let mut wrong_host = valid.clone();
    wrong_host.host = "unconfigured".to_owned();
    invalid.push(wrong_host);
    let mut wrong_root = valid.clone();
    wrong_root.physical_root.push_str("/forged");
    invalid.push(wrong_root);
    let mut huge_bash = valid.clone();
    huge_bash.shell = ShellMetadata {
        kind: ShellName::Bash,
        version: Some("x".repeat(257)),
        fallback: false,
    };
    invalid.push(huge_bash);
    let mut sh_version = valid.clone();
    sh_version.shell = ShellMetadata {
        kind: ShellName::Sh,
        version: Some("invented".to_owned()),
        fallback: false,
    };
    invalid.push(sh_version);
    let mut login_version = valid.clone();
    login_version.shell = ShellMetadata {
        kind: ShellName::Login,
        version: Some("invented".to_owned()),
        fallback: false,
    };
    invalid.push(login_version);
    let mut login_fallback = valid.clone();
    login_fallback.shell = ShellMetadata {
        kind: ShellName::Login,
        version: None,
        fallback: true,
    };
    invalid.push(login_fallback);
    if cached_shell.kind == ShellName::Bash {
        let mut wrong_bash = valid.clone();
        wrong_bash.shell = ShellMetadata {
            kind: ShellName::Bash,
            version: Some(format!(
                "{}-forged",
                cached_shell.version.as_deref().unwrap()
            )),
            fallback: false,
        };
        invalid.push(wrong_bash);
        let mut bash_fallback = valid.clone();
        bash_fallback.shell = ShellMetadata {
            kind: ShellName::Bash,
            version: cached_shell.version.clone(),
            fallback: true,
        };
        invalid.push(bash_fallback);
        let mut false_sh_fallback = valid.clone();
        false_sh_fallback.shell = ShellMetadata {
            kind: ShellName::Sh,
            version: None,
            fallback: true,
        };
        invalid.push(false_sh_fallback);
    }

    for provenance in invalid {
        let error = bridge
            .retain_serialized_detail(
                RetentionProvenance::Remote(provenance),
                CountingDetail {
                    serializations: Arc::clone(&serializations),
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert_eq!(serializations.load(Ordering::Acquire), 0);
        assert_eq!(spool_file_count(runtime.path()), 0);
    }

    let reference = bridge
        .retain_serialized_detail(
            RetentionProvenance::Remote(valid.clone()),
            vec!["valid cached provenance"],
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let page = bridge
        .output_read(
            codex_ssh_bridge::remote::OutputReadRequest {
                output_ref: reference.as_str().to_owned(),
                stream: StreamKind::Stdout,
                offset: 0,
                max_bytes: 1024,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(page.provenance, RetentionProvenance::Remote(valid));
}

#[tokio::test]
async fn task8_retention_spool_round_trips_remote_and_aggregate_provenance() {
    let root = tempfile::TempDir::new().unwrap();
    let (_runtime, _runner, bridge) = fixture(root.path(), true);
    let remote_context = cached_context(&bridge).await;
    let owned = vec!["TASK8_RETAINED_DETAIL", "second"];
    let expected = serde_json::to_vec(&owned).unwrap();
    let reference = bridge
        .retain_serialized_detail(
            RetentionProvenance::Remote(remote_context.clone()),
            owned,
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let page = bridge
        .output_read(
            codex_ssh_bridge::remote::OutputReadRequest {
                output_ref: reference.as_str().to_owned(),
                stream: StreamKind::Stdout,
                offset: 0,
                max_bytes: 1024,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(page.provenance, RetentionProvenance::Remote(remote_context));
    assert_eq!(page.data.encoding, ValueEncoding::Utf8);
    assert_eq!(page.data.value.as_bytes(), expected);
    assert!(serde_json::to_value(&page).is_ok());

    let aggregate = RetentionProvenance::Aggregate {
        kind: AggregateKind::Hosts,
        source_count: 37,
    };
    let reference = bridge
        .retain_serialized_detail(
            aggregate.clone(),
            vec!["host-a", "host-b"],
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let page = bridge
        .output_read(
            codex_ssh_bridge::remote::OutputReadRequest {
                output_ref: reference.as_str().to_owned(),
                stream: StreamKind::Stdout,
                offset: 0,
                max_bytes: 1024,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(page.provenance, aggregate);
    assert!(serde_json::to_value(&page).is_ok());
}

#[tokio::test]
async fn task8_retention_spool_accepts_exact_serialized_limit_and_rejects_first_byte_over() {
    let root = tempfile::TempDir::new().unwrap();
    let (_runtime, _runner, bridge) = fixture(root.path(), true);
    let remote_context = cached_context(&bridge).await;
    let exact = "x".repeat(codex_ssh_bridge::MAX_OUTPUT_BYTES as usize - 2);
    let reference = bridge
        .retain_serialized_detail(
            RetentionProvenance::Remote(remote_context.clone()),
            exact,
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let page = bridge
        .output_read(
            codex_ssh_bridge::remote::OutputReadRequest {
                output_ref: reference.as_str().to_owned(),
                stream: StreamKind::Stdout,
                offset: codex_ssh_bridge::MAX_OUTPUT_BYTES - 1,
                max_bytes: 1,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(page.data.value, "\"");
    assert!(page.eof);

    let over = "x".repeat(codex_ssh_bridge::MAX_OUTPUT_BYTES as usize - 1);
    let error = bridge
        .retain_serialized_detail(
            RetentionProvenance::Remote(remote_context),
            over,
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Io);
}

struct CancellableDetail {
    progress: Arc<AtomicUsize>,
    chunk: String,
}

impl Serialize for CancellableDetail {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(1_024))?;
        for _ in 0..1_024 {
            self.progress.fetch_add(1, Ordering::Release);
            sequence.serialize_element(&self.chunk)?;
            std::thread::yield_now();
        }
        sequence.end()
    }
}

#[tokio::test]
async fn task8_retention_spool_cancellation_is_polled_and_blocking_join_is_awaited() {
    let root = tempfile::TempDir::new().unwrap();
    let (_runtime, _runner, bridge) = fixture(root.path(), true);
    let remote_context = cached_context(&bridge).await;
    let progress = Arc::new(AtomicUsize::new(0));
    let cancel = CancellationToken::new();
    let future = bridge.retain_serialized_detail(
        RetentionProvenance::Remote(remote_context),
        CancellableDetail {
            progress: Arc::clone(&progress),
            chunk: "x".repeat(64 * 1024),
        },
        cancel.clone(),
    );
    tokio::pin!(future);
    while progress.load(Ordering::Acquire) < 2 {
        tokio::select! {
            result = &mut future => panic!("serialization finished before cancellation: {result:?}"),
            () = tokio::task::yield_now() => {}
        }
    }
    cancel.cancel();
    let error = tokio::time::timeout(Duration::from_secs(2), &mut future)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Cancelled);
    let stopped = progress.load(Ordering::Acquire);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(progress.load(Ordering::Acquire), stopped);
}

fn value(value: &str) -> EncodedValue {
    EncodedValue {
        encoding: ValueEncoding::Utf8,
        value: value.to_owned(),
    }
}

#[test]
fn task78_remote_run_public_shapes_are_closed() {
    let request = RemoteRunRequest {
        host: "dev".to_owned(),
        command: "printf ok".to_owned(),
        cwd: Some("sub dir".to_owned()),
        shell: RunShell::Sh,
        timeout_ms: Some(1_250),
        stdin: Some(RunStdin {
            encoding: WriteEncoding::Base64,
            value: "AAE=".to_owned(),
        }),
    };
    assert_eq!(request.shell, RunShell::Sh);
    assert_eq!(request.timeout_ms, Some(1_250));
}

fn command_call_count(path: &std::path::Path) -> usize {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| *line == "C")
        .count()
}

#[tokio::test]
async fn task78_remote_run_is_bridge_owned_and_reports_explicit_shell() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(remote.path().join("sub dir")).unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);

    let result = bridge
        .run(
            RemoteRunRequest {
                host: "dev".to_owned(),
                command: "pwd; od -An -tx1".to_owned(),
                cwd: Some("sub dir".to_owned()),
                shell: RunShell::Sh,
                timeout_ms: Some(2_000),
                stdin: Some(RunStdin {
                    encoding: WriteEncoding::Base64,
                    value: "AAEJ".to_owned(),
                }),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(result.context.shell.kind, ShellName::Sh);
    assert!(!result.context.shell.fallback);
    assert_eq!(
        result.warnings,
        [
            "selected POSIX sh does not support Bash arrays, [[ ]], source, pipefail, or Bash substitutions; use POSIX syntax, or request Bash and ensure it is installed"
        ]
    );
    assert_eq!(result.exit_status, 0);
    assert_eq!(result.context.physical_root, "/");
    assert!(result.stdout.head.value.contains("sub dir"));
    assert!(result.stdout.head.value.contains("00 01 09"));
}

#[tokio::test]
async fn remote_run_nonzero_exit_retains_large_stderr_for_paging() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    let stderr_bytes = 300 * 1024_u64;

    let result = bridge
        .run(
            RemoteRunRequest {
                host: "dev".to_owned(),
                command: format!(
                    "printf applied > review-side-effect; dd if=/dev/zero bs=1024 count={} >&2 2>/dev/null; exit 2",
                    stderr_bytes / 1024
                ),
                cwd: None,
                shell: RunShell::Sh,
                timeout_ms: Some(5_000),
                stdin: None,
            },
            CancellationToken::new(),
        )
        .await
        .expect("nonzero user command output must remain inspectable");

    assert_eq!(result.exit_status, 2);
    assert_eq!(result.stderr.raw_bytes, stderr_bytes);
    assert!(result.stderr.truncated);
    assert!(!result.remote_process_may_continue);
    assert_eq!(
        std::fs::read_to_string(remote.path().join("review-side-effect")).unwrap(),
        "applied"
    );
    let output_ref = result.output_ref.expect("large stderr must be retained");
    let page = bridge
        .output_read(
            codex_ssh_bridge::remote::OutputReadRequest {
                output_ref,
                stream: StreamKind::Stderr,
                offset: 256 * 1024,
                max_bytes: 4096,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(page.data.encoding, ValueEncoding::Base64);
    assert_eq!(
        page.data.value,
        base64::engine::general_purpose::STANDARD.encode(vec![0; 4096])
    );
    assert_eq!(page.next_offset, 260 * 1024);
    assert!(!page.eof);
}

#[tokio::test]
async fn task78_remote_run_rejects_relative_cwd_and_nul_before_command_child() {
    let remote = tempfile::TempDir::new().unwrap();
    for (name, command, cwd, expected) in [
        (
            "relative-cwd",
            "printf unsafe",
            Some("../escape"),
            ErrorCode::RemoteAbsolutePathRequired,
        ),
        (
            "nul",
            "printf\0unsafe",
            remote.path().to_str(),
            ErrorCode::InvalidArgument,
        ),
    ] {
        let log_dir = tempfile::TempDir::new().unwrap();
        let log = log_dir.path().join(format!("{name}.log"));
        let (_runtime, _runner, bridge) = fixture_with_patch_policy(
            remote.path(),
            None,
            None,
            false,
            &[("FAKE_SSH_LOG", log.clone().into_os_string())],
        );
        let error = bridge
            .inner
            .run(
                RemoteRunRequest {
                    host: "dev".to_owned(),
                    command: command.to_owned(),
                    cwd: cwd.map(str::to_owned),
                    shell: RunShell::Sh,
                    timeout_ms: Some(2_000),
                    stdin: None,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, expected, "{name}: {error:?}");
        assert_eq!(command_call_count(&log), 0, "{name}");
    }
}

#[tokio::test]
async fn task78_remote_run_requires_canonical_bounded_base64_before_command_child() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let remote = tempfile::TempDir::new().unwrap();
    let oversized = STANDARD.encode(vec![0; codex_ssh_bridge::MAX_WRITE_BYTES + 1]);
    for (name, value, expected) in [
        (
            "whitespace",
            "AAEJ\n".to_owned(),
            ErrorCode::InvalidArgument,
        ),
        (
            "missing-padding",
            "AAE".to_owned(),
            ErrorCode::InvalidArgument,
        ),
        ("url-safe", "__8=".to_owned(), ErrorCode::InvalidArgument),
        (
            "trailing-bits",
            "AB==".to_owned(),
            ErrorCode::InvalidArgument,
        ),
        ("decoded-over-limit", oversized, ErrorCode::RequestTooLarge),
    ] {
        let log_dir = tempfile::TempDir::new().unwrap();
        let log = log_dir.path().join(format!("{name}.log"));
        let (_runtime, _runner, bridge) = fixture_with_options(
            remote.path(),
            false,
            None,
            &[("FAKE_SSH_LOG", log.clone().into_os_string())],
        );
        let error = bridge
            .run(
                RemoteRunRequest {
                    host: "dev".to_owned(),
                    command: "cat".to_owned(),
                    cwd: None,
                    shell: RunShell::Sh,
                    timeout_ms: Some(2_000),
                    stdin: Some(RunStdin {
                        encoding: WriteEncoding::Base64,
                        value,
                    }),
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, expected, "{name}: {error:?}");
        assert_eq!(command_call_count(&log), 0, "{name}");
    }
}

#[tokio::test]
async fn task78_remote_run_requires_explicit_bash_support() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("FAKE_SSH_MODE", OsString::from("echo-command"))],
    );
    let error = bridge
        .run(
            RemoteRunRequest {
                host: "dev".to_owned(),
                command: "printf safe".to_owned(),
                cwd: None,
                shell: RunShell::Bash,
                timeout_ms: Some(2_000),
                stdin: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RemoteCapabilityMissing);

    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("missing-bash.log");
    let (_runtime, _runner, missing_bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("FAKE_SSH_MODE", OsString::from("echo-command")),
            ("FAKE_SSH_LOG", log.clone().into_os_string()),
        ],
    );
    let error = missing_bridge
        .run(
            RemoteRunRequest {
                host: "dev".to_owned(),
                command: "printf safe".to_owned(),
                cwd: None,
                shell: RunShell::Bash,
                timeout_ms: Some(2_000),
                stdin: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RemoteCapabilityMissing);
    assert_eq!(command_call_count(&log), 0);
}

#[tokio::test]
async fn task78_remote_run_early_stdin_close_preserves_actual_exit() {
    let remote = tempfile::TempDir::new().unwrap();
    for (command, expected_status) in [("exit 0", 0), ("exit 7", 7)] {
        let (_runtime, _runner, bridge) = fixture(remote.path(), false);
        let request = RemoteRunRequest {
            host: "dev".to_owned(),
            command: command.to_owned(),
            cwd: None,
            shell: RunShell::Sh,
            timeout_ms: Some(2_000),
            stdin: Some(RunStdin {
                encoding: WriteEncoding::Utf8,
                value: "x".repeat(codex_ssh_bridge::MAX_WRITE_BYTES),
            }),
        };
        let result = bridge.run(request, CancellationToken::new()).await.unwrap();
        assert_eq!(result.exit_status, expected_status);
        assert_eq!(result.context.shell.kind, ShellName::Sh);
        assert_eq!(result.context.physical_root, "/");
        assert!(!result.remote_process_may_continue);
    }
}

#[tokio::test]
async fn task78_remote_run_facade_timeout_retains_selected_context() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("FAKE_SSH_MODE", OsString::from("sleep")),
            ("FAKE_SSH_SLEEP_SECONDS", OsString::from("5")),
        ],
    );
    let error = bridge
        .run(
            RemoteRunRequest {
                host: "dev".to_owned(),
                command: "sleep 5".to_owned(),
                cwd: None,
                shell: RunShell::Sh,
                timeout_ms: Some(30),
                stdin: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::CommandTimeout);
    assert_eq!(error.details.host.as_deref(), Some("dev"));
    assert_eq!(error.details.physical_root.as_deref(), Some("/"));
    assert_eq!(
        error
            .details
            .shell
            .as_ref()
            .map(|shell| shell.kind.as_str()),
        Some("sh")
    );
}

#[tokio::test]
async fn task78_remote_run_errors_after_selection_carry_shell_context() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("FAKE_SSH_MODE", OsString::from("error")),
            ("FAKE_SSH_ERROR", OsString::from("remote")),
            ("FAKE_SSH_EXIT_STATUS", OsString::from("255")),
        ],
    );
    let result = bridge
        .run(
            RemoteRunRequest {
                host: "dev".to_owned(),
                command: "exit 255".to_owned(),
                cwd: None,
                shell: RunShell::Sh,
                timeout_ms: Some(2_000),
                stdin: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.exit_status, 255);
    assert_eq!(result.context.shell.kind, ShellName::Sh);
}

#[tokio::test]
async fn task78_remote_run_treats_hostile_cwd_bytes_as_literal_data() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let sentinel = controls.path().join("cwd-injection");
    let component = format!(
        "quote'\n* -leading `tick` $(printf injected); touch {}; printf unsafe",
        sentinel.display()
    );
    std::fs::create_dir_all(remote.path().join(&component)).unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    for shell in [RunShell::Sh, RunShell::Bash, RunShell::Login] {
        let result = bridge
            .run(
                RemoteRunRequest {
                    host: "dev".to_owned(),
                    command: "pwd".to_owned(),
                    cwd: Some(component.clone()),
                    shell,
                    timeout_ms: Some(2_000),
                    stdin: None,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            result.stdout.head.value,
            format!("{}\n", remote.path().join(&component).display()),
            "{shell:?}"
        );
        assert!(!sentinel.exists(), "{shell:?}");
    }
}

#[test]
fn task78_error_shell_metadata_is_closed() {
    let mut error = BridgeError::new(ErrorCode::RemoteExit, "remote command failed", false);
    error.details.shell = Some(codex_ssh_bridge::error::ErrorShellMetadata {
        kind: "sh".to_owned(),
        version: None,
        fallback: true,
    });
    error.details.physical_root = Some("/srv/app".to_owned());
    assert_eq!(
        serde_json::to_value(&error).unwrap()["details"]["shell"],
        serde_json::json!({"kind":"sh","version":null,"fallback":true})
    );
    assert_eq!(
        serde_json::to_value(&error).unwrap()["details"]["physical_root"],
        "/srv/app"
    );

    let pre_probe = BridgeError::new(ErrorCode::AuthRequired, "authentication required", false);
    let serialized = serde_json::to_value(pre_probe).unwrap();
    assert!(serialized["details"].get("physical_root").is_none());
    assert!(serialized["details"].get("shell").is_none());
}

#[test]
fn task78_domain_error_remote_context_helper_fills_only_missing_safe_fields() {
    use codex_ssh_bridge::error::{ErrorShellMetadata, attach_available_remote_context};

    let shell = ErrorShellMetadata {
        kind: "bash".to_owned(),
        version: Some("5.2".to_owned()),
        fallback: false,
    };
    let mut error = BridgeError::new(ErrorCode::WriteConflict, "conflict", false);
    error.details.host = Some("original".to_owned());
    attach_available_remote_context(
        &mut error,
        Some("replacement"),
        Some("/srv/app"),
        Some(&shell),
    );
    assert_eq!(error.code, ErrorCode::WriteConflict);
    assert_eq!(error.details.host.as_deref(), Some("original"));
    assert_eq!(error.details.physical_root.as_deref(), Some("/srv/app"));
    assert_eq!(error.details.shell.as_ref(), Some(&shell));
}

fn assert_task78_fixed_context(error: &BridgeError, _root: &std::path::Path) {
    assert_eq!(error.details.host.as_deref(), Some("dev"), "{error:?}");
    assert_eq!(
        error.details.physical_root.as_deref(),
        Some("/"),
        "{error:?}"
    );
    let shell = error.details.shell.as_ref().expect("fixed shell context");
    assert_eq!(shell.kind, "sh");
    assert_eq!(shell.version, None);
    assert!(!shell.fallback);
}

#[tokio::test]
async fn task78_domain_error_remote_context_is_attached_after_fixed_exit_zero() {
    let read_root = tempfile::TempDir::new().unwrap();
    std::fs::write(read_root.path().join("read.txt"), b"safe\n").unwrap();
    let (_runtime, _runner, read_bridge) = fixture_with_options(
        read_root.path(),
        false,
        None,
        &[("FAKE_SSH_LOCAL_FIXED_POST", OsString::from("stderr"))],
    );
    let read_error = read_bridge
        .read(
            ReadRequest {
                host: "dev".to_owned(),
                paths: vec!["read.txt".to_owned()],
                start_line: None,
                max_lines: None,
                max_bytes: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(read_error.code, ErrorCode::ProtocolError);
    assert_task78_fixed_context(&read_error, read_root.path());

    let write_root = tempfile::TempDir::new().unwrap();
    std::fs::write(write_root.path().join("exists"), b"old").unwrap();
    let (_runtime, _runner, write_bridge) = fixture(write_root.path(), false);
    let write_error = write_bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "exists".to_owned(),
                content: "new".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(write_error.code, ErrorCode::WriteConflict);
    assert_task78_fixed_context(&write_error, write_root.path());

    let patch_root = tempfile::TempDir::new().unwrap();
    std::fs::write(patch_root.path().join("target"), b"old\n").unwrap();
    let (_runtime, _runner, patch_bridge) = fixture_with_options(
        patch_root.path(),
        false,
        None,
        &[("FAKE_SSH_LOCAL_FIXED_POST", OsString::from("stderr"))],
    );
    let patch_error = patch_bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: "--- a/target\n+++ b/target\n@@ -1 +1 @@\n-old\n+new\n".to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(patch_error.code, ErrorCode::ProtocolError);
    assert_eq!(patch_error.details.failed_path.as_deref(), Some("target"));
    assert_eq!(patch_error.details.changed_paths, Some(Vec::new()));
    assert_eq!(
        patch_error.details.not_changed_paths,
        Some(vec!["target".to_owned()])
    );
    assert_eq!(patch_error.details.outcome_unknown_paths, Some(Vec::new()));
    assert_task78_fixed_context(&patch_error, patch_root.path());
}

#[tokio::test]
async fn task78_metadata_and_candidate_search_malicious_exit_zero_errors_keep_context() {
    let list_root = tempfile::TempDir::new().unwrap();
    std::fs::write(list_root.path().join("entry"), b"x").unwrap();
    let (_runtime, _runner, list_bridge) = fixture_with_options(
        list_root.path(),
        false,
        None,
        &[("FAKE_SSH_LOCAL_FIXED_POST", OsString::from("stderr"))],
    );
    let list_error = list_bridge
        .list(
            ListRequest {
                host: "dev".to_owned(),
                path: None,
                depth: None,
                include_hidden: None,
                max_entries: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(list_error.code, ErrorCode::ProtocolError);
    assert_task78_fixed_context(&list_error, list_root.path());

    let stat_root = tempfile::TempDir::new().unwrap();
    std::fs::write(stat_root.path().join("entry"), b"x").unwrap();
    let (_runtime, _runner, stat_bridge) = fixture_with_options(
        stat_root.path(),
        false,
        None,
        &[("FAKE_SSH_LOCAL_FIXED_POST", OsString::from("stderr"))],
    );
    let stat_error = stat_bridge
        .stat(
            StatRequest {
                host: "dev".to_owned(),
                paths: vec!["entry".to_owned()],
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(stat_error.code, ErrorCode::ProtocolError);
    assert_task78_fixed_context(&stat_error, stat_root.path());

    let candidate_root = tempfile::TempDir::new().unwrap();
    std::fs::write(candidate_root.path().join("entry"), b"needle\n").unwrap();
    let (_runtime, _runner, candidate_bridge) = fixture_with_options(
        candidate_root.path(),
        false,
        None,
        &[("FAKE_SSH_LOCAL_FIXED_POST", OsString::from("stderr"))],
    );
    let candidate_error = candidate_bridge
        .search(
            SearchRequest {
                host: "dev".to_owned(),
                query: "needle".to_owned(),
                path: None,
                globs: Vec::new(),
                max_results: None,
                binary: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(candidate_error.code, ErrorCode::ProtocolError);
    assert_task78_fixed_context(&candidate_error, candidate_root.path());
}

#[tokio::test]
async fn task78_search_engine_malicious_exit_zero_cursor_error_keeps_context() {
    let remote = tempfile::TempDir::new().unwrap();
    let target = remote.path().join("entry");
    std::fs::write(&target, b"needle\n").unwrap();
    let shim = tempfile::TempDir::new().unwrap();
    write_executable(
        &shim.path().join("grep"),
        "#!/bin/sh\nlast=\nfor last do :; done\ncase \" $* \" in *\" -- needle \"*) case \"$last\" in */entry) printf 'BROKEN\\n'; exit 0;; esac;; esac\nexec /usr/bin/grep \"$@\"\n",
    );
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) =
        fixture_with_options(remote.path(), false, None, &[("PATH", path)]);
    let error = bridge
        .search(
            SearchRequest {
                host: "dev".to_owned(),
                query: "needle".to_owned(),
                path: None,
                globs: Vec::new(),
                max_results: None,
                binary: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ProtocolError);
    assert_task78_fixed_context(&error, remote.path());
}

#[tokio::test]
async fn task78_patch_mutation_result_corruption_keeps_context_and_progress_truth() {
    let remote = tempfile::TempDir::new().unwrap();
    let shim = tempfile::TempDir::new().unwrap();
    write_executable(
        &shim.path().join("ln"),
        "#!/bin/sh\ncase \" $* \" in *\" ./malformed\"*) /usr/bin/ln \"$@\"; status=$?; printf GARBAGE; exit \"$status\";; esac\nexec /usr/bin/ln \"$@\"\n",
    );
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) =
        fixture_with_options(remote.path(), false, None, &[("PATH", path)]);
    let error = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: concat!(
                    "--- /dev/null\n+++ b/malformed\n@@ -0,0 +1 @@\n+first\n",
                    "--- /dev/null\n+++ b/later\n@@ -0,0 +1 @@\n+second\n",
                )
                .to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
    assert_eq!(error.details.mutation_may_have_applied, Some(true));
    assert_eq!(error.details.failed_path.as_deref(), Some("malformed"));
    assert_eq!(error.details.changed_paths, Some(Vec::new()));
    assert_eq!(
        error.details.outcome_unknown_paths,
        Some(vec!["malformed".to_owned()])
    );
    assert_eq!(
        error.details.not_changed_paths,
        Some(vec!["later".to_owned()])
    );
    assert_task78_fixed_context(&error, remote.path());
    assert_eq!(
        std::fs::read(remote.path().join("malformed")).unwrap(),
        b"first\n"
    );
    assert!(!remote.path().join("later").exists());
}

#[tokio::test]
async fn task78_patch_second_snapshot_cancellation_keeps_first_snapshot_context() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a"), b"old\n").unwrap();
    std::fs::write(remote.path().join("b"), b"old\n").unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let second_started = controls.path().join("second-started");
    let shim = tempfile::TempDir::new().unwrap();
    write_executable(
        &shim.path().join("stat"),
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" -- ./b \"*) : >{}; /usr/bin/sleep 10;; esac\nexec /usr/bin/stat \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(second_started.to_str().unwrap()).unwrap(),
        ),
    );
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) =
        fixture_with_options(remote.path(), false, None, &[("PATH", path)]);
    let bridge = Arc::new(bridge);
    let cancel = CancellationToken::new();
    let task_bridge = Arc::clone(&bridge);
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        task_bridge
            .apply_patch(
                ApplyPatchRequest {
                    host: "dev".to_owned(),
                    patch: concat!(
                        "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n",
                        "--- a/b\n+++ b/b\n@@ -1 +1 @@\n-old\n+new\n",
                    )
                    .to_owned(),
                },
                task_cancel,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while !second_started.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("second snapshot did not start");
    cancel.cancel();
    let error = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("cancelled patch did not stop")
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Cancelled, "{error:?}");
    assert_task78_fixed_context(&error, remote.path());
    assert_eq!(error.details.failed_path.as_deref(), Some("b"));
    assert_eq!(error.details.changed_paths, Some(Vec::new()));
    assert_eq!(
        error.details.not_changed_paths,
        Some(vec!["a".to_owned(), "b".to_owned()])
    );
    assert_eq!(error.details.outcome_unknown_paths, Some(Vec::new()));
    assert_eq!(error.details.mutation_may_have_applied, None);
    assert_eq!(std::fs::read(remote.path().join("a")).unwrap(), b"old\n");
    assert_eq!(std::fs::read(remote.path().join("b")).unwrap(), b"old\n");
}

#[tokio::test]
async fn task78_read_second_reprobe_cancellation_uses_first_result_context() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("entry"), b"payload\n").unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let mismatch = controls.path().join("mismatch-used");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("FAKE_SSH_MISMATCH_FILE", mismatch.as_os_str().to_owned()),
            ("FAKE_SSH_MISMATCH_KEY", OsString::from("read_slice")),
            ("FAKE_SSH_FIXED_SLEEP_SECONDS", OsString::from("10")),
        ],
    );
    let bridge = Arc::new(bridge);
    let cancel = CancellationToken::new();
    let task_bridge = Arc::clone(&bridge);
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        task_bridge
            .read(
                ReadRequest {
                    host: "dev".to_owned(),
                    paths: vec!["entry".to_owned()],
                    start_line: None,
                    max_lines: None,
                    max_bytes: None,
                },
                task_cancel,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while !mismatch.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first capability mismatch was not observed");
    cancel.cancel();
    let error = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("cancelled reprobe did not stop")
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Cancelled, "{error:?}");
    assert_task78_fixed_context(&error, remote.path());
}

#[tokio::test]
async fn task78_search_engine_cancellation_keeps_candidate_context() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("entry"), b"needle\n").unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let engine_started = controls.path().join("engine-started");
    let shim = tempfile::TempDir::new().unwrap();
    write_executable(
        &shim.path().join("grep"),
        format!(
            "#!/bin/sh\nlast=\nfor last do :; done\ncase \"$last\" in */entry) : >{}; /usr/bin/sleep 10;; esac\nexec /usr/bin/grep \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(engine_started.to_str().unwrap()).unwrap(),
        ),
    );
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) =
        fixture_with_options(remote.path(), false, None, &[("PATH", path)]);
    let bridge = Arc::new(bridge);
    let cancel = CancellationToken::new();
    let task_bridge = Arc::clone(&bridge);
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        task_bridge
            .search(
                SearchRequest {
                    host: "dev".to_owned(),
                    query: "needle".to_owned(),
                    path: None,
                    globs: Vec::new(),
                    max_results: None,
                    binary: None,
                },
                task_cancel,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while !engine_started.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("search engine did not start");
    cancel.cancel();
    let error = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("cancelled search did not stop")
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Cancelled, "{error:?}");
    assert_task78_fixed_context(&error, remote.path());
}

fn metadata() -> RemoteMetadata {
    RemoteMetadata {
        kind: RemoteFileKind::File,
        size: 3,
        mode: 0o644,
        mtime_seconds: -1,
        mtime_nanoseconds: 2,
    }
}

fn ssh_call_count(log: &std::path::Path, marker: &str) -> usize {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|line| *line == marker)
        .count()
}

fn phase_log(log: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn write_executable(path: &std::path::Path, script: impl AsRef<[u8]>) {
    std::fs::write(path, script).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[tokio::test]
async fn physical_root_retarget_read_uses_cached_diagnostics_and_new_filesystem_target() {
    use std::os::unix::fs::symlink;

    let container = tempfile::TempDir::new().unwrap();
    let first = container.path().join("first");
    let second = container.path().join("second");
    let active = container.path().join("active");
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir(&second).unwrap();
    std::fs::write(first.join("value"), b"first\n").unwrap();
    std::fs::write(second.join("value"), b"second\n").unwrap();
    symlink(&first, &active).unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("ssh.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        &active,
        false,
        None,
        &[("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );

    let first_read = bridge
        .read(
            ReadRequest {
                host: "dev".to_owned(),
                paths: vec!["value".to_owned()],
                start_line: None,
                max_lines: None,
                max_bytes: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(first_read.context.physical_root, "/");

    std::fs::remove_file(&active).unwrap();
    symlink(&second, &active).unwrap();
    let second_read = bridge
        .read(
            ReadRequest {
                host: "dev".to_owned(),
                paths: vec!["value".to_owned()],
                start_line: None,
                max_lines: None,
                max_bytes: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(second_read.context.physical_root, "/");
    assert!(matches!(
        &second_read.files[0],
        ReadEntry::Success { content, .. } if content.value == "second\n"
    ));
    assert_eq!(bridge.hosts().await.unwrap().hosts[0].host, "dev");
    assert_eq!(
        ssh_call_count(&log, "P"),
        1,
        "tool capabilities stay cached"
    );
    assert_eq!(
        ssh_call_count(&log, "R"),
        0,
        "root is not observed per read"
    );
}

#[tokio::test]
async fn write_root_retarget_follows_the_current_filesystem_target() {
    use std::os::unix::fs::symlink;

    let container = tempfile::TempDir::new().unwrap();
    let first = container.path().join("first");
    let second = container.path().join("second");
    let active = container.path().join("active");
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir(&second).unwrap();
    symlink(&first, &active).unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("ssh.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        &active,
        false,
        None,
        &[("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    std::fs::remove_file(&active).unwrap();
    symlink(&second, &active).unwrap();

    let result = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "created".to_owned(),
                content: "payload".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.operation, WriteOperation::Create);
    assert!(!first.join("created").exists());
    assert_eq!(std::fs::read(second.join("created")).unwrap(), b"payload");
    assert_eq!(
        ssh_call_count(&log, "P"),
        1,
        "tool capabilities stay cached"
    );
    assert_eq!(ssh_call_count(&log, "R"), 0);
}

#[tokio::test]
async fn cached_root_retarget_allows_a_later_mutation_on_the_current_target() {
    use std::os::unix::fs::symlink;

    let container = tempfile::TempDir::new().unwrap();
    let first = container.path().join("first");
    let second = container.path().join("second");
    let active = container.path().join("active");
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir(&second).unwrap();
    std::fs::write(first.join("value"), b"first\n").unwrap();
    std::fs::write(second.join("value"), b"second\n").unwrap();
    symlink(&first, &active).unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("ssh.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        &active,
        false,
        None,
        &[("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    bridge
        .read(
            ReadRequest {
                host: "dev".to_owned(),
                paths: vec!["value".to_owned()],
                start_line: None,
                max_lines: None,
                max_bytes: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    std::fs::remove_file(&active).unwrap();
    symlink(&second, &active).unwrap();

    let result = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "blocked".to_owned(),
                content: "payload".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(!first.join("blocked").exists());
    assert_eq!(std::fs::read(second.join("blocked")).unwrap(), b"payload");
    assert_eq!(
        ssh_call_count(&log, "P"),
        1,
        "root checks do not reprobe tools"
    );

    assert_eq!(result.operation, WriteOperation::Create);
}

#[tokio::test]
async fn cached_root_retarget_allows_remote_run_on_the_current_target() {
    use std::os::unix::fs::symlink;

    let container = tempfile::TempDir::new().unwrap();
    let first = container.path().join("first");
    let second = container.path().join("second");
    let active = container.path().join("active");
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir(&second).unwrap();
    std::fs::write(first.join("value"), b"first\n").unwrap();
    symlink(&first, &active).unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("ssh.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        &active,
        false,
        None,
        &[("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    bridge
        .read(
            ReadRequest {
                host: "dev".to_owned(),
                paths: vec!["value".to_owned()],
                start_line: None,
                max_lines: None,
                max_bytes: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    std::fs::remove_file(&active).unwrap();
    symlink(&second, &active).unwrap();

    let result = bridge
        .run(
            RemoteRunRequest {
                host: "dev".to_owned(),
                command: "printf payload > blocked".to_owned(),
                cwd: None,
                shell: RunShell::Sh,
                timeout_ms: None,
                stdin: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.exit_status, 0);
    assert!(!first.join("blocked").exists());
    assert_eq!(std::fs::read(second.join("blocked")).unwrap(), b"payload");
    assert_eq!(
        ssh_call_count(&log, "P"),
        1,
        "run reuses the cached capability probe"
    );
    assert_eq!(ssh_call_count(&log, "R"), 0);
}

#[tokio::test]
async fn patch_root_retarget_follows_the_current_filesystem_target() {
    use std::os::unix::fs::symlink;

    let container = tempfile::TempDir::new().unwrap();
    let first = container.path().join("first");
    let second = container.path().join("second");
    let active = container.path().join("active");
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir(&second).unwrap();
    std::fs::write(first.join("target"), b"old\n").unwrap();
    std::fs::write(second.join("target"), b"old\n").unwrap();
    symlink(&first, &active).unwrap();
    let (_runtime, _runner, bridge) = fixture(&active, false);
    bridge
        .read(
            ReadRequest {
                host: "dev".to_owned(),
                paths: vec!["target".to_owned()],
                start_line: None,
                max_lines: None,
                max_bytes: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    std::fs::remove_file(&active).unwrap();
    symlink(&second, &active).unwrap();

    let result = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: "--- a/target\n+++ b/target\n@@ -1 +1 @@\n-old\n+new\n".to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.changed_paths, vec!["target"]);
    assert_eq!(std::fs::read(first.join("target")).unwrap(), b"old\n");
    assert_eq!(std::fs::read(second.join("target")).unwrap(), b"new\n");
}

#[tokio::test]
async fn tool_capability_refresh_updates_connection_diagnostics_only() {
    use std::os::unix::fs::symlink;

    let container = tempfile::TempDir::new().unwrap();
    let first = container.path().join("first");
    let second = container.path().join("second");
    let active = container.path().join("active");
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir(&second).unwrap();
    std::fs::write(first.join("value"), b"first\n").unwrap();
    std::fs::write(second.join("value"), b"second\n").unwrap();
    symlink(&first, &active).unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let mismatch = controls.path().join("mismatch-used");
    let log = controls.path().join("ssh.log");
    std::fs::write(&mismatch, b"armed-later").unwrap();
    let (_runtime, _runner, bridge) = fixture_with_options(
        &active,
        false,
        None,
        &[
            ("FAKE_SSH_LOG", log.as_os_str().to_owned()),
            ("FAKE_SSH_MISMATCH_FILE", mismatch.as_os_str().to_owned()),
            ("FAKE_SSH_MISMATCH_KEY", OsString::from("read_slice")),
        ],
    );
    bridge
        .read(
            ReadRequest {
                host: "dev".to_owned(),
                paths: vec!["value".to_owned()],
                start_line: None,
                max_lines: None,
                max_bytes: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    std::fs::remove_file(&active).unwrap();
    symlink(&second, &active).unwrap();
    std::fs::remove_file(&mismatch).unwrap();
    let refreshed = bridge
        .read(
            ReadRequest {
                host: "dev".to_owned(),
                paths: vec!["value".to_owned()],
                start_line: None,
                max_lines: None,
                max_bytes: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(refreshed.context.physical_root, "/");
    assert_eq!(ssh_call_count(&log, "P"), 2);

    let result = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "blocked".to_owned(),
                content: "payload".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.operation, WriteOperation::Create);
    assert!(!first.join("blocked").exists());
    assert_eq!(std::fs::read(second.join("blocked")).unwrap(), b"payload");
}

async fn assert_guard_pins_replaced_root(raw: bool) {
    let container = tempfile::TempDir::new().unwrap();
    let root = container.path().join("root");
    let pinned = container.path().join("pinned-root");
    std::fs::create_dir(&root).unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let marker = controls.path().join("root-replaced");
    let shim = tempfile::TempDir::new().unwrap();
    write_executable(
        &shim.path().join("stat"),
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" -L -c %d:%i -- . \"*) if [ ! -e {} ]; then out=$(/usr/bin/stat \"$@\")||exit; /usr/bin/mv -- {} {}||exit; /usr/bin/mkdir -- {}||exit; : >{}; printf %s \"$out\"; exit 0; fi;; esac\nexec /usr/bin/stat \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
            codex_ssh_bridge::quote::shell_word(root.to_str().unwrap()).unwrap(),
            codex_ssh_bridge::quote::shell_word(pinned.to_str().unwrap()).unwrap(),
            codex_ssh_bridge::quote::shell_word(root.to_str().unwrap()).unwrap(),
            codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
        ),
    );
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(&root, false, None, &[("PATH", path)]);
    if raw {
        bridge
            .run(
                RemoteRunRequest {
                    host: "dev".to_owned(),
                    command: "printf raw > payload".to_owned(),
                    cwd: None,
                    shell: RunShell::Sh,
                    timeout_ms: None,
                    stdin: None,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();
    } else {
        bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: "payload".to_owned(),
                    content: "fixed".to_owned(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Create,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();
    }
    assert!(marker.exists(), "guard hook did not replace the root");
    let expected = if raw {
        b"raw".as_slice()
    } else {
        b"fixed".as_slice()
    };
    assert_eq!(std::fs::read(pinned.join("payload")).unwrap(), expected);
    assert!(!root.join("payload").exists());
}

#[tokio::test]
#[ignore = "strict physical-root pinning is not part of the default trusted-server mode"]
async fn fixed_guard_uses_the_verified_root_inode_after_its_path_is_replaced() {
    assert_guard_pins_replaced_root(false).await;
}

#[tokio::test]
#[ignore = "strict physical-root pinning is not part of the default trusted-server mode"]
async fn raw_guard_uses_the_verified_root_inode_after_its_path_is_replaced() {
    assert_guard_pins_replaced_root(true).await;
}

#[tokio::test]
async fn raw_remote_run_preserves_the_callers_configured_locale() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("LC_ALL", OsString::from("codex_TEST.UTF-8"))],
    );
    let result = bridge
        .run(
            RemoteRunRequest {
                host: "dev".to_owned(),
                command: "printf %s \"$LC_ALL\"".to_owned(),
                cwd: None,
                shell: RunShell::Sh,
                timeout_ms: None,
                stdin: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.exit_status, 0);
    assert_eq!(result.stdout.head.value, "codex_TEST.UTF-8");
}

#[tokio::test]
async fn login_run_is_interpreted_by_the_account_shell_after_root_guarding() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, _runner, bridge, _controls) =
        fixture_with_probed_login_shell(remote.path(), std::path::Path::new("/bin/bash"));
    let result = bridge
        .run(
            RemoteRunRequest {
                host: "dev".to_owned(),
                command: "[[ -n $BASH_VERSION ]] && printf login-bash".to_owned(),
                cwd: None,
                shell: RunShell::Login,
                timeout_ms: None,
                stdin: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.exit_status, 0);
    assert_eq!(result.stdout.head.value, "login-bash");
}

#[tokio::test]
async fn login_run_uses_the_probed_non_posix_account_shell_and_ignores_shell_environment() {
    use std::os::unix::fs::MetadataExt;

    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let account_shell = controls.path().join("non-posix-account-shell");
    write_executable(
        &account_shell,
        "#!/bin/sh\n[ \"$1\" = -c ] || exit 91\ncase \"$2\" in 'exec sh -c '*) exec /bin/sh -c \"$2\";; '[['*) exec /bin/bash --noprofile --norc -c \"$2\";; *) exit 91;; esac\n",
    );
    let evil_marker = controls.path().join("evil-ran");
    let evil_shell = controls.path().join("evil-shell");
    write_executable(
        &evil_shell,
        format!(
            "#!/bin/sh\n: >{}\nexit 92\n",
            codex_ssh_bridge::quote::shell_word(evil_marker.to_str().unwrap()).unwrap()
        ),
    );
    let uid = std::fs::metadata(remote.path()).unwrap().uid();
    let getent = controls.path().join("getent");
    write_executable(
        &getent,
        format!(
            "#!/bin/sh\n[ \"$1:$2\" = passwd:{uid} ] || exit 2\nprintf '%s\\n' {}\n",
            codex_ssh_bridge::quote::shell_word(&format!(
                "fixture:x:{uid}:{uid}::/tmp:{}",
                account_shell.display()
            ))
            .unwrap(),
        ),
    );
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        controls.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("PATH", path),
            (
                "FAKE_SSH_ACCOUNT_SHELL",
                account_shell.as_os_str().to_owned(),
            ),
            ("SHELL", evil_shell.as_os_str().to_owned()),
        ],
    );
    let result = bridge
        .run(
            RemoteRunRequest {
                host: "dev".to_owned(),
                command: "[[ -n $BASH_VERSION ]] && printf probed-login".to_owned(),
                cwd: None,
                shell: RunShell::Login,
                timeout_ms: None,
                stdin: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.exit_status, 0);
    assert_eq!(result.stdout.head.value, "probed-login");
    assert!(!evil_marker.exists());
}

#[tokio::test]
async fn login_guard_does_not_enable_nounset_for_the_user_payload() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, _runner, bridge, _controls) =
        fixture_with_probed_login_shell(remote.path(), std::path::Path::new("/bin/bash"));
    let result = bridge
        .run(
            RemoteRunRequest {
                host: "dev".to_owned(),
                command: "printf '<%s>' \"$CODEX_SSH_BRIDGE_UNSET\"".to_owned(),
                cwd: None,
                shell: RunShell::Login,
                timeout_ms: None,
                stdin: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.exit_status, 0);
    assert_eq!(result.stdout.head.value, "<>");
}

#[tokio::test]
#[ignore = "strict physical-root pinning is not part of the default trusted-server mode"]
async fn same_physical_path_with_a_new_directory_identity_blocks_mutation() {
    let container = tempfile::TempDir::new().unwrap();
    let root = container.path().join("root");
    let old = container.path().join("old-root");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("value"), b"old\n").unwrap();
    let (_runtime, _runner, bridge) = fixture(&root, false);
    bridge
        .read(
            ReadRequest {
                host: "dev".to_owned(),
                paths: vec!["value".to_owned()],
                start_line: None,
                max_lines: None,
                max_bytes: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    std::fs::rename(&root, &old).unwrap();
    std::fs::create_dir(&root).unwrap();

    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "blocked".to_owned(),
                content: "payload".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::WriteConflict, "{error:?}");
    assert_eq!(error.details.mutation_may_have_applied, Some(false));
    assert!(!old.join("blocked").exists());
    assert!(!root.join("blocked").exists());
}

#[test]
fn task4_request_and_result_shapes_are_closed_and_serializable() {
    let read = ReadRequest {
        host: "dev".to_owned(),
        paths: vec!["a".to_owned()],
        start_line: None,
        max_lines: None,
        max_bytes: None,
    };
    assert_eq!(read.start_line, None);
    let _ = ListRequest {
        host: "dev".to_owned(),
        path: None,
        depth: None,
        include_hidden: None,
        max_entries: None,
    };
    let _ = StatRequest {
        host: "dev".to_owned(),
        paths: vec![],
    };
    let _ = SearchRequest {
        host: "dev".to_owned(),
        query: "x".to_owned(),
        path: None,
        globs: vec![],
        max_results: None,
        binary: None,
    };

    let hosts = HostsResult {
        hosts: vec![HostInfo {
            host: "dev".to_owned(),
        }],
    };
    assert_eq!(
        serde_json::to_value(hosts).unwrap(),
        serde_json::json!({"hosts":[{"host":"dev"}]})
    );

    let list = ListResult {
        context: context(),
        actual_path: value("/root"),
        relative_path: value(""),
        entries: vec![ListEntry {
            actual_path: value("/root/a"),
            relative_path: value("a"),
            metadata: metadata(),
        }],
        truncated: false,
    };
    assert_eq!(
        serde_json::to_value(list).unwrap()["shell"]["version"],
        serde_json::Value::Null
    );

    let stat = StatResult {
        context: context(),
        entries: vec![
            StatEntry::Success {
                actual_path: value("/root/a"),
                relative_path: value("a"),
                metadata: metadata(),
            },
            StatEntry::Error {
                actual_path: value("/root/b"),
                relative_path: value("b"),
                error: EntryError {
                    code: EntryErrorCode::NotFound,
                    message: "remote path was not found",
                },
            },
        ],
    };
    let stat_json = serde_json::to_value(stat).unwrap();
    assert_eq!(stat_json["entries"][0]["status"], "success");
    assert_eq!(stat_json["entries"][1]["error"]["code"], "NOT_FOUND");

    let read_result = ReadResult {
        context: context(),
        files: vec![ReadEntry::Success {
            actual_path: value("/root/a"),
            relative_path: value("a"),
            content: value("abc"),
            raw_bytes: 3,
            sha256: "0".repeat(64),
            truncated_before: false,
            truncated_after: false,
            truncated: false,
        }],
        returned_raw_bytes: 3,
    };
    assert_eq!(
        serde_json::to_value(read_result).unwrap()["files"][0]["status"],
        "success"
    );

    let search = SearchResult {
        context: context(),
        engine: SearchEngine::Rg,
        matches: vec![SearchMatch {
            actual_path: value("/root/a"),
            relative_path: value("a"),
            line: 1,
            column: 2,
            content: value("abc"),
        }],
        truncated: false,
    };
    assert_eq!(serde_json::to_value(search).unwrap()["engine"], "rg");

    let page = OutputReadResult {
        provenance: RetentionProvenance::Remote(context()),
        stream: StreamKind::Stdout,
        offset: 0,
        next_offset: 3,
        eof: true,
        data: value("abc"),
    };
    assert_eq!(serde_json::to_value(page).unwrap()["stream"], "stdout");

    let error = BridgeError::new(
        ErrorCode::ReadConflict,
        "remote file changed while being read",
        false,
    );
    assert_eq!(
        serde_json::to_value(error).unwrap()["code"],
        "READ_CONFLICT"
    );
}

#[test]
fn task5_write_result_shape_and_unknown_error_are_closed() {
    let create = WriteRequest {
        host: "dev".to_owned(),
        path: "a".to_owned(),
        content: "abc".to_owned(),
        encoding: WriteEncoding::Utf8,
        mode: WriteMode::Create,
    };
    assert_eq!(create.path, "a");
    let replace = WriteRequest {
        host: "dev".to_owned(),
        path: "a".to_owned(),
        content: "YWJj".to_owned(),
        encoding: WriteEncoding::Base64,
        mode: WriteMode::Replace {
            expected_sha256: Some("0".repeat(64)),
        },
    };
    assert!(matches!(replace.mode, WriteMode::Replace { .. }));

    let result = WriteResult {
        context: context(),
        actual_path: value("/root/a"),
        relative_path: value("a"),
        operation: WriteOperation::Replace,
        raw_bytes: 3,
        sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_owned(),
        mode: 0o640,
        temporary_cleanup_confirmed: true,
    };
    assert_eq!(
        serde_json::to_value(result).unwrap(),
        serde_json::json!({
            "remote": true,
            "host": "dev",
            "physical_root": "/physical/root",
            "shell": {"kind": "sh", "version": null, "fallback": false},
            "actual_path": {"encoding": "utf8", "value": "/root/a"},
            "relative_path": {"encoding": "utf8", "value": "a"},
            "operation": "replace",
            "raw_bytes": 3,
            "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "mode": 416,
            "temporary_cleanup_confirmed": true
        })
    );

    let mut error = BridgeError::new(
        ErrorCode::MutationOutcomeUnknown,
        "remote mutation outcome could not be confirmed",
        false,
    );
    error.details.mutation_may_have_applied = Some(true);
    assert_eq!(
        serde_json::to_value(error).unwrap(),
        serde_json::json!({
            "code": "MUTATION_OUTCOME_UNKNOWN",
            "message": "remote mutation outcome could not be confirmed",
            "retryable": false,
            "details": {"mutation_may_have_applied": true}
        })
    );
}

#[test]
fn task6_request_result_and_error_progress_shapes_are_closed() {
    let request = ApplyPatchRequest {
        host: "dev".to_owned(),
        patch: "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n".to_owned(),
    };
    assert_eq!(request.host, "dev");

    let result = ApplyPatchResult {
        context: context(),
        changed_paths: vec!["a".to_owned()],
    };
    assert_eq!(
        serde_json::to_value(result).unwrap(),
        serde_json::json!({
            "remote": true,
            "host": "dev",
            "physical_root": "/physical/root",
            "shell": {"kind": "sh", "version": null, "fallback": false},
            "changed_paths": ["a"]
        })
    );

    let error = BridgeError {
        code: ErrorCode::WriteConflict,
        message: "patch failed".to_owned(),
        retryable: false,
        details: codex_ssh_bridge::ErrorDetails {
            failed_path: Some("b".to_owned()),
            changed_paths: Some(vec!["a".to_owned()]),
            not_changed_paths: Some(vec!["b".to_owned(), "c".to_owned()]),
            outcome_unknown_paths: Some(Vec::new()),
            ..Default::default()
        },
    };
    let json = serde_json::to_value(error).unwrap();
    assert_eq!(json["details"]["failed_path"], "b");
    assert_eq!(json["details"]["changed_paths"], serde_json::json!(["a"]));
    assert_eq!(
        json["details"]["not_changed_paths"],
        serde_json::json!(["b", "c"])
    );
    assert_eq!(
        json["details"]["outcome_unknown_paths"],
        serde_json::json!([])
    );
}

#[tokio::test]
async fn task6_preparse_rejection_has_no_progress_details() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    let error = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: "GIT binary patch\n".to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(error.details.failed_path, None);
    assert_eq!(error.details.changed_paths, None);
    assert_eq!(error.details.not_changed_paths, None);
    assert_eq!(error.details.outcome_unknown_paths, None);
}

#[tokio::test]
async fn task6_postparse_prepared_mutations_execute_after_local_validation() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a"), b"old\n").unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    let result = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: concat!(
                    "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n",
                    "--- /dev/null\n+++ b/b\n@@ -0,0 +1 @@\n+new\n",
                )
                .to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.changed_paths, vec!["a".to_owned(), "b".to_owned()]);
    assert_eq!(std::fs::read(remote.path().join("a")).unwrap(), b"new\n");
    assert_eq!(std::fs::read(remote.path().join("b")).unwrap(), b"new\n");
}

#[tokio::test]
async fn task6_preparation_snapshots_every_base_before_any_output_failure_or_mutation() {
    let remote = tempfile::TempDir::new().unwrap();
    let mut large = b"old\n".to_vec();
    large.extend(std::iter::repeat_n(b'x', 1024 * 1024 + 257));
    std::fs::write(remote.path().join("large"), &large).unwrap();
    std::fs::write(remote.path().join("second"), b"actual\n").unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned())],
    );

    let error = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: concat!(
                    "--- a/large\n+++ b/large\n@@ -1 +1 @@\n-old\n+new\n",
                    "--- a/second\n+++ b/second\n@@ -1 +1 @@\n-wrong\n+new\n",
                )
                .to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.code, ErrorCode::WriteConflict);
    assert_eq!(error.details.failed_path.as_deref(), Some("second"));
    assert_eq!(error.details.changed_paths, Some(Vec::new()));
    assert_eq!(
        error.details.not_changed_paths,
        Some(vec!["large".to_owned(), "second".to_owned()])
    );
    assert_eq!(error.details.outcome_unknown_paths, Some(Vec::new()));
    assert_eq!(phase_log(&phases), ["S", "S"]);
    assert_eq!(std::fs::read(remote.path().join("large")).unwrap(), large);
    assert_eq!(
        std::fs::read(remote.path().join("second")).unwrap(),
        b"actual\n"
    );
}

#[tokio::test]
async fn task6_snapshot_rejects_final_symlinks_and_special_files_without_mutation() {
    use std::os::unix::fs::symlink;

    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("outside"), b"outside\n").unwrap();
    symlink("outside", remote.path().join("link")).unwrap();
    symlink("missing-outside", remote.path().join("dangling")).unwrap();
    std::fs::create_dir(remote.path().join("directory")).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(remote.path().join("fifo"))
            .status()
            .unwrap()
            .success()
    );
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned())],
    );

    for name in ["link", "dangling", "directory", "fifo"] {
        let error = bridge
            .apply_patch(
                ApplyPatchRequest {
                    host: "dev".to_owned(),
                    patch: format!("--- a/{name}\n+++ b/{name}\n@@ -1 +1 @@\n-old\n+new\n"),
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::WriteConflict, "name={name}");
        assert_eq!(error.details.failed_path.as_deref(), Some(name));
        assert_eq!(error.details.changed_paths, Some(Vec::new()));
        assert_eq!(error.details.not_changed_paths, Some(vec![name.to_owned()]));
        assert_eq!(error.details.outcome_unknown_paths, Some(Vec::new()));
    }
    assert_eq!(phase_log(&phases), ["S", "S", "S", "S"]);
    assert_eq!(
        std::fs::read(remote.path().join("outside")).unwrap(),
        b"outside\n"
    );
}

#[tokio::test]
async fn task6_snapshot_detects_identity_drift_before_preparation_completes() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("race"), b"old\n").unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let count = controls.path().join("stat-count");
    let shim = tempfile::TempDir::new().unwrap();
    write_executable(
        &shim.path().join("stat"),
        format!(
            "#!/bin/sh\nlast=\nfor last do :; done\nif [ \"$last\" = ./race ]; then marker={}; count=$(/usr/bin/cat \"$marker\" 2>/dev/null || printf 0); count=$((count + 1)); printf %s \"$count\" >\"$marker\"; if [ \"$count\" -eq 1 ]; then printf '8180:0:600:4:1:2:1\\n'; else printf '8180:0:600:4:1:3:1\\n'; fi; exit 0; fi\nexec /usr/bin/stat \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(count.to_str().unwrap()).unwrap()
        ),
    );
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("PATH", path),
            ("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned()),
        ],
    );
    let error = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: "--- a/race\n+++ b/race\n@@ -1 +1 @@\n-old\n+new\n".to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ReadConflict);
    assert_eq!(error.details.failed_path.as_deref(), Some("race"));
    assert_eq!(phase_log(&phases), ["S"]);
    assert_eq!(std::fs::read(remote.path().join("race")).unwrap(), b"old\n");
}

#[tokio::test]
async fn task6_snapshot_detects_hash_drift_before_preparation_completes() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("race"), b"old\n").unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let count = controls.path().join("dd-count");
    let shim = tempfile::TempDir::new().unwrap();
    write_executable(
        &shim.path().join("dd"),
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" if=./race \"*) marker={}; count=$(/usr/bin/cat \"$marker\" 2>/dev/null || printf 0); count=$((count + 1)); printf %s \"$count\" >\"$marker\"; /usr/bin/dd \"$@\"; status=$?; if [ \"$count\" -eq 2 ]; then printf 'new\\n' >./race; fi; exit \"$status\";; esac\nexec /usr/bin/dd \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(count.to_str().unwrap()).unwrap()
        ),
    );
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("PATH", path),
            ("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned()),
        ],
    );
    let error = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: "--- a/race\n+++ b/race\n@@ -1 +1 @@\n-old\n+new\n".to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ReadConflict);
    assert_eq!(error.details.failed_path.as_deref(), Some("race"));
    assert_eq!(phase_log(&phases), ["S"]);
}

#[tokio::test]
async fn task6_snapshot_malformed_closed_metadata_is_protocol_error_with_known_progress() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("target"), b"old\n").unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned()),
            ("FAKE_SSH_LOCAL_FIXED_POST", OsString::from("stderr")),
        ],
    );
    let error = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: "--- a/target\n+++ b/target\n@@ -1 +1 @@\n-old\n+new\n".to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ProtocolError);
    assert_eq!(error.details.failed_path.as_deref(), Some("target"));
    assert_eq!(error.details.changed_paths, Some(Vec::new()));
    assert_eq!(
        error.details.not_changed_paths,
        Some(vec!["target".to_owned()])
    );
    assert_eq!(error.details.outcome_unknown_paths, Some(Vec::new()));
    assert_eq!(phase_log(&phases), ["S"]);
}

#[tokio::test]
async fn task6_snapshot_oversized_stderr_metadata_is_protocol_error() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("target"), b"old\n").unwrap();
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("FAKE_SSH_FIXED_SLEEP_SECONDS", OsString::from("0.01")),
            ("FAKE_SSH_FIXED_STDERR_BYTES", OsString::from("1025")),
        ],
    );
    let error = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: "--- a/target\n+++ b/target\n@@ -1 +1 @@\n-old\n+new\n".to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ProtocolError);
    assert_eq!(error.details.failed_path.as_deref(), Some("target"));
}

#[tokio::test]
async fn task6_snapshot_capability_mismatch_with_stdout_is_not_retried() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("target"), b"old\n").unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let mismatch = controls.path().join("mismatch");
    let ssh_log = controls.path().join("ssh");
    let phases = controls.path().join("phases");
    let (runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("FAKE_SSH_MISMATCH_FILE", mismatch.as_os_str().to_owned()),
            ("FAKE_SSH_MISMATCH_KEY", OsString::from("safe_write")),
            ("FAKE_SSH_MISMATCH_STDOUT", OsString::from("raw")),
            ("FAKE_SSH_LOG", ssh_log.as_os_str().to_owned()),
            ("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned()),
        ],
    );
    let error = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: "--- a/target\n+++ b/target\n@@ -1 +1 @@\n-old\n+new\n".to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ProtocolError);
    assert_eq!(ssh_call_count(&ssh_log, "P"), 1);
    assert_eq!(ssh_call_count(&ssh_log, "C"), 1);
    assert_eq!(phase_log(&phases), ["S"]);
    assert_eq!(
        spool_file_count(&runtime.path().join("codex-ssh-bridge")),
        0
    );
}

#[tokio::test]
async fn task6_snapshot_cancel_and_abort_remove_internal_spools() {
    async fn wait_for_spools(directory: &std::path::Path, expected: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if spool_file_count(directory) == expected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    let patch = "--- a/target\n+++ b/target\n@@ -1 +1 @@\n-old\n+new\n";
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("target"), b"old\n").unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let ready = controls.path().join("first-ready");
    let (runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("FAKE_SSH_FIXED_SLEEP_SECONDS", OsString::from("30")),
            ("FAKE_SSH_FIXED_READY_FILE", ready.as_os_str().to_owned()),
        ],
    );
    let runtime_directory = runtime.path().join("codex-ssh-bridge");
    let cancel = CancellationToken::new();
    let child_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        bridge
            .apply_patch(
                ApplyPatchRequest {
                    host: "dev".to_owned(),
                    patch: patch.to_owned(),
                },
                child_cancel,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while !ready.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    cancel.cancel();
    let error = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert_eq!(error.details.changed_paths, Some(Vec::new()));
    assert_eq!(
        error.details.not_changed_paths,
        Some(vec!["target".to_owned()])
    );
    wait_for_spools(&runtime_directory, 0).await;

    let controls = tempfile::TempDir::new().unwrap();
    let ready = controls.path().join("second-ready");
    let (runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("FAKE_SSH_FIXED_SLEEP_SECONDS", OsString::from("30")),
            ("FAKE_SSH_FIXED_READY_FILE", ready.as_os_str().to_owned()),
        ],
    );
    let runtime_directory = runtime.path().join("codex-ssh-bridge");
    let task = tokio::spawn(async move {
        bridge
            .apply_patch(
                ApplyPatchRequest {
                    host: "dev".to_owned(),
                    patch: patch.to_owned(),
                },
                CancellationToken::new(),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while !ready.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    wait_for_spools(&runtime_directory, 0).await;
}

#[tokio::test]
async fn task6_five_concurrent_large_snapshots_bound_rss_and_spools() {
    const HOSTS: usize = 5;
    const RSS_DELTA_CEILING_KIB: u64 = 64 * 1024;

    let remote = tempfile::TempDir::new().unwrap();
    let base = b"x\n".repeat(512 * 1024 + 1);
    for index in 0..HOSTS {
        std::fs::write(remote.path().join(format!("target-{index}")), &base).unwrap();
    }
    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let runtime_directory = runtime.directory().to_owned();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let mut config = support::config_with_host("host-0", remote.path().to_str().unwrap());
    let profile = config.hosts.get("host-0").unwrap().clone();
    for index in 1..HOSTS {
        config
            .hosts
            .insert(format!("host-{index}"), profile.clone());
    }
    let environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (OsString::from("FAKE_SSH_ROOT"), OsString::from("/")),
        (
            OsString::from("FAKE_SSH_FIXED_SLEEP_SECONDS"),
            OsString::from("0.2"),
        ),
    ]);
    let runner = Arc::new(
        SshRunner::with_executable(
            Arc::new(config),
            runtime,
            store,
            support::fake_ssh_path(),
            environment,
        )
        .unwrap(),
    );
    let bridge = Arc::new(FixtureBridge::new(
        RemoteBridge::new_immediate_for_transport_tests(runner),
        remote.path(),
    ));
    let baseline_rss = resident_kib();
    let stop = CancellationToken::new();
    let monitor_stop = stop.clone();
    let observed = Arc::new(std::sync::Mutex::new((baseline_rss, 0usize)));
    let monitor_observed = Arc::clone(&observed);
    let monitor_directory = runtime_directory.clone();
    let monitor = tokio::spawn(async move {
        loop {
            {
                let mut sample = monitor_observed.lock().unwrap();
                sample.0 = sample.0.max(resident_kib());
                sample.1 = sample.1.max(spool_file_count(&monitor_directory));
            }
            tokio::select! {
                biased;
                () = monitor_stop.cancelled() => break,
                () = tokio::time::sleep(Duration::from_millis(2)) => {}
            }
        }
    });

    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..HOSTS {
        let bridge = Arc::clone(&bridge);
        tasks.spawn(async move {
            bridge
                .apply_patch(
                    ApplyPatchRequest {
                        host: format!("host-{index}"),
                        patch: format!(
                            "--- a/target-{index}\n+++ b/target-{index}\n@@ -1 +1 @@\n-x\n+y\n"
                        ),
                    },
                    CancellationToken::new(),
                )
                .await
                .unwrap()
        });
    }
    while let Some(result) = tasks.join_next().await {
        assert_eq!(result.unwrap().changed_paths.len(), 1);
    }
    stop.cancel();
    monitor.await.unwrap();
    let (peak_rss, peak_spools) = *observed.lock().unwrap();
    let rss_delta = peak_rss.saturating_sub(baseline_rss);
    eprintln!(
        "task6 snapshot RSS sample: baseline={baseline_rss} KiB peak={peak_rss} KiB delta={rss_delta} KiB peak_spools={peak_spools}"
    );
    assert!(peak_spools <= HOSTS * 2, "peak_spools={peak_spools}");
    assert!(peak_spools > 0, "no internal output spool was observed");
    assert!(
        rss_delta < RSS_DELTA_CEILING_KIB,
        "baseline={baseline_rss} peak={peak_rss} delta={rss_delta}"
    );
    assert_eq!(spool_file_count(&runtime_directory), 0);
}

#[tokio::test]
async fn task6_snapshot_parent_classification_is_bounded_to_thirty_two_ancestors() {
    let remote = tempfile::TempDir::new().unwrap();
    let requested = (0..40)
        .map(|index| format!("missing-{index}"))
        .chain(std::iter::once("target".to_owned()))
        .collect::<Vec<_>>()
        .join("/");
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let count = controls.path().join("ancestor-count");
    let shim = tempfile::TempDir::new().unwrap();
    write_executable(
        &shim.path().join("stat"),
        format!(
            "#!/bin/sh\nlast=\nfor last do :; done\ncase \"$last\" in */missing-*) case \" $* \" in *\" -L \"*) ;; *) marker={}; count=$(/usr/bin/cat \"$marker\" 2>/dev/null || printf 0); count=$((count + 1)); printf %s \"$count\" >\"$marker\";; esac;; esac\nexec /usr/bin/stat \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(count.to_str().unwrap()).unwrap()
        ),
    );
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("PATH", path),
            ("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned()),
        ],
    );
    let error = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: format!("--- a/{requested}\n+++ b/{requested}\n@@ -1 +1 @@\n-old\n+new\n"),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RemoteExit);
    assert_eq!(std::fs::read_to_string(count).unwrap(), "32");
    assert_eq!(
        error.details.failed_path.as_deref(),
        Some(requested.as_str())
    );
    assert_eq!(phase_log(&phases), ["S"]);
}

#[tokio::test]
async fn task6_snapshot_semantic_sentinel_requires_the_exact_nofollow_forms() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("target"), b"old\n").unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let shim = tempfile::TempDir::new().unwrap();
    write_executable(
        &shim.path().join("stat"),
        b"#!/bin/sh\ncase \" $* \" in *\" -L --printf=%f:%u:%a:%s:%d:%i:%h\\n -- \"*codex-sentinel-patch-snapshot*/parent-link*) printf '41c0:0:700:0:1:2:1:extra\\n'; exit 0;; esac\nexec /usr/bin/stat \"$@\"\n",
    );
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("PATH", path),
            ("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned()),
        ],
    );
    let error = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: "--- a/target\n+++ b/target\n@@ -1 +1 @@\n-old\n+new\n".to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RemoteCapabilityMissing);
    assert_eq!(error.details.failed_path.as_deref(), Some("target"));
    assert_eq!(phase_log(&phases), ["S", "S"]);
    assert_eq!(
        std::fs::read(remote.path().join("target")).unwrap(),
        b"old\n"
    );
}

#[tokio::test]
async fn task6_snapshot_accepts_exact_write_limit_rejects_plus_one_and_cleans_spools() {
    let remote = tempfile::TempDir::new().unwrap();
    let exact = b"x\n".repeat(codex_ssh_bridge::MAX_WRITE_BYTES / 2);
    let mut plus_one = exact.clone();
    plus_one.push(b'x');
    std::fs::write(remote.path().join("exact"), &exact).unwrap();
    std::fs::write(remote.path().join("plus-one"), &plus_one).unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let (runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned())],
    );

    let exact_result = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: "--- a/exact\n+++ b/exact\n@@ -1 +1 @@\n-x\n+y\n".to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(exact_result.changed_paths, ["exact".to_owned()]);

    let plus_one_error = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: "--- a/plus-one\n+++ b/plus-one\n@@ -1 +1 @@\n-x\n+y\n".to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(plus_one_error.code, ErrorCode::RequestTooLarge);
    assert_eq!(
        plus_one_error.details.failed_path.as_deref(),
        Some("plus-one")
    );
    assert_eq!(phase_log(&phases), ["S", "M", "S"]);
    assert_eq!(
        spool_file_count(&runtime.path().join("codex-ssh-bridge")),
        0
    );
}

#[tokio::test]
async fn task6_snapshot_success_raw_maximum_plus_one_is_contract_request_too_large() {
    let remote = tempfile::TempDir::new().unwrap();
    let base = format!("{}\n", "x".repeat(255));
    std::fs::write(remote.path().join("target"), &base).unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let count = controls.path().join("dd-count");
    let shim = tempfile::TempDir::new().unwrap();
    write_executable(
        &shim.path().join("dd"),
        format!(
            "#!/bin/sh\nmatched=0\nfor argument do case \"$argument\" in if=*/target) matched=1;; esac; done\nif [ \"$matched\" -eq 1 ]; then marker={}; count=$(/usr/bin/cat \"$marker\" 2>/dev/null || printf 0); count=$((count + 1)); printf %s \"$count\" >\"$marker\"; if [ \"$count\" -eq 2 ]; then /usr/bin/dd \"$@\"; status=$?; [ \"$status\" -eq 0 ] || exit \"$status\"; printf y; exit 0; fi; fi\nexec /usr/bin/dd \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(count.to_str().unwrap()).unwrap(),
        ),
    );
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (runtime, _runner, bridge) = fixture_with_patch_policy(
        remote.path(),
        Some(256),
        None,
        false,
        &[
            ("PATH", path),
            ("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned()),
        ],
    );
    let error = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: "--- a/target\n+++ b/target\n@@ -0,0 +1 @@\n+new\n".to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RequestTooLarge, "{error:?}");
    assert_eq!(
        error.message,
        "patch base exceeds the configured write limit"
    );
    assert_eq!(error.details.failed_path.as_deref(), Some("target"));
    assert_eq!(std::fs::read_to_string(&count).unwrap(), "3");
    assert_eq!(phase_log(&phases), ["S"]);
    assert_eq!(
        spool_file_count(&runtime.path().join("codex-ssh-bridge")),
        0
    );
}

#[tokio::test]
async fn task6_preparation_preflights_every_future_mutation_frame_before_first_mutation() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        Some(32 * 1024),
        &[("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned())],
    );
    let large_output = "x".repeat(24 * 1024);
    let patch = format!(
        "--- /dev/null\n+++ b/first\n@@ -0,0 +1 @@\n+first\n--- /dev/null\n+++ b/second\n@@ -0,0 +1 @@\n+{large_output}\n"
    );
    let error = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RequestTooLarge);
    assert_eq!(error.details.failed_path.as_deref(), Some("second"));
    assert_eq!(error.details.changed_paths, Some(Vec::new()));
    assert_eq!(
        error.details.not_changed_paths,
        Some(vec!["first".to_owned(), "second".to_owned()])
    );
    assert_eq!(error.details.outcome_unknown_paths, Some(Vec::new()));
    assert_task78_fixed_context(&error, remote.path());
    assert_eq!(phase_log(&phases), ["S", "S"]);
    assert!(!remote.path().join("first").exists());
    assert!(!remote.path().join("second").exists());
}

#[tokio::test]
async fn task6_snapshot_reserves_protocol_within_the_host_output_limit() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("target"), b"old\n").unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let (_runtime, _runner, bridge) = fixture_with_patch_policy(
        remote.path(),
        None,
        Some(4096),
        false,
        &[("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned())],
    );
    let result = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: "--- a/target\n+++ b/target\n@@ -1 +1 @@\n-old\n+new\n".to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.changed_paths, ["target".to_owned()]);
    assert_eq!(phase_log(&phases), ["S", "M"]);
    assert_eq!(
        std::fs::read(remote.path().join("target")).unwrap(),
        b"new\n"
    );
}

#[tokio::test]
async fn task6_host_and_size_rejections_are_preparse_without_progress_or_ssh() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let ssh_log = controls.path().join("ssh");
    let patch = "--- /dev/null\n+++ b/a\n@@ -0,0 +1 @@\n+x\n";

    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("FAKE_SSH_LOG", ssh_log.as_os_str().to_owned())],
    );
    let invalid_host = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "missing".to_owned(),
                patch: patch.to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();

    let (_runtime, _runner, limited) = fixture_with_patch_policy(
        remote.path(),
        Some(48),
        None,
        false,
        &[("FAKE_SSH_LOG", ssh_log.as_os_str().to_owned())],
    );
    let limited = limited
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: format!("{patch}{}", " ".repeat(49)),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();

    assert_eq!(invalid_host.code, ErrorCode::InvalidConfig);
    assert_eq!(limited.code, ErrorCode::RequestTooLarge);
    for error in [invalid_host, limited] {
        assert_eq!(error.details.failed_path, None);
        assert_eq!(error.details.changed_paths, None);
        assert_eq!(error.details.not_changed_paths, None);
        assert_eq!(error.details.outcome_unknown_paths, None);
    }
    assert!(!ssh_log.exists());
}

#[tokio::test]
async fn task6_aggregate_base_and_output_budgets_accept_exact_and_reject_plus_one() {
    let remote = tempfile::TempDir::new().unwrap();
    let half = b"x\n".repeat(codex_ssh_bridge::MAX_WRITE_BYTES / 4);
    std::fs::write(remote.path().join("a"), &half).unwrap();
    std::fs::write(remote.path().join("b"), &half).unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned())],
    );

    let exact = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: concat!(
                    "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-x\n+y\n",
                    "--- a/b\n+++ b/b\n@@ -1 +1 @@\n-x\n+y\n",
                )
                .to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(exact.changed_paths, ["a".to_owned(), "b".to_owned()]);
    std::fs::write(remote.path().join("a"), &half).unwrap();
    std::fs::write(remote.path().join("b"), &half).unwrap();

    let output_plus_one = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: concat!(
                    "--- a/a\n+++ b/a\n@@ -0,0 +1 @@\n+h\n",
                    "--- a/b\n+++ b/b\n@@ -0,0 +1 @@\n+h\n",
                )
                .to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(output_plus_one.code, ErrorCode::RequestTooLarge);
    assert_eq!(output_plus_one.details.failed_path.as_deref(), Some("b"));

    let mut over_half = half.clone();
    over_half.push(b'x');
    std::fs::write(remote.path().join("b"), over_half).unwrap();
    let base_plus_one = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: concat!(
                    "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-x\n+y\n",
                    "--- a/b\n+++ b/b\n@@ -1 +1 @@\n-x\n+y\n",
                )
                .to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(base_plus_one.code, ErrorCode::RequestTooLarge);
    assert_eq!(base_plus_one.details.failed_path.as_deref(), Some("b"));
    assert_eq!(phase_log(&phases), ["S", "S", "M", "M", "S", "S", "S", "S"]);
}

#[tokio::test]
async fn task6_pre_cancel_is_zero_phase_with_every_path_known_not_changed() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a"), b"old\n").unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned())],
    );
    let cancel = CancellationToken::new();
    cancel.cancel();
    let error = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n".to_owned(),
            },
            cancel,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert_eq!(error.details.failed_path, None);
    assert_eq!(error.details.changed_paths, Some(Vec::new()));
    assert_eq!(error.details.not_changed_paths, Some(vec!["a".to_owned()]));
    assert_eq!(error.details.outcome_unknown_paths, Some(Vec::new()));
    assert_eq!(error.details.mutation_may_have_applied, None);
    assert_eq!(phase_log(&phases), Vec::<String>::new());
}

#[tokio::test]
async fn task6_snapshot_raw_read_partial_failure_is_closed_read_conflict() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("race"), b"old\n").unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let count = controls.path().join("dd-count");
    let shim = tempfile::TempDir::new().unwrap();
    write_executable(
        &shim.path().join("dd"),
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" if=./race bs=262144 status=none iflag=nofollow \"*) marker={}; count=$(/usr/bin/cat \"$marker\" 2>/dev/null || printf 0); count=$((count + 1)); printf %s \"$count\" >\"$marker\"; if [ \"$count\" -eq 2 ]; then printf partial; exit 9; fi;; esac\nexec /usr/bin/dd \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(count.to_str().unwrap()).unwrap(),
        ),
    );
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("PATH", path),
            ("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned()),
        ],
    );
    let error = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: "--- a/race\n+++ b/race\n@@ -1 +1 @@\n-old\n+new\n".to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ReadConflict);
    assert_ne!(error.code, ErrorCode::RemoteExit);
    assert_ne!(error.code, ErrorCode::ProtocolError);
    assert_eq!(error.details.failed_path.as_deref(), Some("race"));
    assert_eq!(phase_log(&phases), ["S"]);
    assert_eq!(std::fs::read_to_string(&count).unwrap(), "2");
    assert_eq!(std::fs::read(remote.path().join("race")).unwrap(), b"old\n");
    assert_eq!(
        spool_file_count(&runtime.path().join("codex-ssh-bridge")),
        0
    );
}

#[tokio::test]
async fn task6_snapshot_output_limit_mapping_preserves_runner_metadata() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("target"), b"old\n").unwrap();
    let (_runtime, _runner, bridge) = fixture_with_patch_policy(
        remote.path(),
        None,
        Some(4096),
        false,
        &[
            ("FAKE_SSH_FIXED_SLEEP_SECONDS", OsString::from("1")),
            ("FAKE_SSH_FIXED_STDOUT_BYTES", OsString::from("4097")),
        ],
    );
    let error = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: "--- a/target\n+++ b/target\n@@ -1 +1 @@\n-old\n+new\n".to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RequestTooLarge);
    assert_eq!(error.details.host.as_deref(), Some("dev"));
    assert!(error.details.elapsed_ms.is_some());
    assert!(error.details.bytes_seen.is_some_and(|bytes| bytes > 0));
    assert_eq!(error.details.remote_process_may_continue, Some(true));
    assert_eq!(error.details.failed_path.as_deref(), Some("target"));
}

#[tokio::test]
async fn task6_snapshot_types_unreadable_and_special_mode_bases_without_mutation() {
    let remote = tempfile::TempDir::new().unwrap();
    let unreadable = remote.path().join("unreadable");
    let special = remote.path().join("special");
    std::fs::write(&unreadable, b"old\n").unwrap();
    std::fs::write(&special, b"old\n").unwrap();
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
    std::fs::set_permissions(&special, std::fs::Permissions::from_mode(0o4600)).unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned())],
    );
    for (name, expected) in [
        ("unreadable", ErrorCode::PermissionDenied),
        ("special", ErrorCode::WriteConflict),
    ] {
        let error = bridge
            .apply_patch(
                ApplyPatchRequest {
                    host: "dev".to_owned(),
                    patch: format!("--- a/{name}\n+++ b/{name}\n@@ -1 +1 @@\n-old\n+new\n"),
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, expected, "name={name}");
    }
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&special, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(phase_log(&phases), ["S", "S"]);
}

#[tokio::test]
#[ignore = "strict physical-root pinning is not part of the default trusted-server mode"]
async fn task6_second_snapshot_reprobe_physical_root_drift_is_zero_mutation_conflict() {
    use std::os::unix::fs::symlink;

    let container = tempfile::TempDir::new().unwrap();
    let first_root = container.path().join("root-one");
    let second_root = container.path().join("root-two");
    let active_root = container.path().join("active");
    std::fs::create_dir(&first_root).unwrap();
    std::fs::create_dir(&second_root).unwrap();
    for root in [&first_root, &second_root] {
        std::fs::write(root.join("a"), b"old\n").unwrap();
        std::fs::write(root.join("b"), b"old\n").unwrap();
    }
    symlink(&first_root, &active_root).unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let count = controls.path().join("sentinel-count");
    let shim = tempfile::TempDir::new().unwrap();
    write_executable(
        &shim.path().join("stat"),
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" -L --printf=%f:%u:%a:%s:%d:%i:%h\\n -- \"*codex-sentinel-patch-snapshot*/parent-link*) marker={}; count=$(/usr/bin/cat \"$marker\" 2>/dev/null || printf 0); count=$((count + 1)); printf %s \"$count\" >\"$marker\"; if [ \"$count\" -eq 2 ]; then /usr/bin/ln -sfn -- {} {}; printf '41c0:0:700:0:1:2:1:extra\\n'; exit 0; fi;; esac\nexec /usr/bin/stat \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(count.to_str().unwrap()).unwrap(),
            codex_ssh_bridge::quote::shell_word(second_root.to_str().unwrap()).unwrap(),
            codex_ssh_bridge::quote::shell_word(active_root.to_str().unwrap()).unwrap(),
        ),
    );
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        &active_root,
        false,
        None,
        &[
            ("PATH", path),
            ("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned()),
        ],
    );
    let error = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: concat!(
                    "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n",
                    "--- a/b\n+++ b/b\n@@ -1 +1 @@\n-old\n+new\n",
                )
                .to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ReadConflict);
    assert_eq!(error.details.failed_path.as_deref(), Some("b"));
    assert_task78_fixed_context(&error, &second_root);
    assert_eq!(phase_log(&phases), ["S", "S"]);
    assert_eq!(std::fs::read(first_root.join("a")).unwrap(), b"old\n");
    assert_eq!(std::fs::read(second_root.join("b")).unwrap(), b"old\n");
}

#[tokio::test]
async fn task6_prepared_create_update_delete_execute_in_patch_order() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("update"), b"old\n").unwrap();
    std::fs::write(remote.path().join("delete"), b"gone\n").unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned())],
    );

    let result = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: concat!(
                    "--- /dev/null\n+++ b/create\n@@ -0,0 +1 @@\n+created\n",
                    "--- a/update\n+++ b/update\n@@ -1 +1 @@\n-old\n+updated\n",
                    "--- a/delete\n+++ /dev/null\n@@ -1 +0,0 @@\n-gone\n",
                )
                .to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(
        result.changed_paths,
        ["create", "update", "delete"].map(str::to_owned)
    );
    assert_eq!(result.context.host, "dev");
    assert_eq!(phase_log(&phases), ["S", "S", "S", "M", "M", "M"]);
    assert_eq!(
        std::fs::read(remote.path().join("create")).unwrap(),
        b"created\n"
    );
    assert_eq!(
        std::fs::read(remote.path().join("update")).unwrap(),
        b"updated\n"
    );
    assert!(!remote.path().join("delete").exists());
}

#[tokio::test]
async fn task6_prepared_update_uses_the_complete_base_above_public_read_limit() {
    let remote = tempfile::TempDir::new().unwrap();
    let base = b"x\n".repeat(600_000);
    assert!(base.len() > 1024 * 1024);
    std::fs::write(remote.path().join("large"), &base).unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned())],
    );

    let result = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: "--- a/large\n+++ b/large\n@@ -1 +1 @@\n-x\n+y\n".to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();

    let output = std::fs::read(remote.path().join("large")).unwrap();
    assert_eq!(result.changed_paths, ["large".to_owned()]);
    assert_eq!(output.len(), base.len());
    assert_eq!(&output[..4], b"y\nx\n");
    assert_eq!(phase_log(&phases), ["S", "M"]);
}

#[tokio::test]
async fn task6_update_to_empty_is_a_guarded_replace_not_a_delete() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("empty"), b"old\n").unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned())],
    );

    let result = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: "--- a/empty\n+++ b/empty\n@@ -1 +0,0 @@\n-old\n".to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(result.changed_paths, ["empty".to_owned()]);
    assert!(remote.path().join("empty").is_file());
    assert_eq!(std::fs::read(remote.path().join("empty")).unwrap(), b"");
    assert_eq!(phase_log(&phases), ["S", "M"]);
}

#[tokio::test]
async fn task6_second_definite_failure_reports_confirmed_prefix_and_stops_suffix() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a"), b"old\n").unwrap();
    std::fs::write(remote.path().join("b"), b"gone\n").unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let shim = tempfile::TempDir::new().unwrap();
    write_executable(
        &shim.path().join("mv"),
        "#!/bin/sh\ntarget=\nfor argument do target=$argument; done\n/usr/bin/mv \"$@\"\nstatus=$?\nif [ \"$status\" -eq 0 ] && [ \"$target\" = ./a ]; then printf raced >./b; fi\nexit \"$status\"\n",
    );
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("PATH", path),
            ("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned()),
        ],
    );

    let error = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: concat!(
                    "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n",
                    "--- a/b\n+++ /dev/null\n@@ -1 +0,0 @@\n-gone\n",
                    "--- /dev/null\n+++ b/c\n@@ -0,0 +1 @@\n+later\n",
                )
                .to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.code, ErrorCode::WriteConflict, "{error:?}");
    assert_eq!(error.details.failed_path.as_deref(), Some("b"));
    assert_eq!(error.details.changed_paths, Some(vec!["a".to_owned()]));
    assert_eq!(
        error.details.not_changed_paths,
        Some(vec!["b".to_owned(), "c".to_owned()])
    );
    assert_eq!(error.details.outcome_unknown_paths, Some(Vec::new()));
    assert_eq!(error.details.mutation_may_have_applied, None);
    assert_eq!(phase_log(&phases), ["S", "S", "S", "M", "M"]);
    assert_eq!(std::fs::read(remote.path().join("a")).unwrap(), b"new\n");
    assert_eq!(std::fs::read(remote.path().join("b")).unwrap(), b"raced");
    assert!(!remote.path().join("c").exists());
}

#[tokio::test]
async fn task6_second_malformed_postcommit_is_only_current_unknown_and_stops_suffix() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a"), b"old\n").unwrap();
    std::fs::write(remote.path().join("b"), b"gone\n").unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let shim = tempfile::TempDir::new().unwrap();
    write_executable(
        &shim.path().join("rm"),
        "#!/bin/sh\ntarget=\nfor argument do target=$argument; done\n/usr/bin/rm \"$@\"\nstatus=$?\nif [ \"$status\" -eq 0 ] && [ \"$target\" = ./b ]; then printf GARBAGE; fi\nexit \"$status\"\n",
    );
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("PATH", path),
            ("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned()),
        ],
    );

    let error = bridge
        .apply_patch(
            ApplyPatchRequest {
                host: "dev".to_owned(),
                patch: concat!(
                    "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n",
                    "--- a/b\n+++ /dev/null\n@@ -1 +0,0 @@\n-gone\n",
                    "--- /dev/null\n+++ b/c\n@@ -0,0 +1 @@\n+later\n",
                )
                .to_owned(),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown, "{error:?}");
    assert!(!error.retryable);
    assert_eq!(error.details.mutation_may_have_applied, Some(true));
    assert_eq!(error.details.failed_path.as_deref(), Some("b"));
    assert_eq!(error.details.changed_paths, Some(vec!["a".to_owned()]));
    assert_eq!(error.details.not_changed_paths, Some(vec!["c".to_owned()]));
    assert_eq!(
        error.details.outcome_unknown_paths,
        Some(vec!["b".to_owned()])
    );
    assert_eq!(phase_log(&phases), ["S", "S", "S", "M", "M"]);
    assert_eq!(std::fs::read(remote.path().join("a")).unwrap(), b"new\n");
    assert!(!remote.path().join("b").exists());
    assert!(!remote.path().join("c").exists());
}

async fn task6_assert_cached_root_drift_is_definite_conflict(delete: bool) {
    use std::os::unix::fs::symlink;

    let container = tempfile::TempDir::new().unwrap();
    let first_root = container.path().join("root-one");
    let second_root = container.path().join("root-two");
    let active_root = container.path().join("active");
    std::fs::create_dir(&first_root).unwrap();
    std::fs::create_dir(&second_root).unwrap();
    for root in [&first_root, &second_root] {
        std::fs::write(root.join("target"), b"old\n").unwrap();
    }
    symlink(&first_root, &active_root).unwrap();

    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let ssh_log = controls.path().join("ssh.log");
    let hash_count = controls.path().join("target-hash-count");
    let snapshot_ready = controls.path().join("snapshot-ready");
    let expected = controls.path().join("expected");
    let gate = controls.path().join("snapshot-gate");
    let stale_stat = controls.path().join("stale-stat");
    std::fs::write(&expected, b"old\n").unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&gate)
            .status()
            .unwrap()
            .success()
    );

    let shim = tempfile::TempDir::new().unwrap();
    write_executable(
        &shim.path().join("sha256sum"),
        format!(
            "#!/bin/sh\ndata=$(/usr/bin/mktemp) || exit 9\ntrap '/usr/bin/rm -f -- \"$data\"' 0 HUP INT TERM\n/usr/bin/cat >\"$data\" || exit 9\nif /usr/bin/cmp -s -- \"$data\" {}; then marker={}; count=$(/usr/bin/cat \"$marker\" 2>/dev/null || printf 0); count=$((count + 1)); printf %s \"$count\" >\"$marker\"; if [ \"$count\" -eq 2 ]; then : >{}; /usr/bin/cat {} >/dev/null; fi; fi\n/usr/bin/sha256sum <\"$data\"\n",
            codex_ssh_bridge::quote::shell_word(expected.to_str().unwrap()).unwrap(),
            codex_ssh_bridge::quote::shell_word(hash_count.to_str().unwrap()).unwrap(),
            codex_ssh_bridge::quote::shell_word(snapshot_ready.to_str().unwrap()).unwrap(),
            codex_ssh_bridge::quote::shell_word(gate.to_str().unwrap()).unwrap(),
        ),
    );
    write_executable(
        &shim.path().join("stat"),
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" --printf=%f -- \"*codex-sentinel-stat.*) marker={}; if [ ! -e \"$marker\" ]; then : >\"$marker\"; printf bad; exit 0; fi;; esac\nexec /usr/bin/stat \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(stale_stat.to_str().unwrap()).unwrap(),
        ),
    );
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        &active_root,
        false,
        None,
        &[
            ("PATH", path),
            ("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned()),
            ("FAKE_SSH_LOG", ssh_log.as_os_str().to_owned()),
        ],
    );
    let bridge = Arc::new(bridge);
    let patch_bridge = Arc::clone(&bridge);
    let patch = if delete {
        "--- a/target\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n"
    } else {
        "--- a/target\n+++ b/target\n@@ -1 +1 @@\n-old\n+new\n"
    };
    let task = tokio::spawn(async move {
        patch_bridge
            .apply_patch(
                ApplyPatchRequest {
                    host: "dev".to_owned(),
                    patch: patch.to_owned(),
                },
                CancellationToken::new(),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while !snapshot_ready.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("snapshot did not reach the post-read barrier");

    std::fs::remove_file(&active_root).unwrap();
    symlink(&second_root, &active_root).unwrap();
    let reprobe = bridge
        .stat(
            StatRequest {
                host: "dev".to_owned(),
                paths: vec!["target".to_owned()],
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(reprobe.context.physical_root, second_root.to_str().unwrap());
    std::fs::write(&gate, b"release").unwrap();

    let error = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("patch did not finish after releasing the snapshot")
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::WriteConflict, "{error:?}");
    assert!(!error.retryable);
    assert_eq!(error.details.mutation_may_have_applied, Some(false));
    assert_eq!(error.details.failed_path.as_deref(), Some("target"));
    assert_eq!(error.details.changed_paths, Some(Vec::new()));
    assert_eq!(
        error.details.not_changed_paths,
        Some(vec!["target".to_owned()])
    );
    assert_eq!(error.details.outcome_unknown_paths, Some(Vec::new()));
    assert_task78_fixed_context(&error, &second_root);
    assert_eq!(phase_log(&phases), ["S"]);
    assert_eq!(ssh_call_count(&ssh_log, "P"), 2);
    assert_eq!(std::fs::read(first_root.join("target")).unwrap(), b"old\n");
    assert_eq!(std::fs::read(second_root.join("target")).unwrap(), b"old\n");
}

#[tokio::test]
#[ignore = "strict physical-root pinning is not part of the default trusted-server mode"]
async fn task6_cached_root_drift_before_write_is_definite_and_changes_neither_tree() {
    task6_assert_cached_root_drift_is_definite_conflict(false).await;
}

#[tokio::test]
#[ignore = "strict physical-root pinning is not part of the default trusted-server mode"]
async fn task6_cached_root_drift_before_delete_is_definite_and_changes_neither_tree() {
    task6_assert_cached_root_drift_is_definite_conflict(true).await;
}

#[tokio::test]
async fn task6_postspawn_cancel_on_second_mutation_marks_only_current_unknown_and_cleans_up() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let phases = controls.path().join("phases");
    let ready = controls.path().join("second-ready");
    let count = controls.path().join("dd-count");
    let gate = controls.path().join("gate");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&gate)
            .status()
            .unwrap()
            .success()
    );
    let shim = tempfile::TempDir::new().unwrap();
    write_executable(
        &shim.path().join("dd"),
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" of=./.codex-ssh-bridge.\"*\" bs=262144 \"*\" oflag=nofollow \"*) marker={}; count=$(/usr/bin/cat \"$marker\" 2>/dev/null || printf 0); count=$((count + 1)); printf %s \"$count\" >\"$marker\"; if [ \"$count\" -eq 2 ]; then : >{}; exec /usr/bin/cat {}; fi;; esac\nexec /usr/bin/dd \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(count.to_str().unwrap()).unwrap(),
            codex_ssh_bridge::quote::shell_word(ready.to_str().unwrap()).unwrap(),
            codex_ssh_bridge::quote::shell_word(gate.to_str().unwrap()).unwrap(),
        ),
    );
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("PATH", path),
            ("FAKE_SSH_PHASE_LOG", phases.as_os_str().to_owned()),
            ("FAKE_SSH_MUTATION_READY_FILE", ready.as_os_str().to_owned()),
            ("FAKE_SSH_MUTATION_READY_AFTER", OsString::from("2")),
        ],
    );
    let runtime_directory = runtime.path().join("codex-ssh-bridge");
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        bridge
            .apply_patch(
                ApplyPatchRequest {
                    host: "dev".to_owned(),
                    patch: concat!(
                        "--- /dev/null\n+++ b/a\n@@ -0,0 +1 @@\n+first\n",
                        "--- /dev/null\n+++ b/b\n@@ -0,0 +1 @@\n+second\n",
                        "--- /dev/null\n+++ b/c\n@@ -0,0 +1 @@\n+third\n",
                    )
                    .to_owned(),
                },
                task_cancel,
            )
            .await
    });
    // This is only a fixture-readiness barrier. The full remote_ops suite runs
    // many process-heavy tests concurrently, so runner load must not masquerade
    // as a cancellation latency failure.
    tokio::time::timeout(Duration::from_secs(10), async {
        while !ready.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("second mutation did not reach caller staging");
    cancel.cancel();
    let error = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("cancelled patch mutation did not terminate")
        .unwrap()
        .unwrap_err();

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let has_remote_stage = std::fs::read_dir(remote.path()).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".codex-ssh-bridge.")
            });
            if !has_remote_stage && spool_file_count(&runtime_directory) == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled patch left mutation staging behind");

    assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown, "{error:?}");
    assert_eq!(error.details.mutation_may_have_applied, Some(true));
    assert_eq!(error.details.failed_path.as_deref(), Some("b"));
    assert_eq!(error.details.changed_paths, Some(vec!["a".to_owned()]));
    assert_eq!(error.details.not_changed_paths, Some(vec!["c".to_owned()]));
    assert_eq!(
        error.details.outcome_unknown_paths,
        Some(vec!["b".to_owned()])
    );
    assert_task78_fixed_context(&error, remote.path());
    assert_eq!(phase_log(&phases), ["S", "S", "S", "M", "M"]);
    assert_eq!(std::fs::read(remote.path().join("a")).unwrap(), b"first\n");
    assert!(!remote.path().join("c").exists());
}

#[tokio::test]
async fn task5_create_writes_exact_bytes_and_closed_result() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    let result = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "created.bin".to_owned(),
                content: "a\0b".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(
        std::fs::read(remote.path().join("created.bin")).unwrap(),
        b"a\0b"
    );
    assert_eq!(result.operation, WriteOperation::Create);
    assert_eq!(result.raw_bytes, 3);
    assert_eq!(
        result.sha256,
        "59b271ae1bbcb1d31d41929817f4b16fb439eb4f31520b5ad1d5ce98920a7138"
    );
    assert_eq!(result.mode, 0o600);
    assert!(result.temporary_cleanup_confirmed);
    assert_eq!(result.context.shell.kind, ShellName::Sh);
}

#[tokio::test]
async fn task5_base64_is_strict_and_oversize_preflight_launches_nothing() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("ssh.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    for (index, invalid) in ["Y Q==", "_w==", "YQ", "YR=="].into_iter().enumerate() {
        let error = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: format!("invalid-{index}"),
                    content: invalid.to_owned(),
                    encoding: WriteEncoding::Base64,
                    mode: WriteMode::Create,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument, "input={invalid:?}");
    }
    assert_eq!(ssh_call_count(&log, "G"), 0);
    assert_eq!(ssh_call_count(&log, "P"), 0);
    assert_eq!(ssh_call_count(&log, "C"), 0);

    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let mut config = support::config_with_host("dev", remote.path().to_str().unwrap());
    config.limits.max_write_bytes = 4;
    let oversize_log = runtime_base.path().join("oversize.log");
    let environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (OsString::from("FAKE_SSH_ROOT"), OsString::from("/")),
        (
            OsString::from("FAKE_SSH_LOG"),
            oversize_log.as_os_str().to_owned(),
        ),
    ]);
    let runner = Arc::new(
        SshRunner::with_executable(
            Arc::new(config),
            runtime,
            store,
            support::fake_ssh_path(),
            environment,
        )
        .unwrap(),
    );
    let bridge = FixtureBridge::new(
        RemoteBridge::new_immediate_for_transport_tests(runner),
        remote.path(),
    );
    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "oversize".to_owned(),
                content: "QUFBQUE=".to_owned(),
                encoding: WriteEncoding::Base64,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RequestTooLarge);
    assert_eq!(ssh_call_count(&oversize_log, "G"), 0);
}

#[tokio::test]
async fn task5_pre_stdin_closed_records_survive_large_input_early_close() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("exists"), b"old").unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let collision_log = controls.path().join("collision.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("FAKE_SSH_LOG", collision_log.as_os_str().to_owned())],
    );
    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "exists".to_owned(),
                content: "x".repeat(4 * 1024 * 1024),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::WriteConflict);
    assert_eq!(std::fs::read(remote.path().join("exists")).unwrap(), b"old");
    assert_eq!(ssh_call_count(&collision_log, "C"), 1);
    assert_eq!(ssh_call_count(&collision_log, "P"), 1);

    let mismatch_log = controls.path().join("mismatch.log");
    let shim = tempfile::TempDir::new().unwrap();
    let stat = shim.path().join("stat");
    std::fs::write(
        &stat,
        "#!/bin/sh\ncase \" $* \" in *codex-sentinel-safe-write*parent-link*) printf '41c0:0:700:0:1:2:1:extra\\n'; exit 0;; esac\nexec /usr/bin/stat \"$@\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&stat, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("PATH", path),
            ("FAKE_SSH_LOG", mismatch_log.as_os_str().to_owned()),
        ],
    );
    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "missing-parent/target".to_owned(),
                content: "y".repeat(4 * 1024 * 1024),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RemoteCapabilityMissing);
    assert_eq!(ssh_call_count(&mismatch_log, "C"), 1);
    assert_eq!(ssh_call_count(&mismatch_log, "P"), 1);
}

#[tokio::test]
async fn task5_stale_write_sentinel_invalidates_only_a_future_request() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("ssh.log");
    let marker = controls.path().join("mismatch-used");
    let shim = tempfile::TempDir::new().unwrap();
    let stat = shim.path().join("stat");
    std::fs::write(
        &stat,
        format!(
            "#!/bin/sh\ncase \" $* \" in *codex-sentinel-safe-write*parent-link*) marker={}; if [ ! -e \"$marker\" ]; then : >\"$marker\"; printf '41c0:0:700:0:1:2:1:extra\\n'; exit 0; fi;; esac\nexec /usr/bin/stat \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&stat, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    let first = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "first".to_owned(),
                content: "first".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(first.code, ErrorCode::RemoteCapabilityMissing);
    assert!(!remote.path().join("first").exists());
    assert_eq!(ssh_call_count(&log, "P"), 1);
    assert_eq!(ssh_call_count(&log, "C"), 1);

    let second = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "second".to_owned(),
                content: "second".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(second.operation, WriteOperation::Create);
    assert_eq!(
        std::fs::read(remote.path().join("second")).unwrap(),
        b"second"
    );
    assert_eq!(ssh_call_count(&log, "P"), 2);
    assert_eq!(ssh_call_count(&log, "C"), 2);
}

#[tokio::test]
async fn task5_missing_required_write_command_is_a_future_only_capability_mismatch() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("ssh.log");
    let marker = controls.path().join("missing-path-used");
    let empty_path = controls.path().join("empty-path");
    let scratch = controls.path().join("scratch");
    std::fs::create_dir(&empty_path).unwrap();
    std::os::unix::fs::symlink("/bin/sh", empty_path.join("sh")).unwrap();
    std::os::unix::fs::symlink("/usr/bin/stat", empty_path.join("stat")).unwrap();
    std::fs::create_dir(&scratch).unwrap();
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("FAKE_SSH_LOG", log.as_os_str().to_owned()),
            (
                "FAKE_SSH_LOCAL_FIXED_PATH_ONCE",
                empty_path.as_os_str().to_owned(),
            ),
            (
                "FAKE_SSH_LOCAL_FIXED_PATH_MARKER",
                marker.as_os_str().to_owned(),
            ),
            ("TMPDIR", scratch.as_os_str().to_owned()),
        ],
    );

    let first = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "first".to_owned(),
                content: "first payload".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(first.code, ErrorCode::RemoteCapabilityMissing);
    assert_eq!(std::fs::read_dir(remote.path()).unwrap().count(), 0);
    assert_no_dispatcher_request_artifacts(&scratch);
    assert_eq!(ssh_call_count(&log, "P"), 1);
    assert_eq!(ssh_call_count(&log, "C"), 1);

    bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "second".to_owned(),
                content: "second payload".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(remote.path().join("second")).unwrap(),
        b"second payload"
    );
    assert_eq!(ssh_call_count(&log, "P"), 2);
    assert_eq!(ssh_call_count(&log, "C"), 2);
}

#[tokio::test]
async fn task5_write_exact_form_sentinel_matrix_is_semantic_and_future_only() {
    struct Case {
        form: &'static str,
        tool: &'static str,
        rule: &'static str,
    }

    let cases = [
        Case {
            form: "parent-follow",
            tool: "stat",
            rule: r#"case " $* " in
  *" -L --printf=%f:%u:%a:%s:%d:%i:%h\n -- "*codex-sentinel-safe-write*/work/parent-link*)
    if [ ! -e "$marker" ]; then : >"$marker"; printf '41ed:0:700:0:0:0:2\n'; exit 0; fi;;
esac"#,
        },
        Case {
            form: "lstat",
            tool: "stat",
            rule: r#"case " $* " in
  *" --printf=%f:%u:%a:%s:%d:%i:%h\n -- "*codex-sentinel-safe-write*/work/.codex-ssh-bridge.*)
    if [ ! -e "$marker" ]; then : >"$marker"; printf '8180:0:600:8:0:0:1\n'; exit 0; fi;;
esac"#,
        },
        Case {
            form: "lstat-symlink-no-follow",
            tool: "stat",
            rule: r#"case " $* " in
  *" --printf=%f:%u:%a:%s:%d:%i:%h\n -- "*codex-sentinel-safe-write*/work/link*)
    if [ ! -e "$marker" ]; then : >"$marker"; printf '8180:0:600:7:0:0:1\n'; exit 0; fi;;
esac"#,
        },
        Case {
            form: "dd-output",
            tool: "dd",
            rule: r#"case " $* " in
  *codex-sentinel-safe-write*/work/.codex-ssh-bridge.*bs=262144*status=none*conv=notrunc*oflag=nofollow*)
    if [ ! -e "$marker" ]; then : >"$marker"; exec /usr/bin/dd of=/dev/null bs=262144 status=none; fi;;
esac"#,
        },
        Case {
            form: "dd-input-hash",
            tool: "dd",
            rule: r#"case " $* " in
  *codex-sentinel-safe-write*/work/.codex-ssh-bridge.*bs=262144*status=none*iflag=nofollow*)
    if [ ! -e "$marker" ]; then : >"$marker"; printf corrupt; exit 0; fi;;
esac"#,
        },
        Case {
            form: "sha256sum-hash",
            tool: "sha256sum",
            rule: r#"if [ -e "$armed" ] && [ ! -e "$marker" ]; then
  : >"$marker"
  /usr/bin/rm -f -- "$armed"
  /usr/bin/dd of=/dev/null status=none
  printf '0000000000000000000000000000000000000000000000000000000000000000  -\n'
  exit 0
fi"#,
        },
        Case {
            form: "ln",
            tool: "ln",
            rule: r#"case " $* " in
  *" -T -- "*codex-sentinel-safe-write*/work/.codex-ssh-bridge.*codex-sentinel-safe-write*/work/created*)
    destination=; for destination do :; done
    if [ -e "$destination" ] && [ ! -e "$marker" ]; then : >"$marker"; exit 0; fi;;
esac"#,
        },
        Case {
            form: "mv",
            tool: "mv",
            rule: r#"case " $* " in
  *" -T -- "*codex-sentinel-safe-write*/work/.codex-ssh-bridge.*codex-sentinel-safe-write*/work/replaced*)
    if [ ! -e "$marker" ]; then : >"$marker"; exit 0; fi;;
esac"#,
        },
        Case {
            form: "rm",
            tool: "rm",
            rule: r#"case " $* " in
  *" -f -- "*codex-sentinel-safe-write*/work/created*)
    if [ ! -e "$marker" ]; then : >"$marker"; exit 0; fi;;
esac"#,
        },
    ];

    for case in cases {
        let remote = tempfile::TempDir::new().unwrap();
        let controls = tempfile::TempDir::new().unwrap();
        let log = controls.path().join("ssh.log");
        let marker = controls.path().join("semantic-drift-used");
        let armed = controls.path().join("sentinel-hash-armed");
        let scratch = controls.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        let shim = tempfile::TempDir::new().unwrap();
        let executable = shim.path().join(case.tool);
        std::fs::write(
            &executable,
            format!(
                "#!/bin/sh\nmarker={}\narmed={}\n{}\nexec /usr/bin/{} \"$@\"\n",
                codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
                codex_ssh_bridge::quote::shell_word(armed.to_str().unwrap()).unwrap(),
                case.rule,
                case.tool,
            ),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        if case.tool == "sha256sum" {
            let stat = shim.path().join("stat");
            std::fs::write(
                &stat,
                format!(
                    "#!/bin/sh\ncase \" $* \" in *\" --printf=%f:%u:%a:%s:%d:%i:%h\\n -- \"*codex-sentinel-safe-write*/work/.codex-ssh-bridge.*) : >{};; esac\nexec /usr/bin/stat \"$@\"\n",
                    codex_ssh_bridge::quote::shell_word(armed.to_str().unwrap()).unwrap(),
                ),
            )
            .unwrap();
            std::fs::set_permissions(&stat, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path = OsString::from(format!(
            "{}:/usr/local/bin:/usr/bin:/bin",
            shim.path().display()
        ));
        let (_runtime, _runner, bridge) = fixture_with_options(
            remote.path(),
            false,
            None,
            &[
                ("PATH", path),
                ("TMPDIR", scratch.as_os_str().to_owned()),
                ("FAKE_SSH_LOG", log.as_os_str().to_owned()),
            ],
        );

        let first = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: "first".to_owned(),
                    content: "first payload".to_owned(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Create,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            first.code,
            ErrorCode::RemoteCapabilityMissing,
            "form={}",
            case.form
        );
        assert!(marker.exists(), "form={}", case.form);
        assert!(!remote.path().join("first").exists(), "form={}", case.form);
        assert_eq!(
            std::fs::read_dir(remote.path()).unwrap().count(),
            0,
            "form={}",
            case.form
        );
        assert_eq!(ssh_call_count(&log, "P"), 1, "form={}", case.form);
        assert_eq!(ssh_call_count(&log, "C"), 1, "form={}", case.form);
        assert_no_dispatcher_request_artifacts(&scratch);

        let second = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: "second".to_owned(),
                    content: "second payload".to_owned(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Create,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            second.operation,
            WriteOperation::Create,
            "form={}",
            case.form
        );
        assert_eq!(
            std::fs::read(remote.path().join("second")).unwrap(),
            b"second payload",
            "form={}",
            case.form
        );
        assert_eq!(ssh_call_count(&log, "P"), 2, "form={}", case.form);
        assert_eq!(ssh_call_count(&log, "C"), 2, "form={}", case.form);
    }
}

#[tokio::test]
async fn task5_malformed_post_child_success_is_unknown_and_never_retried() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("ssh.log");
    let shim = tempfile::TempDir::new().unwrap();
    let ln = shim.path().join("ln");
    std::fs::write(
        &ln,
        "#!/bin/sh\ncase \" $* \" in *\" ./malformed\"*) /usr/bin/ln \"$@\"; status=$?; printf GARBAGE; exit \"$status\";; esac\nexec /usr/bin/ln \"$@\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&ln, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "malformed".to_owned(),
                content: "payload".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
    assert_eq!(error.details.mutation_may_have_applied, Some(true));
    assert_eq!(ssh_call_count(&log, "C"), 1);
    assert_eq!(ssh_call_count(&log, "P"), 1);
}

#[tokio::test]
async fn task5_unknown_postcommit_transport_and_protocol_outcomes_never_retry() {
    for post in ["disconnect", "malformed", "trailing", "stderr"] {
        let remote = tempfile::TempDir::new().unwrap();
        let controls = tempfile::TempDir::new().unwrap();
        let log = controls.path().join("ssh.log");
        let (_runtime, _runner, bridge) = fixture_with_options(
            remote.path(),
            false,
            None,
            &[
                ("FAKE_SSH_LOG", log.as_os_str().to_owned()),
                ("FAKE_SSH_LOCAL_FIXED_POST", OsString::from(post)),
            ],
        );
        let error = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: post.to_owned(),
                    content: "payload".to_owned(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Create,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown, "post={post}");
        assert!(!error.retryable, "post={post}");
        assert_eq!(
            error.details.mutation_may_have_applied,
            Some(true),
            "post={post}"
        );
        assert_eq!(std::fs::read(remote.path().join(post)).unwrap(), b"payload");
        assert_eq!(ssh_call_count(&log, "C"), 1, "post={post}");
    }
}

#[tokio::test]
async fn task5_hash_command_failure_without_digest_is_unknown_not_mismatch() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("ssh.log");
    let count = controls.path().join("sha-count");
    let shim = tempfile::TempDir::new().unwrap();
    let sha = shim.path().join("sha256sum");
    std::fs::write(
        &sha,
        format!(
            "#!/bin/sh\nmarker={}\ncount=$(/usr/bin/cat \"$marker\" 2>/dev/null || printf 0)\ncount=$((count + 1))\nprintf %s \"$count\" >\"$marker\"\nif [ \"$count\" -eq 6 ]; then exit 64; fi\nexec /usr/bin/sha256sum \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(count.to_str().unwrap()).unwrap()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&sha, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "target".to_owned(),
                content: "payload".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
    assert_eq!(error.details.mutation_may_have_applied, Some(true));
    assert_eq!(std::fs::read_to_string(count).unwrap(), "6");
    assert_eq!(ssh_call_count(&log, "P"), 1);
    assert_eq!(ssh_call_count(&log, "C"), 1);
}

#[tokio::test]
async fn task5_write_local_validation_and_final_render_bound_launch_zero_processes() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("validation.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    let cases = [
        ("".to_owned(), ErrorCode::InvalidArgument),
        (".".to_owned(), ErrorCode::InvalidArgument),
        ("/".to_owned(), ErrorCode::InvalidArgument),
        (
            "../escape".to_owned(),
            ErrorCode::RemoteAbsolutePathRequired,
        ),
        (
            format!("{}/nul\0path", remote.path().display()),
            ErrorCode::InvalidArgument,
        ),
    ];
    for (path, expected) in cases {
        let error = bridge
            .inner
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: path.clone(),
                    content: String::new(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Create,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, expected, "path={path:?}");
    }
    let error = bridge
        .inner
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: format!("/{}", "x".repeat(64 * 1024 + 1)),
                content: String::new(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RequestTooLarge);
    let error = bridge
        .inner
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: remote.path().join("replace").to_string_lossy().into_owned(),
                content: "not base64".to_owned(),
                encoding: WriteEncoding::Base64,
                mode: WriteMode::Replace {
                    expected_sha256: Some("A".repeat(64)),
                },
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(ssh_call_count(&log, "G"), 0);

    let quote_log = controls.path().join("quote-frame.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        Some(32 * 1024),
        &[("FAKE_SSH_LOG", quote_log.as_os_str().to_owned())],
    );
    let error = bridge
        .inner
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: remote
                    .path()
                    .join("'".repeat(12 * 1024))
                    .to_string_lossy()
                    .into_owned(),
                content: String::new(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RequestTooLarge);
    assert_eq!(ssh_call_count(&quote_log, "G"), 0);
}

#[tokio::test]
async fn task5_create_collisions_hostile_names_empty_content_and_parent_symlink() {
    use std::os::unix::fs::symlink;

    let remote = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(remote.path().join("directory")).unwrap();
    std::fs::write(remote.path().join("referent"), b"keep").unwrap();
    symlink("referent", remote.path().join("live-link")).unwrap();
    symlink("missing", remote.path().join("dangling-link")).unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    for path in ["directory", "live-link", "dangling-link"] {
        let error = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: path.to_owned(),
                    content: "new".to_owned(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Create,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::WriteConflict, "path={path}");
    }
    assert_eq!(
        std::fs::read(remote.path().join("referent")).unwrap(),
        b"keep"
    );

    let hostile = " -quote' line\n*?[$]`$(touch SHOULD_NOT_EXIST)`-雪 ";
    let result = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: hostile.to_owned(),
                content: "a\0b".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.mode, 0o600);
    assert_eq!(std::fs::read(remote.path().join(hostile)).unwrap(), b"a\0b");
    assert!(!remote.path().join("SHOULD_NOT_EXIST").exists());

    bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "empty".to_owned(),
                content: String::new(),
                encoding: WriteEncoding::Base64,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(std::fs::read(remote.path().join("empty")).unwrap(), b"");

    let actual_parent = remote.path().join("actual-parent");
    std::fs::create_dir(&actual_parent).unwrap();
    symlink(&actual_parent, remote.path().join("parent-link")).unwrap();
    bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "parent-link/through-link".to_owned(),
                content: "linked".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(actual_parent.join("through-link")).unwrap(),
        b"linked"
    );

    for directory in [remote.path(), actual_parent.as_path()] {
        assert!(std::fs::read_dir(directory).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".codex-ssh-bridge.")
        }));
    }
}

#[tokio::test]
async fn task5_create_link_race_never_follows_a_symlink_to_an_outside_directory() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let outside = controls.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("keep"), b"unchanged").unwrap();
    let log = controls.path().join("ssh.log");
    let shim = tempfile::TempDir::new().unwrap();
    let ln = shim.path().join("ln");
    std::fs::write(
        &ln,
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" -T -- \"*\" ./target \"*) /usr/bin/rm -f -- ./target; /usr/bin/ln -s -- {} ./target;; esac\nexec /usr/bin/ln \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(outside.to_str().unwrap()).unwrap(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&ln, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );

    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "target".to_owned(),
                content: "payload".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();

    assert!(
        std::fs::symlink_metadata(remote.path().join("target"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        std::fs::read_link(remote.path().join("target")).unwrap(),
        outside
    );
    assert_eq!(
        std::fs::read(controls.path().join("outside/keep")).unwrap(),
        b"unchanged"
    );
    assert_eq!(
        std::fs::read_dir(controls.path().join("outside"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(error.code, ErrorCode::WriteConflict);
    assert_eq!(ssh_call_count(&log, "P"), 1);
    assert_eq!(ssh_call_count(&log, "C"), 1);
}

#[tokio::test]
async fn task5_parent_identity_race_fails_before_staging() {
    use std::os::unix::fs::symlink;

    let remote = tempfile::TempDir::new().unwrap();
    let old_parent = remote.path().join("old-parent");
    let new_parent = remote.path().join("new-parent");
    let parent_link = remote.path().join("parent-link");
    std::fs::create_dir(&old_parent).unwrap();
    std::fs::create_dir(&new_parent).unwrap();
    symlink(&old_parent, &parent_link).unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("ssh.log");
    let shim = tempfile::TempDir::new().unwrap();
    let stat = shim.path().join("stat");
    std::fs::write(
        &stat,
        format!(
            "#!/bin/sh\nlast=\nfor last do :; done\ncase \" $* \" in *\" -L \"*) if [ \"$last\" = {} ]; then /usr/bin/stat \"$@\"; status=$?; /usr/bin/rm -f -- {}; /usr/bin/ln -s -- {} {}; exit \"$status\"; fi;; esac\nexec /usr/bin/stat \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(&format!(".{}", parent_link.display())).unwrap(),
            codex_ssh_bridge::quote::shell_word(parent_link.to_str().unwrap()).unwrap(),
            codex_ssh_bridge::quote::shell_word(new_parent.to_str().unwrap()).unwrap(),
            codex_ssh_bridge::quote::shell_word(parent_link.to_str().unwrap()).unwrap(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&stat, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "parent-link/target".to_owned(),
                content: "z".repeat(4 * 1024 * 1024),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
    assert!(!old_parent.join("target").exists());
    assert!(!new_parent.join("target").exists());
    for directory in [&old_parent, &new_parent] {
        assert!(std::fs::read_dir(directory).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".codex-ssh-bridge.")
        }));
    }
    assert_eq!(ssh_call_count(&log, "C"), 1);
}

#[tokio::test]
async fn task5_staging_symlink_attack_never_modifies_referent() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let outside = controls.path().join("outside-root-sentinel");
    std::fs::write(&outside, b"OUTSIDE-SENTINEL").unwrap();
    let log = controls.path().join("ssh.log");
    let shim = tempfile::TempDir::new().unwrap();
    let dd = shim.path().join("dd");
    std::fs::write(
        &dd,
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" of=./.codex-ssh-bridge.\"*bs=262144*oflag=nofollow*) target=; for argument do case \"$argument\" in of=*) target=${{argument#of=}};; esac; done; /usr/bin/rm -f -- \"$target\"; /usr/bin/ln -s -- {} \"$target\"; exec /usr/bin/dd \"$@\";; esac\nexec /usr/bin/dd \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(outside.to_str().unwrap()).unwrap()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&dd, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "target".to_owned(),
                content: "ATTACK".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
    assert_eq!(std::fs::read(&outside).unwrap(), b"OUTSIDE-SENTINEL");
    assert!(!remote.path().join("target").exists());
    assert!(std::fs::read_dir(remote.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".codex-ssh-bridge.")
    }));
    assert_eq!(ssh_call_count(&log, "C"), 1);
}

#[tokio::test]
async fn task5_cleanup_signal_removes_remote_stage_and_local_spools() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let ready = controls.path().join("stage-ready");
    let ssh_log = controls.path().join("ssh.log");
    let shim = tempfile::TempDir::new().unwrap();
    let dd = shim.path().join("dd");
    std::fs::write(
        &dd,
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" of=./.codex-ssh-bridge.\"*bs=262144*oflag=nofollow*) : >{}; exec sleep 10;; esac\nexec /usr/bin/dd \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(ready.to_str().unwrap()).unwrap(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&dd, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("PATH", path),
            ("FAKE_SSH_LOG", ssh_log.as_os_str().to_owned()),
        ],
    );
    let cancel = CancellationToken::new();
    let task = tokio::spawn({
        let cancel = cancel.clone();
        async move {
            bridge
                .write(
                    WriteRequest {
                        host: "dev".to_owned(),
                        path: "cancelled".to_owned(),
                        content: "x".repeat(4 * 1024 * 1024),
                        encoding: WriteEncoding::Utf8,
                        mode: WriteMode::Create,
                    },
                    cancel,
                )
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while !ready.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("caller staging dd never started");
    cancel.cancel();
    let error = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("cancelled mutation did not terminate")
        .unwrap()
        .unwrap_err();
    let cleanup = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let has_residual = std::fs::read_dir(remote.path()).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".codex-ssh-bridge.")
            });
            if !has_residual {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    if cleanup.is_err() {
        let residual = std::fs::read_dir(remote.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".codex-ssh-bridge.")
            })
            .map(|entry| {
                let metadata = std::fs::symlink_metadata(entry.path()).unwrap();
                (
                    entry.file_name(),
                    metadata.file_type().is_file(),
                    metadata.file_type().is_symlink(),
                    metadata.permissions().mode() & 0o7777,
                )
            })
            .collect::<Vec<_>>();
        let processes = std::process::Command::new("ps")
            .args(["-eo", "pid,ppid,pgid,stat,args"])
            .output()
            .unwrap();
        panic!(
            "facade={:?}; residual={residual:?}; process_status={:?}; processes=\n{}",
            error.code,
            processes.status.code(),
            String::from_utf8_lossy(&processes.stdout)
        );
    }
    assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
    assert_eq!(error.details.mutation_may_have_applied, Some(true));
    assert!(!remote.path().join("cancelled").exists());
    assert_eq!(ssh_call_count(&ssh_log, "C"), 1);
    assert_eq!(
        spool_file_count(&runtime.path().join("codex-ssh-bridge")),
        0
    );
}

#[tokio::test]
async fn task5_cleanup_aborted_facade_removes_remote_stage_and_local_spools() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let ready = controls.path().join("stage-ready");
    let ssh_log = controls.path().join("ssh.log");
    let shim = tempfile::TempDir::new().unwrap();
    let dd = shim.path().join("dd");
    std::fs::write(
        &dd,
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" of=./.codex-ssh-bridge.\"*bs=262144*oflag=nofollow*) : >{}; exec sleep 10;; esac\nexec /usr/bin/dd \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(ready.to_str().unwrap()).unwrap()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&dd, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("PATH", path),
            ("FAKE_SSH_LOG", ssh_log.as_os_str().to_owned()),
        ],
    );
    let runtime_directory = runtime.path().join("codex-ssh-bridge");
    let task = tokio::spawn(async move {
        bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: "aborted".to_owned(),
                    content: "x".repeat(4 * 1024 * 1024),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Create,
                },
                CancellationToken::new(),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let has_remote_temp = std::fs::read_dir(remote.path()).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".codex-ssh-bridge.")
            });
            if ready.exists() && has_remote_temp {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("aborted write never reached staged/spooled state");
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());

    let cleanup = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let has_remote_temp = std::fs::read_dir(remote.path()).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".codex-ssh-bridge.")
            });
            if !has_remote_temp
                && !remote.path().join("aborted").exists()
                && spool_file_count(&runtime_directory) == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    if cleanup.is_err() {
        let residual = std::fs::read_dir(remote.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect::<Vec<_>>();
        let processes = std::process::Command::new("ps")
            .args(["-eo", "pid,ppid,pgid,stat,args"])
            .output()
            .unwrap();
        panic!(
            "residual={residual:?}; spool_count={}; processes=\n{}",
            spool_file_count(&runtime_directory),
            String::from_utf8_lossy(&processes.stdout)
        );
    }
    assert_eq!(ssh_call_count(&ssh_log, "C"), 1);
}

#[tokio::test]
async fn task5_replace_preserves_modes_including_unreadable_final_modes() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    for (index, mode) in [0o000, 0o200, 0o600, 0o640, 0o777].into_iter().enumerate() {
        let name = format!("mode-{mode:o}");
        let path = remote.path().join(&name);
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let content = format!("new-{index}");
        let result = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: name,
                    content: content.clone(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Replace {
                        expected_sha256: (mode & 0o400 != 0).then(|| sha256(b"old")),
                    },
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(result.operation, WriteOperation::Replace);
        assert_eq!(result.mode, mode);
        assert_eq!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            mode
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), content.as_bytes());
    }
}

#[tokio::test]
async fn task5_parent_domain_errors_are_closed_before_large_stdin() {
    use std::os::unix::fs::symlink;

    let remote = tempfile::TempDir::new().unwrap();
    symlink("missing-target", remote.path().join("dangling-parent")).unwrap();
    std::fs::write(remote.path().join("regular-parent"), b"not a directory").unwrap();
    let denied = remote.path().join("denied-parent");
    std::fs::create_dir(&denied).unwrap();
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o000)).unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("ssh.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    for (path, expected, mutation_may_have_applied) in [
        ("missing-parent/target", ErrorCode::NotFound, None),
        (
            "dangling-parent/target",
            ErrorCode::MutationOutcomeUnknown,
            Some(true),
        ),
        ("regular-parent/target", ErrorCode::NotDirectory, None),
        ("denied-parent/target", ErrorCode::PermissionDenied, None),
    ] {
        let error = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: path.to_owned(),
                    content: "x".repeat(4 * 1024 * 1024),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Create,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, expected, "path={path}");
        assert_eq!(
            error.details.mutation_may_have_applied, mutation_may_have_applied,
            "path={path}"
        );
    }
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(ssh_call_count(&log, "P"), 1);
    assert_eq!(ssh_call_count(&log, "C"), 4);
}

#[tokio::test]
async fn task5_write_inaccessible_ancestor_is_not_reported_as_not_found() {
    let remote = tempfile::TempDir::new().unwrap();
    let locked = remote.path().join("locked");
    let parent = locked.join("parent");
    std::fs::create_dir_all(&parent).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);

    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "locked/parent/target".to_owned(),
                content: "payload".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();

    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert!(!parent.join("target").exists());
}

#[tokio::test]
async fn task5_replace_precommit_conflicts_preserve_existing_entries() {
    use std::os::unix::fs::symlink;

    let remote = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(remote.path().join("directory")).unwrap();
    let fifo = remote.path().join("fifo");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    std::fs::write(remote.path().join("referent"), b"outside").unwrap();
    symlink("referent", remote.path().join("live-link")).unwrap();
    symlink("missing", remote.path().join("dangling-link")).unwrap();
    for (name, mode) in [("setuid", 0o4600), ("setgid", 0o2600), ("sticky", 0o1600)] {
        let path = remote.path().join(name);
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    std::fs::write(remote.path().join("hash-mismatch"), b"old").unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);

    let missing = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "missing".to_owned(),
                content: "new".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Replace {
                    expected_sha256: None,
                },
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(missing.code, ErrorCode::NotFound);

    for path in [
        "directory",
        "fifo",
        "live-link",
        "dangling-link",
        "setuid",
        "setgid",
        "sticky",
    ] {
        let error = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: path.to_owned(),
                    content: "new".to_owned(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Replace {
                        expected_sha256: None,
                    },
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::WriteConflict, "path={path}");
    }
    let mismatch = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "hash-mismatch".to_owned(),
                content: "new".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Replace {
                    expected_sha256: Some("0".repeat(64)),
                },
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(mismatch.code, ErrorCode::WriteConflict);
    assert_eq!(
        std::fs::read(remote.path().join("hash-mismatch")).unwrap(),
        b"old"
    );
    assert_eq!(
        std::fs::read(remote.path().join("referent")).unwrap(),
        b"outside"
    );
    for path in ["setuid", "setgid", "sticky"] {
        assert_eq!(std::fs::read(remote.path().join(path)).unwrap(), b"old");
    }
}

#[tokio::test]
async fn task5_expected_hash_operational_failures_are_unknown_not_conflicts() {
    for followup_stat_fails in [false, true] {
        let remote = tempfile::TempDir::new().unwrap();
        let name = if followup_stat_fails {
            "stat-op"
        } else {
            "hash-op"
        };
        std::fs::write(remote.path().join(name), b"old").unwrap();
        let controls = tempfile::TempDir::new().unwrap();
        let marker = controls.path().join("hash-failed");
        let log = controls.path().join("ssh.log");
        let shim = tempfile::TempDir::new().unwrap();
        let dd = shim.path().join("dd");
        std::fs::write(
            &dd,
            format!(
                "#!/bin/sh\ncase \" $* \" in *\" if=./{} \"*bs=262144*iflag=nofollow*) : >{}; exit 64;; esac\nexec /usr/bin/dd \"$@\"\n",
                name,
                codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&dd, std::fs::Permissions::from_mode(0o755)).unwrap();
        if followup_stat_fails {
            let stat = shim.path().join("stat");
            std::fs::write(
                &stat,
                format!(
                    "#!/bin/sh\nif [ -e {} ]; then case \" $* \" in *\" ./{} \"*) exit 64;; esac; fi\nexec /usr/bin/stat \"$@\"\n",
                    codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
                    name,
                ),
            )
            .unwrap();
            std::fs::set_permissions(&stat, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path = OsString::from(format!(
            "{}:/usr/local/bin:/usr/bin:/bin",
            shim.path().display()
        ));
        let (_runtime, _runner, bridge) = fixture_with_options(
            remote.path(),
            false,
            None,
            &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
        );
        let error = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: name.to_owned(),
                    content: "new".to_owned(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Replace {
                        expected_sha256: Some(sha256(b"old")),
                    },
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
        assert_eq!(std::fs::read(remote.path().join(name)).unwrap(), b"old");
        assert_eq!(ssh_call_count(&log, "C"), 1);
    }
}

#[tokio::test]
async fn task5_replace_target_stat_operational_failures_are_unknown() {
    for (phase, failing_call, expected_sha256) in [
        ("initial", 1, None),
        ("precommit", 2, None),
        ("post-hash", 3, Some(sha256(b"old"))),
    ] {
        let remote = tempfile::TempDir::new().unwrap();
        let name = format!("stat-{phase}");
        let target = remote.path().join(&name);
        std::fs::write(&target, b"old").unwrap();
        let controls = tempfile::TempDir::new().unwrap();
        let marker = controls.path().join("stat-count");
        let log = controls.path().join("ssh.log");
        let shim = tempfile::TempDir::new().unwrap();
        let stat = shim.path().join("stat");
        std::fs::write(
            &stat,
            format!(
                "#!/bin/sh\ncase \" $* \" in *\" ./{} \"*) marker={}; count=$(/usr/bin/cat \"$marker\" 2>/dev/null || printf 0); count=$((count + 1)); printf %s \"$count\" >\"$marker\"; if [ \"$count\" -eq {} ]; then exit 64; fi;; esac\nexec /usr/bin/stat \"$@\"\n",
                name,
                codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
                failing_call,
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stat, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = OsString::from(format!(
            "{}:/usr/local/bin:/usr/bin:/bin",
            shim.path().display()
        ));
        let (_runtime, _runner, bridge) = fixture_with_options(
            remote.path(),
            false,
            None,
            &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
        );
        let error = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: name,
                    content: "new".to_owned(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Replace { expected_sha256 },
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.code,
            ErrorCode::MutationOutcomeUnknown,
            "phase={phase}"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"old", "phase={phase}");
        assert_eq!(ssh_call_count(&log, "C"), 1, "phase={phase}");
        assert!(std::fs::read_dir(remote.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".codex-ssh-bridge.")
        }));
    }
}

#[tokio::test]
async fn task5_replace_identity_mode_and_hash_races_conflict_before_commit() {
    for race in ["identity", "mode", "hash"] {
        let remote = tempfile::TempDir::new().unwrap();
        let name = format!("{race}-race");
        let target = remote.path().join(&name);
        std::fs::write(&target, b"old").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let controls = tempfile::TempDir::new().unwrap();
        let log = controls.path().join("ssh.log");
        let shim = tempfile::TempDir::new().unwrap();
        let executable = shim.path().join("dd");
        let action = match race {
            "identity" => format!(
                "swap={}; printf raced >\"$swap\"; /usr/bin/mv -T -- \"$swap\" {}",
                codex_ssh_bridge::quote::shell_word(
                    remote.path().join("identity-swap").to_str().unwrap()
                )
                .unwrap(),
                codex_ssh_bridge::quote::shell_word(target.to_str().unwrap()).unwrap(),
            ),
            "mode" => format!(
                "/usr/bin/chmod 0644 -- {}",
                codex_ssh_bridge::quote::shell_word(target.to_str().unwrap()).unwrap()
            ),
            "hash" => format!(
                "printf changed >{}",
                codex_ssh_bridge::quote::shell_word(target.to_str().unwrap()).unwrap()
            ),
            _ => unreachable!(),
        };
        let body = if race == "hash" {
            format!(
                "#!/bin/sh\ncase \" $* \" in *\" if=./{} \"*bs=262144*iflag=nofollow*) {}; exec /usr/bin/dd \"$@\";; esac\nexec /usr/bin/dd \"$@\"\n",
                name, action
            )
        } else {
            format!(
                "#!/bin/sh\ncase \" $* \" in *\" of=./.codex-ssh-bridge.\"*bs=262144*oflag=nofollow*) /usr/bin/dd \"$@\"; status=$?; {}; exit \"$status\";; esac\nexec /usr/bin/dd \"$@\"\n",
                action
            )
        };
        std::fs::write(&executable, body).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = OsString::from(format!(
            "{}:/usr/local/bin:/usr/bin:/bin",
            shim.path().display()
        ));
        let (_runtime, _runner, bridge) = fixture_with_options(
            remote.path(),
            false,
            None,
            &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
        );
        let error = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: name.clone(),
                    content: "payload".to_owned(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Replace {
                        expected_sha256: (race == "hash").then(|| sha256(b"old")),
                    },
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::WriteConflict, "race={race}");
        assert_ne!(std::fs::read(&target).unwrap(), b"payload", "race={race}");
        assert_eq!(ssh_call_count(&log, "C"), 1);
    }
}

#[tokio::test]
async fn task5_replace_mode_application_uses_the_verified_private_inode() {
    for race in ["verify-fail"] {
        let remote = tempfile::TempDir::new().unwrap();
        let target = remote.path().join(race);
        std::fs::write(&target, b"old").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        let controls = tempfile::TempDir::new().unwrap();
        let outside = controls.path().join("outside");
        std::fs::write(&outside, b"OUTSIDE").unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600)).unwrap();
        let log = controls.path().join("ssh.log");
        let marker = controls.path().join("stat-count");
        let shim = tempfile::TempDir::new().unwrap();
        let (tool, body) = match race {
            "verify-fail" => (
                "stat",
                format!(
                    "#!/bin/sh\ncase \" $* \" in *\" ./{} \"*) marker={}; count=$(/usr/bin/cat \"$marker\" 2>/dev/null || printf 0); count=$((count + 1)); printf %s \"$count\" >\"$marker\"; if [ \"$count\" -eq 4 ]; then printf '81a0:0:640:7:1:2:1:extra\\n'; exit 0; fi;; esac\nexec /usr/bin/stat \"$@\"\n",
                    race,
                    codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
                ),
            ),
            _ => unreachable!(),
        };
        let executable = shim.path().join(tool);
        std::fs::write(&executable, body).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = OsString::from(format!(
            "{}:/usr/local/bin:/usr/bin:/bin",
            shim.path().display()
        ));
        let (_runtime, _runner, bridge) = fixture_with_options(
            remote.path(),
            false,
            None,
            &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
        );
        let result = bridge
            .write(
                WriteRequest {
                    host: "dev".to_owned(),
                    path: race.to_owned(),
                    content: "payload".to_owned(),
                    encoding: WriteEncoding::Utf8,
                    mode: WriteMode::Replace {
                        expected_sha256: None,
                    },
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(result.operation, WriteOperation::Replace);
        assert_eq!(std::fs::read(&outside).unwrap(), b"OUTSIDE", "race={race}");
        assert_eq!(
            std::fs::symlink_metadata(&outside)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "race={race}"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"payload", "race={race}");
        assert_eq!(ssh_call_count(&log, "C"), 1);
    }
}

#[tokio::test]
async fn task5_target_created_during_upload_is_a_closed_conflict() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("ssh.log");
    let raced_target = remote.path().join("raced-target");
    let shim = tempfile::TempDir::new().unwrap();
    let dd = shim.path().join("dd");
    std::fs::write(
        &dd,
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" of=./.codex-ssh-bridge.\"*bs=262144*oflag=nofollow*) /usr/bin/dd \"$@\"; status=$?; printf RACE >{}; exit \"$status\";; esac\nexec /usr/bin/dd \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(raced_target.to_str().unwrap()).unwrap()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&dd, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        shim.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    let error = bridge
        .write(
            WriteRequest {
                host: "dev".to_owned(),
                path: "raced-target".to_owned(),
                content: "payload".to_owned(),
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::WriteConflict);
    assert_eq!(std::fs::read(&raced_target).unwrap(), b"RACE");
    assert!(std::fs::read_dir(remote.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".codex-ssh-bridge.")
    }));
    assert_eq!(ssh_call_count(&log, "C"), 1);
}

#[tokio::test]
async fn metadata_read_and_grep_search_run_through_fixed_spools() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("alpha.txt"), b"one\ntwo needle\nthree").unwrap();
    std::fs::create_dir(remote.path().join("dir")).unwrap();
    std::fs::write(remote.path().join(".hidden"), b"needle").unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    let cancel = CancellationToken::new();

    let list = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: Some(1),
                include_hidden: Some(false),
                max_entries: None,
            },
            cancel.clone(),
        )
        .await
        .unwrap();
    assert_eq!(list.entries.len(), 2);
    assert!(
        list.entries
            .iter()
            .all(|entry| entry.relative_path.value != ".hidden")
    );

    let stat = bridge
        .stat(
            StatRequest {
                host: "dev".into(),
                paths: vec!["alpha.txt".into(), "missing".into()],
            },
            cancel.clone(),
        )
        .await
        .unwrap();
    assert!(matches!(stat.entries[0], StatEntry::Success { .. }));
    assert!(matches!(stat.entries[1], StatEntry::Error { .. }));

    let read = bridge
        .read(
            ReadRequest {
                host: "dev".into(),
                paths: vec!["alpha.txt".into()],
                start_line: Some(2),
                max_lines: Some(1),
                max_bytes: Some(1024),
            },
            cancel.clone(),
        )
        .await
        .unwrap();
    match &read.files[0] {
        ReadEntry::Success {
            content,
            truncated_before,
            truncated_after,
            ..
        } => {
            assert_eq!(content.value, "two needle\n");
            assert!(*truncated_before);
            assert!(*truncated_after);
        }
        _ => panic!("expected read success"),
    }

    let search = bridge
        .search(
            SearchRequest {
                host: "dev".into(),
                query: "needle".into(),
                path: None,
                globs: vec!["**/*.txt".into()],
                max_results: None,
                binary: Some(false),
            },
            cancel,
        )
        .await
        .unwrap();
    assert_eq!(search.engine, SearchEngine::Grep);
    assert_eq!(search.matches.len(), 1, "{search:?}");
    assert_eq!(search.matches[0].column, 5);
}

#[tokio::test]
async fn output_read_requires_and_uses_command_provenance() {
    let remote = tempfile::TempDir::new().unwrap();
    let (_runtime, runner, bridge) = fixture(remote.path(), false);
    let result = runner
        .execute(
            RunRequest {
                host: "dev".into(),
                command: "head -c 300000 /dev/zero".into(),
                cwd: remote.path().to_str().unwrap().into(),
                shell: ShellRequest::Auto,
                stdin: None,
                timeout: Duration::from_secs(5),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let reference = result.output.reference.unwrap();
    let page = bridge
        .output_read(
            codex_ssh_bridge::remote::OutputReadRequest {
                output_ref: reference.as_str().into(),
                stream: StreamKind::Stdout,
                offset: 0,
                max_bytes: 16,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(matches!(
        &page.provenance,
        RetentionProvenance::Remote(context) if context.host == "dev"
    ));
    assert_eq!(page.data.encoding, ValueEncoding::Base64);
    assert_eq!(page.next_offset, 16);

    let offset_error = bridge
        .output_read(
            codex_ssh_bridge::remote::OutputReadRequest {
                output_ref: reference.as_str().into(),
                stream: StreamKind::Stdout,
                offset: 300_001,
                max_bytes: 16,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(offset_error.code, ErrorCode::InvalidArgument);
    assert_eq!(offset_error.details.host.as_deref(), Some("dev"));
    assert_eq!(offset_error.details.physical_root.as_deref(), Some("/"));
    assert!(offset_error.details.shell.is_some());

    let cancel = CancellationToken::new();
    cancel.cancel();
    let cancel_error = bridge
        .output_read(
            codex_ssh_bridge::remote::OutputReadRequest {
                output_ref: reference.as_str().into(),
                stream: StreamKind::Stdout,
                offset: 0,
                max_bytes: 16,
            },
            cancel,
        )
        .await
        .unwrap_err();
    assert_eq!(cancel_error.code, ErrorCode::Cancelled);
    assert_eq!(cancel_error.details.host.as_deref(), Some("dev"));
    assert_eq!(cancel_error.details.physical_root.as_deref(), Some("/"));
    assert!(cancel_error.details.shell.is_some());
}

#[tokio::test]
async fn readonly_real_mismatch_retries_exactly_once_from_the_list_script() {
    use std::os::unix::fs::PermissionsExt;

    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a"), b"x").unwrap();
    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let marker = runtime_base.path().join("find-stale-once");
    let log = runtime_base.path().join("ssh.log");
    let bin = tempfile::TempDir::new().unwrap();
    let find = bin.path().join("find");
    std::fs::write(
        &find,
        format!(
            "#!/bin/sh\ncase \" $* \" in *codex-probe-find*) exec /usr/bin/find \"$@\";; *codex-sentinel-list-production*) if [ ! -e {} ]; then : >{}; printf 'corrupt\\000'; exit 0; fi;; esac\nexec /usr/bin/find \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
            codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&find, std::fs::Permissions::from_mode(0o755)).unwrap();
    let environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (OsString::from("FAKE_SSH_ROOT"), OsString::from("/")),
        (
            OsString::from("PATH"),
            OsString::from(format!(
                "{}:/usr/local/bin:/usr/bin:/bin",
                bin.path().display()
            )),
        ),
        (OsString::from("FAKE_SSH_LOG"), log.as_os_str().to_owned()),
    ]);
    let config = Arc::new(support::config_with_host(
        "dev",
        remote.path().to_str().unwrap(),
    ));
    let runner = Arc::new(
        SshRunner::with_executable(
            config,
            runtime,
            store,
            support::fake_ssh_path(),
            environment,
        )
        .unwrap(),
    );
    let bridge = FixtureBridge::new(
        RemoteBridge::new_immediate_for_transport_tests(runner),
        remote.path(),
    );
    let result = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: None,
                include_hidden: None,
                max_entries: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.entries.len(), 1);
    let log = std::fs::read_to_string(log).unwrap();
    assert_eq!(log.lines().filter(|line| *line == "P").count(), 2);
    assert_eq!(log.lines().filter(|line| *line == "C").count(), 2);
}

#[tokio::test]
async fn readonly_stale_sentinel_retries_each_production_form_exactly_once() {
    struct Case {
        tool: &'static str,
        sentinel: &'static str,
        failure: &'static str,
        operation: &'static str,
        rg: bool,
        expected_commands: usize,
        expected_sentinel_invocations: usize,
    }

    let cases = [
        Case {
            tool: "find",
            sentinel: "codex-sentinel-list-production",
            failure: "printf 'corrupt\\000'; exit 0",
            operation: "list",
            rg: true,
            expected_commands: 2,
            expected_sentinel_invocations: 6,
        },
        Case {
            tool: "xargs",
            sentinel: "codex-sentinel-list-xargs",
            failure: "exit 0",
            operation: "list",
            rg: true,
            expected_commands: 2,
            expected_sentinel_invocations: 4,
        },
        Case {
            tool: "head",
            sentinel: "bound",
            failure: "printf zzz; exit 0",
            operation: "list",
            rg: true,
            expected_commands: 2,
            expected_sentinel_invocations: 2,
        },
        Case {
            tool: "mktemp",
            sentinel: "codex-sentinel-bound",
            failure: "shift; d=${1%XXXXXX}bad; mkdir -m 755 \"$d\"; printf '%s\\n' \"$d\"; exit 0",
            operation: "list",
            rg: true,
            expected_commands: 2,
            expected_sentinel_invocations: 2,
        },
        Case {
            tool: "mkfifo",
            sentinel: "codex-sentinel-bound",
            failure: ": >\"$1\"; exit 0",
            operation: "list",
            rg: true,
            expected_commands: 2,
            expected_sentinel_invocations: 2,
        },
        Case {
            tool: "stat",
            sentinel: "codex-sentinel-stat",
            failure: "printf corrupt; exit 0",
            operation: "stat",
            rg: true,
            expected_commands: 2,
            expected_sentinel_invocations: 8,
        },
        Case {
            tool: "tail",
            sentinel: "codex-sentinel-read",
            failure: "printf z; exit 0",
            operation: "read",
            rg: true,
            expected_commands: 2,
            expected_sentinel_invocations: 4,
        },
        Case {
            tool: "find",
            sentinel: "codex-sentinel-search-find",
            failure: "printf 'corrupt\\000'; exit 0",
            operation: "rg-search",
            rg: true,
            expected_commands: 3,
            expected_sentinel_invocations: 2,
        },
        Case {
            tool: "rg",
            sentinel: "codex-sentinel-rg",
            failure: "printf '%s\\n' '{\"type\":\"mystery\"}'; exit 0",
            operation: "rg-search",
            rg: true,
            expected_commands: 3,
            expected_sentinel_invocations: 4,
        },
        Case {
            tool: "grep",
            sentinel: "codex-sentinel-grep",
            failure: "printf corrupt; exit 0",
            operation: "grep-search",
            rg: false,
            expected_commands: 3,
            expected_sentinel_invocations: 4,
        },
    ];

    let started = Instant::now();
    for case in cases {
        let remote = tempfile::TempDir::new().unwrap();
        std::fs::write(remote.path().join("a"), b"needle\n").unwrap();
        let real_tool = executable_on_path(case.tool);
        let state = tempfile::TempDir::new().unwrap();
        let marker = state.path().join("failed-once");
        let sentinel_log = state.path().join("sentinel.log");
        let log = state.path().join("ssh.log");
        let bin = tempfile::TempDir::new().unwrap();
        let executable = bin.path().join(case.tool);
        std::fs::write(
            &executable,
            format!(
                "#!/bin/sh\ncase \"${{CODEX_SSH_SENTINEL:-}}: $*\" in *{}*) printf 'S\\n' >>{}; if [ ! -e {} ]; then : >{}; {}; fi;; esac\nexec {} \"$@\"\n",
                case.sentinel,
                codex_ssh_bridge::quote::shell_word(sentinel_log.to_str().unwrap()).unwrap(),
                codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
                codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
                case.failure,
                codex_ssh_bridge::quote::shell_word(real_tool.to_str().unwrap()).unwrap(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = OsString::from(format!(
            "{}:/usr/local/bin:/usr/bin:/bin",
            bin.path().display()
        ));
        let (_runtime, _runner, bridge) = fixture_with_options(
            remote.path(),
            case.rg,
            None,
            &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
        );
        let result = match case.operation {
            "list" => bridge
                .list(
                    ListRequest {
                        host: "dev".into(),
                        path: None,
                        depth: None,
                        include_hidden: None,
                        max_entries: None,
                    },
                    CancellationToken::new(),
                )
                .await
                .map(|_| ()),
            "stat" => bridge
                .stat(
                    StatRequest {
                        host: "dev".into(),
                        paths: vec!["a".into()],
                    },
                    CancellationToken::new(),
                )
                .await
                .map(|_| ()),
            "read" => bridge
                .read(
                    ReadRequest {
                        host: "dev".into(),
                        paths: vec!["a".into()],
                        start_line: None,
                        max_lines: None,
                        max_bytes: None,
                    },
                    CancellationToken::new(),
                )
                .await
                .map(|_| ()),
            "rg-search" | "grep-search" => bridge
                .search(
                    SearchRequest {
                        host: "dev".into(),
                        query: "needle".into(),
                        path: None,
                        globs: vec![],
                        max_results: None,
                        binary: Some(false),
                    },
                    CancellationToken::new(),
                )
                .await
                .map(|_| ()),
            _ => unreachable!(),
        };
        result.unwrap_or_else(|error| {
            panic!("tool={}, sentinel={}: {error:?}", case.tool, case.sentinel)
        });
        let log = std::fs::read_to_string(log).unwrap();
        assert_eq!(
            log.lines().filter(|line| *line == "P").count(),
            2,
            "tool={}, sentinel={}",
            case.tool,
            case.sentinel
        );
        assert_eq!(
            log.lines().filter(|line| *line == "C").count(),
            case.expected_commands,
            "tool={}, sentinel={}",
            case.tool,
            case.sentinel
        );
        assert_eq!(
            std::fs::read_to_string(&sentinel_log)
                .unwrap()
                .lines()
                .count(),
            case.expected_sentinel_invocations,
            "tool={}, sentinel={}",
            case.tool,
            case.sentinel
        );
    }
    eprintln!(
        "ten stale-sentinel retry cases completed in {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn readonly_stale_list_production_forms_retry_exactly_once() {
    struct Case {
        name: &'static str,
        tool: &'static str,
        detect: &'static str,
        failure: &'static str,
        persistent: bool,
    }

    let cases = [
        Case {
            name: "dynamic-depth",
            tool: "find",
            detect: "p=; for a do [ \"$p\" = -maxdepth ] && [ \"$a\" = 3 ] && hit=1; p=$a; done",
            failure: "printf 'corrupt\\000'; exit 0",
            persistent: false,
        },
        Case {
            name: "hidden-prune",
            tool: "find",
            detect: "a=0; b=0; for v do [ \"$v\" = './.*' ] && a=1; [ \"$v\" = '*/.*' ] && b=1; done; [ \"$a:$b\" = 1:1 ] && hit=1",
            failure: "printf 'corrupt\\000'; exit 0",
            persistent: false,
        },
        Case {
            name: "xargs-n100",
            tool: "xargs",
            detect: "p=; for a do [ \"$p\" = -n ] && [ \"$a\" = 100 ] && hit=1; p=$a; done",
            failure: "exit 64",
            persistent: false,
        },
        Case {
            name: "persistent-dynamic-depth",
            tool: "find",
            detect: "p=; for a do [ \"$p\" = -maxdepth ] && [ \"$a\" = 3 ] && hit=1; p=$a; done",
            failure: "printf 'corrupt\\000'; exit 0",
            persistent: true,
        },
    ];

    for case in cases {
        let remote = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(remote.path().join("visible")).unwrap();
        std::fs::write(remote.path().join("visible/leaf"), b"x").unwrap();
        let state = tempfile::TempDir::new().unwrap();
        let marker = state.path().join("failed-once");
        let log = state.path().join("ssh.log");
        let bin = tempfile::TempDir::new().unwrap();
        let executable = bin.path().join(case.tool);
        let failure_guard = if case.persistent {
            case.failure.to_owned()
        } else {
            format!(
                "if [ ! -e {} ]; then : >{}; {}; fi",
                codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
                codex_ssh_bridge::quote::shell_word(marker.to_str().unwrap()).unwrap(),
                case.failure,
            )
        };
        std::fs::write(
            &executable,
            format!(
                "#!/bin/sh\nhit=0; {}\nif [ \"$hit\" = 1 ]; then {}; fi\nexec /usr/bin/{} \"$@\"\n",
                case.detect, failure_guard, case.tool,
            ),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = OsString::from(format!(
            "{}:/usr/local/bin:/usr/bin:/bin",
            bin.path().display()
        ));
        let (_runtime, _runner, bridge) = fixture_with_options(
            remote.path(),
            true,
            None,
            &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
        );
        let result = bridge
            .list(
                ListRequest {
                    host: "dev".into(),
                    path: None,
                    depth: Some(3),
                    include_hidden: Some(false),
                    max_entries: Some(10),
                },
                CancellationToken::new(),
            )
            .await;
        if case.persistent {
            assert_eq!(
                result.unwrap_err().code,
                ErrorCode::RemoteCapabilityMissing,
                "{}",
                case.name
            );
        } else {
            result.unwrap_or_else(|error| panic!("{}: {error:?}", case.name));
        }
        let log = std::fs::read_to_string(log).unwrap();
        assert_eq!(
            log.lines().filter(|line| *line == "P").count(),
            2,
            "{}",
            case.name
        );
        assert_eq!(
            log.lines().filter(|line| *line == "C").count(),
            2,
            "{}",
            case.name
        );
    }

    let remote = tempfile::TempDir::new().unwrap();
    let state = tempfile::TempDir::new().unwrap();
    let log = state.path().join("ssh.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        true,
        None,
        &[("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    let error = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: Some("missing".into()),
                depth: Some(3),
                include_hidden: Some(false),
                max_entries: Some(10),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
    let log = std::fs::read_to_string(log).unwrap();
    assert_eq!(log.lines().filter(|line| *line == "P").count(), 1);
    assert_eq!(log.lines().filter(|line| *line == "C").count(), 1);
}

#[tokio::test]
async fn readonly_warm_operation_sentinel_latency_evidence() {
    fn report(name: &str, samples: &mut [Duration]) {
        samples.sort_unstable();
        let milliseconds = |duration: Duration| duration.as_secs_f64() * 1_000.0;
        eprintln!(
            "warm {name}: p50={:.2}ms range={:.2}..{:.2}ms (n={})",
            milliseconds(samples[samples.len() / 2]),
            milliseconds(samples[0]),
            milliseconds(samples[samples.len() - 1]),
            samples.len()
        );
    }

    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a"), b"needle\n").unwrap();
    let (_runtime, _runner, rg_bridge) = fixture(remote.path(), true);
    rg_bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: None,
                include_hidden: None,
                max_entries: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();

    let mut list = Vec::new();
    let mut stat = Vec::new();
    let mut read = Vec::new();
    let mut rg = Vec::new();
    for _ in 0..5 {
        let started = Instant::now();
        rg_bridge
            .list(
                ListRequest {
                    host: "dev".into(),
                    path: None,
                    depth: None,
                    include_hidden: None,
                    max_entries: None,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();
        list.push(started.elapsed());

        let started = Instant::now();
        rg_bridge
            .stat(
                StatRequest {
                    host: "dev".into(),
                    paths: vec!["a".into()],
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();
        stat.push(started.elapsed());

        let started = Instant::now();
        rg_bridge
            .read(
                ReadRequest {
                    host: "dev".into(),
                    paths: vec!["a".into()],
                    start_line: None,
                    max_lines: None,
                    max_bytes: None,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();
        read.push(started.elapsed());

        let started = Instant::now();
        rg_bridge
            .search(
                SearchRequest {
                    host: "dev".into(),
                    query: "needle".into(),
                    path: None,
                    globs: vec![],
                    max_results: None,
                    binary: Some(false),
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();
        rg.push(started.elapsed());
    }

    let (_runtime, _runner, grep_bridge) = fixture(remote.path(), false);
    grep_bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: None,
                include_hidden: None,
                max_entries: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let mut grep = Vec::new();
    for _ in 0..5 {
        let started = Instant::now();
        grep_bridge
            .search(
                SearchRequest {
                    host: "dev".into(),
                    query: "needle".into(),
                    path: None,
                    globs: vec![],
                    max_results: None,
                    binary: Some(false),
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();
        grep.push(started.elapsed());
    }

    report("list", &mut list);
    report("stat", &mut stat);
    report("read", &mut read);
    report("rg-search", &mut rg);
    report("grep-search", &mut grep);
}

#[tokio::test]
async fn readonly_stale_sentinel_that_remains_bad_is_capability_missing() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a"), b"x").unwrap();
    let state = tempfile::TempDir::new().unwrap();
    let log = state.path().join("ssh.log");
    let bin = tempfile::TempDir::new().unwrap();
    let find = bin.path().join("find");
    std::fs::write(
        &find,
        b"#!/bin/sh\ncase \" $* \" in *codex-sentinel-list-production*) printf 'corrupt\\000'; exit 0;; esac\nexec /usr/bin/find \"$@\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&find, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        bin.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        true,
        None,
        &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    let error = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: None,
                include_hidden: None,
                max_entries: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RemoteCapabilityMissing);
    let log = std::fs::read_to_string(log).unwrap();
    assert_eq!(log.lines().filter(|line| *line == "P").count(), 2);
    assert_eq!(log.lines().filter(|line| *line == "C").count(), 2);
}

#[tokio::test]
async fn readonly_sentinel_setup_failure_is_not_retried() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a"), b"x").unwrap();
    let state = tempfile::TempDir::new().unwrap();
    let log = state.path().join("ssh.log");
    let bin = tempfile::TempDir::new().unwrap();
    let mktemp = bin.path().join("mktemp");
    std::fs::write(
        &mktemp,
        b"#!/bin/sh\ncase \" $* \" in *codex-sentinel-bound*) exit 1;; esac\nexec /usr/bin/mktemp \"$@\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&mktemp, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        bin.path().display()
    ));
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        true,
        None,
        &[("PATH", path), ("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    let error = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: None,
                include_hidden: None,
                max_entries: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RemoteExit);
    let log = std::fs::read_to_string(log).unwrap();
    assert_eq!(log.lines().filter(|line| *line == "P").count(), 1);
    assert_eq!(log.lines().filter(|line| *line == "C").count(), 1);
}

#[tokio::test]
async fn readonly_filesystem_error_is_not_retried() {
    let remote = tempfile::TempDir::new().unwrap();
    let runtime_base = tempfile::TempDir::new().unwrap();
    let log = runtime_base.path().join("ssh.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[("FAKE_SSH_LOG", log.as_os_str().to_owned())],
    );
    let error = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: Some("missing".into()),
                depth: None,
                include_hidden: None,
                max_entries: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
    let log = std::fs::read_to_string(log).unwrap();
    assert_eq!(log.lines().filter(|line| *line == "C").count(), 1);
}

#[tokio::test]
async fn readonly_transport_error_is_not_retried() {
    let remote = tempfile::TempDir::new().unwrap();
    let runtime_base = tempfile::TempDir::new().unwrap();
    let log = runtime_base.path().join("ssh.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("FAKE_SSH_MODE", OsString::from("error")),
            ("FAKE_SSH_PROBE_ERROR", OsString::from("connect-timeout")),
            ("FAKE_SSH_LOG", log.as_os_str().to_owned()),
        ],
    );
    let error = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: None,
                include_hidden: None,
                max_entries: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ConnectTimeout);
    let log = std::fs::read_to_string(log).unwrap();
    assert_eq!(log.lines().filter(|line| *line == "P").count(), 1);
    assert_eq!(log.lines().filter(|line| *line == "C").count(), 0);
}

#[tokio::test]
async fn capability_mismatch_unknown_key_is_protocol_error_without_retry() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a"), b"x").unwrap();
    let marker = remote.path().join("mismatch-marker");
    let runtime_base = tempfile::TempDir::new().unwrap();
    let log = runtime_base.path().join("ssh.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            ("FAKE_SSH_MISMATCH_FILE", marker.as_os_str().to_owned()),
            ("FAKE_SSH_MISMATCH_KEY", OsString::from("unexpected_key")),
            ("FAKE_SSH_LOG", log.as_os_str().to_owned()),
        ],
    );
    let error = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: None,
                include_hidden: None,
                max_entries: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ProtocolError);
    let log = std::fs::read_to_string(log).unwrap();
    assert_eq!(log.lines().filter(|line| *line == "C").count(), 1);
}

#[tokio::test]
async fn non_utf8_paths_and_binary_content_are_lossless() {
    let remote = tempfile::TempDir::new().unwrap();
    let raw_name = OsString::from_vec(b"raw-\xff".to_vec());
    std::fs::write(remote.path().join(&raw_name), b"needle\n").unwrap();
    std::fs::write(remote.path().join("binary"), b"a\0needle\xff\n").unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), true);
    let list = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: None,
                include_hidden: Some(true),
                max_entries: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(
        list.entries
            .iter()
            .any(|entry| entry.relative_path.encoding == ValueEncoding::Base64)
    );
    let search = bridge
        .search(
            SearchRequest {
                host: "dev".into(),
                query: "needle".into(),
                path: None,
                globs: vec![],
                max_results: None,
                binary: Some(true),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(search.engine, SearchEngine::Rg);
    assert!(
        search
            .matches
            .iter()
            .any(|entry| entry.actual_path.encoding == ValueEncoding::Base64)
    );
    assert!(
        search
            .matches
            .iter()
            .any(|entry| entry.content.encoding == ValueEncoding::Base64)
    );
    let read = bridge
        .read(
            ReadRequest {
                host: "dev".into(),
                paths: vec!["binary".into()],
                start_line: None,
                max_lines: None,
                max_bytes: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(
        matches!(&read.files[0], ReadEntry::Success { content, .. } if content.encoding == ValueEncoding::Base64)
    );
}

#[tokio::test]
async fn hosts_are_local_and_list_and_read_bounds_are_exact() {
    let remote = tempfile::TempDir::new().unwrap();
    for name in ["a", "b", "c"] {
        std::fs::write(remote.path().join(name), b"1234").unwrap();
    }
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    let hosts = bridge.hosts().await.unwrap();
    assert_eq!(hosts.hosts[0].host, "dev");
    let list = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: None,
                include_hidden: None,
                max_entries: Some(1),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(list.entries.len(), 1);
    assert!(list.truncated);
    let read = bridge
        .read(
            ReadRequest {
                host: "dev".into(),
                paths: vec!["a".into(), "b".into()],
                start_line: None,
                max_lines: None,
                max_bytes: Some(5),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(read.returned_raw_bytes, 5);
    assert!(matches!(&read.files[1], ReadEntry::Success { truncated, .. } if *truncated));
}

#[tokio::test]
async fn aborting_a_fixed_facade_unlinks_internal_spools_without_ttl() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a"), b"x").unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let ready = controls.path().join("ready");
    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let runtime_directory = runtime.directory().to_owned();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (OsString::from("FAKE_SSH_ROOT"), OsString::from("/")),
        (
            OsString::from("FAKE_SSH_FIXED_SLEEP_SECONDS"),
            OsString::from("0.5"),
        ),
        (
            OsString::from("FAKE_SSH_FIXED_READY_FILE"),
            ready.as_os_str().to_owned(),
        ),
    ]);
    let config = Arc::new(support::config_with_host(
        "dev",
        remote.path().to_str().unwrap(),
    ));
    let runner = Arc::new(
        SshRunner::with_executable(
            config,
            runtime,
            store,
            support::fake_ssh_path(),
            environment,
        )
        .unwrap(),
    );
    let bridge = FixtureBridge::new(
        RemoteBridge::new_immediate_for_transport_tests(runner),
        remote.path(),
    );
    let task = tokio::spawn(async move {
        bridge
            .list(
                ListRequest {
                    host: "dev".into(),
                    path: None,
                    depth: None,
                    include_hidden: None,
                    max_entries: None,
                },
                CancellationToken::new(),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while !ready.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    for _ in 0..100 {
        if spool_file_count(&runtime_directory) == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(spool_file_count(&runtime_directory), 0);
}

fn spool_file_count(runtime: &std::path::Path) -> usize {
    std::fs::read_dir(runtime)
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            if entry.file_type().ok()?.is_dir()
                && entry.file_name().to_string_lossy().starts_with("output-")
            {
                Some(entry.path())
            } else {
                None
            }
        })
        .map(|directory| std::fs::read_dir(directory).unwrap().count())
        .sum()
}

fn assert_no_dispatcher_request_artifacts(scratch: &std::path::Path) {
    let unexpected = std::fs::read_dir(scratch)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .filter(|name| {
            !name
                .to_string_lossy()
                .starts_with("codex-ssh-bridge-dispatcher.")
        })
        .collect::<Vec<_>>();
    assert!(
        unexpected.is_empty(),
        "dispatcher request artifacts remain: {unexpected:?}"
    );
}

fn spool_files(runtime: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(runtime)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().is_ok_and(|kind| kind.is_dir())
                && entry.file_name().to_string_lossy().starts_with("output-")
        })
        .flat_map(|entry| {
            std::fs::read_dir(entry.path())
                .ok()
                .into_iter()
                .flatten()
                .filter_map(Result::ok)
                .map(|file| file.path())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn resident_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse().ok())
        })
        .unwrap()
}

fn stage_metadata_sample_is_secure(metadata: std::io::Result<std::fs::Metadata>) -> bool {
    match metadata {
        Ok(metadata) => metadata.is_file() && metadata.permissions().mode() & 0o777 == 0o600,
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
    }
}

#[test]
fn task5_stage_sampler_ignores_only_entries_removed_during_metadata_lookup() {
    let disappeared = std::io::Error::from(std::io::ErrorKind::NotFound);
    assert!(stage_metadata_sample_is_secure(Err(disappeared)));

    let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    assert!(!stage_metadata_sample_is_secure(Err(denied)));

    let fixture = tempfile::TempDir::new().unwrap();
    let stage = fixture.path().join("stage");
    std::fs::write(&stage, b"payload").unwrap();
    std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(stage_metadata_sample_is_secure(std::fs::metadata(&stage)));
    std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(!stage_metadata_sample_is_secure(std::fs::metadata(&stage)));
    assert!(!stage_metadata_sample_is_secure(std::fs::metadata(
        fixture.path()
    )));
}

#[tokio::test]
async fn task5_five_hosts_write_four_mib_with_bounded_rss_and_complete_cleanup() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use codex_ssh_bridge::config::HostProfile;

    const RAW_BYTES: usize = 4 * 1024 * 1024;
    const EXPECTED_HASH: &str = "baa7a6d36ffa957552df230235c2d51d735f28d49c58a5f3438a3a973a25a37d";
    const RSS_DELTA_CEILING_KIB: u64 = 64 * 1024;

    let remote_base = tempfile::TempDir::new().unwrap();
    let mut roots = Vec::new();
    for index in 0..5 {
        let root = remote_base.path().join(format!("h{index}"));
        std::fs::create_dir(&root).unwrap();
        roots.push(root);
    }
    let controls = tempfile::TempDir::new().unwrap();
    let ready_directory = controls.path().join("ready");
    std::fs::create_dir(&ready_directory).unwrap();
    let release = controls.path().join("release");
    let ssh_log = controls.path().join("ssh.log");
    let shim = tempfile::TempDir::new().unwrap();
    let dd = shim.path().join("dd");
    std::fs::write(
        &dd,
        format!(
            "#!/bin/sh\ncase \" $* \" in *\" of=./.codex-ssh-bridge.\"*bs=262144*oflag=nofollow*) ready={}; release={}; : >\"$ready/${{PWD##*/}}\"; while [ ! -e \"$release\" ]; do sleep 0.005; done;; esac\nexec /usr/bin/dd \"$@\"\n",
            codex_ssh_bridge::quote::shell_word(ready_directory.to_str().unwrap()).unwrap(),
            codex_ssh_bridge::quote::shell_word(release.to_str().unwrap()).unwrap(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&dd, std::fs::Permissions::from_mode(0o755)).unwrap();

    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let runtime_directory = runtime.directory().to_owned();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let mut config = support::config_with_host("h0", roots[0].to_str().unwrap());
    let profile: HostProfile = config.hosts["h0"].clone();
    for (index, root) in roots.iter().enumerate().skip(1) {
        let mut host = profile.clone();
        host.root = root.to_str().unwrap().to_owned();
        config.hosts.insert(format!("h{index}"), host);
    }
    let environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (OsString::from("FAKE_SSH_ROOT"), OsString::from("/")),
        (
            OsString::from("FAKE_SSH_LOG"),
            ssh_log.as_os_str().to_owned(),
        ),
        (
            OsString::from("PATH"),
            OsString::from(format!(
                "{}:/usr/local/bin:/usr/bin:/bin",
                shim.path().display()
            )),
        ),
    ]);
    let runner = Arc::new(
        SshRunner::with_executable(
            Arc::new(config),
            runtime,
            store,
            support::fake_ssh_path(),
            environment,
        )
        .unwrap(),
    );
    let bridge = Arc::new(RemoteBridge::new_immediate_for_transport_tests(runner));

    let encoded = STANDARD.encode(vec![b'x'; RAW_BYTES]);
    let mut sources = (0..5).map(|_| encoded.clone()).collect::<Vec<_>>();
    drop(encoded);
    let source_bytes = sources.iter().map(String::len).sum::<usize>();
    let touched = sources
        .iter()
        .flat_map(|source| source.as_bytes().iter().step_by(4096))
        .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
    std::hint::black_box(touched);
    let baseline_rss = resident_kib();

    let monitor_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = Arc::new(std::sync::Mutex::new((baseline_rss, 0usize, 0usize, true)));
    let monitor = {
        let stop = Arc::clone(&monitor_stop);
        let observed = Arc::clone(&observed);
        let roots = roots.clone();
        let runtime_directory = runtime_directory.clone();
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let stages = roots
                    .iter()
                    .flat_map(|root| std::fs::read_dir(root).unwrap())
                    .filter_map(Result::ok)
                    .filter(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".codex-ssh-bridge.")
                    })
                    .collect::<Vec<_>>();
                let spool_count = spool_file_count(&runtime_directory);
                let rss = resident_kib();
                let mut sample = observed.lock().unwrap();
                sample.0 = sample.0.max(rss);
                sample.1 = sample.1.max(stages.len());
                sample.2 = sample.2.max(spool_count);
                sample.3 &= stages
                    .iter()
                    .all(|entry| stage_metadata_sample_is_secure(entry.metadata()));
                drop(sample);
                std::thread::sleep(Duration::from_millis(2));
            }
        })
    };

    let mut tasks = tokio::task::JoinSet::new();
    for (index, content) in sources.drain(..).enumerate() {
        let bridge = Arc::clone(&bridge);
        let path = roots[index].join("payload").to_string_lossy().into_owned();
        tasks.spawn(async move {
            let result = bridge
                .write(
                    WriteRequest {
                        host: format!("h{index}"),
                        path,
                        content,
                        encoding: WriteEncoding::Base64,
                        mode: WriteMode::Create,
                    },
                    CancellationToken::new(),
                )
                .await;
            (index, result)
        });
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let ready = std::fs::read_dir(&ready_directory).unwrap().count();
            let sample = *observed.lock().unwrap();
            if ready == 5 && sample.1 == 5 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("five writes never reached the simultaneous staged state");
    std::fs::write(&release, b"release").unwrap();

    let mut results = Vec::new();
    while let Some(result) = tasks.join_next().await {
        results.push(result.unwrap());
    }
    monitor_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    monitor.join().unwrap();
    results.sort_by_key(|(index, _)| *index);
    for (index, result) in results {
        let result = result.unwrap();
        assert_eq!(result.raw_bytes, RAW_BYTES as u64, "host=h{index}");
        assert_eq!(result.sha256, EXPECTED_HASH, "host=h{index}");
        assert_eq!(result.mode, 0o600, "host=h{index}");
        assert!(result.temporary_cleanup_confirmed, "host=h{index}");
        let path = roots[index].join("payload");
        assert_eq!(path.metadata().unwrap().len(), RAW_BYTES as u64);
        assert_eq!(sha256(&std::fs::read(path).unwrap()), EXPECTED_HASH);
    }

    let (peak_rss, max_stages, max_spools, all_stages_secure) = *observed.lock().unwrap();
    let rss_delta = peak_rss.saturating_sub(baseline_rss);
    eprintln!(
        "task5 write RSS sample: baseline={baseline_rss} KiB peak={peak_rss} KiB delta={rss_delta} KiB source_bytes={source_bytes}"
    );
    assert_eq!(max_stages, 5);
    assert!(max_spools <= 10, "max_spools={max_spools}");
    assert!(all_stages_secure);
    assert!(
        rss_delta < RSS_DELTA_CEILING_KIB,
        "baseline={baseline_rss} KiB peak={peak_rss} KiB delta={rss_delta} KiB source_bytes={source_bytes}"
    );
    assert_eq!(ssh_call_count(&ssh_log, "C"), 5);
    assert_eq!(spool_file_count(&runtime_directory), 0);
    for root in &roots {
        assert!(std::fs::read_dir(root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".codex-ssh-bridge.")
        }));
    }
}

#[tokio::test]
async fn five_hosts_successfully_stream_forty_mib_below_rss_bound() {
    use codex_ssh_bridge::config::HostProfile;
    use std::os::unix::fs::PermissionsExt;
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a"), b"x").unwrap();
    let runtime_base = tempfile::TempDir::new().unwrap();
    let ssh_log = runtime_base.path().join("ssh.log");
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let runtime_directory = runtime.directory().to_owned();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let mut config = support::config_with_host("h0", remote.path().to_str().unwrap());
    let profile: HostProfile = config.hosts["h0"].clone();
    for index in 1..5 {
        config.hosts.insert(format!("h{index}"), profile.clone());
    }
    let environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("large-candidates"),
        ),
        (OsString::from("FAKE_SSH_ROOT"), OsString::from("/")),
        (
            OsString::from("FAKE_SSH_CANDIDATE_ROOT"),
            OsString::from("."),
        ),
        (
            OsString::from("FAKE_SSH_FIXED_SLEEP_SECONDS"),
            OsString::from("0.3"),
        ),
        (
            OsString::from("FAKE_SSH_LOG"),
            ssh_log.as_os_str().to_owned(),
        ),
    ]);
    let runner = Arc::new(
        SshRunner::with_executable(
            Arc::new(config),
            runtime,
            store,
            support::fake_ssh_path(),
            environment,
        )
        .unwrap(),
    );
    let bridge = Arc::new(RemoteBridge::new_immediate_for_transport_tests(runner));
    let baseline_rss = resident_kib();
    let monitor_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let monitor_peak = Arc::new(std::sync::Mutex::new((0usize, 0u64, baseline_rss, true)));
    let monitor = {
        let stop = Arc::clone(&monitor_stop);
        let peak = Arc::clone(&monitor_peak);
        let directory = runtime_directory.clone();
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let files = spool_files(&directory);
                let stdout_bytes = files
                    .iter()
                    .filter(|path| path.to_string_lossy().ends_with(".stdout"))
                    .filter_map(|path| path.metadata().ok().map(|metadata| metadata.len()))
                    .max()
                    .unwrap_or(0);
                let rss = resident_kib();
                let mut observed = peak.lock().unwrap();
                observed.0 = observed.0.max(files.len());
                observed.1 = observed.1.max(stdout_bytes);
                observed.2 = observed.2.max(rss);
                drop(observed);
                std::thread::sleep(Duration::from_millis(2));
            }
        })
    };
    let started = std::time::Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..5 {
        let bridge = Arc::clone(&bridge);
        tasks.spawn(async move {
            bridge
                .search(
                    SearchRequest {
                        host: format!("h{index}"),
                        path: Some("/".to_owned()),
                        query: "needle".into(),
                        globs: vec!["accept/**".into()],
                        max_results: None,
                        binary: None,
                    },
                    CancellationToken::new(),
                )
                .await
        });
    }
    let mut completed = 0;
    while let Some(result) = tasks.join_next().await {
        let result = result.unwrap().unwrap();
        assert!(result.matches.is_empty());
        assert!(result.truncated);
        completed += 1;
    }
    monitor_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    monitor.join().unwrap();
    let (observed_files, observed_stdout_bytes, peak_rss, _all_secure) =
        *monitor_peak.lock().unwrap();
    let all_secure = spool_files(&runtime_directory).iter().all(|path| {
        path.metadata()
            .is_ok_and(|metadata| metadata.permissions().mode() & 0o777 == 0o600)
    });
    assert!(
        (2..=10).contains(&observed_files),
        "streaming capture should expose at least one complete spool entry, observed {observed_files}"
    );
    assert_eq!(observed_stdout_bytes, 8 * 1024 * 1024);
    assert!(all_secure);
    assert!(
        peak_rss.saturating_sub(baseline_rss) < 96 * 1024,
        "RSS grew {} KiB",
        peak_rss.saturating_sub(baseline_rss)
    );
    assert_eq!(completed, 5);
    let elapsed = started.elapsed();
    // Exact phase counts below prove concurrency work is not skipped; the release
    // performance_acceptance suite remains the authoritative latency gate.
    assert!(
        elapsed < Duration::from_secs(8),
        "five-host debug stress took {elapsed:?}"
    );
    assert_eq!(ssh_call_count(&ssh_log, "G"), 5);
    assert_eq!(ssh_call_count(&ssh_log, "P"), 5);
    assert_eq!(ssh_call_count(&ssh_log, "R"), 0);
    assert_eq!(ssh_call_count(&ssh_log, "C"), 10);
    assert_eq!(spool_file_count(&runtime_directory), 0);
}

#[tokio::test]
async fn search_all_match_batch_reserves_the_final_command_frame() {
    let remote = tempfile::TempDir::new().unwrap();
    let controls = tempfile::TempDir::new().unwrap();
    let log = controls.path().join("ssh.log");
    let (_runtime, _runner, bridge) = fixture_with_options(
        remote.path(),
        false,
        None,
        &[
            (
                "FAKE_SSH_MODE",
                OsString::from("large-candidates-all-match"),
            ),
            ("FAKE_SSH_CANDIDATE_ROOT", OsString::from(".")),
            ("FAKE_SSH_LOG", log.as_os_str().to_owned()),
        ],
    );
    let result = bridge
        .search(
            SearchRequest {
                host: "dev".to_owned(),
                path: Some("/".to_owned()),
                query: "needle".to_owned(),
                globs: vec!["accept/**".to_owned()],
                max_results: None,
                binary: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(result.truncated);
    assert!(result.matches.is_empty());
    assert_eq!(ssh_call_count(&log, "R"), 0);
    assert_eq!(ssh_call_count(&log, "C"), 2);
}

#[tokio::test]
async fn metadata_list_stat_preserve_order_kinds_and_hidden_depth() {
    use std::os::unix::fs::symlink;
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(remote.path().join("dir/.nested")).unwrap();
    std::fs::write(remote.path().join("file"), b"abc").unwrap();
    symlink("file", remote.path().join("link")).unwrap();
    std::fs::write(remote.path().join("dir/.nested/secret"), b"x").unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    let list = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: Some(3),
                include_hidden: Some(false),
                max_entries: None,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(
        list.entries
            .iter()
            .all(|entry| !entry.relative_path.value.contains(".nested"))
    );
    let stat = bridge
        .stat(
            StatRequest {
                host: "dev".into(),
                paths: vec!["link".into(), "file".into()],
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(
        matches!(&stat.entries[0], StatEntry::Success { metadata, .. } if metadata.kind == RemoteFileKind::Symlink)
    );
    assert!(
        matches!(&stat.entries[1], StatEntry::Success { metadata, .. } if metadata.kind == RemoteFileKind::File && metadata.size == 3)
    );
}

#[tokio::test]
async fn list_hidden_flood_does_not_consume_remote_cap() {
    let remote = tempfile::TempDir::new().unwrap();
    let hidden = remote.path().join(".hidden");
    std::fs::create_dir(&hidden).unwrap();
    for index in 0..200 {
        std::fs::write(
            hidden.join(format!("hidden-{index:04}-{}", "x".repeat(64))),
            b"",
        )
        .unwrap();
    }
    let visible_dir = remote.path().join("visible-dir");
    let nested_hidden = visible_dir.join(".nested-hidden");
    std::fs::create_dir_all(&nested_hidden).unwrap();
    for index in 0..200 {
        std::fs::write(
            nested_hidden.join(format!("hidden-{index:04}-{}", "y".repeat(64))),
            b"",
        )
        .unwrap();
    }
    std::fs::write(visible_dir.join("visible-c"), b"").unwrap();
    std::fs::write(remote.path().join("visible-a"), b"").unwrap();
    std::fs::write(remote.path().join("visible-b"), b"").unwrap();
    let (_runtime, _runner, bridge) = fixture_with_options(remote.path(), false, Some(4096), &[]);
    let visible = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: Some(3),
                include_hidden: Some(false),
                max_entries: Some(4),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        visible
            .entries
            .iter()
            .map(|entry| entry.relative_path.value.as_str())
            .collect::<Vec<_>>(),
        [
            "visible-a",
            "visible-b",
            "visible-dir",
            "visible-dir/visible-c"
        ]
    );
    assert!(!visible.truncated);

    let all = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: Some(3),
                include_hidden: Some(true),
                max_entries: Some(4),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(all.entries.len(), 4);
    assert!(all.truncated);
}

#[tokio::test]
async fn metadata_ten_thousand_lookahead_permission_fifo_socket_and_pre_epoch() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    let remote = tempfile::TempDir::new().unwrap();
    let many = remote.path().join("many");
    std::fs::create_dir(&many).unwrap();
    for index in 0..10_001 {
        std::fs::write(many.join(format!("f{index:05}")), b"").unwrap();
    }
    let fifo = remote.path().join("fifo");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let socket_path = remote.path().join("socket");
    let socket_listener = UnixListener::bind(&socket_path).ok();
    let socket_available = socket_listener.is_some()
        || find_existing_socket()
            .is_some_and(|source| std::fs::hard_link(source, &socket_path).is_ok());
    let old = remote.path().join("old");
    std::fs::write(&old, b"x").unwrap();
    let pre_epoch_supported = std::process::Command::new("touch")
        .args(["-d", "@-1", "--"])
        .arg(&old)
        .status()
        .unwrap()
        .success();
    let denied = remote.path().join("denied");
    std::fs::create_dir(&denied).unwrap();
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o000)).unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    let list = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: Some("many".into()),
                depth: Some(1),
                include_hidden: Some(true),
                max_entries: Some(10_000),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(list.entries.len(), 10_000);
    assert!(list.truncated);
    let mut stat_paths = vec!["fifo".into()];
    if socket_available {
        stat_paths.push("socket".into());
    }
    stat_paths.push("old".into());
    let stat = bridge
        .stat(
            StatRequest {
                host: "dev".into(),
                paths: stat_paths,
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(
        matches!(&stat.entries[0], StatEntry::Success { metadata, .. } if metadata.kind == RemoteFileKind::Fifo)
    );
    let old_index = if socket_available {
        assert!(
            matches!(&stat.entries[1], StatEntry::Success { metadata, .. } if metadata.kind == RemoteFileKind::Socket)
        );
        2
    } else {
        eprintln!(
            "platform skip: sandbox denied AF_UNIX bind and exposed no linkable existing socket"
        );
        1
    };
    if pre_epoch_supported {
        assert!(
            matches!(&stat.entries[old_index], StatEntry::Success { metadata, .. } if metadata.mtime_seconds == -1)
        );
    } else {
        eprintln!("platform skip: filesystem/touch does not support pre-epoch timestamp");
    }
    let effective_uid = std::process::Command::new("id").arg("-u").output().unwrap();
    if effective_uid.stdout != b"0\n" {
        let error = bridge
            .list(
                ListRequest {
                    host: "dev".into(),
                    path: Some("denied".into()),
                    depth: None,
                    include_hidden: None,
                    max_entries: None,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::PermissionDenied);
    } else {
        eprintln!("platform skip: permission denial cannot be asserted as effective uid 0");
    }
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn find_existing_socket() -> Option<std::path::PathBuf> {
    use std::os::unix::fs::FileTypeExt;
    std::fs::read_dir("/tmp")
        .ok()?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("tmux-"))
        .find_map(|entry| {
            let candidate = entry.path().join("default");
            candidate
                .symlink_metadata()
                .ok()
                .filter(|metadata| metadata.file_type().is_socket())
                .map(|_| candidate)
        })
}

#[tokio::test]
async fn read_full_hash_missing_symlink_and_aggregate_truncation() {
    use std::os::unix::fs::symlink;
    let remote = tempfile::TempDir::new().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(outside.path(), b"outside").unwrap();
    symlink(outside.path(), remote.path().join("outside-link")).unwrap();
    std::fs::write(remote.path().join("a"), b"abc").unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    let result = bridge
        .read(
            ReadRequest {
                host: "dev".into(),
                paths: vec!["a".into(), "missing".into(), "outside-link".into()],
                start_line: None,
                max_lines: None,
                max_bytes: Some(8),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(
        matches!(&result.files[0], ReadEntry::Success { sha256, truncated, .. } if sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" && !truncated)
    );
    assert!(
        matches!(&result.files[1], ReadEntry::Error { error, .. } if error.code == EntryErrorCode::NotFound)
    );
    assert!(matches!(&result.files[2], ReadEntry::Success { truncated, .. } if *truncated));
    assert_eq!(result.returned_raw_bytes, 8);
}

#[tokio::test]
async fn read_final_symlink_errors_are_safe_and_follow_the_target() {
    use std::os::unix::fs::symlink;

    let remote = tempfile::TempDir::new().unwrap();
    symlink("missing-target", remote.path().join("dangling")).unwrap();
    let denied_target = remote.path().join("denied-target");
    std::fs::write(&denied_target, b"secret").unwrap();
    symlink("denied-target", remote.path().join("denied-link")).unwrap();
    std::fs::set_permissions(&denied_target, std::fs::Permissions::from_mode(0o000)).unwrap();
    let denied_parent = remote.path().join("denied-parent");
    std::fs::create_dir(&denied_parent).unwrap();
    std::fs::write(denied_parent.join("secret"), b"secret").unwrap();
    std::fs::set_permissions(&denied_parent, std::fs::Permissions::from_mode(0o000)).unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    let result = bridge
        .read(
            ReadRequest {
                host: "dev".into(),
                paths: vec![
                    "dangling".into(),
                    "denied-link".into(),
                    "denied-parent/secret".into(),
                ],
                start_line: None,
                max_lines: None,
                max_bytes: Some(64),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(
        matches!(&result.files[0], ReadEntry::Error { error, .. } if error.code == EntryErrorCode::NotFound)
    );
    let effective_uid = std::process::Command::new("id").arg("-u").output().unwrap();
    if effective_uid.stdout != b"0\n" {
        assert!(
            matches!(&result.files[1], ReadEntry::Error { error, .. } if error.code == EntryErrorCode::PermissionDenied)
        );
        assert!(
            matches!(&result.files[2], ReadEntry::Error { error, .. } if error.code == EntryErrorCode::PermissionDenied)
        );
    } else {
        eprintln!("platform skip: unreadable target cannot be asserted as effective uid 0");
    }
    std::fs::set_permissions(&denied_target, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&denied_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[tokio::test]
async fn read_hash_before_after_race_is_a_contentless_read_conflict() {
    use std::io::Write as _;
    let remote = tempfile::TempDir::new().unwrap();
    let path = remote.path().join("racing");
    std::fs::File::create(&path)
        .unwrap()
        .set_len(128 * 1024 * 1024)
        .unwrap();
    let runtime_base = tempfile::TempDir::new().unwrap();
    let runtime = RuntimePaths::ensure_from_base(runtime_base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let log = runtime_base.path().join("ssh.log");
    let environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (OsString::from("FAKE_SSH_ROOT"), OsString::from("/")),
        (OsString::from("FAKE_SSH_LOG"), log.as_os_str().to_owned()),
    ]);
    let config = Arc::new(support::config_with_host(
        "dev",
        remote.path().to_str().unwrap(),
    ));
    let runner = Arc::new(
        SshRunner::with_executable(
            config,
            runtime,
            store,
            support::fake_ssh_path(),
            environment,
        )
        .unwrap(),
    );
    let bridge = FixtureBridge::new(
        RemoteBridge::new_immediate_for_transport_tests(runner),
        remote.path(),
    );
    let task = tokio::spawn(async move {
        bridge
            .read(
                ReadRequest {
                    host: "dev".into(),
                    paths: vec!["racing".into()],
                    start_line: None,
                    max_lines: Some(1),
                    max_bytes: Some(1),
                },
                CancellationToken::new(),
            )
            .await
    });
    for _ in 0..200 {
        if std::fs::read_to_string(&log).is_ok_and(|value| value.lines().any(|line| line == "C")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
    for _ in 0..200 {
        if task.is_finished() {
            break;
        }
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let result = task.await.unwrap().unwrap();
    assert!(
        matches!(&result.files[0], ReadEntry::Error { error, .. } if error.code == EntryErrorCode::ReadConflict)
    );
    let json = serde_json::to_value(&result.files[0]).unwrap();
    assert!(json.get("content").is_none());
}

#[tokio::test]
async fn search_rg_and_grep_share_literal_glob_and_byte_column_semantics() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("a.txt"), b"xx a.b yy\n").unwrap();
    std::fs::write(remote.path().join("skip.log"), b"a.b\n").unwrap();
    for rg in [false, true] {
        let (_runtime, _runner, bridge) = fixture(remote.path(), rg);
        let result = bridge
            .search(
                SearchRequest {
                    host: "dev".into(),
                    query: "a.b".into(),
                    path: None,
                    globs: vec!["*.txt".into()],
                    max_results: Some(10),
                    binary: Some(false),
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(result.matches.len(), 1, "engine={:?}", result.engine);
        assert_eq!((result.matches[0].line, result.matches[0].column), (1, 4));
        assert_eq!(result.matches[0].relative_path.value, "a.txt");
    }
}

#[tokio::test]
async fn search_globs_are_slash_aware_for_star_question_class_and_double_star() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(remote.path().join("nested")).unwrap();
    for path in [
        "root.txt",
        "nested/a.txt",
        "nested/b.txt",
        "nested/c.txt",
        "nested/ab.txt",
    ] {
        std::fs::write(remote.path().join(path), b"needle\n").unwrap();
    }
    for rg in [false, true] {
        let (_runtime, _runner, bridge) = fixture(remote.path(), rg);
        for (glob, expected) in [
            (
                "*.txt",
                vec![
                    "nested/a.txt",
                    "nested/ab.txt",
                    "nested/b.txt",
                    "nested/c.txt",
                    "root.txt",
                ],
            ),
            (
                "nested/?.txt",
                vec!["nested/a.txt", "nested/b.txt", "nested/c.txt"],
            ),
            ("nested/[ab].txt", vec!["nested/a.txt", "nested/b.txt"]),
            (
                "**/*.txt",
                vec![
                    "nested/a.txt",
                    "nested/ab.txt",
                    "nested/b.txt",
                    "nested/c.txt",
                    "root.txt",
                ],
            ),
        ] {
            let result = bridge
                .search(
                    SearchRequest {
                        host: "dev".into(),
                        query: "needle".into(),
                        path: None,
                        globs: vec![glob.into()],
                        max_results: Some(20),
                        binary: Some(false),
                    },
                    CancellationToken::new(),
                )
                .await
                .unwrap();
            assert_eq!(
                result
                    .matches
                    .iter()
                    .map(|matched| matched.relative_path.value.as_str())
                    .collect::<Vec<_>>(),
                expected,
                "engine={:?}, glob={glob}",
                result.engine
            );
        }
    }
}

#[tokio::test]
async fn search_byte_cap_accepts_complete_prefix_and_rejects_oversized_first_event() {
    let remote = tempfile::TempDir::new().unwrap();
    let mut many = Vec::new();
    for _ in 0..2_000 {
        many.extend_from_slice(b"needle\n");
    }
    std::fs::write(remote.path().join("many"), many).unwrap();
    let (_runtime, _runner, bridge) =
        fixture_with_options(remote.path(), false, Some(4 * 1024), &[]);
    let result = bridge
        .search(
            SearchRequest {
                host: "dev".into(),
                query: "needle".into(),
                path: None,
                globs: vec![],
                max_results: Some(10_000),
                binary: Some(false),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(result.truncated);
    assert!(!result.matches.is_empty(), "{result:?}");

    let oversized = tempfile::TempDir::new().unwrap();
    let mut line = vec![b'x'; 5 * 1024];
    line.extend_from_slice(b"needle\n");
    std::fs::write(oversized.path().join("one"), line).unwrap();
    let (_runtime, _runner, bridge) =
        fixture_with_options(oversized.path(), false, Some(4 * 1024), &[]);
    let error = bridge
        .search(
            SearchRequest {
                host: "dev".into(),
                query: "needle".into(),
                path: None,
                globs: vec![],
                max_results: None,
                binary: Some(false),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ProtocolError);
}

#[tokio::test]
async fn search_real_engine_failure_is_fixed_and_redacted() {
    use std::os::unix::fs::PermissionsExt;
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("secret-name"), b"needle\n").unwrap();
    let bin = tempfile::TempDir::new().unwrap();
    let grep = bin.path().join("grep");
    std::fs::write(
        &grep,
        b"#!/bin/sh\ncase \" $* \" in *codex-probe-grep*|*codex-sentinel-grep*|*/dev/null*) exec /usr/bin/grep \"$@\";; esac\nprintf 'VERY_SECRET_ENGINE_DIAGNOSTIC\\n' >&2\nexit 2\n",
    )
    .unwrap();
    std::fs::set_permissions(&grep, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!("{}:/usr/bin:/bin", bin.path().display()));
    let (_runtime, _runner, bridge) =
        fixture_with_options(remote.path(), false, None, &[("PATH", path)]);
    let error = bridge
        .search(
            SearchRequest {
                host: "dev".into(),
                query: "needle".into(),
                path: None,
                globs: vec![],
                max_results: None,
                binary: Some(false),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RemoteExit);
    assert!(!error.message.contains("VERY_SECRET"));
    assert!(!error.message.contains("secret-name"));
}

#[tokio::test]
async fn list_from_configured_filesystem_root_uses_single_separator() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(remote.path().join("etc")).unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), true);
    let result = bridge
        .list(
            ListRequest {
                host: "dev".into(),
                path: None,
                depth: Some(1),
                include_hidden: Some(true),
                max_entries: Some(10_000),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let etc = result
        .entries
        .iter()
        .find(|entry| entry.relative_path.value == "etc")
        .expect("the filesystem root should contain /etc");
    assert_eq!(
        etc.actual_path,
        value(remote.path().join("etc").to_str().unwrap())
    );
    assert!(
        result
            .entries
            .iter()
            .all(|entry| !entry.actual_path.value.starts_with("//"))
    );
}

#[tokio::test]
async fn search_from_configured_filesystem_root_derives_relative_paths() {
    let remote = tempfile::TempDir::new().unwrap();
    let file = remote.path().join("a");
    std::fs::write(&file, b"needle\n").unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    let result = bridge
        .search(
            SearchRequest {
                host: "dev".into(),
                query: "needle".into(),
                path: Some(remote.path().to_str().unwrap().into()),
                globs: vec![],
                max_results: None,
                binary: Some(false),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.matches.len(), 1);
    assert_eq!(result.matches[0].actual_path.value, file.to_str().unwrap());
    assert_eq!(result.matches[0].relative_path.value, "a");
}

#[tokio::test]
async fn search_basename_glob_matches_nested_files_like_local_search() {
    let remote = tempfile::TempDir::new().unwrap();
    let nested = remote.path().join("src");
    std::fs::create_dir(&nested).unwrap();
    let file = nested.join("module.py");
    std::fs::write(&file, b"import json\n").unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);
    let result = bridge
        .search(
            SearchRequest {
                host: "dev".into(),
                query: "import".into(),
                path: Some(remote.path().to_str().unwrap().into()),
                globs: vec!["*.py".into()],
                max_results: Some(10),
                binary: Some(false),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.matches.len(), 1, "{result:?}");
    assert_eq!(result.matches[0].actual_path.value, file.to_str().unwrap());
    assert_eq!(result.matches[0].relative_path.value, "src/module.py");
}

#[tokio::test]
async fn search_finds_the_only_match_after_the_old_candidate_prefix_bound() {
    let remote = tempfile::TempDir::new().unwrap();
    let prefix = remote.path().join("prefix");
    std::fs::create_dir(&prefix).unwrap();
    let padding = "x".repeat(180);
    for index in 0..700 {
        std::fs::write(prefix.join(format!("{index:04}-{padding}.txt")), b"").unwrap();
    }
    let target = remote.path().join("tail.py");
    std::fs::write(&target, b"CODEX_SEARCH_TAIL_SENTINEL = True\n").unwrap();
    let (_runtime, _runner, bridge) = fixture(remote.path(), false);

    let result = bridge
        .search(
            SearchRequest {
                host: "dev".into(),
                query: "CODEX_SEARCH_TAIL_SENTINEL".into(),
                path: Some(remote.path().to_str().unwrap().into()),
                globs: vec!["*.py".into()],
                max_results: Some(10),
                binary: Some(false),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(result.matches.len(), 1, "{result:?}");
    assert_eq!(
        result.matches[0].actual_path.value,
        target.to_str().unwrap()
    );
    assert_eq!(result.matches[0].relative_path.value, "tail.py");
    assert!(
        !result.truncated,
        "a complete one-match search must not report a candidate-prefix truncation"
    );
}

#[tokio::test]
async fn search_quote_amplification_over_frame_is_request_too_large() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("candidate"), b"x\n").unwrap();
    let (_runtime, _runner, bridge) = fixture_with_options(remote.path(), false, Some(4096), &[]);
    let error = bridge
        .search(
            SearchRequest {
                host: "dev".into(),
                query: "'".repeat(300),
                path: None,
                globs: vec![],
                max_results: None,
                binary: Some(false),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RequestTooLarge);
    assert_task78_fixed_context(&error, remote.path());
}

#[tokio::test]
async fn search_full_prefix_then_exit_two_is_error() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("candidate"), b"needle\n").unwrap();
    let bin = tempfile::TempDir::new().unwrap();
    let grep = bin.path().join("grep");
    std::fs::write(
        &grep,
        b"#!/bin/sh\ncase \" $* \" in *codex-probe-grep*|*codex-sentinel-grep*|*/dev/null*) exec /usr/bin/grep \"$@\";; esac\nfor value do candidate=$value; done\ni=0\nwhile [ \"$i\" -lt 1000 ]; do printf '%s\\000%d:needle\\n' \"$candidate\" \"$((i + 1))\"; i=$((i + 1)); done\nprintf 'VERY_SECRET_LATE_ENGINE_ERROR\\n' >&2\nexit 2\n",
    )
    .unwrap();
    std::fs::set_permissions(&grep, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        bin.path().display()
    ));
    let (_runtime, _runner, bridge) =
        fixture_with_options(remote.path(), false, Some(4096), &[("PATH", path)]);
    let error = bridge
        .search(
            SearchRequest {
                host: "dev".into(),
                query: "needle".into(),
                path: None,
                globs: vec![],
                max_results: Some(10_000),
                binary: Some(false),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RemoteExit);
    assert!(!error.message.contains("VERY_SECRET"));
}

#[tokio::test]
async fn search_unknown_rg_event_is_protocol_error() {
    let remote = tempfile::TempDir::new().unwrap();
    std::fs::write(remote.path().join("candidate"), b"needle\n").unwrap();
    let real_rg = executable_on_path("rg");
    let bin = tempfile::TempDir::new().unwrap();
    let rg = bin.path().join("rg");
    std::fs::write(
        &rg,
        format!(
            "#!/bin/sh\ncase \" $* \" in *codex-probe-rg*|*codex-sentinel-rg*|*/dev/null*) exec {} \"$@\";; esac\nprintf '%s\\n' '{{\"type\":\"mystery\",\"data\":{{}}}}'\nexit 0\n",
            codex_ssh_bridge::quote::shell_word(real_rg.to_str().unwrap()).unwrap()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&rg, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = OsString::from(format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        bin.path().display()
    ));
    let (_runtime, _runner, bridge) =
        fixture_with_options(remote.path(), true, None, &[("PATH", path)]);
    let error = bridge
        .search(
            SearchRequest {
                host: "dev".into(),
                query: "needle".into(),
                path: None,
                globs: vec![],
                max_results: None,
                binary: Some(false),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ProtocolError);
}

#[test]
fn task15_remote_job_requests_validate_exact_boundaries() {
    let valid = RemoteJobStartRequest {
        host: "dev".to_owned(),
        command: "printf ok".to_owned(),
        cwd: "/srv/project".to_owned(),
        shell: RunShell::Bash,
        stdin: None,
        timeout_ms: None,
        label: Some("training".to_owned()),
    };
    assert_eq!(valid.cwd, "/srv/project");
    assert_eq!(valid.label.as_deref(), Some("training"));
    assert_eq!(valid.timeout_ms, None);
}
