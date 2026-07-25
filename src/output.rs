#![allow(
    clippy::result_large_err,
    reason = "Task 1 fixes BridgeResult<T> to an inline BridgeError representation"
)]

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::capability::ShellSelection;
use crate::config::{
    DEFAULT_GLOBAL_SPOOL_QUOTA_BYTES, DEFAULT_RETENTION_SERIALIZATION_JOBS,
    MAX_GLOBAL_SPOOL_QUOTA_BYTES, MAX_RETENTION_SERIALIZATION_JOBS, MAX_SPOOL_ENTRIES,
    MIN_GLOBAL_SPOOL_QUOTA_BYTES,
};
use crate::error::{BridgeError, BridgeResult, ErrorCode};
use crate::ssh::HelperMode;
use crate::ssh::RuntimePaths;
use crate::{MAX_FRAME_BYTES, MAX_OUTPUT_BYTES, MAX_READ_BYTES};

const SPILL_THRESHOLD_BYTES: u64 = 256 * 1024;
const DEFAULT_TTL: Duration = Duration::from_secs(10 * 60);
const READ_BUFFER_BYTES: usize = 64 * 1024;
const UNKNOWN_REFERENCE: &str = "output reference is unknown or expired";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StreamKind {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OutputReference(String);

impl OutputReference {
    pub fn parse(value: &str) -> BridgeResult<Self> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(BridgeError::invalid_argument(UNKNOWN_REFERENCE));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputPage {
    pub bytes: Vec<u8>,
    pub offset: u64,
    pub next_offset: u64,
    pub eof: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct InternalCapturedOutput {
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    pub(crate) stdout_len: u64,
    pub(crate) stderr_len: u64,
    pub(crate) aggregate_bytes: u64,
}

impl InternalCapturedOutput {
    #[cfg(test)]
    pub(crate) fn for_test(directory: &Path, stdout: &[u8], stderr: &[u8]) -> Self {
        let stdout_path = directory.join("cursor.stdout");
        let stderr_path = directory.join("cursor.stderr");
        std::fs::write(&stdout_path, stdout).expect("write cursor stdout fixture");
        std::fs::write(&stderr_path, stderr).expect("write cursor stderr fixture");
        Self {
            stdout_path,
            stderr_path,
            stdout_len: stdout.len() as u64,
            stderr_len: stderr.len() as u64,
            aggregate_bytes: (stdout.len() + stderr.len()) as u64,
        }
    }

    pub(crate) async fn read(
        &self,
        stream: StreamKind,
        offset: u64,
        max_bytes: usize,
    ) -> BridgeResult<OutputPage> {
        if max_bytes == 0 || max_bytes > MAX_FRAME_BYTES + 1 {
            return Err(BridgeError::invalid_argument(
                "internal output page size is invalid",
            ));
        }
        let (path, length) = match stream {
            StreamKind::Stdout => (&self.stdout_path, self.stdout_len),
            StreamKind::Stderr => (&self.stderr_path, self.stderr_len),
        };
        if offset > length {
            return Err(BridgeError::invalid_argument(
                "output offset exceeds stream length",
            ));
        }
        let wanted = usize::try_from((length - offset).min(max_bytes as u64)).map_err(|_| {
            BridgeError::new(
                ErrorCode::ProtocolError,
                "internal output length is invalid",
                false,
            )
        })?;
        let mut bytes = vec![0; wanted];
        if wanted != 0 {
            let mut file = tokio::fs::File::open(path).await.map_err(BridgeError::io)?;
            file.seek(std::io::SeekFrom::Start(offset))
                .await
                .map_err(BridgeError::io)?;
            file.read_exact(&mut bytes).await.map_err(BridgeError::io)?;
        }
        let next_offset = offset.checked_add(bytes.len() as u64).ok_or_else(|| {
            BridgeError::new(
                ErrorCode::ProtocolError,
                "internal output offset overflowed",
                false,
            )
        })?;
        Ok(OutputPage {
            bytes,
            offset,
            next_offset,
            eof: next_offset == length,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputPreview {
    pub head: Vec<u8>,
    pub tail: Vec<u8>,
    pub bytes_seen: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct StderrSignals {
    pub(crate) host_key: bool,
    pub(crate) authentication: bool,
    pub(crate) connect_timeout: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedOutput {
    pub stdout: OutputPreview,
    pub stderr: OutputPreview,
    pub reference: Option<OutputReference>,
    pub aggregate_bytes: u64,
    pub(crate) stderr_signals: StderrSignals,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureLimits {
    pub preview_bytes: usize,
    pub max_output_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutputProvenance {
    pub host: String,
    pub physical_root: String,
    pub shell: ShellSelection,
    pub helper_mode: HelperMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoredAggregateKind {
    Hosts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StoredProvenance {
    Remote(OutputProvenance),
    Aggregate {
        kind: StoredAggregateKind,
        source_count: usize,
    },
}

#[derive(Debug)]
struct ByteQuota {
    limit: u64,
    used: AtomicU64,
}

impl ByteQuota {
    fn new(limit: u64) -> Self {
        Self {
            limit,
            used: AtomicU64::new(0),
        }
    }

    fn try_reserve(&self, bytes: u64) -> bool {
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            let Some(next) = used.checked_add(bytes) else {
                return false;
            };
            if next > self.limit {
                return false;
            }
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(observed) => used = observed,
            }
        }
    }

    fn release(&self, bytes: u64) {
        let previous = self.used.fetch_sub(bytes, Ordering::AcqRel);
        debug_assert!(previous >= bytes);
    }

    #[cfg(test)]
    fn used(&self) -> u64 {
        self.used.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
struct EntrySlot {
    permit: StdMutex<Option<OwnedSemaphorePermit>>,
}

impl EntrySlot {
    fn new() -> Self {
        Self {
            permit: StdMutex::new(None),
        }
    }

    fn with_permit(permit: OwnedSemaphorePermit) -> Self {
        Self {
            permit: StdMutex::new(Some(permit)),
        }
    }

    fn attach(&self, permit: OwnedSemaphorePermit) -> Result<(), OwnedSemaphorePermit> {
        let mut owned = self
            .permit
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if owned.is_some() {
            Err(permit)
        } else {
            *owned = Some(permit);
            Ok(())
        }
    }
}

#[derive(Debug)]
struct FileAccounting {
    quota: Arc<ByteQuota>,
    bytes: AtomicU64,
    _slot: Arc<EntrySlot>,
}

impl FileAccounting {
    fn new(quota: Arc<ByteQuota>, slot: Arc<EntrySlot>) -> Self {
        Self {
            quota,
            bytes: AtomicU64::new(0),
            _slot: slot,
        }
    }

    fn with_reservation(quota: Arc<ByteQuota>, bytes: u64, slot: Arc<EntrySlot>) -> Self {
        Self {
            quota,
            bytes: AtomicU64::new(bytes),
            _slot: slot,
        }
    }

    fn reserve(&self, bytes: u64) -> bool {
        if !self.quota.try_reserve(bytes) {
            return false;
        }
        self.bytes.fetch_add(bytes, Ordering::AcqRel);
        true
    }

    fn release(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let previous = self.bytes.fetch_sub(bytes, Ordering::AcqRel);
        debug_assert!(previous >= bytes);
        self.quota.release(bytes);
    }

    fn shrink_to(&self, actual: u64) {
        let reserved = self.bytes.swap(actual, Ordering::AcqRel);
        debug_assert!(reserved >= actual);
        self.quota.release(reserved - actual);
    }
}

impl Drop for FileAccounting {
    fn drop(&mut self) {
        self.quota.release(self.bytes.load(Ordering::Acquire));
    }
}

#[derive(Debug)]
struct EntryAccounting {
    slot: Arc<EntrySlot>,
    stdout: Arc<FileAccounting>,
    stderr: Option<Arc<FileAccounting>>,
}

impl EntryAccounting {
    fn new(quota: Arc<ByteQuota>) -> Self {
        let slot = Arc::new(EntrySlot::new());
        Self {
            stdout: Arc::new(FileAccounting::new(Arc::clone(&quota), Arc::clone(&slot))),
            stderr: Some(Arc::new(FileAccounting::new(quota, Arc::clone(&slot)))),
            slot,
        }
    }

    fn with_reservation(quota: Arc<ByteQuota>, bytes: u64, permit: OwnedSemaphorePermit) -> Self {
        let slot = Arc::new(EntrySlot::with_permit(permit));
        Self {
            stdout: Arc::new(FileAccounting::with_reservation(
                quota,
                bytes,
                Arc::clone(&slot),
            )),
            stderr: None,
            slot,
        }
    }

    fn file(&self, stream: StreamKind) -> &Arc<FileAccounting> {
        match stream {
            StreamKind::Stdout => &self.stdout,
            StreamKind::Stderr => self.stderr.as_ref().expect("capture has stderr accounting"),
        }
    }

    fn reserve(&self, stream: StreamKind, bytes: u64) -> bool {
        self.file(stream).reserve(bytes)
    }

    fn release(&self, stream: StreamKind, bytes: u64) {
        self.file(stream).release(bytes);
    }

    fn attach_slot(&self, permit: OwnedSemaphorePermit) -> Result<(), OwnedSemaphorePermit> {
        self.slot.attach(permit)
    }

    fn shrink_stdout_to(&self, actual: u64) {
        self.stdout.shrink_to(actual);
    }

    fn shrink_to(&self, stream: StreamKind, actual: u64) {
        self.file(stream).shrink_to(actual);
    }

    fn cleanup_targets(&self, paths: Vec<PathBuf>) -> Vec<CleanupTarget> {
        let mut paths = paths.into_iter();
        let mut targets = Vec::with_capacity(if self.stderr.is_some() { 2 } else { 1 });
        if let Some(path) = paths.next() {
            targets.push(CleanupTarget {
                path,
                _accounting: Some(Arc::clone(&self.stdout)),
            });
        }
        if let (Some(path), Some(stderr)) = (paths.next(), self.stderr.as_ref()) {
            targets.push(CleanupTarget {
                path,
                _accounting: Some(Arc::clone(stderr)),
            });
        }
        targets.extend(paths.map(|path| CleanupTarget {
            path,
            _accounting: None,
        }));
        targets
    }
}

#[derive(Debug, Default)]
struct CleanupState {
    closed: bool,
    paths: Vec<PathBuf>,
    accounting: Vec<Arc<EntryAccounting>>,
    tombstones: Option<Arc<StdMutex<Vec<CleanupTombstone>>>>,
}

#[derive(Debug)]
pub(crate) struct InternalSpoolOwner {
    state: Arc<StdMutex<CleanupState>>,
}

#[derive(Debug, Clone)]
pub(crate) struct InternalSpoolRegistration {
    state: Weak<StdMutex<CleanupState>>,
}

impl InternalSpoolOwner {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new(StdMutex::new(CleanupState::default())),
        }
    }

    pub(crate) fn registration(&self) -> InternalSpoolRegistration {
        InternalSpoolRegistration {
            state: Arc::downgrade(&self.state),
        }
    }
}

impl Drop for InternalSpoolOwner {
    fn drop(&mut self) {
        let (paths, accounting, tombstones) = match self.state.lock() {
            Ok(mut state) => {
                state.closed = true;
                (
                    std::mem::take(&mut state.paths),
                    std::mem::take(&mut state.accounting),
                    state.tombstones.take(),
                )
            }
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.closed = true;
                (
                    std::mem::take(&mut state.paths),
                    std::mem::take(&mut state.accounting),
                    state.tombstones.take(),
                )
            }
        };
        if let Some(tombstones) = tombstones {
            cleanup_paths(paths, accounting, &tombstones);
        } else {
            for path in paths {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

impl InternalSpoolRegistration {
    pub(crate) fn register(&self, path: PathBuf) -> BridgeResult<()> {
        let Some(state) = self.state.upgrade() else {
            let _ = std::fs::remove_file(&path);
            return Err(BridgeError::new(
                ErrorCode::Cancelled,
                "internal output owner was dropped",
                false,
            ));
        };
        let mut state = state.lock().map_err(|_| {
            BridgeError::new(
                ErrorCode::Io,
                "internal output cleanup lock poisoned",
                false,
            )
        })?;
        if state.closed {
            drop(state);
            let _ = std::fs::remove_file(&path);
            return Err(BridgeError::new(
                ErrorCode::Cancelled,
                "internal output owner was dropped",
                false,
            ));
        }
        state.paths.push(path);
        Ok(())
    }

    fn register_accounting(
        &self,
        accounting: Arc<EntryAccounting>,
        tombstones: Arc<StdMutex<Vec<CleanupTombstone>>>,
    ) -> BridgeResult<()> {
        let Some(state) = self.state.upgrade() else {
            return Err(BridgeError::new(
                ErrorCode::Cancelled,
                "internal output owner was dropped",
                false,
            ));
        };
        let mut state = state.lock().map_err(|_| {
            BridgeError::new(
                ErrorCode::Io,
                "internal output cleanup lock poisoned",
                false,
            )
        })?;
        if state.closed {
            return Err(BridgeError::new(
                ErrorCode::Cancelled,
                "internal output owner was dropped",
                false,
            ));
        }
        state.accounting.push(accounting);
        state.tombstones = Some(tombstones);
        Ok(())
    }
}

#[derive(Debug)]
struct SpoolEntry {
    stdout_path: PathBuf,
    stderr_path: Option<PathBuf>,
    stdout_len: u64,
    stderr_len: u64,
    expires_at: Instant,
    provenance: Option<StoredProvenance>,
    accounting: Option<Arc<EntryAccounting>>,
}

#[derive(Debug)]
struct CleanupTombstone {
    targets: Vec<CleanupTarget>,
}

#[derive(Debug)]
struct CleanupTarget {
    path: PathBuf,
    _accounting: Option<Arc<FileAccounting>>,
}

#[derive(Debug)]
pub struct OutputStore {
    spool_directory: tempfile::TempDir,
    ttl: Duration,
    entries: Arc<StdMutex<HashMap<String, SpoolEntry>>>,
    quota: Arc<ByteQuota>,
    entry_slots: Arc<Semaphore>,
    retention_jobs: Arc<Semaphore>,
    tombstones: Arc<StdMutex<Vec<CleanupTombstone>>>,
}

impl OutputStore {
    pub fn new(runtime: &RuntimePaths) -> BridgeResult<Self> {
        Self::with_ttl(runtime, DEFAULT_TTL)
    }

    pub fn with_ttl(runtime: &RuntimePaths, ttl: Duration) -> BridgeResult<Self> {
        Self::with_ttl_and_limits(
            runtime,
            ttl,
            DEFAULT_GLOBAL_SPOOL_QUOTA_BYTES,
            DEFAULT_RETENTION_SERIALIZATION_JOBS,
        )
    }

    pub fn with_limits(
        runtime: &RuntimePaths,
        global_spool_quota_bytes: u64,
        retention_serialization_jobs: usize,
    ) -> BridgeResult<Self> {
        Self::with_ttl_and_limits(
            runtime,
            DEFAULT_TTL,
            global_spool_quota_bytes,
            retention_serialization_jobs,
        )
    }

    pub fn with_ttl_and_limits(
        runtime: &RuntimePaths,
        ttl: Duration,
        global_spool_quota_bytes: u64,
        retention_serialization_jobs: usize,
    ) -> BridgeResult<Self> {
        if ttl.is_zero() || ttl > DEFAULT_TTL {
            return Err(BridgeError::invalid_argument(
                "output reference TTL must be between one nanosecond and ten minutes",
            ));
        }
        if !(MIN_GLOBAL_SPOOL_QUOTA_BYTES..=MAX_GLOBAL_SPOOL_QUOTA_BYTES)
            .contains(&global_spool_quota_bytes)
        {
            return Err(BridgeError::invalid_argument(
                "global spool quota is outside the compiled bounds",
            ));
        }
        if retention_serialization_jobs == 0
            || retention_serialization_jobs > MAX_RETENTION_SERIALIZATION_JOBS
        {
            return Err(BridgeError::invalid_argument(
                "retention serialization job count is outside the compiled bounds",
            ));
        }
        let spool_directory = tempfile::Builder::new()
            .prefix("output-")
            .tempdir_in(runtime.directory())
            .map_err(BridgeError::io)?;
        std::fs::set_permissions(
            spool_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .map_err(BridgeError::io)?;
        Ok(Self {
            spool_directory,
            ttl,
            entries: Arc::new(StdMutex::new(HashMap::new())),
            quota: Arc::new(ByteQuota::new(global_spool_quota_bytes)),
            entry_slots: Arc::new(Semaphore::new(MAX_SPOOL_ENTRIES)),
            retention_jobs: Arc::new(Semaphore::new(retention_serialization_jobs)),
            tombstones: Arc::new(StdMutex::new(Vec::new())),
        })
    }

    pub(crate) async fn retain_serialized_detail<T: Serialize + Send + 'static>(
        &self,
        provenance: StoredProvenance,
        owned: T,
        cancel: CancellationToken,
    ) -> BridgeResult<OutputReference> {
        retry_tombstones(&self.tombstones);
        let _job = Arc::clone(&self.retention_jobs)
            .try_acquire_owned()
            .map_err(|_| retention_unavailable())?;
        let slot = Arc::clone(&self.entry_slots)
            .try_acquire_owned()
            .map_err(|_| retention_unavailable())?;
        if !self.quota.try_reserve(MAX_OUTPUT_BYTES) {
            return Err(retention_unavailable());
        }
        let accounting = Arc::new(EntryAccounting::with_reservation(
            Arc::clone(&self.quota),
            MAX_OUTPUT_BYTES,
            slot,
        ));
        if cancel.is_cancelled() {
            return Err(retention_cancelled());
        }

        let (token, path, file) = create_detail_file(self.spool_directory.path())?;
        let worker_cancel = cancel.child_token();
        let actual_written = Arc::new(AtomicU64::new(0));
        let (sender, receiver) = oneshot::channel();
        let handle = match std::thread::Builder::new()
            .name("codex-retention-serializer".to_owned())
            .spawn({
                let worker_cancel = worker_cancel.clone();
                let actual_written = Arc::clone(&actual_written);
                move || {
                    let mut writer = CappedDetailWriter::new(file, worker_cancel, actual_written);
                    let result = match serde_json::to_writer(&mut writer, &owned) {
                        Ok(()) => writer.finish(),
                        Err(_) if writer.cancel.is_cancelled() => Err(retention_cancelled()),
                        Err(_) => Err(retention_serialization_failed()),
                    };
                    let _ = sender.send(result);
                }
            }) {
            Ok(handle) => handle,
            Err(error) => {
                accounting.shrink_stdout_to(0);
                cleanup_paths(vec![path], vec![accounting], &self.tombstones);
                return Err(BridgeError::io(error));
            }
        };
        let guard = SerializationJoinGuard::new(
            handle,
            worker_cancel,
            path,
            accounting,
            actual_written,
            Arc::clone(&self.tombstones),
        );
        let serialization = receiver
            .await
            .unwrap_or_else(|_| Err(retention_serialization_failed()));
        let (path, length, accounting) = guard.finish(serialization)?;
        if cancel.is_cancelled() {
            cleanup_paths(vec![path], vec![accounting], &self.tombstones);
            return Err(retention_cancelled());
        }
        let expires_at = Instant::now() + self.ttl;
        self.entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(
                token.clone(),
                SpoolEntry {
                    stdout_path: path,
                    stderr_path: None,
                    stdout_len: length,
                    stderr_len: 0,
                    expires_at,
                    provenance: Some(provenance),
                    accounting: Some(accounting),
                },
            );
        schedule_expiry(
            Arc::clone(&self.entries),
            Arc::clone(&self.tombstones),
            token.clone(),
            expires_at,
        );
        Ok(OutputReference(token))
    }

    pub(crate) async fn retain_bytes(
        &self,
        provenance: StoredProvenance,
        owned: Vec<u8>,
        cancel: CancellationToken,
    ) -> BridgeResult<OutputReference> {
        retry_tombstones(&self.tombstones);
        let _job = Arc::clone(&self.retention_jobs)
            .try_acquire_owned()
            .map_err(|_| retention_unavailable())?;
        let slot = Arc::clone(&self.entry_slots)
            .try_acquire_owned()
            .map_err(|_| retention_unavailable())?;
        if !self.quota.try_reserve(MAX_OUTPUT_BYTES) {
            return Err(retention_unavailable());
        }
        let accounting = Arc::new(EntryAccounting::with_reservation(
            Arc::clone(&self.quota),
            MAX_OUTPUT_BYTES,
            slot,
        ));
        if cancel.is_cancelled() {
            return Err(retention_cancelled());
        }

        let (token, path, file) = create_detail_file(self.spool_directory.path())?;
        let worker_cancel = cancel.child_token();
        let actual_written = Arc::new(AtomicU64::new(0));
        let (sender, receiver) = oneshot::channel();
        let handle = match std::thread::Builder::new()
            .name("codex-retention-writer".to_owned())
            .spawn({
                let worker_cancel = worker_cancel.clone();
                let actual_written = Arc::clone(&actual_written);
                move || {
                    let mut writer = CappedDetailWriter::new(file, worker_cancel, actual_written);
                    let result = match std::io::Write::write_all(&mut writer, &owned) {
                        Ok(()) => writer.finish(),
                        Err(_) if writer.cancel.is_cancelled() => Err(retention_cancelled()),
                        Err(_) => Err(retention_serialization_failed()),
                    };
                    let _ = sender.send(result);
                }
            }) {
            Ok(handle) => handle,
            Err(error) => {
                accounting.shrink_stdout_to(0);
                cleanup_paths(vec![path], vec![accounting], &self.tombstones);
                return Err(BridgeError::io(error));
            }
        };
        let guard = SerializationJoinGuard::new(
            handle,
            worker_cancel,
            path,
            accounting,
            actual_written,
            Arc::clone(&self.tombstones),
        );
        let retention = receiver
            .await
            .unwrap_or_else(|_| Err(retention_serialization_failed()));
        let (path, length, accounting) = guard.finish(retention)?;
        if cancel.is_cancelled() {
            cleanup_paths(vec![path], vec![accounting], &self.tombstones);
            return Err(retention_cancelled());
        }
        let expires_at = Instant::now() + self.ttl;
        self.entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(
                token.clone(),
                SpoolEntry {
                    stdout_path: path,
                    stderr_path: None,
                    stdout_len: length,
                    stderr_len: 0,
                    expires_at,
                    provenance: Some(provenance),
                    accounting: Some(accounting),
                },
            );
        schedule_expiry(
            Arc::clone(&self.entries),
            Arc::clone(&self.tombstones),
            token.clone(),
            expires_at,
        );
        Ok(OutputReference(token))
    }

    pub async fn capture<Stdout, Stderr>(
        &self,
        stdout: Stdout,
        stderr: Stderr,
        limits: CaptureLimits,
        cancel: CancellationToken,
    ) -> BridgeResult<CapturedOutput>
    where
        Stdout: AsyncRead + Unpin + Send + 'static,
        Stderr: AsyncRead + Unpin + Send + 'static,
    {
        self.capture_with_limit_signal(stdout, stderr, limits, cancel, CancellationToken::new())
            .await
    }

    pub(crate) async fn capture_with_limit_signal<Stdout, Stderr>(
        &self,
        stdout: Stdout,
        stderr: Stderr,
        limits: CaptureLimits,
        cancel: CancellationToken,
        output_limit: CancellationToken,
    ) -> BridgeResult<CapturedOutput>
    where
        Stdout: AsyncRead + Unpin + Send + 'static,
        Stderr: AsyncRead + Unpin + Send + 'static,
    {
        let sink = self
            .capture_sink(stdout, stderr, limits, cancel, output_limit, None)
            .await?;
        sink.finish(self).await
    }

    pub(crate) async fn capture_internal<Stdout, Stderr>(
        &self,
        stdout: Stdout,
        stderr: Stderr,
        limits: CaptureLimits,
        cancel: CancellationToken,
        output_limit: CancellationToken,
        registration: InternalSpoolRegistration,
    ) -> BridgeResult<InternalCapturedOutput>
    where
        Stdout: AsyncRead + Unpin + Send + 'static,
        Stderr: AsyncRead + Unpin + Send + 'static,
    {
        let sink = self
            .capture_sink(
                stdout,
                stderr,
                limits,
                cancel,
                output_limit,
                Some(registration),
            )
            .await?;
        sink.finish_internal().await
    }

    async fn capture_sink<Stdout, Stderr>(
        &self,
        stdout: Stdout,
        stderr: Stderr,
        limits: CaptureLimits,
        cancel: CancellationToken,
        output_limit: CancellationToken,
        registration: Option<InternalSpoolRegistration>,
    ) -> BridgeResult<OutputSink>
    where
        Stdout: AsyncRead + Unpin + Send + 'static,
        Stderr: AsyncRead + Unpin + Send + 'static,
    {
        let _profile = crate::bridge_profile_span!(crate::profile::ProfileEvent {
            phase: "output_capture",
            host: None,
            request_id: None,
            class: None,
            elapsed_us: 0,
            bytes: None,
        });
        if limits.preview_bytes == 0
            || limits.preview_bytes > MAX_FRAME_BYTES
            || limits.max_output_bytes == 0
            || limits.max_output_bytes > MAX_OUTPUT_BYTES
        {
            return Err(BridgeError::invalid_argument(
                "output capture limits exceed the compiled bounds",
            ));
        }
        if cancel.is_cancelled() {
            return Err(capture_cancelled(0));
        }

        let (sender, mut receiver) = mpsc::channel(8);
        let mut stdout_task =
            tokio::spawn(drain_stream(stdout, StreamKind::Stdout, sender.clone()));
        let mut stderr_task = tokio::spawn(drain_stream(stderr, StreamKind::Stderr, sender));
        let mut sink = OutputSink::new(
            limits.preview_bytes,
            limits.max_output_bytes,
            Arc::new(EntryAccounting::new(Arc::clone(&self.quota))),
            Arc::clone(&self.entry_slots),
            Arc::clone(&self.tombstones),
        );
        if let Some(registration) = registration {
            sink.start_spooling(self.spool_directory.path()).await?;
            let RetainedOutput::Spool(spool) = &sink.retained else {
                unreachable!()
            };
            registration.register(spool.stdout_path.clone())?;
            registration.register(spool.stderr_path.clone())?;
            registration
                .register_accounting(Arc::clone(&sink.accounting), Arc::clone(&self.tombstones))?;
        }
        let mut finished_streams = 0;

        while finished_streams != 2 {
            let event = tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    abort_drains(&mut stdout_task, &mut stderr_task).await;
                    sink.cleanup_incomplete();
                    return Err(capture_cancelled(sink.aggregate_bytes));
                }
                event = receiver.recv() => event,
            };
            match event {
                Some(StreamEvent::Bytes { stream, bytes }) => {
                    if let Err(error) = sink
                        .append(self.spool_directory.path(), stream, &bytes)
                        .await
                    {
                        if error.code == ErrorCode::OutputLimit {
                            output_limit.cancel();
                        }
                        abort_drains(&mut stdout_task, &mut stderr_task).await;
                        sink.cleanup_incomplete();
                        return Err(error);
                    }
                }
                Some(StreamEvent::Finished { error: Some(error) }) => {
                    abort_drains(&mut stdout_task, &mut stderr_task).await;
                    sink.cleanup_incomplete();
                    return Err(BridgeError::io(error));
                }
                Some(StreamEvent::Finished { error: None }) => {
                    finished_streams += 1;
                }
                None => break,
            }
        }
        if let Err(error) = stdout_task.await {
            stderr_task.abort();
            let _ = stderr_task.await;
            sink.cleanup_incomplete();
            return Err(join_error(error));
        }
        if let Err(error) = stderr_task.await {
            sink.cleanup_incomplete();
            return Err(join_error(error));
        }
        Ok(sink)
    }

    pub async fn read(
        &self,
        reference: &OutputReference,
        stream: StreamKind,
        offset: u64,
        max_bytes: usize,
    ) -> BridgeResult<OutputPage> {
        retry_tombstones(&self.tombstones);
        if !(1..=MAX_READ_BYTES).contains(&max_bytes) {
            return Err(BridgeError::invalid_argument(format!(
                "max_bytes must be between 1 and {MAX_READ_BYTES}"
            )));
        }

        let (file, length, _lease) = self.open_independent(reference, stream, offset)?;

        let wanted = (length - offset).min(max_bytes as u64) as usize;
        let mut bytes = vec![0; wanted];
        if wanted != 0 {
            let mut file = tokio::fs::File::from_std(file);
            file.seek(std::io::SeekFrom::Start(offset))
                .await
                .map_err(BridgeError::io)?;
            file.read_exact(&mut bytes).await.map_err(BridgeError::io)?;
        }
        let next_offset = offset + bytes.len() as u64;
        Ok(OutputPage {
            bytes,
            offset,
            next_offset,
            eof: next_offset == length,
        })
    }

    fn open_independent(
        &self,
        reference: &OutputReference,
        stream: StreamKind,
        offset: u64,
    ) -> BridgeResult<(std::fs::File, u64, Option<Arc<EntryAccounting>>)> {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if entries
            .get(reference.as_str())
            .is_some_and(|entry| entry.expires_at <= now)
        {
            let entry = entries
                .remove(reference.as_str())
                .expect("entry was present");
            cleanup_entry(entry, &self.tombstones);
            return Err(unknown_reference());
        }
        let entry = entries
            .get(reference.as_str())
            .ok_or_else(unknown_reference)?;
        let (path, length) = match stream {
            StreamKind::Stdout => (&entry.stdout_path, entry.stdout_len),
            StreamKind::Stderr => (
                entry.stderr_path.as_ref().ok_or_else(unknown_reference)?,
                entry.stderr_len,
            ),
        };
        if offset > length {
            return Err(BridgeError::invalid_argument(
                "output offset exceeds stream length",
            ));
        }
        // Opening precedes lease publication while the entry lock is held.
        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|_| unknown_reference())?;
        let lease = entry.accounting.clone();
        Ok((file, length, lease))
    }

    pub(crate) async fn discard(&self, captured: &CapturedOutput) {
        retry_tombstones(&self.tombstones);
        let Some(reference) = &captured.reference else {
            return;
        };
        let entry = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(reference.as_str());
        if let Some(entry) = entry {
            cleanup_entry(entry, &self.tombstones);
        }
    }

    pub(crate) async fn set_provenance(
        &self,
        captured: &CapturedOutput,
        provenance: OutputProvenance,
    ) {
        if let Some(reference) = &captured.reference
            && let Some(entry) = self
                .entries
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .get_mut(reference.as_str())
        {
            entry.provenance = Some(StoredProvenance::Remote(provenance));
        }
    }

    pub(crate) async fn provenance(
        &self,
        reference: &OutputReference,
    ) -> BridgeResult<StoredProvenance> {
        self.entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(reference.as_str())
            .and_then(|entry| entry.provenance.clone())
            .ok_or_else(unknown_reference)
    }
}

impl Drop for OutputStore {
    fn drop(&mut self) {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .drain()
            .map(|(_, entry)| entry)
            .collect::<Vec<_>>();
        for entry in entries {
            cleanup_entry(entry, &self.tombstones);
        }
        for _ in 0..3 {
            retry_tombstones(&self.tombstones);
            if self
                .tombstones
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty()
            {
                break;
            }
        }
    }
}

fn join_error(error: tokio::task::JoinError) -> BridgeError {
    BridgeError::new(
        ErrorCode::Io,
        format!("output drain task failed: {error}"),
        false,
    )
}

fn unknown_reference() -> BridgeError {
    BridgeError::invalid_argument(UNKNOWN_REFERENCE)
}

fn cleanup_entry(entry: SpoolEntry, tombstones: &Arc<StdMutex<Vec<CleanupTombstone>>>) {
    let mut paths = vec![entry.stdout_path];
    if let Some(stderr_path) = entry.stderr_path {
        paths.push(stderr_path);
    }
    cleanup_paths(paths, entry.accounting.into_iter().collect(), tombstones);
}

fn cleanup_paths(
    paths: Vec<PathBuf>,
    accounting: Vec<Arc<EntryAccounting>>,
    tombstones: &Arc<StdMutex<Vec<CleanupTombstone>>>,
) {
    let mut paths = paths.into_iter();
    let mut targets = Vec::new();
    for accounting in accounting {
        let count = if accounting.stderr.is_some() { 2 } else { 1 };
        let owned_paths = paths.by_ref().take(count).collect();
        targets.extend(accounting.cleanup_targets(owned_paths));
    }
    targets.extend(paths.map(|path| CleanupTarget {
        path,
        _accounting: None,
    }));
    cleanup_targets(targets, tombstones);
}

fn cleanup_targets(targets: Vec<CleanupTarget>, tombstones: &Arc<StdMutex<Vec<CleanupTombstone>>>) {
    let failed = targets
        .into_iter()
        .filter(|target| match std::fs::remove_file(&target.path) {
            Ok(()) => false,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(_) => true,
        })
        .collect::<Vec<_>>();
    if failed.is_empty() {
        return;
    }
    tombstones
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .push(CleanupTombstone { targets: failed });
}

fn retry_tombstones(tombstones: &Arc<StdMutex<Vec<CleanupTombstone>>>) {
    let mut tombstones = tombstones.lock().unwrap_or_else(|error| error.into_inner());
    let mut remaining = Vec::new();
    for mut tombstone in tombstones.drain(..) {
        tombstone
            .targets
            .retain(|target| match std::fs::remove_file(&target.path) {
                Ok(()) => false,
                Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                Err(_) => true,
            });
        if !tombstone.targets.is_empty() {
            remaining.push(tombstone);
        }
    }
    *tombstones = remaining;
}

fn retention_unavailable() -> BridgeError {
    BridgeError::new(
        ErrorCode::OutputLimit,
        "result retention capacity is unavailable",
        true,
    )
}

fn retention_cancelled() -> BridgeError {
    BridgeError::new(
        ErrorCode::Cancelled,
        "result retention was cancelled",
        false,
    )
}

fn retention_serialization_failed() -> BridgeError {
    BridgeError::new(
        ErrorCode::Io,
        "result retention serialization failed",
        false,
    )
}

struct SerializationJoinGuard {
    handle: Option<std::thread::JoinHandle<()>>,
    cancel: CancellationToken,
    path: Option<PathBuf>,
    accounting: Option<Arc<EntryAccounting>>,
    actual_written: Arc<AtomicU64>,
    tombstones: Arc<StdMutex<Vec<CleanupTombstone>>>,
}

impl SerializationJoinGuard {
    fn new(
        handle: std::thread::JoinHandle<()>,
        cancel: CancellationToken,
        path: PathBuf,
        accounting: Arc<EntryAccounting>,
        actual_written: Arc<AtomicU64>,
        tombstones: Arc<StdMutex<Vec<CleanupTombstone>>>,
    ) -> Self {
        Self {
            handle: Some(handle),
            cancel,
            path: Some(path),
            accounting: Some(accounting),
            actual_written,
            tombstones,
        }
    }

    fn finish(
        mut self,
        result: BridgeResult<u64>,
    ) -> BridgeResult<(PathBuf, u64, Arc<EntryAccounting>)> {
        let joined = self
            .handle
            .take()
            .expect("serializer join handle is owned")
            .join();
        let result = if joined.is_err() {
            Err(retention_serialization_failed())
        } else {
            result
        };
        self.reconcile_accounting();
        match result {
            Ok(length) => Ok((
                self.path.take().expect("serializer path is owned"),
                length,
                self.accounting
                    .take()
                    .expect("serializer accounting is owned"),
            )),
            Err(error) => {
                self.cleanup();
                Err(error)
            }
        }
    }

    fn cleanup(&mut self) {
        self.reconcile_accounting();
        let paths = self.path.take().into_iter().collect();
        let accounting = self.accounting.take().into_iter().collect();
        cleanup_paths(paths, accounting, &self.tombstones);
    }

    fn reconcile_accounting(&self) {
        if let Some(accounting) = &self.accounting {
            accounting.shrink_stdout_to(self.actual_written.load(Ordering::Acquire));
        }
    }
}

impl Drop for SerializationJoinGuard {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.cleanup();
    }
}

struct CappedDetailWriter {
    file: std::fs::File,
    cancel: CancellationToken,
    bytes: u64,
    actual_written: Arc<AtomicU64>,
}

impl CappedDetailWriter {
    fn new(file: std::fs::File, cancel: CancellationToken, actual_written: Arc<AtomicU64>) -> Self {
        Self {
            file,
            cancel,
            bytes: 0,
            actual_written,
        }
    }

    fn finish(mut self) -> BridgeResult<u64> {
        if self.cancel.is_cancelled() {
            return Err(retention_cancelled());
        }
        std::io::Write::flush(&mut self.file).map_err(BridgeError::io)?;
        Ok(self.bytes)
    }
}

impl std::io::Write for CappedDetailWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < buffer.len() {
            if self.cancel.is_cancelled() {
                return Err(io::Error::other("retention cancelled"));
            }
            let remaining = MAX_OUTPUT_BYTES.saturating_sub(self.bytes);
            if remaining == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::StorageFull,
                    "retention limit exceeded",
                ));
            }
            let count = (buffer.len() - written)
                .min(READ_BUFFER_BYTES)
                .min(remaining as usize);
            match std::io::Write::write(&mut self.file, &buffer[written..written + count])? {
                0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write retained detail",
                    ));
                }
                count => {
                    self.bytes += count as u64;
                    written += count;
                    self.actual_written.store(self.bytes, Ordering::Release);
                }
            }
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        std::io::Write::flush(&mut self.file)
    }
}

fn create_detail_file(directory: &Path) -> BridgeResult<(String, PathBuf, std::fs::File)> {
    loop {
        let token = random_token();
        let path = directory.join(format!("{token}.stdout"));
        match create_private_file(&path) {
            Ok(file) => return Ok((token, path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(BridgeError::io(error)),
        }
    }
}

enum StreamEvent {
    Bytes { stream: StreamKind, bytes: Vec<u8> },
    Finished { error: Option<io::Error> },
}

async fn drain_stream<R>(mut reader: R, stream: StreamKind, sender: mpsc::Sender<StreamEvent>)
where
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0; READ_BUFFER_BYTES];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => {
                let _ = sender.send(StreamEvent::Finished { error: None }).await;
                return;
            }
            Ok(count) => {
                if sender
                    .send(StreamEvent::Bytes {
                        stream,
                        bytes: buffer[..count].to_vec(),
                    })
                    .await
                    .is_err()
                {
                    return;
                }
            }
            Err(error) => {
                let _ = sender
                    .send(StreamEvent::Finished { error: Some(error) })
                    .await;
                return;
            }
        }
    }
}

async fn abort_drains(
    stdout: &mut tokio::task::JoinHandle<()>,
    stderr: &mut tokio::task::JoinHandle<()>,
) {
    stdout.abort();
    stderr.abort();
    let _ = stdout.await;
    let _ = stderr.await;
}

fn capture_cancelled(bytes_seen: u64) -> BridgeError {
    let mut error = BridgeError::new(ErrorCode::Cancelled, "output capture was cancelled", false);
    error.details.bytes_seen = Some(bytes_seen);
    error
}

struct OutputSink {
    max_output_bytes: u64,
    aggregate_bytes: u64,
    stdout: PreviewSink,
    stderr: PreviewSink,
    retained: RetainedOutput,
    stderr_scanner: DiagnosticScanner,
    accounting: Arc<EntryAccounting>,
    entry_slots: Arc<Semaphore>,
    tombstones: Arc<StdMutex<Vec<CleanupTombstone>>>,
}

impl OutputSink {
    fn new(
        preview_bytes: usize,
        max_output_bytes: u64,
        accounting: Arc<EntryAccounting>,
        entry_slots: Arc<Semaphore>,
        tombstones: Arc<StdMutex<Vec<CleanupTombstone>>>,
    ) -> Self {
        // The aggregate budget is deterministically divided between streams,
        // then each stream allocation is divided between its head and tail.
        let stdout_budget = preview_bytes / 2;
        let stderr_budget = preview_bytes - stdout_budget;
        Self {
            max_output_bytes,
            aggregate_bytes: 0,
            stdout: PreviewSink::new(stdout_budget),
            stderr: PreviewSink::new(stderr_budget),
            retained: RetainedOutput::Memory {
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
            stderr_scanner: DiagnosticScanner::default(),
            accounting,
            entry_slots,
            tombstones,
        }
    }

    async fn append(
        &mut self,
        spool_directory: &Path,
        stream: StreamKind,
        bytes: &[u8],
    ) -> BridgeResult<()> {
        let remaining = self.max_output_bytes - self.aggregate_bytes;
        if bytes.len() as u64 > remaining {
            let allowed = remaining as usize;
            if allowed != 0 {
                self.append_allowed(spool_directory, stream, &bytes[..allowed])
                    .await?;
            }
            self.aggregate_bytes = self.max_output_bytes + 1;
            self.cleanup_incomplete();
            let mut error = BridgeError::new(
                ErrorCode::OutputLimit,
                "command output exceeded the configured limit",
                false,
            );
            error.details.bytes_seen = Some(self.aggregate_bytes);
            return Err(error);
        }
        self.append_allowed(spool_directory, stream, bytes).await
    }

    async fn append_allowed(
        &mut self,
        spool_directory: &Path,
        stream: StreamKind,
        bytes: &[u8],
    ) -> BridgeResult<()> {
        if !self.accounting.reserve(stream, bytes.len() as u64) {
            let mut error = BridgeError::new(
                ErrorCode::OutputLimit,
                "global output spool quota is exhausted",
                false,
            );
            error.details.bytes_seen = Some(self.aggregate_bytes.saturating_add(1));
            return Err(error);
        }
        if stream == StreamKind::Stderr {
            self.stderr_scanner.push(bytes);
        }
        match stream {
            StreamKind::Stdout => self.stdout.push(bytes),
            StreamKind::Stderr => self.stderr.push(bytes),
        }

        let next_aggregate = self.aggregate_bytes + bytes.len() as u64;
        if next_aggregate > SPILL_THRESHOLD_BYTES
            && matches!(self.retained, RetainedOutput::Memory { .. })
        {
            self.start_spooling(spool_directory).await?;
        }
        self.retained.write(stream, bytes).await?;
        self.aggregate_bytes = next_aggregate;
        Ok(())
    }

    async fn start_spooling(&mut self, directory: &Path) -> BridgeResult<()> {
        let (stdout_bytes, stderr_bytes) = match std::mem::replace(
            &mut self.retained,
            RetainedOutput::Memory {
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
        ) {
            RetainedOutput::Memory { stdout, stderr } => (stdout, stderr),
            retained @ RetainedOutput::Spool(_) => {
                self.retained = retained;
                return Ok(());
            }
        };
        let slot = Arc::clone(&self.entry_slots)
            .try_acquire_owned()
            .map_err(|_| {
                BridgeError::new(
                    ErrorCode::OutputLimit,
                    "output spool entry limit is exhausted",
                    false,
                )
            })?;
        self.accounting
            .attach_slot(slot)
            .map_err(|_| BridgeError::new(ErrorCode::Io, "output slot was duplicated", false))?;
        let mut spool = create_spool(
            directory,
            Arc::clone(&self.accounting),
            Arc::clone(&self.tombstones),
        )?;
        let (stdout_result, stdout_written) =
            write_all_counted(&mut spool.stdout, &stdout_bytes).await;
        if let Err(error) = stdout_result {
            self.accounting
                .shrink_to(StreamKind::Stdout, stdout_written as u64);
            self.accounting.shrink_to(StreamKind::Stderr, 0);
            return Err(BridgeError::io(error));
        }
        let (stderr_result, stderr_written) = write_all_counted(
            spool.stderr.as_mut().expect("completed pending spool"),
            &stderr_bytes,
        )
        .await;
        if let Err(error) = stderr_result {
            self.accounting
                .shrink_to(StreamKind::Stdout, stdout_written as u64);
            self.accounting
                .shrink_to(StreamKind::Stderr, stderr_written as u64);
            return Err(BridgeError::io(error));
        }
        self.retained = RetainedOutput::Spool(Box::new(spool));
        Ok(())
    }

    fn cleanup_incomplete(&mut self) {
        if matches!(self.retained, RetainedOutput::Spool(_)) {
            self.retained = RetainedOutput::Memory {
                stdout: Vec::new(),
                stderr: Vec::new(),
            };
        }
    }

    async fn finish(mut self, store: &OutputStore) -> BridgeResult<CapturedOutput> {
        self.stderr_scanner.finish_pending_line(false);
        let reference = match &mut self.retained {
            RetainedOutput::Memory { .. } => None,
            RetainedOutput::Spool(spool) => {
                spool.stdout.flush().await.map_err(BridgeError::io)?;
                spool
                    .stderr
                    .as_mut()
                    .expect("completed pending spool")
                    .flush()
                    .await
                    .map_err(BridgeError::io)?;
                let token = spool.token.clone();
                let reference = OutputReference(token.clone());
                let expires_at = Instant::now() + store.ttl;
                store
                    .entries
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .insert(
                        token.clone(),
                        SpoolEntry {
                            stdout_path: spool.stdout_path.clone(),
                            stderr_path: Some(spool.stderr_path.clone()),
                            stdout_len: self.stdout.bytes_seen,
                            stderr_len: self.stderr.bytes_seen,
                            expires_at,
                            provenance: None,
                            accounting: Some(Arc::clone(&self.accounting)),
                        },
                    );
                spool.armed = false;
                schedule_expiry(
                    Arc::clone(&store.entries),
                    Arc::clone(&store.tombstones),
                    token,
                    expires_at,
                );
                Some(reference)
            }
        };
        Ok(CapturedOutput {
            stdout: self.stdout.finish(),
            stderr: self.stderr.finish(),
            reference,
            aggregate_bytes: self.aggregate_bytes,
            stderr_signals: self.stderr_scanner.signals,
        })
    }

    async fn finish_internal(mut self) -> BridgeResult<InternalCapturedOutput> {
        self.stderr_scanner.finish_pending_line(false);
        let RetainedOutput::Spool(spool) = &mut self.retained else {
            return Err(BridgeError::new(
                ErrorCode::Io,
                "internal output was not spooled",
                false,
            ));
        };
        spool.stdout.flush().await.map_err(BridgeError::io)?;
        spool
            .stderr
            .as_mut()
            .expect("completed pending spool")
            .flush()
            .await
            .map_err(BridgeError::io)?;
        let output = InternalCapturedOutput {
            stdout_path: spool.stdout_path.clone(),
            stderr_path: spool.stderr_path.clone(),
            stdout_len: self.stdout.bytes_seen,
            stderr_len: self.stderr.bytes_seen,
            aggregate_bytes: self.aggregate_bytes,
        };
        spool.armed = false;
        Ok(output)
    }
}

fn schedule_expiry(
    entries: Arc<StdMutex<HashMap<String, SpoolEntry>>>,
    tombstones: Arc<StdMutex<Vec<CleanupTombstone>>>,
    token: String,
    expires_at: Instant,
) {
    tokio::spawn(async move {
        tokio::time::sleep_until(tokio::time::Instant::from_std(expires_at)).await;
        let entry = {
            let mut entries = entries.lock().unwrap_or_else(|error| error.into_inner());
            if entries
                .get(&token)
                .is_some_and(|entry| entry.expires_at <= Instant::now())
            {
                entries.remove(&token)
            } else {
                None
            }
        };
        if let Some(entry) = entry {
            cleanup_entry(entry, &tombstones);
        }
    });
}

struct PreviewSink {
    head_capacity: usize,
    tail_capacity: usize,
    head: Vec<u8>,
    tail: Vec<u8>,
    bytes_seen: u64,
}

impl PreviewSink {
    fn new(budget: usize) -> Self {
        let head_capacity = budget / 2;
        Self {
            head_capacity,
            tail_capacity: budget - head_capacity,
            head: Vec::with_capacity(head_capacity),
            tail: Vec::with_capacity(budget - head_capacity),
            bytes_seen: 0,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        self.bytes_seen += bytes.len() as u64;
        let head_needed = self.head_capacity - self.head.len();
        let head_count = head_needed.min(bytes.len());
        self.head.extend_from_slice(&bytes[..head_count]);
        let remaining = &bytes[head_count..];
        if self.tail_capacity == 0 || remaining.is_empty() {
            return;
        }
        if remaining.len() >= self.tail_capacity {
            self.tail.clear();
            self.tail
                .extend_from_slice(&remaining[remaining.len() - self.tail_capacity..]);
            return;
        }
        let excess = self
            .tail
            .len()
            .saturating_add(remaining.len())
            .saturating_sub(self.tail_capacity);
        if excess != 0 {
            self.tail.drain(..excess);
        }
        self.tail.extend_from_slice(remaining);
    }

    fn finish(self) -> OutputPreview {
        let retained = self.head.len() + self.tail.len();
        OutputPreview {
            head: self.head,
            tail: self.tail,
            bytes_seen: self.bytes_seen,
            truncated: self.bytes_seen > retained as u64,
        }
    }
}

enum RetainedOutput {
    Memory { stdout: Vec<u8>, stderr: Vec<u8> },
    Spool(Box<PendingSpool>),
}

async fn write_all_counted<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
) -> (io::Result<()>, usize) {
    let mut written = 0;
    while written < bytes.len() {
        match writer.write(&bytes[written..]).await {
            Ok(0) => {
                return (
                    Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write buffered output",
                    )),
                    written,
                );
            }
            Ok(count) => written += count,
            Err(error) => return (Err(error), written),
        }
    }
    (Ok(()), written)
}

impl RetainedOutput {
    async fn write(&mut self, stream: StreamKind, bytes: &[u8]) -> BridgeResult<()> {
        match (self, stream) {
            (Self::Memory { stdout, .. }, StreamKind::Stdout) => stdout.extend_from_slice(bytes),
            (Self::Memory { stderr, .. }, StreamKind::Stderr) => stderr.extend_from_slice(bytes),
            (Self::Spool(spool), StreamKind::Stdout) => {
                let (result, written) = write_all_counted(&mut spool.stdout, bytes).await;
                if let Err(error) = result {
                    spool
                        .accounting
                        .release(StreamKind::Stdout, (bytes.len() - written) as u64);
                    return Err(BridgeError::io(error));
                }
            }
            (Self::Spool(spool), StreamKind::Stderr) => {
                let (result, written) = write_all_counted(
                    spool.stderr.as_mut().expect("completed pending spool"),
                    bytes,
                )
                .await;
                if let Err(error) = result {
                    spool
                        .accounting
                        .release(StreamKind::Stderr, (bytes.len() - written) as u64);
                    return Err(BridgeError::io(error));
                }
            }
        }
        Ok(())
    }
}

struct PendingSpool {
    token: String,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    stdout: tokio::fs::File,
    stderr: Option<tokio::fs::File>,
    armed: bool,
    accounting: Arc<EntryAccounting>,
    tombstones: Arc<StdMutex<Vec<CleanupTombstone>>>,
}

impl Drop for PendingSpool {
    fn drop(&mut self) {
        if self.armed {
            if self.stderr.is_none() {
                // A partial spool has only created stdout; no retained bytes have
                // been written yet. Its cleanup lease must keep the shared entry
                // slot, but must not inherit reservations intended for a later
                // retry or for the in-memory capture being abandoned.
                let accounting = Arc::new(FileAccounting::new(
                    Arc::clone(&self.accounting.stdout.quota),
                    Arc::clone(&self.accounting.slot),
                ));
                cleanup_targets(
                    vec![CleanupTarget {
                        path: self.stdout_path.clone(),
                        _accounting: Some(accounting),
                    }],
                    &self.tombstones,
                );
                return;
            }
            let mut paths = vec![self.stdout_path.clone()];
            paths.push(self.stderr_path.clone());
            cleanup_paths(paths, vec![Arc::clone(&self.accounting)], &self.tombstones);
        }
    }
}

fn create_spool(
    directory: &Path,
    accounting: Arc<EntryAccounting>,
    tombstones: Arc<StdMutex<Vec<CleanupTombstone>>>,
) -> BridgeResult<PendingSpool> {
    loop {
        let token = random_token();
        let stdout_path = directory.join(format!("{token}.stdout"));
        let stderr_path = directory.join(format!("{token}.stderr"));
        let stdout = match create_private_file(&stdout_path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(BridgeError::io(error)),
        };
        let mut spool = PendingSpool {
            token,
            stdout_path,
            stderr_path,
            stdout: tokio::fs::File::from_std(stdout),
            stderr: None,
            armed: true,
            accounting: Arc::clone(&accounting),
            tombstones: Arc::clone(&tombstones),
        };
        let stderr = match create_private_file(&spool.stderr_path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                drop(spool);
                continue;
            }
            Err(error) => return Err(BridgeError::io(error)),
        };
        spool.stderr = Some(tokio::fs::File::from_std(stderr));
        return Ok(spool);
    }
}

fn create_private_file(path: &Path) -> io::Result<std::fs::File> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    if let Err(error) = file.set_permissions(std::fs::Permissions::from_mode(0o600)) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(error);
    }
    Ok(file)
}

fn random_token() -> String {
    let random: [u8; 16] = rand::random();
    let mut token = String::with_capacity(32);
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut token, "{byte:02x}").expect("writing to a String cannot fail");
    }
    token
}

#[derive(Default)]
struct DiagnosticScanner {
    signals: StderrSignals,
    line: Vec<u8>,
    line_overflowed: bool,
}

impl DiagnosticScanner {
    fn push(&mut self, bytes: &[u8]) {
        const MAX_DIAGNOSTIC_LINE_BYTES: usize = 1024;
        for byte in bytes {
            if *byte == b'\n' {
                self.finish_pending_line(true);
            } else if !self.line_overflowed {
                if self.line.len() == MAX_DIAGNOSTIC_LINE_BYTES {
                    self.line.clear();
                    self.line_overflowed = true;
                } else {
                    self.line.push(*byte);
                }
            }
        }
    }

    fn finish_pending_line(&mut self, line_ended_by_lf: bool) {
        if !self.line_overflowed {
            let diagnostic_line = if line_ended_by_lf {
                self.line.strip_suffix(b"\r").unwrap_or(&self.line)
            } else {
                &self.line
            };
            if let Ok(line) = std::str::from_utf8(diagnostic_line) {
                self.signals.host_key |= is_host_key_diagnostic(line);
                self.signals.authentication |= is_authentication_diagnostic(line);
                self.signals.connect_timeout |= is_connect_timeout_diagnostic(line);
            }
        }
        self.line.clear();
        self.line_overflowed = false;
    }
}

fn is_host_key_diagnostic(line: &str) -> bool {
    if line == "Host key verification failed."
        || line == "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @"
    {
        return true;
    }
    let Some(rest) = line.strip_prefix("No ") else {
        return false;
    };
    let Some((algorithm, rest)) = rest.split_once(" host key is known for ") else {
        return false;
    };
    let Some(host) = rest.strip_suffix(" and you have requested strict checking.") else {
        return false;
    };
    matches!(algorithm, "ED25519" | "RSA" | "ECDSA") && is_single_diagnostic_field(host)
}

fn is_authentication_diagnostic(line: &str) -> bool {
    let Some((identity, methods)) = line.split_once(": Permission denied (") else {
        return false;
    };
    let Some(methods) = methods.strip_suffix(").") else {
        return false;
    };
    let Some((user, host)) = identity.split_once('@') else {
        return false;
    };
    is_single_diagnostic_field(user)
        && is_single_diagnostic_field(host)
        && methods.split(',').all(|method| {
            matches!(
                method,
                "publickey" | "password" | "keyboard-interactive" | "hostbased" | "gssapi-with-mic"
            )
        })
}

fn is_connect_timeout_diagnostic(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("ssh: connect to host ") else {
        return false;
    };
    let Some((destination, reason)) = rest.rsplit_once(": ") else {
        return false;
    };
    let Some((host, port)) = destination.rsplit_once(" port ") else {
        return false;
    };
    is_single_diagnostic_field(host)
        && port.parse::<u16>().is_ok_and(|port| port != 0)
        && matches!(reason, "Connection timed out" | "Operation timed out")
}

fn is_single_diagnostic_field(value: &str) -> bool {
    !value.is_empty()
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::{Arc, Condvar, Mutex as StdMutex};
    use std::task::{Context, Poll};

    use super::{
        ByteQuota, CleanupTombstone, DiagnosticScanner, EntryAccounting, InternalSpoolOwner,
        OutputStore, PendingSpool, StoredAggregateKind, StoredProvenance, cleanup_entry,
        cleanup_paths, create_private_file, create_spool, retry_tombstones, write_all_counted,
    };
    use crate::config::{
        MAX_GLOBAL_SPOOL_QUOTA_BYTES, MAX_SPOOL_ENTRIES, MIN_GLOBAL_SPOOL_QUOTA_BYTES,
    };
    use crate::ssh::RuntimePaths;
    use serde::Serialize;
    use serde::ser::{SerializeSeq, Serializer};
    use tokio::io::AsyncReadExt as _;
    use tokio_util::sync::CancellationToken;

    struct ErrorAfterBytes {
        remaining: usize,
    }

    struct AbortDetail {
        progress: Arc<std::sync::atomic::AtomicU64>,
        chunk: String,
    }

    struct FailingDetail;

    struct PanicDetail;

    struct BlockingFailDetail {
        gate: Arc<(StdMutex<(bool, bool)>, Condvar)>,
        payload: String,
    }

    struct PartialErrorWriter {
        first_write: usize,
        wrote_once: bool,
    }

    impl Serialize for FailingDetail {
        fn serialize<S>(&self, _: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Err(serde::ser::Error::custom("injected serializer failure"))
        }
    }

    impl Serialize for PanicDetail {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut sequence = serializer.serialize_seq(Some(2))?;
            sequence.serialize_element("prefix written before panic")?;
            panic!("injected serializer panic");
        }
    }

    impl Serialize for BlockingFailDetail {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut sequence = serializer.serialize_seq(Some(2))?;
            sequence.serialize_element(&self.payload)?;
            let (lock, ready) = &*self.gate;
            let mut state = lock.lock().unwrap();
            state.0 = true;
            ready.notify_all();
            while !state.1 {
                state = ready.wait(state).unwrap();
            }
            Err(serde::ser::Error::custom("injected failure after prefix"))
        }
    }

    impl tokio::io::AsyncWrite for PartialErrorWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.wrote_once {
                return Poll::Ready(Err(std::io::Error::other("injected partial write")));
            }
            self.wrote_once = true;
            Poll::Ready(Ok(self.first_write.min(bytes.len())))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Serialize for AbortDetail {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut sequence = serializer.serialize_seq(Some(1_024))?;
            for _ in 0..1_024 {
                self.progress
                    .fetch_add(1, std::sync::atomic::Ordering::Release);
                sequence.serialize_element(&self.chunk)?;
                std::thread::yield_now();
            }
            sequence.end()
        }
    }

    impl tokio::io::AsyncRead for ErrorAfterBytes {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.remaining == 0 {
                return Poll::Ready(Err(std::io::Error::other("injected read failure")));
            }
            let count = self.remaining.min(buffer.remaining());
            buffer.put_slice(&vec![b'x'; count]);
            self.remaining -= count;
            Poll::Ready(Ok(()))
        }
    }

    fn pending_resources() -> (Arc<EntryAccounting>, Arc<StdMutex<Vec<CleanupTombstone>>>) {
        let quota = Arc::new(ByteQuota::new(64 * 1024 * 1024));
        let accounting = Arc::new(EntryAccounting::new(quota));
        accounting
            .attach_slot(
                Arc::new(tokio::sync::Semaphore::new(1))
                    .try_acquire_owned()
                    .unwrap(),
            )
            .unwrap();
        (accounting, Arc::new(StdMutex::new(Vec::new())))
    }

    async fn spooled_capture(store: &OutputStore) -> super::CapturedOutput {
        store
            .capture(
                tokio::io::repeat(b'x').take(300 * 1024),
                tokio::io::empty(),
                super::CaptureLimits {
                    preview_bytes: 16,
                    max_output_bytes: 1024 * 1024,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap()
    }

    #[test]
    fn diagnostic_scanner_classifies_crlf_split_between_chunks() {
        let mut scanner = DiagnosticScanner::default();

        scanner.push(b"Host key verification failed.\r");
        assert!(
            !scanner.signals.host_key,
            "an incomplete line is not classified"
        );
        scanner.push(b"\n");

        assert!(scanner.signals.host_key);
    }

    #[test]
    fn diagnostic_scanner_does_not_strip_arbitrary_control_bytes_before_crlf() {
        let mut scanner = DiagnosticScanner::default();

        scanner.push(b"Host key verification failed.\x0b\r\n");

        assert!(!scanner.signals.host_key);
    }

    #[test]
    fn diagnostic_scanner_does_not_treat_a_bare_carriage_return_as_crlf() {
        let mut scanner = DiagnosticScanner::default();

        scanner.push(b"Host key verification failed.\r");
        scanner.finish_pending_line(false);

        assert!(!scanner.signals.host_key);
    }

    #[tokio::test]
    async fn crlf_diagnostic_classification_preserves_captured_stderr_bytes() {
        let base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
        let store = OutputStore::with_limits(&runtime, MAX_GLOBAL_SPOOL_QUOTA_BYTES, 1).unwrap();
        let stderr = b"Host key verification failed.\r\n";

        let captured = store
            .capture(
                tokio::io::empty(),
                std::io::Cursor::new(stderr),
                super::CaptureLimits {
                    preview_bytes: 128,
                    max_output_bytes: 1024,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();

        assert_eq!(captured.stderr.head, stderr);
        assert!(captured.stderr.tail.is_empty());
        assert_eq!(captured.stderr.bytes_seen, stderr.len() as u64);
        assert!(!captured.stderr.truncated);
        assert_eq!(captured.aggregate_bytes, stderr.len() as u64);
        assert!(captured.stderr_signals.host_key);
    }

    #[test]
    fn dropping_an_unregistered_spool_removes_both_files() {
        let directory = tempfile::TempDir::new().unwrap();
        let (accounting, tombstones) = pending_resources();
        let spool = create_spool(directory.path(), accounting, tombstones).unwrap();
        let stdout_path = spool.stdout_path.clone();
        let stderr_path = spool.stderr_path.clone();
        assert!(stdout_path.exists());
        assert!(stderr_path.exists());

        drop(spool);

        assert!(!stdout_path.exists());
        assert!(!stderr_path.exists());
    }

    #[test]
    fn dropping_a_partial_spool_preserves_an_unowned_stderr_collision() {
        let directory = tempfile::TempDir::new().unwrap();
        let stdout_path = directory.path().join("partial.stdout");
        let stderr_path = directory.path().join("partial.stderr");
        let stdout = create_private_file(&stdout_path).unwrap();
        let (accounting, tombstones) = pending_resources();
        std::fs::write(&stderr_path, b"pre-existing sentinel").unwrap();
        let spool = PendingSpool {
            token: "partial".to_owned(),
            stdout_path: stdout_path.clone(),
            stderr_path: stderr_path.clone(),
            stdout: tokio::fs::File::from_std(stdout),
            stderr: None,
            armed: true,
            accounting,
            tombstones,
        };

        drop(spool);

        assert!(!stdout_path.exists());
        assert_eq!(
            std::fs::read(&stderr_path).unwrap(),
            b"pre-existing sentinel"
        );
    }

    #[test]
    fn failed_partial_spool_unlink_keeps_only_a_zero_byte_slot_lease() {
        let directory = tempfile::TempDir::new().unwrap();
        let stdout_path = directory.path().join("partial-unlink.stdout");
        let stderr_path = directory.path().join("partial-unlink.stderr");
        let stdout = create_private_file(&stdout_path).unwrap();
        let quota = Arc::new(ByteQuota::new(1024));
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let accounting = Arc::new(EntryAccounting::new(Arc::clone(&quota)));
        assert!(accounting.reserve(super::StreamKind::Stdout, 23));
        accounting
            .attach_slot(Arc::clone(&slots).try_acquire_owned().unwrap())
            .unwrap();
        let tombstones = Arc::new(StdMutex::new(Vec::new()));

        std::fs::remove_file(&stdout_path).unwrap();
        std::fs::create_dir(&stdout_path).unwrap();
        let blocker = stdout_path.join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let spool = PendingSpool {
            token: "partial-unlink".to_owned(),
            stdout_path: stdout_path.clone(),
            stderr_path,
            stdout: tokio::fs::File::from_std(stdout),
            stderr: None,
            armed: true,
            accounting: Arc::clone(&accounting),
            tombstones: Arc::clone(&tombstones),
        };

        drop(spool);
        assert_eq!(
            quota.used(),
            23,
            "reservations for a subsequent retry stay with the active accounting"
        );
        drop(accounting);

        assert_eq!(quota.used(), 0, "the abandoned stdout file is empty");
        assert_eq!(
            slots.available_permits(),
            0,
            "the failed unlink still owns the shared entry slot"
        );
        assert_eq!(tombstones.lock().unwrap().len(), 1);

        std::fs::remove_file(blocker).unwrap();
        std::fs::remove_dir(stdout_path).unwrap();
        retry_tombstones(&tombstones);
        assert_eq!(slots.available_permits(), 1);
    }

    #[test]
    fn internal_spool_owner_unlinks_registered_paths_on_drop() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("internal");
        std::fs::write(&path, b"data").unwrap();
        let owner = InternalSpoolOwner::new();
        owner.registration().register(path.clone()).unwrap();
        drop(owner);
        assert!(!path.exists());
    }

    #[test]
    fn late_internal_registration_unlinks_immediately() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("late");
        let owner = InternalSpoolOwner::new();
        let registration = owner.registration();
        drop(owner);
        std::fs::write(&path, b"data").unwrap();
        assert!(registration.register(path.clone()).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn task8_spool_quota_exact_limit_succeeds_and_next_byte_fails_atomically() {
        let quota = Arc::new(ByteQuota::new(64 * 1024 * 1024));
        assert!(quota.try_reserve(64 * 1024 * 1024));
        assert!(!quota.try_reserve(1));
        assert_eq!(quota.used(), 64 * 1024 * 1024);
        quota.release(64 * 1024 * 1024);
        assert_eq!(quota.used(), 0);
    }

    #[test]
    fn task8_spool_quota_concurrent_reservations_never_exceed_the_limit() {
        let quota = Arc::new(ByteQuota::new(64 * 1024 * 1024));
        let mut workers = Vec::new();
        for _ in 0..16 {
            let quota = Arc::clone(&quota);
            workers.push(std::thread::spawn(move || {
                quota.try_reserve(8 * 1024 * 1024)
            }));
        }
        let accepted = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|accepted| *accepted)
            .count();
        assert_eq!(accepted, 8);
        assert_eq!(quota.used(), 64 * 1024 * 1024);
    }

    #[test]
    fn task8_spool_quota_five_outputs_two_retention_reservations_leave_headroom() {
        let quota = ByteQuota::new(MAX_GLOBAL_SPOOL_QUOTA_BYTES);
        for _ in 0..5 {
            assert!(quota.try_reserve(crate::MAX_OUTPUT_BYTES));
        }
        for _ in 0..2 {
            assert!(quota.try_reserve(crate::MAX_OUTPUT_BYTES));
        }
        assert_eq!(quota.used(), 448 * 1024 * 1024);
        assert!(quota.try_reserve(64 * 1024 * 1024));
        assert!(!quota.try_reserve(1));
    }

    #[test]
    fn retention_cleanup_releases_each_unlinked_stream_but_keeps_the_shared_slot() {
        let directory = tempfile::TempDir::new().unwrap();
        let stdout_path = directory.path().join("mixed.stdout");
        let stderr_path = directory.path().join("mixed.stderr");
        std::fs::write(&stdout_path, b"0123456789").unwrap();
        std::fs::create_dir(&stderr_path).unwrap();
        let blocker = stderr_path.join("blocker");
        std::fs::write(&blocker, b"x").unwrap();

        let quota = Arc::new(ByteQuota::new(1024));
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let accounting = Arc::new(EntryAccounting::new(Arc::clone(&quota)));
        assert!(accounting.reserve(super::StreamKind::Stdout, 10));
        assert!(accounting.reserve(super::StreamKind::Stderr, 20));
        accounting
            .attach_slot(Arc::clone(&slots).try_acquire_owned().unwrap())
            .unwrap();
        let tombstones = Arc::new(StdMutex::new(Vec::new()));

        cleanup_paths(
            vec![stdout_path.clone(), stderr_path.clone()],
            vec![accounting],
            &tombstones,
        );

        assert!(!stdout_path.exists());
        assert_eq!(
            quota.used(),
            20,
            "only the failed stderr path stays charged"
        );
        assert_eq!(slots.available_permits(), 0, "the entry slot is shared");

        std::fs::remove_file(blocker).unwrap();
        std::fs::remove_dir(stderr_path).unwrap();
        retry_tombstones(&tombstones);
        assert_eq!(quota.used(), 0);
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn retention_partial_write_reports_exact_bytes_for_reservation_rollback() {
        let quota = Arc::new(ByteQuota::new(1024));
        let accounting = Arc::new(EntryAccounting::new(Arc::clone(&quota)));
        let intended = b"abcdef";
        assert!(accounting.reserve(super::StreamKind::Stdout, intended.len() as u64));
        let mut writer = PartialErrorWriter {
            first_write: 2,
            wrote_once: false,
        };

        let (result, written) = write_all_counted(&mut writer, intended).await;
        assert!(result.is_err());
        accounting.release(super::StreamKind::Stdout, (intended.len() - written) as u64);
        assert_eq!(written, 2);
        assert_eq!(quota.used(), 2);
        drop(accounting);
        assert_eq!(quota.used(), 0);
    }

    #[test]
    fn retention_cleanup_treats_not_found_as_success_and_releases_resources() {
        let directory = tempfile::TempDir::new().unwrap();
        let missing = directory.path().join("already-gone.stdout");
        let quota = Arc::new(ByteQuota::new(1024));
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let accounting = Arc::new(EntryAccounting::new(Arc::clone(&quota)));
        assert!(accounting.reserve(super::StreamKind::Stdout, 7));
        accounting
            .attach_slot(Arc::clone(&slots).try_acquire_owned().unwrap())
            .unwrap();
        let tombstones = Arc::new(StdMutex::new(Vec::new()));

        cleanup_paths(vec![missing], vec![accounting], &tombstones);

        assert_eq!(quota.used(), 0);
        assert_eq!(slots.available_permits(), 1);
        assert!(tombstones.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn task8_spool_quota_failed_capture_rolls_back_bytes_files_and_slot() {
        let base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
        let store = OutputStore::with_limits(&runtime, MAX_GLOBAL_SPOOL_QUOTA_BYTES, 1).unwrap();
        let error = store
            .capture(
                ErrorAfterBytes {
                    remaining: 300 * 1024,
                },
                tokio::io::empty(),
                super::CaptureLimits {
                    preview_bytes: 16,
                    max_output_bytes: 1024 * 1024,
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, crate::ErrorCode::Io);
        assert_eq!(store.quota.used(), 0);
        assert_eq!(store.entry_slots.available_permits(), MAX_SPOOL_ENTRIES);
        assert_eq!(
            std::fs::read_dir(store.spool_directory.path())
                .unwrap()
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn task8_spool_quota_light_capture_reserves_actual_chunks_not_sixty_four_mib() {
        let base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
        let store = OutputStore::with_limits(&runtime, MAX_GLOBAL_SPOOL_QUOTA_BYTES, 1).unwrap();
        let (mut writer, reader) = tokio::io::duplex(2 * 1024);
        let release = Arc::new(tokio::sync::Notify::new());
        let writer_release = Arc::clone(&release);
        let writer_task = tokio::spawn(async move {
            tokio::io::AsyncWriteExt::write_all(&mut writer, &[b'x'; 1024])
                .await
                .unwrap();
            writer_release.notified().await;
            tokio::io::AsyncWriteExt::shutdown(&mut writer)
                .await
                .unwrap();
        });
        let capture = store.capture(
            reader,
            tokio::io::empty(),
            super::CaptureLimits {
                preview_bytes: 16,
                max_output_bytes: 1024 * 1024,
            },
            CancellationToken::new(),
        );
        tokio::pin!(capture);
        while store.quota.used() == 0 {
            tokio::select! {
                result = &mut capture => panic!("capture ended before inspection: {result:?}"),
                () = tokio::task::yield_now() => {}
            }
        }
        assert_eq!(store.quota.used(), 1024);
        assert!(store.quota.used() < crate::MAX_OUTPUT_BYTES);
        release.notify_one();
        let captured = capture.await.unwrap();
        writer_task.await.unwrap();
        assert!(captured.reference.is_none());
        assert_eq!(store.quota.used(), 0);
    }

    #[tokio::test]
    async fn task8_spool_quota_exact_entry_slots_and_no_resident_handle_amplification() {
        let base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
        let store = OutputStore::with_limits(&runtime, MAX_GLOBAL_SPOOL_QUOTA_BYTES, 1).unwrap();
        let before_fds = std::fs::read_dir("/proc/self/fd")
            .ok()
            .map(|entries| entries.count());
        let provenance = StoredProvenance::Aggregate {
            kind: StoredAggregateKind::Hosts,
            source_count: 0,
        };
        let mut references = Vec::with_capacity(MAX_SPOOL_ENTRIES);
        for _ in 0..MAX_SPOOL_ENTRIES {
            references.push(
                store
                    .retain_serialized_detail(
                        provenance.clone(),
                        Vec::<String>::new(),
                        CancellationToken::new(),
                    )
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(
            store
                .entries
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
            MAX_SPOOL_ENTRIES
        );
        assert!(
            store
                .retain_serialized_detail(
                    provenance,
                    Vec::<String>::new(),
                    CancellationToken::new(),
                )
                .await
                .is_err()
        );
        if let Some(before_fds) = before_fds {
            let after_fds = std::fs::read_dir("/proc/self/fd").unwrap().count();
            assert!(
                after_fds <= before_fds + 8,
                "resident fd growth: {before_fds} -> {after_fds}"
            );
        }
        let page = store
            .read(&references[0], super::StreamKind::Stdout, 0, 16)
            .await
            .unwrap();
        assert_eq!(page.bytes, b"[]");
    }

    #[tokio::test]
    async fn task8_spool_quota_job_saturation_rejects_before_creating_a_temp() {
        let base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
        let store = OutputStore::with_limits(&runtime, MIN_GLOBAL_SPOOL_QUOTA_BYTES, 1).unwrap();
        let _job = Arc::clone(&store.retention_jobs)
            .try_acquire_owned()
            .unwrap();
        let before = std::fs::read_dir(store.spool_directory.path())
            .unwrap()
            .count();
        let result = store
            .retain_serialized_detail(
                StoredProvenance::Aggregate {
                    kind: StoredAggregateKind::Hosts,
                    source_count: 1,
                },
                vec!["not serialized"],
                CancellationToken::new(),
            )
            .await;
        assert!(result.is_err());
        assert_eq!(
            std::fs::read_dir(store.spool_directory.path())
                .unwrap()
                .count(),
            before
        );
    }

    #[tokio::test]
    async fn task8_spool_quota_aborted_retain_joins_worker_before_releasing_resources() {
        let base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
        let store =
            Arc::new(OutputStore::with_limits(&runtime, MAX_GLOBAL_SPOOL_QUOTA_BYTES, 1).unwrap());
        let progress = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let task_store = Arc::clone(&store);
        let task_progress = Arc::clone(&progress);
        let task = tokio::spawn(async move {
            task_store
                .retain_serialized_detail(
                    StoredProvenance::Aggregate {
                        kind: StoredAggregateKind::Hosts,
                        source_count: 1,
                    },
                    AbortDetail {
                        progress: task_progress,
                        chunk: "x".repeat(64 * 1024),
                    },
                    CancellationToken::new(),
                )
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while progress.load(std::sync::atomic::Ordering::Acquire) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        task.abort();
        let joined = tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .expect("aborted retain must synchronously join its serializer");
        assert!(joined.unwrap_err().is_cancelled());
        let stopped = progress.load(std::sync::atomic::Ordering::Acquire);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(progress.load(std::sync::atomic::Ordering::Acquire), stopped);
        assert_eq!(store.quota.used(), 0);
        assert_eq!(store.entry_slots.available_permits(), MAX_SPOOL_ENTRIES);
        assert_eq!(store.retention_jobs.available_permits(), 1);
        assert!(
            store
                .entries
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty()
        );
        assert_eq!(
            std::fs::read_dir(store.spool_directory.path())
                .unwrap()
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn task8_spool_quota_serializer_failure_cleans_temp_and_all_accounting() {
        let base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
        let store = OutputStore::with_limits(&runtime, MAX_GLOBAL_SPOOL_QUOTA_BYTES, 1).unwrap();
        let error = store
            .retain_serialized_detail(
                StoredProvenance::Aggregate {
                    kind: StoredAggregateKind::Hosts,
                    source_count: 1,
                },
                FailingDetail,
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, crate::ErrorCode::Io);
        assert!(!error.message.contains("injected"));
        assert_eq!(store.quota.used(), 0);
        assert_eq!(store.entry_slots.available_permits(), MAX_SPOOL_ENTRIES);
        assert_eq!(store.retention_jobs.available_permits(), 1);
        assert_eq!(
            std::fs::read_dir(store.spool_directory.path())
                .unwrap()
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn retention_serializer_panic_reconciles_and_releases_all_resources() {
        let base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
        let store = OutputStore::with_limits(&runtime, MAX_GLOBAL_SPOOL_QUOTA_BYTES, 1).unwrap();
        let error = store
            .retain_serialized_detail(
                StoredProvenance::Aggregate {
                    kind: StoredAggregateKind::Hosts,
                    source_count: 1,
                },
                PanicDetail,
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, crate::ErrorCode::Io);
        assert_eq!(error.message, "result retention serialization failed");
        assert_eq!(store.quota.used(), 0);
        assert_eq!(store.entry_slots.available_permits(), MAX_SPOOL_ENTRIES);
        assert_eq!(store.retention_jobs.available_permits(), 1);
        assert_eq!(
            std::fs::read_dir(store.spool_directory.path())
                .unwrap()
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn retention_failed_serializer_unlink_tombstone_charges_only_actual_bytes() {
        let base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
        let store =
            Arc::new(OutputStore::with_limits(&runtime, MAX_GLOBAL_SPOOL_QUOTA_BYTES, 1).unwrap());
        let gate = Arc::new((StdMutex::new((false, false)), Condvar::new()));
        let task_store = Arc::clone(&store);
        let task_gate = Arc::clone(&gate);
        let task = tokio::spawn(async move {
            task_store
                .retain_serialized_detail(
                    StoredProvenance::Aggregate {
                        kind: StoredAggregateKind::Hosts,
                        source_count: 1,
                    },
                    BlockingFailDetail {
                        gate: task_gate,
                        payload: "x".repeat(4096),
                    },
                    CancellationToken::new(),
                )
                .await
        });

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if gate.0.lock().unwrap().0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let path = std::fs::read_dir(store.spool_directory.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let actual = std::fs::metadata(&path).unwrap().len();
        assert!(actual > 0);
        assert!(actual < crate::MAX_OUTPUT_BYTES);
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let blocker = path.join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        {
            let mut state = gate.0.lock().unwrap();
            state.1 = true;
            gate.1.notify_all();
        }

        let error = task.await.unwrap().unwrap_err();
        assert_eq!(error.code, crate::ErrorCode::Io);
        assert_eq!(store.quota.used(), actual);
        assert_eq!(store.entry_slots.available_permits(), MAX_SPOOL_ENTRIES - 1);
        assert_eq!(store.tombstones.lock().unwrap().len(), 1);

        std::fs::remove_file(blocker).unwrap();
        std::fs::remove_dir(path).unwrap();
        retry_tombstones(&store.tombstones);
        assert_eq!(store.quota.used(), 0);
        assert_eq!(store.entry_slots.available_permits(), MAX_SPOOL_ENTRIES);
    }

    #[tokio::test]
    async fn task8_spool_quota_unlink_failure_pins_charge_and_slot_until_tombstone_retry() {
        let base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
        let store = OutputStore::with_limits(&runtime, MAX_GLOBAL_SPOOL_QUOTA_BYTES, 1).unwrap();
        let reference = store
            .retain_serialized_detail(
                StoredProvenance::Aggregate {
                    kind: StoredAggregateKind::Hosts,
                    source_count: 1,
                },
                vec!["detail"],
                CancellationToken::new(),
            )
            .await
            .unwrap();
        let entry = store
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(reference.as_str())
            .unwrap();
        let path = entry.stdout_path.clone();
        let charged = store.quota.used();
        assert!(charged > 0);
        assert_eq!(store.entry_slots.available_permits(), MAX_SPOOL_ENTRIES - 1);

        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let child = path.join("blocks-remove-file");
        std::fs::write(&child, b"x").unwrap();
        cleanup_entry(entry, &store.tombstones);
        assert_eq!(store.quota.used(), charged);
        assert_eq!(store.entry_slots.available_permits(), MAX_SPOOL_ENTRIES - 1);
        assert_eq!(
            store
                .tombstones
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
            1
        );

        std::fs::remove_file(child).unwrap();
        std::fs::remove_dir(path).unwrap();
        retry_tombstones(&store.tombstones);
        assert_eq!(store.quota.used(), 0);
        assert_eq!(store.entry_slots.available_permits(), MAX_SPOOL_ENTRIES);
    }

    #[tokio::test]
    async fn task8_spool_quota_reader_open_precedes_lease_and_pins_accounting() {
        let base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
        let store = OutputStore::with_limits(&runtime, MAX_GLOBAL_SPOOL_QUOTA_BYTES, 1).unwrap();
        let reference = store
            .retain_serialized_detail(
                StoredProvenance::Aggregate {
                    kind: StoredAggregateKind::Hosts,
                    source_count: 1,
                },
                "0123456789",
                CancellationToken::new(),
            )
            .await
            .unwrap();
        let (mut file, _length, lease) = store
            .open_independent(&reference, super::StreamKind::Stdout, 2)
            .unwrap();
        let lease = lease.expect("retained detail has accounting");
        let entry = store
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(reference.as_str())
            .unwrap();
        cleanup_entry(entry, &store.tombstones);
        assert!(store.quota.used() > 0, "reader lease must pin charge");
        std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(2)).unwrap();
        let mut bytes = [0; 4];
        std::io::Read::read_exact(&mut file, &mut bytes).unwrap();
        assert_eq!(&bytes, b"1234");
        assert!(
            store
                .open_independent(&reference, super::StreamKind::Stdout, 0)
                .is_err(),
            "removal that wins the lock must prevent a new lease"
        );
        drop(file);
        assert!(store.quota.used() > 0);
        drop(lease);
        assert_eq!(store.quota.used(), 0);
    }

    #[tokio::test]
    async fn retention_reader_wins_ttl_and_pins_the_whole_entry_until_release() {
        let base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
        let store = OutputStore::with_ttl_and_limits(
            &runtime,
            std::time::Duration::from_millis(10),
            MAX_GLOBAL_SPOOL_QUOTA_BYTES,
            1,
        )
        .unwrap();
        let reference = store
            .retain_serialized_detail(
                StoredProvenance::Aggregate {
                    kind: StoredAggregateKind::Hosts,
                    source_count: 1,
                },
                "ttl reader wins",
                CancellationToken::new(),
            )
            .await
            .unwrap();
        let (_file, _length, lease) = store
            .open_independent(&reference, super::StreamKind::Stdout, 0)
            .unwrap();
        let lease = lease.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while store
                .entries
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .contains_key(reference.as_str())
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            store
                .open_independent(&reference, super::StreamKind::Stdout, 0)
                .is_err()
        );
        assert!(store.quota.used() > 0);
        assert_eq!(store.entry_slots.available_permits(), MAX_SPOOL_ENTRIES - 1);
        drop(lease);
        assert_eq!(store.quota.used(), 0);
        assert_eq!(store.entry_slots.available_permits(), MAX_SPOOL_ENTRIES);
    }

    #[tokio::test]
    async fn retention_ttl_wins_before_reader_and_releases_resources() {
        let base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
        let store = OutputStore::with_ttl_and_limits(
            &runtime,
            std::time::Duration::from_millis(10),
            MAX_GLOBAL_SPOOL_QUOTA_BYTES,
            1,
        )
        .unwrap();
        let reference = store
            .retain_serialized_detail(
                StoredProvenance::Aggregate {
                    kind: StoredAggregateKind::Hosts,
                    source_count: 1,
                },
                "ttl removal wins",
                CancellationToken::new(),
            )
            .await
            .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while store.quota.used() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            store
                .open_independent(&reference, super::StreamKind::Stdout, 0)
                .is_err()
        );
        assert_eq!(store.entry_slots.available_permits(), MAX_SPOOL_ENTRIES);
    }

    #[tokio::test]
    async fn retention_reader_wins_explicit_discard_and_pins_accounting() {
        let base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
        let store = OutputStore::with_limits(&runtime, MAX_GLOBAL_SPOOL_QUOTA_BYTES, 1).unwrap();
        let captured = spooled_capture(&store).await;
        let reference = captured.reference.as_ref().unwrap();
        let (_file, _length, lease) = store
            .open_independent(reference, super::StreamKind::Stdout, 0)
            .unwrap();
        let lease = lease.unwrap();

        store.discard(&captured).await;

        assert!(
            store
                .open_independent(reference, super::StreamKind::Stdout, 0)
                .is_err()
        );
        assert_eq!(store.quota.used(), captured.aggregate_bytes);
        assert_eq!(store.entry_slots.available_permits(), MAX_SPOOL_ENTRIES - 1);
        drop(lease);
        assert_eq!(store.quota.used(), 0);
        assert_eq!(store.entry_slots.available_permits(), MAX_SPOOL_ENTRIES);
    }

    #[tokio::test]
    async fn retention_explicit_discard_wins_before_reader_and_releases_resources() {
        let base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
        let store = OutputStore::with_limits(&runtime, MAX_GLOBAL_SPOOL_QUOTA_BYTES, 1).unwrap();
        let captured = spooled_capture(&store).await;
        let reference = captured.reference.as_ref().unwrap().clone();

        store.discard(&captured).await;

        assert!(
            store
                .open_independent(&reference, super::StreamKind::Stdout, 0)
                .is_err()
        );
        assert_eq!(store.quota.used(), 0);
        assert_eq!(store.entry_slots.available_permits(), MAX_SPOOL_ENTRIES);
    }

    #[tokio::test]
    async fn task8_spool_quota_concurrent_pages_have_independent_seek_cursors() {
        let base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
        let store = OutputStore::with_limits(&runtime, MAX_GLOBAL_SPOOL_QUOTA_BYTES, 1).unwrap();
        let reference = store
            .retain_serialized_detail(
                StoredProvenance::Aggregate {
                    kind: StoredAggregateKind::Hosts,
                    source_count: 1,
                },
                "abcdefghij",
                CancellationToken::new(),
            )
            .await
            .unwrap();
        let (left, right) = tokio::join!(
            store.read(&reference, super::StreamKind::Stdout, 1, 4),
            store.read(&reference, super::StreamKind::Stdout, 6, 4),
        );
        assert_eq!(left.unwrap().bytes, b"abcd");
        assert_eq!(right.unwrap().bytes, b"fghi");
    }
}
