use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CacheKey {
    pub(crate) host: String,
    pub(crate) path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RemoteBase {
    Missing,
    Regular { sha256: String, mode: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DesiredState {
    Present(Arc<[u8]>),
    Deleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Generation(pub(crate) u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteSnapshot {
    pub(crate) base: RemoteBase,
    pub(crate) desired: DesiredState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommitItem {
    pub(crate) key: CacheKey,
    pub(crate) base: RemoteBase,
    pub(crate) desired: DesiredState,
    pub(crate) generation: Generation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommitSuccess {
    pub(crate) key: CacheKey,
    pub(crate) generation: Generation,
    pub(crate) base: RemoteBase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EditErrorKind {
    Transient,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EditError {
    pub(crate) kind: EditErrorKind,
    pub(crate) message: String,
}

pub(crate) type EditFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, EditError>> + Send + 'a>>;

pub(crate) trait EditBackend: Send + Sync {
    fn fetch_complete<'a>(&'a self, key: &'a CacheKey) -> EditFuture<'a, RemoteSnapshot>;
    fn commit_batch<'a>(
        &'a self,
        host: &'a str,
        items: Vec<CommitItem>,
    ) -> EditFuture<'a, Vec<CommitSuccess>>;
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct EditCacheConfig {
    pub(crate) flush_delay: Duration,
    pub(crate) flush_threshold_bytes: usize,
    pub(crate) max_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MutationDisposition {
    Buffered(Generation),
    ImmediateWriteRequired,
}

pub(crate) struct EditCache {
    _backend: Arc<dyn EditBackend>,
    _config: EditCacheConfig,
}

impl EditCache {
    pub(crate) fn new(config: EditCacheConfig, backend: Arc<dyn EditBackend>) -> Arc<Self> {
        Arc::new(Self {
            _backend: backend,
            _config: config,
        })
    }

    pub(crate) async fn load_complete(&self, _key: CacheKey) -> Result<DesiredState, EditError> {
        todo!()
    }

    pub(crate) async fn lookup_complete(&self, _key: &CacheKey) -> Option<DesiredState> {
        todo!()
    }

    pub(crate) async fn mutate(
        &self,
        _key: CacheKey,
        _desired: DesiredState,
        _payload_bytes: usize,
    ) -> Result<MutationDisposition, EditError> {
        todo!()
    }

    pub(crate) async fn flush_host(&self, _host: &str) -> Result<(), EditError> {
        todo!()
    }

    pub(crate) async fn shutdown(&self) -> Result<(), EditError> {
        todo!()
    }

    pub(crate) async fn cached_bytes(&self) -> usize {
        todo!()
    }
}
