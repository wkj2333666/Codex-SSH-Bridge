use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, Notify};
use tokio::time::Instant;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommitBatchOutcome {
    pub(crate) successes: Vec<CommitSuccess>,
    pub(crate) error: Option<EditError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EditErrorKind {
    Transient,
    Conflict,
    OutcomeUnknown,
    Permanent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EditError {
    pub(crate) kind: EditErrorKind,
    pub(crate) message: String,
}

pub(crate) type EditFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, EditError>> + Send + 'a>>;
pub(crate) type CommitFuture<'a> = Pin<Box<dyn Future<Output = CommitBatchOutcome> + Send + 'a>>;

pub(crate) trait EditBackend: Send + Sync {
    fn fetch_complete<'a>(&'a self, key: &'a CacheKey) -> EditFuture<'a, RemoteSnapshot>;
    fn commit_batch<'a>(&'a self, host: &'a str, items: Vec<CommitItem>) -> CommitFuture<'a>;
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
    backend: Arc<dyn EditBackend>,
    config: EditCacheConfig,
    state: Mutex<CacheState>,
}

struct CacheState {
    hosts: HashMap<String, HostState>,
    cached_bytes: usize,
    lru_sequence: u64,
    next_generation: u64,
    shutting_down: bool,
}

struct HostState {
    entries: HashMap<String, Entry>,
    dirty_payload_bytes: usize,
    first_dirty_deadline: Option<Instant>,
    retry_deadline: Option<Instant>,
    retry_attempt: usize,
    last_transient: Option<EditError>,
    timer_running: bool,
    runtime: Arc<HostRuntime>,
}

struct HostRuntime {
    preparation: Mutex<()>,
    flush: Mutex<()>,
    changed: Notify,
}

struct Entry {
    base: RemoteBase,
    desired: DesiredState,
    generation: Generation,
    dirty: bool,
    in_flight: Option<Generation>,
    conflict: Option<EditError>,
    lru_sequence: u64,
}

impl EditCache {
    pub(crate) fn new(config: EditCacheConfig, backend: Arc<dyn EditBackend>) -> Arc<Self> {
        Arc::new(Self {
            backend,
            config,
            state: Mutex::new(CacheState {
                hosts: HashMap::new(),
                cached_bytes: 0,
                lru_sequence: 0,
                next_generation: 1,
                shutting_down: false,
            }),
        })
    }

    pub(crate) async fn load_complete(&self, key: CacheKey) -> Result<DesiredState, EditError> {
        if let Some(desired) = self.lookup_complete(&key).await {
            return Ok(desired);
        }
        let runtime = self.host_runtime(&key.host).await;
        let _preparation = runtime.preparation.lock().await;
        if let Some(desired) = self.lookup_complete(&key).await {
            return Ok(desired);
        }
        let snapshot = self.backend.fetch_complete(&key).await?;
        let desired = snapshot.desired.clone();
        let size = desired_size(&desired);
        if size > self.config.max_bytes {
            return Ok(desired);
        }
        let mut state = self.state.lock().await;
        if let Some(existing) = state
            .hosts
            .get(&key.host)
            .and_then(|host| host.entries.get(&key.path))
        {
            return Ok(existing.desired.clone());
        }
        if !make_capacity(&mut state, self.config.max_bytes, size, None) {
            return Ok(desired);
        }
        let lru_sequence = next_lru(&mut state);
        host_state_mut(&mut state, &key.host).entries.insert(
            key.path,
            Entry {
                base: snapshot.base,
                desired: snapshot.desired,
                generation: Generation(0),
                dirty: false,
                in_flight: None,
                conflict: None,
                lru_sequence,
            },
        );
        state.cached_bytes = state.cached_bytes.saturating_add(size);
        Ok(desired)
    }

    pub(crate) async fn lookup_complete(&self, key: &CacheKey) -> Option<DesiredState> {
        let mut state = self.state.lock().await;
        let lru_sequence = next_lru(&mut state);
        let entry = state.hosts.get_mut(&key.host)?.entries.get_mut(&key.path)?;
        entry.lru_sequence = lru_sequence;
        Some(entry.desired.clone())
    }

    pub(crate) async fn mutate(
        self: &Arc<Self>,
        key: CacheKey,
        desired: DesiredState,
        payload_bytes: usize,
    ) -> Result<MutationDisposition, EditError> {
        let desired_bytes = desired_size(&desired);
        if desired_bytes > self.config.max_bytes {
            return Ok(MutationDisposition::ImmediateWriteRequired);
        }
        let runtime = self.host_runtime(&key.host).await;
        let _preparation = runtime.preparation.lock().await;
        if self.lookup_complete(&key).await.is_none() {
            let snapshot = self.backend.fetch_complete(&key).await?;
            let snapshot_bytes = desired_size(&snapshot.desired);
            let mut state = self.state.lock().await;
            if snapshot_bytes <= self.config.max_bytes
                && make_capacity(&mut state, self.config.max_bytes, snapshot_bytes, None)
            {
                let lru_sequence = next_lru(&mut state);
                host_state_mut(&mut state, &key.host).entries.insert(
                    key.path.clone(),
                    Entry {
                        base: snapshot.base,
                        desired: snapshot.desired,
                        generation: Generation(0),
                        dirty: false,
                        in_flight: None,
                        conflict: None,
                        lru_sequence,
                    },
                );
                state.cached_bytes = state.cached_bytes.saturating_add(snapshot_bytes);
            }
        }

        let mut state = self.state.lock().await;
        let Some(old_size) = state
            .hosts
            .get(&key.host)
            .and_then(|host| host.entries.get(&key.path))
            .map(|entry| desired_size(&entry.desired))
        else {
            return Ok(MutationDisposition::ImmediateWriteRequired);
        };
        let additional = desired_bytes.saturating_sub(old_size);
        if !make_capacity(&mut state, self.config.max_bytes, additional, Some(&key)) {
            return Ok(MutationDisposition::ImmediateWriteRequired);
        }
        let generation = Generation(state.next_generation);
        state.next_generation = state.next_generation.saturating_add(1);
        let lru_sequence = next_lru(&mut state);
        let host = host_state_mut(&mut state, &key.host);
        let entry = host
            .entries
            .get_mut(&key.path)
            .expect("prepared cache entry disappeared");
        entry.desired = desired;
        entry.generation = generation;
        entry.dirty = true;
        entry.lru_sequence = lru_sequence;
        host.dirty_payload_bytes = host.dirty_payload_bytes.saturating_add(payload_bytes);
        if host.first_dirty_deadline.is_none() {
            host.first_dirty_deadline = Some(Instant::now() + self.config.flush_delay);
        }
        let flush_now = host.dirty_payload_bytes >= self.config.flush_threshold_bytes;
        let start_timer = !host.timer_running;
        if start_timer {
            host.timer_running = true;
        }
        state.cached_bytes = state
            .cached_bytes
            .saturating_sub(old_size)
            .saturating_add(desired_bytes);
        runtime.changed.notify_waiters();
        drop(state);
        if start_timer {
            self.spawn_timer(key.host.clone(), Arc::clone(&runtime));
        }
        if flush_now {
            let cache = Arc::clone(self);
            let host = key.host;
            tokio::spawn(async move {
                let _ = cache.flush_once(&host).await;
            });
        }
        Ok(MutationDisposition::Buffered(generation))
    }

    pub(crate) async fn flush_host(&self, host: &str) -> Result<(), EditError> {
        loop {
            match self.flush_once(host).await? {
                FlushProgress::Clean => return Ok(()),
                FlushProgress::More => {}
            }
        }
    }

    pub(crate) async fn shutdown(&self) -> Result<(), EditError> {
        let hosts = {
            let mut state = self.state.lock().await;
            if state.shutting_down {
                return Ok(());
            }
            state.shutting_down = true;
            state.hosts.keys().cloned().collect::<Vec<_>>()
        };
        let mut first_error = None;
        for host in hosts {
            if let Err(error) = self.flush_host(&host).await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub(crate) async fn cached_bytes(&self) -> usize {
        self.state.lock().await.cached_bytes
    }

    async fn host_runtime(&self, host: &str) -> Arc<HostRuntime> {
        let mut state = self.state.lock().await;
        Arc::clone(&host_state_mut(&mut state, host).runtime)
    }

    fn spawn_timer(self: &Arc<Self>, host: String, runtime: Arc<HostRuntime>) {
        let cache = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                let changed = runtime.changed.notified();
                let Some(cache) = cache.upgrade() else {
                    return;
                };
                let wake = {
                    let mut state = cache.state.lock().await;
                    if state.shutting_down {
                        if let Some(host_state) = state.hosts.get_mut(&host) {
                            host_state.timer_running = false;
                        }
                        return;
                    }
                    let Some(host_state) = state.hosts.get_mut(&host) else {
                        return;
                    };
                    if host_conflict(host_state) || !host_dirty(host_state) {
                        host_state.timer_running = false;
                        return;
                    }
                    if host_state.dirty_payload_bytes >= cache.config.flush_threshold_bytes {
                        Some(Instant::now())
                    } else {
                        host_state
                            .retry_deadline
                            .or(host_state.first_dirty_deadline)
                    }
                };
                let Some(wake) = wake else {
                    changed.await;
                    continue;
                };
                tokio::select! {
                    () = tokio::time::sleep_until(wake) => {
                        let _ = cache.flush_once(&host).await;
                    }
                    () = changed => {}
                }
            }
        });
    }

    async fn flush_once(&self, host: &str) -> Result<FlushProgress, EditError> {
        let runtime = self.host_runtime(host).await;
        let _flush = runtime.flush.lock().await;
        let items = {
            let mut state = self.state.lock().await;
            let Some(host_state) = state.hosts.get_mut(host) else {
                return Ok(FlushProgress::Clean);
            };
            if let Some(error) = host_state
                .entries
                .values()
                .find_map(|entry| entry.conflict.clone())
            {
                return Err(error);
            }
            let mut items = host_state
                .entries
                .iter_mut()
                .filter_map(|(path, entry)| {
                    if !entry.dirty || entry.in_flight.is_some() {
                        return None;
                    }
                    entry.in_flight = Some(entry.generation);
                    Some(CommitItem {
                        key: CacheKey {
                            host: host.to_owned(),
                            path: path.clone(),
                        },
                        base: entry.base.clone(),
                        desired: entry.desired.clone(),
                        generation: entry.generation,
                    })
                })
                .collect::<Vec<_>>();
            items.sort_unstable_by(|left, right| left.key.path.cmp(&right.key.path));
            if items.is_empty() {
                return Ok(FlushProgress::Clean);
            }
            host_state.dirty_payload_bytes = 0;
            host_state.first_dirty_deadline = None;
            host_state.retry_deadline = None;
            items
        };

        let outcome = self.backend.commit_batch(host, items.clone()).await;
        let mut state = self.state.lock().await;
        let host_state = state
            .hosts
            .get_mut(host)
            .expect("flushed host state disappeared");
        for success in outcome.successes {
            let Some(entry) = host_state.entries.get_mut(&success.key.path) else {
                continue;
            };
            if entry.in_flight != Some(success.generation) {
                continue;
            }
            entry.base = success.base;
            entry.in_flight = None;
            if entry.generation == success.generation {
                entry.dirty = false;
            }
        }
        match outcome.error {
            None => {
                host_state.retry_attempt = 0;
                host_state.retry_deadline = None;
                host_state.last_transient = None;
                runtime.changed.notify_waiters();
                Ok(if host_dirty(host_state) {
                    FlushProgress::More
                } else {
                    FlushProgress::Clean
                })
            }
            Some(error) => {
                for item in items {
                    if let Some(entry) = host_state.entries.get_mut(&item.key.path)
                        && entry.in_flight == Some(item.generation)
                    {
                        entry.in_flight = None;
                        if error.kind != EditErrorKind::Transient {
                            entry.conflict = Some(error.clone());
                        }
                    }
                }
                if error.kind == EditErrorKind::Transient {
                    let retry_delay = retry_delay(host_state.retry_attempt);
                    host_state.retry_attempt = host_state.retry_attempt.saturating_add(1);
                    host_state.retry_deadline = Some(Instant::now() + retry_delay);
                    host_state.last_transient = Some(error.clone());
                }
                runtime.changed.notify_waiters();
                Err(error)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlushProgress {
    Clean,
    More,
}

fn host_state_mut<'a>(state: &'a mut CacheState, host: &str) -> &'a mut HostState {
    state
        .hosts
        .entry(host.to_owned())
        .or_insert_with(|| HostState {
            entries: HashMap::new(),
            dirty_payload_bytes: 0,
            first_dirty_deadline: None,
            retry_deadline: None,
            retry_attempt: 0,
            last_transient: None,
            timer_running: false,
            runtime: Arc::new(HostRuntime {
                preparation: Mutex::new(()),
                flush: Mutex::new(()),
                changed: Notify::new(),
            }),
        })
}

fn host_dirty(host: &HostState) -> bool {
    host.entries.values().any(|entry| entry.dirty)
}

fn host_conflict(host: &HostState) -> bool {
    host.entries.values().any(|entry| entry.conflict.is_some())
}

fn desired_size(desired: &DesiredState) -> usize {
    match desired {
        DesiredState::Present(bytes) => bytes.len(),
        DesiredState::Deleted => 0,
    }
}

fn next_lru(state: &mut CacheState) -> u64 {
    state.lru_sequence = state.lru_sequence.saturating_add(1);
    state.lru_sequence
}

fn make_capacity(
    state: &mut CacheState,
    maximum: usize,
    additional: usize,
    protected: Option<&CacheKey>,
) -> bool {
    while state.cached_bytes.saturating_add(additional) > maximum {
        let candidate = state
            .hosts
            .iter()
            .flat_map(|(host, host_state)| {
                host_state.entries.iter().filter_map(move |(path, entry)| {
                    let protected = protected
                        .is_some_and(|key| key.host == host.as_str() && key.path == path.as_str());
                    (!protected && !entry.dirty && entry.in_flight.is_none()).then_some((
                        entry.lru_sequence,
                        host.clone(),
                        path.clone(),
                    ))
                })
            })
            .min_by_key(|(sequence, _, _)| *sequence);
        let Some((_, host, path)) = candidate else {
            return false;
        };
        if let Some(entry) = state
            .hosts
            .get_mut(&host)
            .and_then(|host_state| host_state.entries.remove(&path))
        {
            state.cached_bytes = state
                .cached_bytes
                .saturating_sub(desired_size(&entry.desired));
        }
    }
    true
}

fn retry_delay(attempt: usize) -> Duration {
    const SECONDS: [u64; 6] = [1, 2, 4, 8, 16, 30];
    Duration::from_secs(SECONDS[attempt.min(SECONDS.len() - 1)])
}
