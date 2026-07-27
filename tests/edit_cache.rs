#[path = "../src/remote/edit_cache.rs"]
mod edit_cache;

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use edit_cache::{
    CacheKey, CommitItem, CommitSuccess, DesiredState, EditBackend, EditCache, EditCacheConfig,
    EditError, EditErrorKind, EditFuture, Generation, MutationDisposition, RemoteBase,
    RemoteSnapshot,
};
use tokio::sync::{Notify, Semaphore};
use tokio::time::advance;

struct FakeBackend {
    snapshots: Mutex<HashMap<CacheKey, RemoteSnapshot>>,
    fetches: AtomicUsize,
    commits: Mutex<Vec<Vec<CommitItem>>>,
    outcomes: Mutex<VecDeque<Result<(), EditError>>>,
    commit_started: Notify,
    commit_permits: Semaphore,
}

impl FakeBackend {
    fn new(entries: impl IntoIterator<Item = (CacheKey, RemoteSnapshot)>) -> Arc<Self> {
        Arc::new(Self {
            snapshots: Mutex::new(entries.into_iter().collect()),
            fetches: AtomicUsize::new(0),
            commits: Mutex::new(Vec::new()),
            outcomes: Mutex::new(VecDeque::new()),
            commit_started: Notify::new(),
            commit_permits: Semaphore::new(usize::MAX >> 4),
        })
    }

    fn queue_outcome(&self, outcome: Result<(), EditError>) {
        self.outcomes.lock().unwrap().push_back(outcome);
    }

    fn commit_count(&self) -> usize {
        self.commits.lock().unwrap().len()
    }
}

impl EditBackend for FakeBackend {
    fn fetch_complete<'a>(&'a self, key: &'a CacheKey) -> EditFuture<'a, RemoteSnapshot> {
        Box::pin(async move {
            self.fetches.fetch_add(1, Ordering::Relaxed);
            self.snapshots
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| EditError {
                    kind: EditErrorKind::Transient,
                    message: "missing fake snapshot".to_owned(),
                })
        })
    }

    fn commit_batch<'a>(
        &'a self,
        _host: &'a str,
        items: Vec<CommitItem>,
    ) -> EditFuture<'a, Vec<CommitSuccess>> {
        Box::pin(async move {
            self.commits.lock().unwrap().push(items.clone());
            self.commit_started.notify_waiters();
            let permit = self.commit_permits.acquire().await.map_err(|_| EditError {
                kind: EditErrorKind::Transient,
                message: "fake commit blocked".to_owned(),
            })?;
            permit.forget();
            if let Some(outcome) = self.outcomes.lock().unwrap().pop_front() {
                outcome?;
            }
            let mut snapshots = self.snapshots.lock().unwrap();
            Ok(items
                .into_iter()
                .map(|item| {
                    let base = match &item.desired {
                        DesiredState::Present(bytes) => RemoteBase::Regular {
                            sha256: format!("committed-{}", bytes.len()),
                            mode: match item.base {
                                RemoteBase::Regular { mode, .. } => mode,
                                RemoteBase::Missing => 0o600,
                            },
                        },
                        DesiredState::Deleted => RemoteBase::Missing,
                    };
                    snapshots.insert(
                        item.key.clone(),
                        RemoteSnapshot {
                            base: base.clone(),
                            desired: item.desired.clone(),
                        },
                    );
                    CommitSuccess {
                        key: item.key,
                        generation: item.generation,
                        base,
                    }
                })
                .collect())
        })
    }
}

fn key(host: &str, path: &str) -> CacheKey {
    CacheKey {
        host: host.to_owned(),
        path: path.to_owned(),
    }
}

fn regular(bytes: &'static [u8]) -> RemoteSnapshot {
    RemoteSnapshot {
        base: RemoteBase::Regular {
            sha256: format!("base-{}", bytes.len()),
            mode: 0o640,
        },
        desired: DesiredState::Present(Arc::from(bytes)),
    }
}

fn config() -> EditCacheConfig {
    EditCacheConfig {
        flush_delay: Duration::from_secs(30),
        flush_threshold_bytes: 16 * 1024,
        max_bytes: 16 * 1024 * 1024,
    }
}

#[tokio::test]
async fn complete_fetch_is_cached_but_a_partial_miss_does_not_create_an_entry() {
    let path = key("alpha", "/repo/a.rs");
    let partial = key("alpha", "/repo/partial.rs");
    let backend = FakeBackend::new([
        (path.clone(), regular(b"first")),
        (partial.clone(), regular(b"partial")),
    ]);
    let cache = EditCache::new(config(), backend.clone());

    assert_eq!(
        cache.load_complete(path.clone()).await.unwrap(),
        DesiredState::Present(Arc::from(&b"first"[..]))
    );
    assert_eq!(
        cache.load_complete(path.clone()).await.unwrap(),
        DesiredState::Present(Arc::from(&b"first"[..]))
    );
    assert_eq!(backend.fetches.load(Ordering::Relaxed), 1);
    assert_eq!(cache.lookup_complete(&partial).await, None);
    assert_eq!(backend.fetches.load(Ordering::Relaxed), 1);
}

#[tokio::test(start_paused = true)]
async fn later_edits_do_not_move_the_first_deadline_and_exact_threshold_flushes() {
    let path = key("alpha", "/repo/a.rs");
    let backend = FakeBackend::new([(path.clone(), regular(b"base"))]);
    let cache = EditCache::new(config(), backend.clone());
    cache.load_complete(path.clone()).await.unwrap();

    cache
        .mutate(
            path.clone(),
            DesiredState::Present(Arc::from(&b"one"[..])),
            1,
        )
        .await
        .unwrap();
    advance(Duration::from_secs(29)).await;
    cache
        .mutate(
            path.clone(),
            DesiredState::Present(Arc::from(&b"two"[..])),
            1,
        )
        .await
        .unwrap();
    advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(backend.commit_count(), 1);

    cache
        .mutate(
            path,
            DesiredState::Present(Arc::from(&b"three"[..])),
            16 * 1024,
        )
        .await
        .unwrap();
    tokio::task::yield_now().await;
    assert_eq!(backend.commit_count(), 2);
}

#[tokio::test(start_paused = true)]
async fn transient_retries_are_capped_and_a_barrier_bypasses_the_sleep_once() {
    let path = key("alpha", "/repo/a.rs");
    let backend = FakeBackend::new([(path.clone(), regular(b"base"))]);
    for _ in 0..6 {
        backend.queue_outcome(Err(EditError {
            kind: EditErrorKind::Transient,
            message: "offline".to_owned(),
        }));
    }
    let cache = EditCache::new(config(), backend.clone());
    cache.load_complete(path.clone()).await.unwrap();
    cache
        .mutate(path, DesiredState::Present(Arc::from(&b"dirty"[..])), 1)
        .await
        .unwrap();

    assert!(cache.flush_host("alpha").await.is_err());
    assert_eq!(backend.commit_count(), 1);
    assert!(cache.flush_host("alpha").await.is_err());
    assert_eq!(backend.commit_count(), 2);
    for (delay, expected) in [(2, 3), (4, 4), (8, 5), (16, 6), (30, 7)] {
        advance(Duration::from_secs(delay)).await;
        tokio::task::yield_now().await;
        assert_eq!(backend.commit_count(), expected);
    }
}

#[tokio::test(start_paused = true)]
async fn conflicts_are_sticky_and_retain_the_latest_local_bytes() {
    let path = key("alpha", "/repo/a.rs");
    let backend = FakeBackend::new([(path.clone(), regular(b"base"))]);
    backend.queue_outcome(Err(EditError {
        kind: EditErrorKind::Conflict,
        message: "WRITE_CONFLICT".to_owned(),
    }));
    let cache = EditCache::new(config(), backend.clone());
    cache.load_complete(path.clone()).await.unwrap();
    cache
        .mutate(
            path.clone(),
            DesiredState::Present(Arc::from(&b"local"[..])),
            1,
        )
        .await
        .unwrap();

    let first = cache.flush_host("alpha").await.unwrap_err();
    advance(Duration::from_secs(300)).await;
    tokio::task::yield_now().await;
    assert_eq!(backend.commit_count(), 1);
    assert_eq!(cache.flush_host("alpha").await.unwrap_err(), first);
    assert_eq!(
        cache.lookup_complete(&path).await,
        Some(DesiredState::Present(Arc::from(&b"local"[..])))
    );
}

#[tokio::test]
async fn clean_lru_is_evicted_dirty_content_is_retained_and_oversize_falls_back() {
    let first = key("alpha", "/repo/first");
    let second = key("alpha", "/repo/second");
    let dirty = key("alpha", "/repo/dirty");
    let backend = FakeBackend::new([
        (first.clone(), regular(b"123456")),
        (second.clone(), regular(b"abcdef")),
        (dirty.clone(), regular(b"xy")),
    ]);
    let cache = EditCache::new(
        EditCacheConfig {
            max_bytes: 10,
            ..config()
        },
        backend,
    );
    cache.load_complete(first.clone()).await.unwrap();
    cache.load_complete(second.clone()).await.unwrap();
    assert_eq!(cache.lookup_complete(&first).await, None);
    cache.load_complete(dirty.clone()).await.unwrap();
    cache
        .mutate(
            dirty.clone(),
            DesiredState::Present(Arc::from(&b"dirty"[..])),
            1,
        )
        .await
        .unwrap();
    assert_eq!(
        cache
            .mutate(
                key("alpha", "/repo/huge"),
                DesiredState::Present(Arc::from(&b"01234567890"[..])),
                1,
            )
            .await
            .unwrap(),
        MutationDisposition::ImmediateWriteRequired
    );
    assert!(cache.lookup_complete(&dirty).await.is_some());
    assert!(cache.cached_bytes().await <= 10);
}

#[test]
fn public_generation_order_is_monotonic() {
    assert!(Generation(2) > Generation(1));
    assert_eq!(RemoteBase::Missing, RemoteBase::Missing);
}

#[tokio::test]
async fn shutdown_is_idempotent() {
    let backend = FakeBackend::new([]);
    let cache = EditCache::new(config(), backend);
    cache.shutdown().await.unwrap();
    cache.shutdown().await.unwrap();
}
