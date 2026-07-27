#[allow(
    dead_code,
    reason = "the isolated state-machine fixture omits production routing"
)]
#[path = "../src/remote/edit_cache.rs"]
mod edit_cache;

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use edit_cache::{
    BatchMutationDisposition, CacheKey, CommitBatchOutcome, CommitFuture, CommitItem,
    CommitSuccess, DesiredState, EditBackend, EditCache, EditCacheConfig, EditError, EditErrorKind,
    EditFuture, Generation, LoadEntryDisposition, MutationDisposition, PreparedEdit, RemoteBase,
    RemoteSnapshot,
};
use tokio::sync::{Notify, Semaphore};
use tokio::time::advance;

struct FakeBackend {
    snapshots: Mutex<HashMap<CacheKey, RemoteSnapshot>>,
    fetches: AtomicUsize,
    commits: Mutex<Vec<Vec<CommitItem>>>,
    outcomes: Mutex<VecDeque<Result<(), EditError>>>,
    partial_failures: Mutex<VecDeque<(usize, EditError)>>,
    blocked_hosts: Mutex<HashMap<String, Arc<Semaphore>>>,
    commit_started: Notify,
}

fn cached_entry(disposition: LoadEntryDisposition) -> edit_cache::CachedEntry {
    match disposition {
        LoadEntryDisposition::Cached(entry) => entry,
        LoadEntryDisposition::ImmediateWriteRequired => {
            panic!("test fixture unexpectedly exceeded its cache capacity")
        }
    }
}

impl FakeBackend {
    fn new(entries: impl IntoIterator<Item = (CacheKey, RemoteSnapshot)>) -> Arc<Self> {
        Arc::new(Self {
            snapshots: Mutex::new(entries.into_iter().collect()),
            fetches: AtomicUsize::new(0),
            commits: Mutex::new(Vec::new()),
            outcomes: Mutex::new(VecDeque::new()),
            partial_failures: Mutex::new(VecDeque::new()),
            blocked_hosts: Mutex::new(HashMap::new()),
            commit_started: Notify::new(),
        })
    }

    fn block_host(&self, host: &str) -> Arc<Semaphore> {
        let gate = Arc::new(Semaphore::new(0));
        self.blocked_hosts
            .lock()
            .unwrap()
            .insert(host.to_owned(), Arc::clone(&gate));
        gate
    }

    fn queue_outcome(&self, outcome: Result<(), EditError>) {
        self.outcomes.lock().unwrap().push_back(outcome);
    }

    fn queue_partial_failure(&self, successful_items: usize, error: EditError) {
        self.partial_failures
            .lock()
            .unwrap()
            .push_back((successful_items, error));
    }

    fn commit_count(&self) -> usize {
        self.commits.lock().unwrap().len()
    }

    async fn wait_for_commits(&self, expected: usize) {
        loop {
            let notified = self.commit_started.notified();
            if self.commit_count() >= expected {
                return;
            }
            notified.await;
        }
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
                    code: None,
                    message: "missing fake snapshot".to_owned(),
                })
        })
    }

    fn commit_batch<'a>(&'a self, host: &'a str, items: Vec<CommitItem>) -> CommitFuture<'a> {
        Box::pin(async move {
            self.commits.lock().unwrap().push(items.clone());
            self.commit_started.notify_waiters();
            let gate = self.blocked_hosts.lock().unwrap().remove(host);
            if let Some(gate) = gate {
                let Ok(_permit) = gate.acquire().await else {
                    return CommitBatchOutcome {
                        successes: Vec::new(),
                        error: Some(EditError {
                            kind: EditErrorKind::Transient,
                            code: None,
                            message: "fake commit blocked".to_owned(),
                        }),
                    };
                };
            }
            if let Some(Err(error)) = self.outcomes.lock().unwrap().pop_front() {
                return CommitBatchOutcome {
                    successes: Vec::new(),
                    error: Some(error),
                };
            }
            let partial_failure = self.partial_failures.lock().unwrap().pop_front();
            let successful_items = partial_failure
                .as_ref()
                .map_or(items.len(), |(successful, _)| {
                    (*successful).min(items.len())
                });
            let mut snapshots = self.snapshots.lock().unwrap();
            let successes = items
                .into_iter()
                .take(successful_items)
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
                .collect();
            CommitBatchOutcome {
                successes,
                error: partial_failure.map(|(_, error)| error),
            }
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
            code: None,
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
        code: None,
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
async fn a_partial_batch_applies_confirmed_successes_and_only_poison_unconfirmed_entries() {
    let first = key("alpha", "/repo/a.rs");
    let second = key("alpha", "/repo/b.rs");
    let backend = FakeBackend::new([
        (first.clone(), regular(b"first-base")),
        (second.clone(), regular(b"second-base")),
    ]);
    backend.queue_partial_failure(
        1,
        EditError {
            kind: EditErrorKind::Conflict,
            code: None,
            message: "WRITE_CONFLICT".to_owned(),
        },
    );
    let cache = EditCache::new(config(), backend.clone());
    cache.load_complete(first.clone()).await.unwrap();
    cache.load_complete(second.clone()).await.unwrap();
    cache
        .mutate(
            first.clone(),
            DesiredState::Present(Arc::from(&b"first-local"[..])),
            1,
        )
        .await
        .unwrap();
    cache
        .mutate(
            second.clone(),
            DesiredState::Present(Arc::from(&b"second-local"[..])),
            1,
        )
        .await
        .unwrap();

    assert_eq!(
        cache.flush_host("alpha").await.unwrap_err().kind,
        EditErrorKind::Conflict
    );
    assert_eq!(backend.commit_count(), 1);
    let snapshots = backend.snapshots.lock().unwrap();
    assert_eq!(
        snapshots.get(&first).unwrap().desired,
        DesiredState::Present(Arc::from(&b"first-local"[..]))
    );
    assert_eq!(
        snapshots.get(&second).unwrap().desired,
        DesiredState::Present(Arc::from(&b"second-base"[..]))
    );
}

#[tokio::test]
async fn prepared_multi_file_edits_commit_locally_all_or_none() {
    let first = key("alpha", "/repo/a.rs");
    let second = key("alpha", "/repo/b.rs");
    let backend = FakeBackend::new([
        (first.clone(), regular(b"first-base")),
        (second.clone(), regular(b"second-base")),
    ]);
    let cache = EditCache::new(config(), backend);
    let first_view = cached_entry(cache.load_entry_complete(first.clone()).await.unwrap());
    let stale_second = cached_entry(cache.load_entry_complete(second.clone()).await.unwrap());
    cache
        .mutate(
            second.clone(),
            DesiredState::Present(Arc::from(&b"concurrent"[..])),
            1,
        )
        .await
        .unwrap();

    let error = cache
        .mutate_prepared_batch(vec![
            PreparedEdit {
                key: first.clone(),
                expected_generation: first_view.generation,
                desired: DesiredState::Present(Arc::from(&b"first-local"[..])),
                payload_bytes: 1,
            },
            PreparedEdit {
                key: second.clone(),
                expected_generation: stale_second.generation,
                desired: DesiredState::Present(Arc::from(&b"second-local"[..])),
                payload_bytes: 1,
            },
        ])
        .await
        .unwrap_err();

    assert_eq!(error.kind, EditErrorKind::Transient);
    assert_eq!(
        cache.lookup_complete(&first).await,
        Some(DesiredState::Present(Arc::from(&b"first-base"[..])))
    );
    assert_eq!(
        cache.lookup_complete(&second).await,
        Some(DesiredState::Present(Arc::from(&b"concurrent"[..])))
    );

    let first_view = cached_entry(cache.load_entry_complete(first.clone()).await.unwrap());
    let second_view = cached_entry(cache.load_entry_complete(second.clone()).await.unwrap());
    let disposition = cache
        .mutate_prepared_batch(vec![
            PreparedEdit {
                key: first,
                expected_generation: first_view.generation,
                desired: DesiredState::Present(Arc::from(&b"first-local"[..])),
                payload_bytes: 1,
            },
            PreparedEdit {
                key: second,
                expected_generation: second_view.generation,
                desired: DesiredState::Present(Arc::from(&b"second-local"[..])),
                payload_bytes: 1,
            },
        ])
        .await
        .unwrap();
    let BatchMutationDisposition::Buffered(generations) = disposition else {
        panic!("prepared batch unexpectedly required immediate writes");
    };
    assert_eq!(generations.len(), 2);
}

#[tokio::test]
async fn a_new_generation_rebases_while_the_previous_flush_is_in_flight() {
    let path = key("alpha", "/repo/a.rs");
    let backend = FakeBackend::new([(path.clone(), regular(b"base"))]);
    let release = backend.block_host("alpha");
    let cache = EditCache::new(config(), backend.clone());
    cache.load_complete(path.clone()).await.unwrap();
    cache
        .mutate(
            path.clone(),
            DesiredState::Present(Arc::from(&b"first"[..])),
            1,
        )
        .await
        .unwrap();
    let first_flush = {
        let cache = Arc::clone(&cache);
        tokio::spawn(async move { cache.flush_host("alpha").await })
    };
    backend.wait_for_commits(1).await;
    cache
        .mutate(
            path.clone(),
            DesiredState::Present(Arc::from(&b"second"[..])),
            1,
        )
        .await
        .unwrap();
    let barrier = {
        let cache = Arc::clone(&cache);
        tokio::spawn(async move { cache.flush_host("alpha").await })
    };
    release.add_permits(1);
    first_flush.await.unwrap().unwrap();
    barrier.await.unwrap().unwrap();

    {
        let commits = backend.commits.lock().unwrap();
        assert_eq!(commits.len(), 2);
        assert_eq!(
            commits[1][0].desired,
            DesiredState::Present(Arc::from(&b"second"[..]))
        );
        assert_eq!(
            commits[1][0].base,
            RemoteBase::Regular {
                sha256: "committed-5".to_owned(),
                mode: 0o640,
            }
        );
    }
    assert_eq!(
        cache.lookup_complete(&path).await,
        Some(DesiredState::Present(Arc::from(&b"second"[..])))
    );
}

#[tokio::test]
async fn a_blocked_host_does_not_block_another_hosts_threshold_flush() {
    let alpha = key("alpha", "/repo/a.rs");
    let beta = key("beta", "/repo/b.rs");
    let backend = FakeBackend::new([
        (alpha.clone(), regular(b"a")),
        (beta.clone(), regular(b"b")),
    ]);
    let release = backend.block_host("alpha");
    let cache = EditCache::new(config(), backend.clone());
    cache.load_complete(alpha.clone()).await.unwrap();
    cache.load_complete(beta.clone()).await.unwrap();
    cache
        .mutate(
            alpha,
            DesiredState::Present(Arc::from(&b"blocked"[..])),
            16 * 1024,
        )
        .await
        .unwrap();
    backend.wait_for_commits(1).await;
    cache
        .mutate(
            beta,
            DesiredState::Present(Arc::from(&b"independent"[..])),
            16 * 1024,
        )
        .await
        .unwrap();
    backend.wait_for_commits(2).await;
    assert_eq!(backend.commits.lock().unwrap()[1][0].key.host, "beta");
    release.add_permits(1);
    cache.flush_host("alpha").await.unwrap();
}

#[tokio::test]
async fn a_same_host_barrier_excludes_new_local_generations_until_released() {
    let path = key("alpha", "/repo/a.rs");
    let backend = FakeBackend::new([(path.clone(), regular(b"base"))]);
    let cache = EditCache::new(config(), backend);
    cache.load_complete(path.clone()).await.unwrap();
    let barrier = cache.begin_barrier("alpha").await;
    let mutation = {
        let cache = Arc::clone(&cache);
        tokio::spawn(async move {
            cache
                .mutate(
                    path,
                    DesiredState::Present(Arc::from(&b"after-barrier"[..])),
                    1,
                )
                .await
        })
    };
    tokio::task::yield_now().await;
    assert!(!mutation.is_finished());
    drop(barrier);
    assert!(mutation.await.unwrap().is_ok());
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
    assert_eq!(DesiredState::Deleted, DesiredState::Deleted);
    assert_ne!(EditErrorKind::OutcomeUnknown, EditErrorKind::Permanent);
}

#[tokio::test]
async fn shutdown_is_idempotent() {
    let backend = FakeBackend::new([]);
    let cache = EditCache::new(config(), backend);
    cache.shutdown().await.unwrap();
    cache.shutdown().await.unwrap();
}
