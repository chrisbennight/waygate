use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use uuid::Uuid;

const DEFAULT_CAPACITY: usize = 256;

fn assert_send_sync<T: Send + Sync>() {}
const _: fn() = assert_send_sync::<jsonschema::Validator>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    tool_id: Uuid,
    schema_hash: String,
    schema_value_hash: String,
}

#[derive(Clone)]
pub(super) enum CachedValidator {
    Ready(Arc<jsonschema::Validator>),
    Invalid,
}

struct CacheState {
    entries: HashMap<CacheKey, Arc<OnceLock<CachedValidator>>>,
    insertion_order: VecDeque<CacheKey>,
}

/// Bounded cache of validators for exact approved tool-schema versions.
///
/// The global mutex protects only lookup, insertion, and FIFO eviction.
/// Compilation happens through a per-key [`OnceLock`] after releasing that
/// mutex, so unrelated cache hits continue while one new schema compiles and
/// concurrent admissions for the same resident entry converge on one result.
/// At capacity, a new miss waits for the oldest entry to finish initialization
/// before evicting it; an in-flight exact key is never split across cells.
pub struct SchemaValidatorCache {
    capacity: usize,
    state: Mutex<CacheState>,
    #[cfg(test)]
    compilations: AtomicUsize,
}

impl SchemaValidatorCache {
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::with_capacity(DEFAULT_CAPACITY))
    }

    fn with_capacity(capacity: usize) -> Self {
        assert!(
            capacity > 0,
            "schema validator cache capacity must be non-zero"
        );
        Self {
            capacity,
            state: Mutex::new(CacheState {
                entries: HashMap::with_capacity(capacity),
                insertion_order: VecDeque::with_capacity(capacity),
            }),
            #[cfg(test)]
            compilations: AtomicUsize::new(0),
        }
    }

    pub(super) fn get_or_compile(
        &self,
        tool_id: Uuid,
        schema_hash: &str,
        schema: &serde_json::Value,
    ) -> CachedValidator {
        let key = CacheKey {
            tool_id,
            schema_hash: schema_hash.to_owned(),
            schema_value_hash: waygate_catalog::validator_schema_hash(schema),
        };
        self.get_or_compile_with(key, || match jsonschema::validator_for(schema) {
            Ok(validator) => CachedValidator::Ready(Arc::new(validator)),
            Err(_) => {
                waygate_telemetry::metrics::record_schema_validator_compile_failure();
                CachedValidator::Invalid
            }
        })
    }

    fn get_or_compile_with(
        &self,
        key: CacheKey,
        compile: impl FnOnce() -> CachedValidator,
    ) -> CachedValidator {
        self.get_or_compile_with_wait_hook(key, compile, || {})
    }

    fn get_or_compile_with_wait_hook(
        &self,
        key: CacheKey,
        compile: impl FnOnce() -> CachedValidator,
        on_wait: impl Fn(),
    ) -> CachedValidator {
        let cell = {
            let mut state = self
                .state
                .lock()
                .expect("schema validator cache mutex poisoned");
            if let Some(cached) = state.entries.get(&key) {
                waygate_telemetry::metrics::record_schema_validator_cache_hit();
                Arc::clone(cached)
            } else {
                waygate_telemetry::metrics::record_schema_validator_cache_miss();
                loop {
                    // Another waiter for this exact key may have inserted its
                    // cell while this caller slept on a full cache. Rejoin that
                    // cell before considering eviction so concurrent misses
                    // cannot split one schema across multiple validators.
                    if let Some(cached) = state.entries.get(&key) {
                        break Arc::clone(cached);
                    }
                    if state.entries.len() < self.capacity {
                        let cell = Arc::new(OnceLock::new());
                        state.insertion_order.push_back(key.clone());
                        state.entries.insert(key.clone(), Arc::clone(&cell));
                        break cell;
                    }

                    let oldest = state
                        .insertion_order
                        .front()
                        .expect("full schema validator cache must have an eviction candidate");
                    let oldest_cell = Arc::clone(
                        state
                            .entries
                            .get(oldest)
                            .expect("eviction candidate must exist in the cache"),
                    );
                    if oldest_cell.get().is_none() {
                        on_wait();
                        drop(state);
                        oldest_cell.wait();
                        state = self
                            .state
                            .lock()
                            .expect("schema validator cache mutex poisoned after waiting");
                        continue;
                    }
                    let oldest = state
                        .insertion_order
                        .pop_front()
                        .expect("full schema validator cache must have an eviction candidate");
                    state.entries.remove(&oldest);
                    waygate_telemetry::metrics::record_schema_validator_cache_eviction();
                }
            }
        };

        let result = cell
            .get_or_init(|| {
                #[cfg(test)]
                self.compilations.fetch_add(1, Ordering::SeqCst);
                compile()
            })
            .clone();
        result
    }

    #[cfg(test)]
    pub(super) fn compilation_count(&self) -> usize {
        self.compilations.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::mpsc;
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    use serde_json::json;
    use uuid::Uuid;

    use super::{CacheKey, CachedValidator, SchemaValidatorCache};

    fn ready(result: CachedValidator) -> Arc<jsonschema::Validator> {
        match result {
            CachedValidator::Ready(validator) => validator,
            CachedValidator::Invalid => panic!("test schema must compile"),
        }
    }

    #[test]
    fn concurrent_admissions_share_one_compiled_validator() {
        let cache = Arc::new(SchemaValidatorCache::with_capacity(4));
        let barrier = Arc::new(Barrier::new(3));
        let tool_id = Uuid::new_v4();
        let schema = Arc::new(json!({"type": "object"}));

        let handles: Vec<_> = (0..2)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let barrier = Arc::clone(&barrier);
                let schema = Arc::clone(&schema);
                std::thread::spawn(move || {
                    barrier.wait();
                    ready(cache.get_or_compile(tool_id, "hash-a", &schema))
                })
            })
            .collect();
        barrier.wait();

        let mut validators = handles.into_iter().map(|handle| handle.join().unwrap());
        let first = validators.next().unwrap();
        let second = validators.next().unwrap();
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn cache_key_includes_tool_identity_and_schema_hash() {
        let cache = SchemaValidatorCache::with_capacity(4);
        let schema = json!({"type": "object"});
        let tool_a = Uuid::new_v4();
        let tool_b = Uuid::new_v4();

        let a_v1 = ready(cache.get_or_compile(tool_a, "v1", &schema));
        let a_v2 = ready(cache.get_or_compile(tool_a, "v2", &schema));
        let b_v1 = ready(cache.get_or_compile(tool_b, "v1", &schema));

        assert!(!Arc::ptr_eq(&a_v1, &a_v2));
        assert!(!Arc::ptr_eq(&a_v1, &b_v1));
    }

    #[test]
    fn schema_value_rotation_never_reuses_positive_or_negative_entry() {
        let cache = SchemaValidatorCache::with_capacity(8);
        let tool_id = Uuid::new_v4();

        let integer =
            ready(cache.get_or_compile(tool_id, "catalog-hash", &json!({"type": "integer"})));
        let string =
            ready(cache.get_or_compile(tool_id, "catalog-hash", &json!({"type": "string"})));
        assert!(!Arc::ptr_eq(&integer, &string));
        assert!(integer.validate(&json!(7)).is_ok());
        assert!(string.validate(&json!("rotated")).is_ok());

        assert!(matches!(
            cache.get_or_compile(tool_id, "catalog-hash", &json!({"type": 7})),
            CachedValidator::Invalid
        ));
        let corrected =
            ready(cache.get_or_compile(tool_id, "catalog-hash", &json!({"type": "boolean"})));
        assert!(corrected.validate(&json!(true)).is_ok());
        assert_eq!(cache.compilation_count(), 4);
    }

    #[test]
    fn compiling_one_miss_does_not_block_an_unrelated_hit() {
        let cache = Arc::new(SchemaValidatorCache::with_capacity(4));
        let hit_tool_id = Uuid::new_v4();
        let hit_schema = json!({"type": "integer"});
        let expected = ready(cache.get_or_compile(hit_tool_id, "hit", &hit_schema));

        let miss_schema = json!({"type": "string"});
        let miss_key = CacheKey {
            tool_id: Uuid::new_v4(),
            schema_hash: "miss".into(),
            schema_value_hash: waygate_catalog::validator_schema_hash(&miss_schema),
        };
        let (compile_started_tx, compile_started_rx) = mpsc::channel();
        let (release_compile_tx, release_compile_rx) = mpsc::channel();
        let miss_cache = Arc::clone(&cache);
        let miss = std::thread::spawn(move || {
            miss_cache.get_or_compile_with(miss_key, || {
                compile_started_tx.send(()).unwrap();
                release_compile_rx.recv().unwrap();
                let validator = jsonschema::validator_for(&miss_schema).unwrap();
                CachedValidator::Ready(Arc::new(validator))
            })
        });
        compile_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("miss compilation must start");

        let (hit_tx, hit_rx) = mpsc::channel();
        let hit_cache = Arc::clone(&cache);
        let hit = std::thread::spawn(move || {
            hit_tx
                .send(ready(hit_cache.get_or_compile(
                    hit_tool_id,
                    "hit",
                    &hit_schema,
                )))
                .unwrap();
        });
        let observed_hit = hit_rx.recv_timeout(Duration::from_secs(1));
        release_compile_tx.send(()).unwrap();
        miss.join().unwrap();
        hit.join().unwrap();

        let observed_hit = observed_hit.expect("unrelated hit must not wait for miss compilation");
        assert!(Arc::ptr_eq(&expected, &observed_hit));
    }

    #[test]
    fn full_cache_waits_for_an_in_flight_fifo_entry_before_eviction() {
        let cache = Arc::new(SchemaValidatorCache::with_capacity(1));
        let first_schema = json!({"type": "integer"});
        let first_key = CacheKey {
            tool_id: Uuid::new_v4(),
            schema_hash: "first".into(),
            schema_value_hash: waygate_catalog::validator_schema_hash(&first_schema),
        };
        let (first_started_tx, first_started_rx) = mpsc::channel();
        let (release_first_tx, release_first_rx) = mpsc::channel();
        let first_cache = Arc::clone(&cache);
        let first = std::thread::spawn(move || {
            first_cache.get_or_compile_with(first_key, || {
                first_started_tx.send(()).unwrap();
                release_first_rx.recv().unwrap();
                CachedValidator::Ready(Arc::new(jsonschema::validator_for(&first_schema).unwrap()))
            })
        });
        first_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("first compilation must start");

        let second_schema = json!({"type": "string"});
        let second_key = CacheKey {
            tool_id: Uuid::new_v4(),
            schema_hash: "second".into(),
            schema_value_hash: waygate_catalog::validator_schema_hash(&second_schema),
        };
        let (second_attempted_tx, second_attempted_rx) = mpsc::channel();
        let (second_started_tx, second_started_rx) = mpsc::channel();
        let second_cache = Arc::clone(&cache);
        let second = std::thread::spawn(move || {
            second_attempted_tx.send(()).unwrap();
            second_cache.get_or_compile_with(second_key, || {
                second_started_tx.send(()).unwrap();
                CachedValidator::Ready(Arc::new(jsonschema::validator_for(&second_schema).unwrap()))
            })
        });
        second_attempted_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("second miss must reach the cache");
        assert!(
            second_started_rx
                .recv_timeout(Duration::from_millis(50))
                .is_err(),
            "a full cache must not evict an entry that is still compiling"
        );

        release_first_tx.send(()).unwrap();
        ready(first.join().unwrap());
        second_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("second compilation must start after the FIFO entry is ready");
        ready(second.join().unwrap());
        assert_eq!(cache.compilation_count(), 2);
    }

    #[test]
    fn initialization_finishing_between_readiness_check_and_wait_is_observed() {
        let cache = Arc::new(SchemaValidatorCache::with_capacity(1));
        let first_schema = json!({"type": "integer"});
        let first_key = CacheKey {
            tool_id: Uuid::new_v4(),
            schema_hash: "first".into(),
            schema_value_hash: waygate_catalog::validator_schema_hash(&first_schema),
        };
        let (first_started_tx, first_started_rx) = mpsc::channel();
        let (release_first_tx, release_first_rx) = mpsc::channel();
        let first_cache = Arc::clone(&cache);
        let first = std::thread::spawn(move || {
            first_cache.get_or_compile_with(first_key, || {
                first_started_tx.send(()).unwrap();
                release_first_rx.recv().unwrap();
                CachedValidator::Ready(Arc::new(jsonschema::validator_for(&first_schema).unwrap()))
            })
        });
        first_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("first compilation must start");

        let second_schema = json!({"type": "string"});
        let second_key = CacheKey {
            tool_id: Uuid::new_v4(),
            schema_hash: "second".into(),
            schema_value_hash: waygate_catalog::validator_schema_hash(&second_schema),
        };
        let (readiness_checked_tx, readiness_checked_rx) = mpsc::channel();
        let (resume_wait_tx, resume_wait_rx) = mpsc::channel();
        let (completed_tx, completed_rx) = mpsc::channel();
        let second_cache = Arc::clone(&cache);
        let second = std::thread::spawn(move || {
            let result = second_cache.get_or_compile_with_wait_hook(
                second_key,
                || {
                    CachedValidator::Ready(Arc::new(
                        jsonschema::validator_for(&second_schema).unwrap(),
                    ))
                },
                || {
                    readiness_checked_tx.send(()).unwrap();
                    resume_wait_rx.recv().unwrap();
                },
            );
            completed_tx.send(ready(result)).unwrap();
        });
        readiness_checked_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("full-cache miss must observe the in-flight FIFO entry");

        release_first_tx.send(()).unwrap();
        ready(first.join().unwrap());
        resume_wait_tx.send(()).unwrap();

        let validator = completed_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("completed initialization must be visible without a notification race");
        second.join().unwrap();
        assert!(validator.validate(&json!("ready")).is_ok());
        assert_eq!(cache.compilation_count(), 2);
    }

    #[test]
    fn same_key_waiters_rejoin_the_inserted_cell_after_a_full_cache_wake() {
        let cache = Arc::new(SchemaValidatorCache::with_capacity(1));
        let first_schema = json!({"type": "integer"});
        let first_key = CacheKey {
            tool_id: Uuid::new_v4(),
            schema_hash: "first".into(),
            schema_value_hash: waygate_catalog::validator_schema_hash(&first_schema),
        };
        let (first_started_tx, first_started_rx) = mpsc::channel();
        let (release_first_tx, release_first_rx) = mpsc::channel();
        let first_cache = Arc::clone(&cache);
        let first = std::thread::spawn(move || {
            first_cache.get_or_compile_with(first_key, || {
                first_started_tx.send(()).unwrap();
                release_first_rx.recv().unwrap();
                CachedValidator::Ready(Arc::new(jsonschema::validator_for(&first_schema).unwrap()))
            })
        });
        first_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("first compilation must start");

        let second_schema = Arc::new(json!({"type": "string"}));
        let second_key = CacheKey {
            tool_id: Uuid::new_v4(),
            schema_hash: "second".into(),
            schema_value_hash: waygate_catalog::validator_schema_hash(&second_schema),
        };
        let start = Arc::new(Barrier::new(3));
        let (waiting_tx, waiting_rx) = mpsc::channel();
        let waiters: Vec<_> = (0..2)
            .map(|waiter_id| {
                let cache = Arc::clone(&cache);
                let key = second_key.clone();
                let schema = Arc::clone(&second_schema);
                let start = Arc::clone(&start);
                let waiting_tx = waiting_tx.clone();
                std::thread::spawn(move || {
                    let announced = Cell::new(false);
                    start.wait();
                    ready(cache.get_or_compile_with_wait_hook(
                        key,
                        || {
                            CachedValidator::Ready(Arc::new(
                                jsonschema::validator_for(&schema).unwrap(),
                            ))
                        },
                        || {
                            if !announced.replace(true) {
                                waiting_tx.send(waiter_id).unwrap();
                            }
                        },
                    ))
                })
            })
            .collect();
        start.wait();

        let mut waiting = [
            waiting_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("first same-key miss must wait on the full cache"),
            waiting_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("second same-key miss must wait on the full cache"),
        ];
        waiting.sort_unstable();
        assert_eq!(waiting, [0, 1]);

        release_first_tx.send(()).unwrap();
        ready(first.join().unwrap());
        let mut validators = waiters.into_iter().map(|waiter| waiter.join().unwrap());
        let first_waiter = validators.next().unwrap();
        let second_waiter = validators.next().unwrap();
        assert!(Arc::ptr_eq(&first_waiter, &second_waiter));
        assert_eq!(cache.compilation_count(), 2);
    }

    #[test]
    fn eviction_is_fifo_and_never_returns_an_old_validator() {
        let cache = SchemaValidatorCache::with_capacity(2);
        let tool_id = Uuid::new_v4();

        let first = ready(cache.get_or_compile(tool_id, "v1", &json!({"type": "integer"})));
        let second = ready(cache.get_or_compile(tool_id, "v2", &json!({"type": "string"})));
        assert!(Arc::ptr_eq(
            &first,
            &ready(cache.get_or_compile(tool_id, "v1", &json!({"type": "integer"})))
        ));
        let _third = ready(cache.get_or_compile(tool_id, "v3", &json!({"type": "boolean"})));
        let recompiled_first =
            ready(cache.get_or_compile(tool_id, "v1", &json!({"type": "integer"})));

        assert!(!Arc::ptr_eq(&first, &recompiled_first));
        assert!(recompiled_first.validate(&json!(7)).is_ok());
        assert!(recompiled_first.validate(&json!("wrong schema")).is_err());
        assert!(second.validate(&json!("still v2")).is_ok());
    }

    #[test]
    fn invalid_schema_failure_is_cached_for_the_exact_key() {
        let cache = SchemaValidatorCache::with_capacity(2);
        let tool_id = Uuid::new_v4();
        let invalid = json!({"type": {"operator-secret-marker": 42}});

        let first = cache.get_or_compile(tool_id, "bad", &invalid);
        assert!(matches!(first, CachedValidator::Invalid));
        assert!(matches!(
            cache.get_or_compile(tool_id, "bad", &invalid),
            CachedValidator::Invalid
        ));
        assert_eq!(cache.compilation_count(), 1);
    }
}
