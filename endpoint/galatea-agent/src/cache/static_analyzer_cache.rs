use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime};

use mimic_core::mimic_log;
use galatea_shared::ipc::DetectionDetails;

use crate::probes::file_identity::get_file_index;

use crate::SCAN_WAIT_TIMEOUT_SECS;

/// Maximum time a waiter blocks for an in-flight scan before falling through.
const SCAN_WAIT_TIMEOUT: Duration = Duration::from_secs(SCAN_WAIT_TIMEOUT_SECS);

// ---- Internal types ----

#[derive(Clone)]
struct CacheItemData {
    last_mod_time: SystemTime,
    file_size: u64,
    file_index: Option<u64>,
    details: DetectionDetails,
}

/// Result carried by a completed in-flight scan, including file identity
/// so waiters can re-validate metadata without a second disk hit.
#[derive(Clone)]
pub struct CompletedScan {
    /// The analysis result details.
    pub details: DetectionDetails,
    /// File modification time at scan time.
    pub mod_time: SystemTime,
    /// File size at scan time.
    pub file_size: u64,
    /// NTFS file index at scan time (anti-timestomping).
    pub file_index: Option<u64>,
}

enum ScanState {
    Pending,
    Completed(CompletedScan),
    Failed,
}

/// Synchronisation primitive shared between the scan owner and any waiters.
/// Callers only have access to [`wait`](ScanBarrier::wait).
pub struct ScanBarrier {
    state: Mutex<ScanState>,
    done: Condvar,
}

impl ScanBarrier {
    fn new() -> Self {
        Self {
            state: Mutex::new(ScanState::Pending),
            done: Condvar::new(),
        }
    }

    /// Blocks until the scan owner calls `complete` / `abort`, or until timeout.
    pub fn wait(&self) -> WaitResult {
        let guard = match self.state.lock() {
            Ok(g) => g,
            Err(_) => return WaitResult::Failed,
        };

        let result = self
            .done
            .wait_timeout_while(guard, SCAN_WAIT_TIMEOUT, |s| {
                matches!(s, ScanState::Pending)
            });

        match result {
            Ok((guard, timeout)) => {
                if timeout.timed_out() {
                    return WaitResult::Timeout;
                }
                match &*guard {
                    ScanState::Completed(scan) => WaitResult::Completed(scan.clone()),
                    ScanState::Failed | ScanState::Pending => WaitResult::Failed,
                }
            }
            Err(_) => WaitResult::Failed,
        }
    }

    fn complete(&self, scan: CompletedScan) {
        if let Ok(mut guard) = self.state.lock() {
            *guard = ScanState::Completed(scan);
        }
        self.done.notify_all();
    }

    fn abort(&self) {
        if let Ok(mut guard) = self.state.lock() {
            *guard = ScanState::Failed;
        }
        self.done.notify_all();
    }
}

// ---- Public API types ----

/// Result of waiting on a `ScanBarrier`.
pub enum WaitResult {
    /// The owning thread finished its scan successfully.
    Completed(CompletedScan),
    /// The owning thread aborted (e.g. file unreadable).
    Failed,
    /// The wait timed out before the scan finished.
    Timeout,
}

/// Outcome of `try_acquire_scan`.
pub enum ScanOutcome {
    /// A completed, validated result was found in the cache.
    CacheHit(DetectionDetails),
    /// This caller has claimed the scan slot and must call
    /// [`ScanGuard::complete`] when done. The guard will call
    /// `abort_scan` automatically if dropped without completing.
    Acquired(ScanGuard),
    /// Another thread is already scanning this path.
    /// Call `barrier.wait()` to block for the result.
    Wait(Arc<ScanBarrier>),
}

/// RAII guard that ensures a claimed scan slot is always resolved.
///
/// If the guard is dropped without calling [`complete`](ScanGuard::complete),
/// it aborts the in-progress scan, waking any waiting threads.
pub struct ScanGuard {
    cache: *const StaticResultCache,
    key: Option<String>,
}

// ScanGuard only holds a pointer to the cache which lives in a OnceLock<> static,
// so it is safe to send across threads.
unsafe impl Send for ScanGuard {}

impl ScanGuard {
    /// Completes the scan, promoting the result into the cache and waking waiters.
    /// Consumes the guard so `Drop` won't abort.
    pub fn complete(mut self, scan: CompletedScan) {
        if let Some(key) = self.key.take() {
            // Safety: the cache pointer comes from a &self reference on
            // StaticResultCache which lives in a OnceLock static — it is
            // valid for the program lifetime.
            let cache = unsafe { &*self.cache };
            cache.complete_scan_inner(&key, scan);
        }
    }
}

impl Drop for ScanGuard {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            let cache = unsafe { &*self.cache };
            cache.abort_scan_inner(&key);
        }
    }
}

// ---- Cache implementation ----

/// Thread-safe cache that deduplicates concurrent static analysis scans.
///
/// Two layers:
/// - `completed`: moka cache storing finished results with full metadata.
/// - `in_progress`: tracks paths currently being scanned so a second
///   caller can wait instead of running a redundant scan.
pub struct StaticResultCache {
    completed: moka::sync::Cache<String, CacheItemData>,
    in_progress: Mutex<HashMap<String, Arc<ScanBarrier>>>,
}

impl StaticResultCache {
    /// Creates a new cache with a capacity of 10 000 completed entries.
    pub fn new() -> Self {
        Self {
            completed: moka::sync::Cache::builder()
                .max_capacity(10_000)
                .build(),
            in_progress: Mutex::new(HashMap::new()),
        }
    }

    /// Canonicalizes a raw path to a consistent cache key.
    fn canonicalize_key(raw_path: &str) -> String {
        match dunce::canonicalize(raw_path) {
            Ok(path) => path.to_string_lossy().to_string(),
            Err(_) => raw_path.to_string(),
        }
    }

    /// Attempts to acquire a scan slot or reuse an existing result.
    ///
    /// Returns:
    /// - `CacheHit` if a valid completed result exists.
    /// - `Acquired` if no one is scanning — the caller owns the scan.
    /// - `Wait(barrier)` if another thread is already scanning this path.
    pub fn try_acquire_scan(
        &self,
        raw_path: &str,
        mod_time: SystemTime,
        file_size: u64,
    ) -> ScanOutcome {
        let key = Self::canonicalize_key(raw_path);

        // Fast path: check completed cache
        if let Some(item) = self.completed.get(&key) {
            if item.file_size == file_size && item.last_mod_time == mod_time {
                // Anti-timestomping: validate file index
                if let Some(cached_index) = item.file_index {
                    let current_index = get_file_index(&key);
                    if current_index != Some(cached_index) {
                        mimic_log!(
                            "[CACHE] File index mismatch for '{key}'. Possible replacement. Invalidating."
                        );
                        self.completed.invalidate(&key);
                        // Fall through to acquire
                    } else {
                        return ScanOutcome::CacheHit(item.details.clone());
                    }
                } else {
                    return ScanOutcome::CacheHit(item.details.clone());
                }
            }
            // Metadata changed — invalidate stale entry and fall through
            self.completed.invalidate(&key);
        }

        // Check / insert in-progress
        let mut in_progress = match self.in_progress.lock() {
            Ok(g) => g,
            // Poisoned lock — scan independently, no-op guard (key=None won't clean up)
            Err(_) => return ScanOutcome::Acquired(ScanGuard {
                cache: self as *const StaticResultCache,
                key: None,
            }),
        };

        if let Some(barrier) = in_progress.get(&key) {
            return ScanOutcome::Wait(Arc::clone(barrier));
        }

        let barrier = Arc::new(ScanBarrier::new());
        in_progress.insert(key.clone(), barrier);
        drop(in_progress);

        ScanOutcome::Acquired(ScanGuard {
            cache: self as *const StaticResultCache,
            key: Some(key),
        })
    }

    /// Records a completed scan — called internally by [`ScanGuard::complete`].
    fn complete_scan_inner(
        &self,
        key: &str,
        scan: CompletedScan,
    ) {
        // Insert into completed cache
        self.completed.insert(
            key.to_string(),
            CacheItemData {
                last_mod_time: scan.mod_time,
                file_size: scan.file_size,
                file_index: scan.file_index,
                details: scan.details.clone(),
            },
        );

        // Wake waiters and remove from in-progress
        if let Ok(mut in_progress) = self.in_progress.lock() {
            if let Some(barrier) = in_progress.remove(key) {
                barrier.complete(scan);
            }
        }
    }

    /// Aborts an in-progress scan — called internally by [`ScanGuard`] on drop.
    fn abort_scan_inner(&self, key: &str) {
        if let Ok(mut in_progress) = self.in_progress.lock() {
            if let Some(barrier) = in_progress.remove(key) {
                barrier.abort();
            }
        }
    }

    /// Removes a specific completed entry from the cache.
    pub fn invalidate_result(&self, raw_path: &str) {
        let key = Self::canonicalize_key(raw_path);
        self.completed.invalidate(&key);
    }
}
