use std::time::SystemTime;

use mimic_core::mimic_log;
use galatea_shared::ipc::DetectionDetails;

use crate::probes::file_identity::get_file_index;

#[derive(Clone)]
struct CacheItemData {
    last_mod_time: SystemTime,
    file_size: u64,
    file_index: Option<u64>,
    details: DetectionDetails,
}

pub struct StaticResultCache {
    cache: moka::sync::Cache<String, CacheItemData>,
}

impl StaticResultCache {
    pub fn new() -> Self {
        Self {
            cache: moka::sync::Cache::builder().max_capacity(10_000).build(),
        }
    }

    /// Canonicalizes a raw path to a consistent cache key.
    fn canonicalize_key(raw_path: &str) -> String {
        match dunce::canonicalize(raw_path) {
            Ok(path) => path.to_string_lossy().to_string(),
            Err(_) => raw_path.to_string(),
        }
    }

    /// Inserts or updates a cached analysis result for the given file path.
    pub fn cache_result(
        &self,
        raw_path: &str,
        time: SystemTime,
        size: u64,
        details: DetectionDetails,
    ) {
        let key = Self::canonicalize_key(raw_path);
        let file_index = get_file_index(&key);

        self.cache.insert(
            key,
            CacheItemData {
                last_mod_time: time,
                file_size: size,
                file_index,
                details,
            },
        );
    }

    /// Retrieves a cached result if the file metadata still matches.
    /// Returns `None` on cache miss or if the file has changed.
    pub fn retrieve_result(
        &self,
        raw_path: &str,
        time: SystemTime,
        size: u64,
    ) -> Option<DetectionDetails> {
        let key = Self::canonicalize_key(raw_path);
        let candidate = self.cache.get(&key)?;

        // Validate size and modification time
        if candidate.file_size != size || candidate.last_mod_time != time {
            return None;
        }

        // Validate file index (anti-timestomping)
        if let Some(cached_index) = candidate.file_index {
            let current_index = get_file_index(&key);
            if current_index != Some(cached_index) {
                mimic_log!(
                    "[CACHE] File index mismatch for '{}'. Possible file replacement detected. Invalidating.",
                    raw_path
                );
                self.cache.invalidate(&key);
                return None;
            }
        }

        Some(candidate.details.clone())
    }

    /// Removes a specific entry from the cache (e.g., after a tuning/allowlist change).
    pub fn invalidate_result(&self, raw_path: &str) {
        let key = Self::canonicalize_key(raw_path);
        self.cache.invalidate(&key);
    }
}
