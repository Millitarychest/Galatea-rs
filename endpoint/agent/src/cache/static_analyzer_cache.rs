use std::{collections::HashMap, sync::RwLock, time::SystemTime};

use mimic_core::mimic_error;
use shared::ipc::DetectionDetails;


struct CacheItemData{
    last_mod_time: SystemTime,
    file_size: u64,
    details: DetectionDetails
}

pub struct StaticResultCache{
    cache: RwLock<HashMap<String, CacheItemData>>
}

impl StaticResultCache {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::with_capacity(1000))
        }
    }

    pub fn cache_result(&self, path: String, time: SystemTime, size: u64, details: DetectionDetails){
        let mut map = match self.cache.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                mimic_error!("Static Analysis Cache lock was poisoned. Forcebly clearing the cache to self-heal");
                let mut guard = poisoned.into_inner();
                guard.clear();
                guard
            }
        };
        map.insert(path, CacheItemData {
            last_mod_time: time,
            file_size: size,
            details: details
        });
    }

    pub fn retreive_result(&self, path: &str, time: SystemTime, size: u64) -> Option<DetectionDetails>{
        let map = match self.cache.read() {
            Ok(guard) => guard,
            Err(_) => {
                mimic_error!("[WARN] Cache read lock poisoned! Treating as miss.");
                return None;
            }
        };
        if let Some(candidate) = map.get(path) {
            if candidate.file_size == size && candidate.last_mod_time == time {
                return Some(candidate.details.clone());
            }
        }        
        return None;
    }
}
