use std::sync::{Arc, RwLock};

use galatea_shared::id::GA_PID;
use mimic_core::{mimic_error, mimic_log};
use moka::policy::EvictionPolicy;

use crate::{cache::file_context_cache::{FileContextKey, fsc_canonicalize_path}, engine::signatures::process_signatures};

const PROCESS_CONTEXT_CACHE_CAPACITY: u64 = 10_000;
const HIGH_PRIORITY_PROCESS_CONTEXT_CACHE_CAPACITY: u64 = 2_000;
const NORMAL_PROCESS_CONTEXT_CACHE_CAPACITY: u64 =
    PROCESS_CONTEXT_CACHE_CAPACITY - HIGH_PRIORITY_PROCESS_CONTEXT_CACHE_CAPACITY;

/// Partial process telemetry update data.
#[derive(Debug, Clone, Default)]
pub struct ProcessContextUpdate {
    /// Windows-assigned process ID.
    pub pid: Option<u64>,
    /// Windows process start key.
    pub process_start_key: Option<u64>,
    /// Current behavioural score for the process.
    pub behavioural_score: Option<u64>,
    /// Path of the process image.
    pub image_path: Option<String>,
    /// Context key for the process image file.
    pub image_context_key: Option<FileContextKey>,
    /// Flags matched during process runtime
    pub matching_flags: Option<Vec<process_signatures::ProcessFlags>>
}

/// Contextual information about a process used during correlation.
#[derive(Debug, Clone, Default)]
pub struct ProcessContext {
    /// Windows-assigned process ID.
    pid: Option<u64>,
    /// Windows process start key.
    process_start_key: Option<u64>,
    /// Galatea internal process identity.
    guid: Option<GA_PID>,
    /// Score of all current indicators.
    behavioural_score: Option<u64>,
    /// Path of the process image.
    image_path: Option<String>,
    /// Context key for the process image file.
    image_context_key: Option<FileContextKey>,
    /// Flags matched during process runtime
    matching_flags: Vec<process_signatures::ProcessFlags>
}

impl ProcessContext {
    /// Returns the Windows-assigned process ID if known.
    pub fn pid(&self) -> Option<u64> {
        self.pid
    }

    /// Returns the Windows process start key if known.
    pub fn process_start_key(&self) -> Option<u64> {
        self.process_start_key
    }

    /// Returns the Galatea internal process identity if known.
    pub fn guid(&self) -> Option<GA_PID> {
        self.guid
    }

    /// Returns the current behavioural score if known.
    pub fn behavioural_score(&self) -> Option<u64> {
        self.behavioural_score
    }

    /// Returns the process image path if known.
    pub fn image_path(&self) -> Option<&str> {
        self.image_path.as_deref()
    }

    /// Returns the context key for the process image if known.
    pub fn image_context_key(&self) -> Option<&FileContextKey> {
        self.image_context_key.as_ref()
    }

    /// Returns the accumulated correlation flags.
    pub fn flags(&self) -> &[process_signatures::ProcessFlags] {
        &self.matching_flags
    }

    /// Adds correlation flags to this context.
    pub fn apply_flags(&mut self, mut flags: Vec<process_signatures::ProcessFlags>) {
        self.matching_flags.append(&mut flags);
    }

    fn apply_update(&mut self, update: ProcessContextUpdate) {
        if let Some(pid) = update.pid {
            self.pid = Some(pid);
        }

        if let Some(process_start_key) = update.process_start_key {
            self.process_start_key = Some(process_start_key);
        }

        if let Some(behavioural_score) = update.behavioural_score {
            self.behavioural_score = Some(behavioural_score);
        }

        if let Some(image_path) = update.image_path {
            self.image_path = Some(fsc_canonicalize_path(&image_path));
        }

        if let Some(image_context_key) = update.image_context_key {
            self.image_context_key = Some(image_context_key);
        }
        
        if let Some(flags) = update.matching_flags {
            self.apply_flags(flags);
        }
    }

    fn is_high_priority(&self) -> bool {
        self.behavioural_score.is_some_and(|score| score > 0)
    }
}

/// Thread-safe process context cache for telemetry correlation.
///
/// Contexts with a non-zero behavioural score are retained in a dedicated,
/// bounded tier so low-signal process churn cannot evict them from the normal tier.
pub struct ProcessContextCache {
    normal_entries: moka::sync::Cache<GA_PID, Arc<RwLock<ProcessContext>>>,
    high_priority_entries: moka::sync::Cache<GA_PID, Arc<RwLock<ProcessContext>>>,
}

impl ProcessContextCache {
    /// Creates a new process context cache.
    pub fn new() -> Self {
        Self {
            normal_entries: moka::sync::Cache::builder()
                .max_capacity(NORMAL_PROCESS_CONTEXT_CACHE_CAPACITY)
                .eviction_policy(EvictionPolicy::lru())
                .build(),
            high_priority_entries: moka::sync::Cache::builder()
                .max_capacity(HIGH_PRIORITY_PROCESS_CONTEXT_CACHE_CAPACITY)
                .eviction_policy(EvictionPolicy::lru())
                .build(),
        }
    }

    /// Returns a cloned snapshot of the context for a Galatea process identity.
    pub fn get(&self, guid: &GA_PID) -> Option<ProcessContext> {
        let entry = self.context_entry(guid)?;
        match entry.read() {
            Ok(context) => Some(context.clone()),
            Err(e) => {
                mimic_error!("[PROCESS_CONTEXT] Failed to read poisoned context: {e}");
                None
            }
        }
    }

    /// Inserts or merges partial process telemetry into an existing context.
    pub fn write_telemetry(
        &self,
        guid: GA_PID,
        update: ProcessContextUpdate,
    ) -> Option<ProcessContext> {
        let p = update.image_path.clone();
        self.update_context(guid, |context| context.apply_update(update))
    }

    /// Invalidates a context entry.
    pub fn invalidate(&self, guid: &GA_PID) {
        self.high_priority_entries.invalidate(guid);
        self.normal_entries.invalidate(guid);
    }

    fn update_context(
        &self,
        guid: GA_PID,
        update: impl FnOnce(&mut ProcessContext),
    ) -> Option<ProcessContext> {
        let entry = match self.high_priority_entries.get(&guid) {
            Some(entry) => entry,
            None => {
                let normal_entry = self.normal_entries.get_with(guid, || {
                    Arc::new(RwLock::new(ProcessContext {
                        guid: Some(guid),
                        ..ProcessContext::default()
                    }))
                });
                self.high_priority_entries
                    .get(&guid)
                    .unwrap_or(normal_entry)
            }
        };

        let (context, is_high_priority) = match entry.write() {
            Ok(mut context) => {
                update(&mut context);
                let is_high_priority = context.is_high_priority();
                (context.clone(), is_high_priority)
            }
            Err(e) => {
                mimic_error!("[PROCESS_CONTEXT] Failed to write poisoned context: {e}");
                return None;
            }
        };

        if is_high_priority && !self.high_priority_entries.contains_key(&guid) {
            self.high_priority_entries.insert(guid, entry);
            self.normal_entries.invalidate(&guid);
        }

        Some(context)
    }

    fn context_entry(&self, guid: &GA_PID) -> Option<Arc<RwLock<ProcessContext>>> {
        self.high_priority_entries
            .get(guid)
            .or_else(|| self.normal_entries.get(guid))
    }
}

impl Default for ProcessContextCache {
    fn default() -> Self {
        Self::new()
    }
}

