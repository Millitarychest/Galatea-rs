use std::sync::{Arc, RwLock};

use galatea_shared::id::GA_PID;
use mimic_core::{mimic_error, mimic_log};

use crate::cache::file_context_cache::{FileContextKey, fsc_canonicalize_path};

const PROCESS_CONTEXT_CACHE_CAPACITY: u64 = 10_000;

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
    }
}

/// Thread-safe process context cache for telemetry correlation.
pub struct ProcessContextCache {
    entries: moka::sync::Cache<GA_PID, Arc<RwLock<ProcessContext>>>,
}

impl ProcessContextCache {
    /// Creates a new process context cache.
    pub fn new() -> Self {
        Self {
            entries: moka::sync::Cache::builder()
                .max_capacity(PROCESS_CONTEXT_CACHE_CAPACITY)
                .build(),
        }
    }

    /// Returns a cloned snapshot of the context for a Galatea process identity.
    pub fn get(&self, guid: &GA_PID) -> Option<ProcessContext> {
        let entry = self.entries.get(guid)?;
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
        let a = self.update_context(guid, |context| context.apply_update(update));
        mimic_log!("[PROCESS_CONTEXT] Inserted something: {:?} -> {:?}",guid, p );
        a
    }

    /// Invalidates a context entry.
    pub fn invalidate(&self, guid: &GA_PID) {
        self.entries.invalidate(guid);
    }

    fn update_context(
        &self,
        guid: GA_PID,
        update: impl FnOnce(&mut ProcessContext),
    ) -> Option<ProcessContext> {
        let entry = self.entries.get_with(guid, || {
            Arc::new(RwLock::new(ProcessContext {
                guid: Some(guid),
                ..ProcessContext::default()
            }))
        });

        let context = match entry.write() {
            Ok(mut context) => {
                update(&mut context);
                context.clone()
            }
            Err(e) => {
                mimic_error!("[PROCESS_CONTEXT] Failed to write poisoned context: {e}");
                return None;
            }
        };

        Some(context)
    }
}

impl Default for ProcessContextCache {
    fn default() -> Self {
        Self::new()
    }
}
