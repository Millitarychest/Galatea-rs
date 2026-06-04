use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use mimic_core::mimic_error;

use crate::cache::static_analyzer_cache::ScanSummary;

const FILE_CONTEXT_CACHE_CAPACITY: u64 = 10_000;

/// Stable lookup key for file context entries.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FileContextKey {
    /// NTFS file index when available.
    FileIndex(u64),
    /// Canonicalized path fallback when stable file identity is unavailable.
    Path(String),
}

impl FileContextKey {
    /// Creates a context key from file identity data, preferring file index.
    pub fn from_identity(path: &str, file_index: Option<u64>) -> Self {
        match file_index {
            Some(index) => Self::FileIndex(index),
            None => Self::Path(fsc_canonicalize_path(path)),
        }
    }
}

/// Partial file telemetry update data.
#[derive(Debug, Clone, Default)]
pub struct FileTelemetryUpdate {
    /// Current normalized file path when observed.
    pub normalized_file_path: Option<String>,
    /// NTFS file index when available.
    pub file_index: Option<u64>,
    /// Process image responsible for the latest write.
    ///
    /// Might eventually become a process context reference if the image path is
    /// not enough for correlation.
    pub last_write_process: Option<String>,
    /// Timestamp of the latest observed write.
    pub last_write_time: Option<SystemTime>,
    /// Timestamp of the latest observed rename.
    pub last_rename_time: Option<SystemTime>,
    /// Original file name before a rename when observed.
    pub original_name: Option<String>,
}

/// Contextual information about a file used during correlation.
///
/// Might move in the future.
#[derive(Debug, Clone, Default)]
pub struct FileContext {
    normalized_file_path: Option<String>,
    file_index: Option<u64>,
    // image path of last modifier
    last_write_process: Option<String>,
    last_write_time: Option<SystemTime>,
    last_rename_time: Option<SystemTime>,
    original_name: Option<String>,
    last_scan_summary: Option<ScanSummary>,
    // matching_signatures: todo!()
}

impl FileContext {
    /// Returns the current normalized file path if known.
    pub fn normalized_file_path(&self) -> Option<&str> {
        self.normalized_file_path.as_deref()
    }

    /// Returns the current file index if known.
    pub fn file_index(&self) -> Option<u64> {
        self.file_index
    }

    /// Returns the process image responsible for the latest write if known.
    pub fn last_write_process(&self) -> Option<&str> {
        self.last_write_process.as_deref()
    }

    /// Returns the timestamp of the latest observed write if known.
    pub fn last_write_time(&self) -> Option<SystemTime> {
        self.last_write_time
    }

    /// Returns the timestamp of the latest observed rename if known.
    pub fn last_rename_time(&self) -> Option<SystemTime> {
        self.last_rename_time
    }

    /// Returns the original file name before rename if known.
    pub fn original_name(&self) -> Option<&str> {
        self.original_name.as_deref()
    }

    /// Returns the latest static scan summary if known.
    pub fn last_scan_summary(&self) -> Option<&ScanSummary> {
        self.last_scan_summary.as_ref()
    }

    fn apply_telemetry(&mut self, update: FileTelemetryUpdate) {
        if let Some(path) = update.normalized_file_path {
            self.normalized_file_path = Some(fsc_canonicalize_path(&path));
        }

        if let Some(file_index) = update.file_index {
            self.file_index = Some(file_index);
        }

        if let Some(process) = update.last_write_process {
            self.last_write_process = Some(process);
        }

        if let Some(write_time) = update.last_write_time {
            self.last_write_time = Some(write_time);
        }

        if let Some(rename_time) = update.last_rename_time {
            self.last_rename_time = Some(rename_time);
        }

        if let Some(original_name) = update.original_name {
            self.original_name = Some(original_name);
        }
    }
}

/// Thread-safe file context cache for telemetry and scan correlation.
pub struct FileContextCache {
    entries: moka::sync::Cache<FileContextKey, Arc<RwLock<FileContext>>>,
}

impl FileContextCache {
    /// Creates a new file context cache.
    pub fn new() -> Self {
        Self {
            entries: moka::sync::Cache::builder()
                .max_capacity(FILE_CONTEXT_CACHE_CAPACITY)
                .build(),
        }
    }

    /// Returns a cloned snapshot of the context for the key.
    pub fn get(&self, key: &FileContextKey) -> Option<FileContext> {
        let entry = self.entries.get(key)?;
        match entry.read() {
            Ok(context) => Some(context.clone()),
            Err(e) => {
                mimic_error!("[FILE_CONTEXT] Failed to read poisoned context: {e}");
                None
            }
        }
    }

    /// Returns a cloned snapshot for the path fallback key.
    pub fn get_by_path(&self, path: &str) -> Option<FileContext> {
        self.get(&FileContextKey::Path(fsc_canonicalize_path(path)))
    }

    /// Inserts or merges partial file telemetry into an existing context.
    pub fn write_telemetry(
        &self,
        key: FileContextKey,
        update: FileTelemetryUpdate,
    ) -> Option<FileContext> {
        self.update_context(key, |context| context.apply_telemetry(update))
    }

    /// Inserts or replaces the latest scan summary for a context.
    pub fn write_scan_summary(
        &self,
        key: FileContextKey,
        scan_summary: ScanSummary,
    ) -> Option<FileContext> {
        self.update_context(key, |context| {
            if let Some(file_index) = scan_summary.file_index {
                context.file_index = Some(file_index);
            }
            context.last_scan_summary = Some(scan_summary);
        })
    }

    /// Invalidates a context entry.
    pub fn invalidate(&self, key: &FileContextKey) {
        self.entries.invalidate(key);
    }

    fn update_context(
        &self,
        key: FileContextKey,
        update: impl FnOnce(&mut FileContext),
    ) -> Option<FileContext> {
        let entry = self
            .entries
            .get_with(key, || Arc::new(RwLock::new(FileContext::default())));

        match entry.write() {
            Ok(mut context) => {
                update(&mut context);
                Some(context.clone())
            }
            Err(e) => {
                mimic_error!("[FILE_CONTEXT] Failed to write poisoned context: {e}");
                None
            }
        }
    }
}

impl Default for FileContextCache {
    fn default() -> Self {
        Self::new()
    }
}

pub fn fsc_canonicalize_path(raw_path: &str) -> String {
    match dunce::canonicalize(raw_path) {
        Ok(path) => path.to_string_lossy().to_string(),
        Err(_) => raw_path.to_string(),
    }
}
