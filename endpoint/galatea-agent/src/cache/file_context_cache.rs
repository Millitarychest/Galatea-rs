use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use galatea_shared::ipc::{
    FileContextKeySnapshot, FileContextSnapshot, FileFlagSnapshot, FileScanSummarySnapshot,
    FileVerdictSnapshot,
};
use mimic_core::mimic_error;

use crate::cache::static_analyzer_cache::{FileVerdict, ScanSummary};
use crate::engine::signatures::file_signatures;

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
    /// Matching Flags on the File
    pub matching_flags: Option<Vec<file_signatures::FileFlags>>,
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
    matching_flags: Vec<file_signatures::FileFlags>,
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

    pub fn apply_flags(&mut self, mut flags: Vec<file_signatures::FileFlags>) {
        self.matching_flags.append(&mut flags);
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

        if let Some(mut flags) = update.matching_flags {
            self.matching_flags.append(&mut flags); // I think this is not great?
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

    pub fn flag_file(
        &self,
        key: FileContextKey,
        flags: Vec<file_signatures::FileFlags>,
    ) -> Option<FileContext> {
        self.update_context(key, |context| context.apply_flags(flags))
    }

    /// Returns a bounded cloned snapshot of cache entries for GUI inspection.
    pub fn snapshot(&self, limit: usize) -> Vec<FileContextSnapshot> {
        let mut snapshots = Vec::with_capacity(limit.min(self.entries.entry_count() as usize));

        for entry in self.entries.iter() {
            if snapshots.len() >= limit {
                break;
            }

            let (key, context) = entry;
            match context.read() {
                Ok(context) => snapshots.push(file_context_snapshot(&key, &context)),
                Err(e) => mimic_error!("[FILE_CONTEXT] Failed to snapshot poisoned context: {e}"),
            }
        }

        snapshots
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

fn file_context_snapshot(key: &FileContextKey, context: &FileContext) -> FileContextSnapshot {
    FileContextSnapshot {
        key: match key {
            FileContextKey::FileIndex(file_index) => FileContextKeySnapshot::FileIndex(*file_index),
            FileContextKey::Path(path) => FileContextKeySnapshot::Path(path.clone()),
        },
        normalized_file_path: context.normalized_file_path().map(str::to_string),
        file_index: context.file_index(),
        last_write_process: context.last_write_process().map(str::to_string),
        last_write_time: context.last_write_time().map(system_time_to_utc),
        last_rename_time: context.last_rename_time().map(system_time_to_utc),
        original_name: context.original_name().map(str::to_string),
        matching_flags: file_flag_snapshots(&context.matching_flags),
        last_scan_summary: context.last_scan_summary().map(scan_summary_snapshot),
    }
}

fn file_flag_snapshots(flags: &[file_signatures::FileFlags]) -> Vec<FileFlagSnapshot> {
    let mut snapshots = Vec::new();

    for flag in flags {
        let Some(snapshot) = file_flag_snapshot(*flag) else {
            continue;
        };

        if !snapshots.contains(&snapshot) {
            snapshots.push(snapshot);
        }
    }

    snapshots
}

fn file_flag_snapshot(flag: file_signatures::FileFlags) -> Option<FileFlagSnapshot> {
    match flag {
        file_signatures::FileFlags::None => None,
        file_signatures::FileFlags::FileWriteSuccess => Some(FileFlagSnapshot::FileWriteSuccess),
        file_signatures::FileFlags::WhiteListed => Some(FileFlagSnapshot::WhiteListed),
        file_signatures::FileFlags::BlackListed => Some(FileFlagSnapshot::BlackListed),
        file_signatures::FileFlags::StaticScanMalicious => {
            Some(FileFlagSnapshot::StaticScanMalicious)
        }
        file_signatures::FileFlags::StaticScanSuspicious => {
            Some(FileFlagSnapshot::StaticScanSuspicious)
        }
        file_signatures::FileFlags::StaticScanBeneign => Some(FileFlagSnapshot::StaticScanBeneign),
        file_signatures::FileFlags::InAutoStartLocation => {
            Some(FileFlagSnapshot::InAutoStartLocation)
        }
        file_signatures::FileFlags::InTempLocation => Some(FileFlagSnapshot::InTempLocation),
        file_signatures::FileFlags::RenamedToExecutable => {
            Some(FileFlagSnapshot::RenamedToExecutable)
        }
    }
}

fn scan_summary_snapshot(scan: &ScanSummary) -> FileScanSummarySnapshot {
    FileScanSummarySnapshot {
        verdict: match scan.verdict {
            FileVerdict::Benign => FileVerdictSnapshot::Benign,
            FileVerdict::Suspicious => FileVerdictSnapshot::Suspicious,
            FileVerdict::Malicious => FileVerdictSnapshot::Malicious,
        },
        threat_score: scan.threat_score,
        file_size: scan.file_size,
        mod_time: system_time_to_utc(scan.mod_time),
        file_index: scan.file_index,
    }
}

fn system_time_to_utc(value: SystemTime) -> DateTime<Utc> {
    DateTime::<Utc>::from(value)
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
