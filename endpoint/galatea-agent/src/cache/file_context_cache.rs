use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use galatea_shared::ipc::{
    FileContextKeySnapshot, FileContextSnapshot, FileFlagSnapshot, FileScanSummarySnapshot,
    FileVerdictSnapshot,
};
use mimic_core::mimic_error;
use moka::policy::EvictionPolicy;

use crate::cache::static_analyzer_cache::{FileVerdict, ScanSummary};
use crate::engine::signatures::file_signatures;

const FILE_CONTEXT_CACHE_CAPACITY: u64 = 10_000;
const HIGH_PRIORITY_FILE_CONTEXT_CACHE_CAPACITY: u64 = 2_000;
const NORMAL_FILE_CONTEXT_CACHE_CAPACITY: u64 =
    FILE_CONTEXT_CACHE_CAPACITY - HIGH_PRIORITY_FILE_CONTEXT_CACHE_CAPACITY;

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

    fn canonicalized(&self) -> Self {
        match self {
            Self::FileIndex(index) => Self::FileIndex(*index),
            Self::Path(path) => Self::Path(fsc_canonicalize_path(path)),
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
    /// Matching flags on the file.
    pub matching_flags: Option<Vec<file_signatures::FileFlags>>,
}

/// Contextual information about a file used during correlation.
#[derive(Debug, Clone, Default)]
pub struct FileContext {
    normalized_file_path: Option<String>,
    file_index: Option<u64>,
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

    /// Returns the accumulated correlation flags.
    pub fn flags(&self) -> &[file_signatures::FileFlags] {
        &self.matching_flags
    }

    /// Adds correlation flags to this context.
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

        if let Some(flags) = update.matching_flags {
            self.apply_flags(flags);
        }
    }

    fn is_high_priority(&self) -> bool {
        let has_temp_location = self
            .matching_flags
            .contains(&file_signatures::FileFlags::InTempLocation);
        let renamed_to_executable = self
            .matching_flags
            .contains(&file_signatures::FileFlags::RenamedToExecutable);
        let high_risk_flag = self.matching_flags.iter().any(|flag| {
            matches!(
                flag,
                file_signatures::FileFlags::BlackListed
                    | file_signatures::FileFlags::StaticScanMalicious
                    | file_signatures::FileFlags::StaticScanSuspicious
            )
        });
        let high_risk_scan = self.last_scan_summary.as_ref().is_some_and(|summary| {
            matches!(
                summary.verdict,
                FileVerdict::Suspicious | FileVerdict::Malicious
            )
        });

        high_risk_flag || high_risk_scan || (has_temp_location && renamed_to_executable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FileContextId(u64);

#[derive(Default)]
struct AliasIndexes {
    by_alias: HashMap<FileContextKey, FileContextId>,
    by_context: HashMap<FileContextId, HashSet<FileContextKey>>,
}

/// Thread-safe file context cache for telemetry and scan correlation.
///
/// A logical context is stored exactly once in one of the bounded Moka tiers.
/// Path and file-index keys are aliases that resolve to the same internal context ID.
pub struct FileContextCache {
    normal_entries: moka::sync::Cache<FileContextId, Arc<RwLock<FileContext>>>,
    high_priority_entries: moka::sync::Cache<FileContextId, Arc<RwLock<FileContext>>>,
    aliases: Mutex<AliasIndexes>,
    evicted_contexts: Arc<Mutex<Vec<FileContextId>>>,
    next_context_id: AtomicU64,
}

impl FileContextCache {
    /// Creates a new cache with a protected tier for high-signal file contexts.
    pub fn new() -> Self {
        Self::with_capacities(
            NORMAL_FILE_CONTEXT_CACHE_CAPACITY,
            HIGH_PRIORITY_FILE_CONTEXT_CACHE_CAPACITY,
            EvictionPolicy::tiny_lfu(),
        )
    }

    fn with_capacities(
        normal_capacity: u64,
        high_priority_capacity: u64,
        normal_policy: EvictionPolicy,
    ) -> Self {
        let evicted_contexts = Arc::new(Mutex::new(Vec::new()));
        let normal_evictions = Arc::clone(&evicted_contexts);
        let high_priority_evictions = Arc::clone(&evicted_contexts);

        let normal_entries = moka::sync::Cache::builder()
            .max_capacity(normal_capacity)
            .eviction_policy(normal_policy)
            .eviction_listener(move |key, _value, _cause| {
                if let Ok(mut evicted) = normal_evictions.lock() {
                    evicted.push(*key);
                }
            })
            .build();
        let high_priority_entries = moka::sync::Cache::builder()
            .max_capacity(high_priority_capacity)
            .eviction_policy(EvictionPolicy::lru())
            .eviction_listener(move |key, _value, _cause| {
                if let Ok(mut evicted) = high_priority_evictions.lock() {
                    evicted.push(*key);
                }
            })
            .build();

        Self {
            normal_entries,
            high_priority_entries,
            aliases: Mutex::new(AliasIndexes::default()),
            evicted_contexts,
            next_context_id: AtomicU64::new(1),
        }
    }

    /// Returns a cloned snapshot of the context for either alias key.
    pub fn get(&self, key: &FileContextKey) -> Option<FileContext> {
        self.drain_evicted_contexts();
        let key = key.canonicalized();
        let context_id = self.context_id_for_alias(&key)?;
        let entry = self.context_entry(context_id)?;

        match entry.read() {
            Ok(context) => Some(context.clone()),
            Err(e) => {
                mimic_error!("[FILE_CONTEXT] Failed to read poisoned context: {e}");
                None
            }
        }
    }

    /// Returns a cloned snapshot for a path alias.
    pub fn get_by_path(&self, path: &str) -> Option<FileContext> {
        self.get(&FileContextKey::Path(fsc_canonicalize_path(path)))
    }

    /// Returns a cloned snapshot for a file-index alias.
    pub fn get_by_file_index(&self, file_index: u64) -> Option<FileContext> {
        self.get(&FileContextKey::FileIndex(file_index))
    }

    /// Inserts or merges partial file telemetry into a context identified by any known alias.
    pub fn write_telemetry(
        &self,
        key: FileContextKey,
        update: FileTelemetryUpdate,
    ) -> Option<FileContext> {
        let aliases = telemetry_aliases(&key, &update);
        let retired_path_alias = update
            .original_name
            .as_deref()
            .map(|path| FileContextKey::Path(fsc_canonicalize_path(path)));
        self.update_context(aliases, retired_path_alias, |context| {
            context.apply_telemetry(update)
        })
    }

    /// Inserts or replaces the latest scan summary for a context identified by any known alias.
    pub fn write_scan_summary(
        &self,
        key: FileContextKey,
        scan_summary: ScanSummary,
    ) -> Option<FileContext> {
        let mut aliases = HashSet::from([key.canonicalized()]);
        if let Some(file_index) = scan_summary.file_index {
            aliases.insert(FileContextKey::FileIndex(file_index));
        }

        self.update_context(aliases, None, |context| {
            if let Some(file_index) = scan_summary.file_index {
                context.file_index = Some(file_index);
            }
            context.last_scan_summary = Some(scan_summary);
        })
    }

    /// Removes a logical context and every alias that resolves to it.
    pub fn invalidate(&self, key: &FileContextKey) {
        self.drain_evicted_contexts();
        let key = key.canonicalized();
        let Some(context_id) = self.context_id_for_alias(&key) else {
            return;
        };

        self.remove_context(context_id);
    }

    /// Adds flags to a file context and promotes it when they indicate elevated risk.
    pub fn flag_file(
        &self,
        key: FileContextKey,
        flags: Vec<file_signatures::FileFlags>,
    ) -> Option<FileContext> {
        self.update_context(HashSet::from([key.canonicalized()]), None, |context| {
            context.apply_flags(flags)
        })
    }

    /// Returns a bounded cloned snapshot of logical contexts for GUI inspection.
    pub fn snapshot(&self, limit: usize) -> Vec<FileContextSnapshot> {
        self.drain_evicted_contexts();
        let contexts = match self.aliases.lock() {
            Ok(aliases) => aliases
                .by_context
                .iter()
                .map(|(context_id, aliases)| (*context_id, snapshot_key(aliases)))
                .collect::<Vec<_>>(),
            Err(e) => {
                mimic_error!("[FILE_CONTEXT] Failed to read poisoned alias indexes: {e}");
                return Vec::new();
            }
        };
        let mut snapshots = Vec::with_capacity(limit.min(contexts.len()));
        let mut stale_contexts = Vec::new();

        for (context_id, key) in contexts {
            if snapshots.len() >= limit {
                break;
            }

            let Some(context) = self.context_entry(context_id) else {
                stale_contexts.push(context_id);
                continue;
            };

            match context.read() {
                Ok(context) => snapshots.push(file_context_snapshot(&key, &context)),
                Err(e) => mimic_error!("[FILE_CONTEXT] Failed to snapshot poisoned context: {e}"),
            }
        }

        for context_id in stale_contexts {
            self.remove_context_aliases(context_id);
        }

        snapshots
    }

    fn update_context(
        &self,
        aliases: HashSet<FileContextKey>,
        retired_alias: Option<FileContextKey>,
        update: impl FnOnce(&mut FileContext),
    ) -> Option<FileContext> {
        let (context_id, entry) = self.resolve_context(aliases);

        let context = match entry.write() {
            Ok(mut context) => {
                update(&mut context);
                context.clone()
            }
            Err(e) => {
                mimic_error!("[FILE_CONTEXT] Failed to write poisoned context: {e}");
                return None;
            }
        };

        if context.is_high_priority() {
            self.promote_context(context_id, entry);
        }

        if let Some(retired_alias) = retired_alias {
            self.remove_alias(context_id, &retired_alias);
        }

        Some(context)
    }

    fn resolve_context(
        &self,
        aliases: HashSet<FileContextKey>,
    ) -> (FileContextId, Arc<RwLock<FileContext>>) {
        self.drain_evicted_contexts();
        let mut indexes = match self.aliases.lock() {
            Ok(indexes) => indexes,
            Err(e) => {
                mimic_error!("[FILE_CONTEXT] Failed to lock poisoned alias indexes: {e}");
                return self.create_unindexed_context();
            }
        };
        let context_id = self.resolve_existing_context(&mut indexes, &aliases);

        match context_id.and_then(|context_id| {
            self.context_entry(context_id)
                .map(|entry| (context_id, entry))
        }) {
            Some((context_id, entry)) => {
                for alias in aliases {
                    bind_alias(&mut indexes, alias, context_id);
                }
                (context_id, entry)
            }
            None => {
                if let Some(context_id) = context_id {
                    remove_context_aliases(&mut indexes, context_id);
                }

                let context_id = self.next_context_id();
                let entry = Arc::new(RwLock::new(FileContext::default()));
                self.normal_entries.insert(context_id, Arc::clone(&entry));
                for alias in aliases {
                    bind_alias(&mut indexes, alias, context_id);
                }
                (context_id, entry)
            }
        }
    }

    fn resolve_existing_context(
        &self,
        indexes: &mut AliasIndexes,
        aliases: &HashSet<FileContextKey>,
    ) -> Option<FileContextId> {
        let file_index_context = aliases.iter().find_map(|alias| match alias {
            FileContextKey::FileIndex(_) => indexes.by_alias.get(alias).copied(),
            FileContextKey::Path(_) => None,
        });
        let primary_context = file_index_context.or_else(|| {
            aliases
                .iter()
                .find_map(|alias| indexes.by_alias.get(alias).copied())
        });
        let context_id = primary_context?;

        if self.context_entry(context_id).is_some() {
            Some(context_id)
        } else {
            remove_context_aliases(indexes, context_id);
            None
        }
    }

    fn create_unindexed_context(&self) -> (FileContextId, Arc<RwLock<FileContext>>) {
        let context_id = self.next_context_id();
        let entry = Arc::new(RwLock::new(FileContext::default()));
        self.normal_entries.insert(context_id, Arc::clone(&entry));
        (context_id, entry)
    }

    fn context_id_for_alias(&self, alias: &FileContextKey) -> Option<FileContextId> {
        let context_id = match self.aliases.lock() {
            Ok(indexes) => indexes.by_alias.get(alias).copied(),
            Err(e) => {
                mimic_error!("[FILE_CONTEXT] Failed to read poisoned alias indexes: {e}");
                None
            }
        }?;

        if self.context_entry(context_id).is_some() {
            Some(context_id)
        } else {
            self.remove_context_aliases(context_id);
            None
        }
    }

    fn context_entry(&self, context_id: FileContextId) -> Option<Arc<RwLock<FileContext>>> {
        self.high_priority_entries
            .get(&context_id)
            .or_else(|| self.normal_entries.get(&context_id))
    }

    fn promote_context(&self, context_id: FileContextId, entry: Arc<RwLock<FileContext>>) {
        if self.high_priority_entries.contains_key(&context_id) {
            return;
        }

        self.high_priority_entries.insert(context_id, entry);
        self.normal_entries.invalidate(&context_id);
        self.drain_evicted_contexts();
    }

    fn remove_context(&self, context_id: FileContextId) {
        self.high_priority_entries.invalidate(&context_id);
        self.normal_entries.invalidate(&context_id);
        self.remove_context_aliases(context_id);
    }

    fn remove_context_aliases(&self, context_id: FileContextId) {
        match self.aliases.lock() {
            Ok(mut indexes) => remove_context_aliases(&mut indexes, context_id),
            Err(e) => mimic_error!("[FILE_CONTEXT] Failed to lock poisoned alias indexes: {e}"),
        }
    }

    fn remove_alias(&self, context_id: FileContextId, alias: &FileContextKey) {
        match self.aliases.lock() {
            Ok(mut indexes) => remove_alias(&mut indexes, context_id, alias),
            Err(e) => mimic_error!("[FILE_CONTEXT] Failed to lock poisoned alias indexes: {e}"),
        }
    }

    fn drain_evicted_contexts(&self) {
        let evicted_contexts = match self.evicted_contexts.lock() {
            Ok(mut evicted) => std::mem::take(&mut *evicted),
            Err(e) => {
                mimic_error!("[FILE_CONTEXT] Failed to read eviction queue: {e}");
                return;
            }
        };

        if evicted_contexts.is_empty() {
            return;
        }

        let mut indexes = match self.aliases.lock() {
            Ok(indexes) => indexes,
            Err(e) => {
                mimic_error!("[FILE_CONTEXT] Failed to lock poisoned alias indexes: {e}");
                return;
            }
        };

        for context_id in evicted_contexts {
            if self.context_entry(context_id).is_none() {
                remove_context_aliases(&mut indexes, context_id);
            }
        }
    }

    fn next_context_id(&self) -> FileContextId {
        FileContextId(self.next_context_id.fetch_add(1, Ordering::Relaxed))
    }
}

fn telemetry_aliases(
    key: &FileContextKey,
    update: &FileTelemetryUpdate,
) -> HashSet<FileContextKey> {
    let mut aliases = HashSet::from([key.canonicalized()]);

    if let Some(path) = update.normalized_file_path.as_deref() {
        aliases.insert(FileContextKey::Path(fsc_canonicalize_path(path)));
    }

    if let Some(file_index) = update.file_index {
        aliases.insert(FileContextKey::FileIndex(file_index));
    }

    aliases
}

fn bind_alias(indexes: &mut AliasIndexes, alias: FileContextKey, context_id: FileContextId) {
    if let Some(previous_context_id) = indexes.by_alias.insert(alias.clone(), context_id)
        && previous_context_id != context_id
        && let Some(previous_aliases) = indexes.by_context.get_mut(&previous_context_id)
    {
        previous_aliases.remove(&alias);
    }

    indexes
        .by_context
        .entry(context_id)
        .or_default()
        .insert(alias);
}

fn remove_context_aliases(indexes: &mut AliasIndexes, context_id: FileContextId) {
    let Some(aliases) = indexes.by_context.remove(&context_id) else {
        return;
    };

    for alias in aliases {
        if indexes.by_alias.get(&alias) == Some(&context_id) {
            indexes.by_alias.remove(&alias);
        }
    }
}

fn remove_alias(indexes: &mut AliasIndexes, context_id: FileContextId, alias: &FileContextKey) {
    if indexes.by_alias.get(alias) != Some(&context_id) {
        return;
    }

    indexes.by_alias.remove(alias);
    if let Some(aliases) = indexes.by_context.get_mut(&context_id) {
        aliases.remove(alias);
        if aliases.is_empty() {
            indexes.by_context.remove(&context_id);
        }
    }
}

fn snapshot_key(aliases: &HashSet<FileContextKey>) -> FileContextKey {
    aliases
        .iter()
        .find_map(|alias| match alias {
            FileContextKey::FileIndex(index) => Some(FileContextKey::FileIndex(*index)),
            FileContextKey::Path(_) => None,
        })
        .or_else(|| aliases.iter().next().cloned())
        .unwrap_or_else(|| FileContextKey::Path(String::new()))
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
        matching_flags: file_flag_snapshots(context.flags()),
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

// This is a hacky solution :/ if they overlap maybe create a shared def
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
        file_signatures::FileFlags::FileCreateSuccess => Some(FileFlagSnapshot::FileCreateSuccess),
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

/// Canonicalizes a path for use as a file-context alias.
pub fn fsc_canonicalize_path(raw_path: &str) -> String {
    match dunce::canonicalize(raw_path) {
        Ok(path) => path.to_string_lossy().to_string(),
        Err(_) => raw_path.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn telemetry(path: &str, file_index: Option<u64>) -> FileTelemetryUpdate {
        FileTelemetryUpdate {
            normalized_file_path: Some(path.to_string()),
            file_index,
            last_write_process: None,
            last_write_time: None,
            last_rename_time: None,
            original_name: None,
            matching_flags: Some(vec![file_signatures::FileFlags::FileWriteSuccess]),
        }
    }

    #[test]
    fn path_and_file_index_resolve_to_one_context() {
        let cache = FileContextCache::with_capacities(10, 10, EvictionPolicy::lru());
        let path = "C:\\test\\sample.exe";
        let file_index = 42;

        let _ = cache.write_telemetry(
            FileContextKey::FileIndex(file_index),
            telemetry(path, Some(file_index)),
        );
        let _ = cache.flag_file(
            FileContextKey::Path(path.to_string()),
            vec![file_signatures::FileFlags::BlackListed],
        );

        let by_index = cache.get_by_file_index(file_index);
        let by_path = cache.get_by_path(path);

        assert!(by_index.is_some());
        assert!(by_path.is_some());
        assert!(by_index.as_ref().is_some_and(|context| {
            context
                .flags()
                .contains(&file_signatures::FileFlags::BlackListed)
        }));
        assert!(by_path.as_ref().is_some_and(|context| {
            context
                .flags()
                .contains(&file_signatures::FileFlags::BlackListed)
        }));
    }

    #[test]
    fn invalidating_one_alias_removes_every_alias() {
        let cache = FileContextCache::with_capacities(10, 10, EvictionPolicy::lru());
        let path = "C:\\test\\sample.exe";
        let file_index = 43;

        let _ = cache.write_telemetry(
            FileContextKey::FileIndex(file_index),
            telemetry(path, Some(file_index)),
        );
        cache.invalidate(&FileContextKey::Path(path.to_string()));

        assert!(cache.get_by_path(path).is_none());
        assert!(cache.get_by_file_index(file_index).is_none());
    }

    #[test]
    fn rename_replaces_the_old_path_alias() {
        let cache = FileContextCache::with_capacities(10, 10, EvictionPolicy::lru());
        let old_path = "C:\\test\\payload.tmp";
        let new_path = "C:\\test\\payload.exe";
        let file_index = 45;

        let _ = cache.write_telemetry(
            FileContextKey::FileIndex(file_index),
            telemetry(old_path, Some(file_index)),
        );
        let _ = cache.write_telemetry(
            FileContextKey::FileIndex(file_index),
            FileTelemetryUpdate {
                normalized_file_path: Some(new_path.to_string()),
                file_index: Some(file_index),
                last_write_process: None,
                last_write_time: None,
                last_rename_time: None,
                original_name: Some(old_path.to_string()),
                matching_flags: None,
            },
        );

        assert!(cache.get_by_path(old_path).is_none());
        assert!(cache.get_by_path(new_path).is_some());
        assert!(cache.get_by_file_index(file_index).is_some());
    }

    #[test]
    fn high_risk_context_moves_to_protected_tier() {
        let cache = FileContextCache::with_capacities(10, 10, EvictionPolicy::lru());
        let path = "C:\\test\\payload.exe";
        let file_index = 44;

        let _ = cache.write_telemetry(
            FileContextKey::FileIndex(file_index),
            telemetry(path, Some(file_index)),
        );
        let _ = cache.flag_file(
            FileContextKey::FileIndex(file_index),
            vec![
                file_signatures::FileFlags::InTempLocation,
                file_signatures::FileFlags::RenamedToExecutable,
            ],
        );

        let context_id = cache.context_id_for_alias(&FileContextKey::FileIndex(file_index));
        assert!(context_id.is_some());
        assert!(
            context_id
                .is_some_and(|context_id| cache.high_priority_entries.contains_key(&context_id))
        );
        assert!(
            context_id.is_some_and(|context_id| !cache.normal_entries.contains_key(&context_id))
        );
    }

    #[test]
    fn evicted_context_removes_its_aliases() {
        let cache = FileContextCache::with_capacities(1, 1, EvictionPolicy::lru());
        let first_path = "C:\\test\\first.txt";
        let second_path = "C:\\test\\second.txt";

        let _ = cache.write_telemetry(
            FileContextKey::Path(first_path.to_string()),
            telemetry(first_path, None),
        );
        let _ = cache.write_telemetry(
            FileContextKey::Path(second_path.to_string()),
            telemetry(second_path, None),
        );
        cache.normal_entries.run_pending_tasks();
        cache.drain_evicted_contexts();

        assert!(cache.get_by_path(first_path).is_none());
        assert!(cache.get_by_path(second_path).is_some());
    }
}
