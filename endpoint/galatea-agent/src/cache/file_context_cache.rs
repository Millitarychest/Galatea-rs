use std::time::SystemTime;

use crate::cache::{process_context_cache::ProcessContext, static_analyzer_cache::CompletedScan};


// Contextual information about a file
// Might move in the future
pub struct FileContext {
    n_file_path: String,
    file_index: Option<u64>,
    last_write_proc: Option<String>, // Or does just a image path make more sense here?
    last_write_time: SystemTime,
    last_rename_time: SystemTime,
    original_name: String,
    last_scan_verdict: CompletedScan,
    //matching_signatures: todo!()
}