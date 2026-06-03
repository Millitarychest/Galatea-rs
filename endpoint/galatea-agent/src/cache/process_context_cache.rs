use crate::cache::{file_context_cache::FileContext, static_analyzer_cache::CompletedScan};


// Contextual information about a Process
// Might move in the future
pub struct ProcessContext {
    process_image: Option<String>,
    pid: u64,
    //try get guid to avoid pid colisions
    guid: Option<String>,
    last_scan_verdict: CompletedScan,
    //matching_signatures: todo!(),
    behavioural_score: u64,
    
}