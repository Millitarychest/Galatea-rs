use crate::cache::static_analyzer_cache::ScanSummary;

// Contextual information about a Process
// Might move in the future
pub struct ProcessContext {
    process_image: Option<String>,
    pid: u64,
    //try get guid to avoid pid colisions
    guid: Option<String>,
    last_scan_verdict: ScanSummary,
    //matching_signatures: todo!(),
    behavioural_score: u64,
}
