use chrono::Utc;
use mimic_core::mimic_log;
use galatea_shared::GalateaVerdict;
use galatea_shared::ipc::{DetectionDetails, DetectionEvent, IpcMessage, ProcessInfo, Verdict};
use std::sync::mpsc::Sender;
use uuid::Uuid;

use crate::communication::ipc::SendHandle;
use crate::probes::process_info;
use crate::static_analyzer::AnalysisResult;
use crate::communication::driver::io::ks_send_verdict;

/// Correlates an analysis result with process metadata, broadcasts the detection
/// event to IPC clients, and sends the verdict to the kernel driver.
pub fn correlate_and_broadcast(
    result: AnalysisResult,
    driver: SendHandle,
    ipc_sender: Option<&Sender<IpcMessage>>,
) {
    let image_path = String::from_utf16_lossy(&result.event.image_path)
        .trim_matches(char::from(0))
        .to_string();

    let process_info_data = process_info::get_process_info(result.event.process_id);

    let process_info = ProcessInfo {
        pid: result.event.process_id,
        name: process_info_data
            .as_ref()
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "Unknown".to_string()),
        path: process_info_data
            .as_ref()
            .map(|p| p.path.clone())
            .unwrap_or(image_path.clone()),
        parent_pid: process_info_data.as_ref().and_then(|p| p.parent_pid),
        command_line: process_info_data
            .as_ref()
            .and_then(|p| p.command_line.clone()),
        creation_time: process_info_data.as_ref().and_then(|p| p.creation_time),
    };

    let detection = DetectionDetails {
        threat_score: result.threat_score,
        md5_hash: result.md5_hash,
        signature_match: result.signature_match,
        authenticode: result.authenticode,
        heuristics: result.heuristics,
        ml_prediction: result.ml_prediction,
    };

    let verdict = if result.verdict_allow {
        Verdict::Allowed
    } else {
        Verdict::Blocked
    };

    let detection_event = DetectionEvent {
        event_id: Uuid::new_v4(),
        timestamp: Utc::now(),
        process_info,
        detection,
        verdict,
    };

    // Broadcast to IPC clients
    if let Some(sender) = ipc_sender {
        if let Err(e) = sender.send(IpcMessage::Detection(detection_event.clone())) {
            mimic_log!("[Correlation] Failed to send to IPC: {e}");
        }
    }

    let driver_verdict = GalateaVerdict {
        process_id: result.event.process_id,
        request_id: result.event.request_id,
        allow: result.verdict_allow,
    };
    ks_send_verdict(driver.into(), driver_verdict);
}
