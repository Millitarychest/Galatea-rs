use chrono::Utc;
use mimic_core::mimic_log;
use shared::ipc::{
    AuthenticodeInfo, DetectionDetails, DetectionEvent, HeuristicResults, IpcMessage, MlPrediction,
    ProcessInfo, SignatureMatch, Verdict,
};
use shared::{GalateaEvent, GalateaVerdict};
use std::sync::mpsc::Sender;
use uuid::Uuid;

use super::process_info;
use crate::driver::DriverHandle;
use crate::driver::io::send_verdict;

pub struct AnalysisResult {
    pub event: GalateaEvent,
    pub threat_score: i32,
    pub md5_hash: Option<String>,
    pub signature_match: Option<(String, i32, String)>, // (hash, score, metadata)
    pub authenticode: Option<(bool, bool, bool, Option<String>, i32)>, // (signed, trusted, revoked, signer, score_mod)
    pub heuristics: Option<(bool, Option<String>, bool, bool, Option<String>, i32)>, // (packed, packer, rwx, high_ent, imphash, score)
    pub ml_prediction: Option<(f32, i32)>, // (probability, score_mod)
    pub verdict_allow: bool,
}


pub fn correlate_and_broadcast(
    result: AnalysisResult,
    driver: DriverHandle,
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

    // Build detection details
    let detection =
        DetectionDetails {
            threat_score: result.threat_score,
            md5_hash: result.md5_hash,
            signature_match: result
                .signature_match
                .map(|(hash, score, meta)| SignatureMatch {
                    hash,
                    verdict_score: score,
                    metadata: meta,
                }),
            authenticode: result.authenticode.map(
                |(signed, trusted, revoked, signer, score_mod)| AuthenticodeInfo {
                    is_signed: signed,
                    is_trusted: trusted,
                    is_revoked: revoked,
                    signer,
                    score_modifier: score_mod,
                },
            ),
            heuristics: result
                .heuristics
                .map(
                    |(packed, packer, rwx, high_ent, imphash, score)| HeuristicResults {
                        is_packed: packed,
                        packer_name: packer,
                        has_rwx_sections: rwx,
                        high_entropy: high_ent,
                        imphash,
                        score_modifier: score,
                    },
                ),
            ml_prediction: result.ml_prediction.map(|(prob, score)| MlPrediction {
                malicious_probability: prob,
                score_modifier: score,
            }),
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
            mimic_log!("[Correlation] Failed to send to IPC: {}", e);
        }
    }

    
    let driver_verdict = GalateaVerdict {
        process_id: result.event.process_id,
        request_id: result.event.request_id,
        allow: result.verdict_allow,
    };
    send_verdict(driver.0, driver_verdict);
}
