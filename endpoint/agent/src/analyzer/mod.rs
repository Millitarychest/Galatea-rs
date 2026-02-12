use std::fs;
use std::sync::{Arc, mpsc::Sender};
use std::time::SystemTime;

use goblin::pe::PE;
use mimic_core::{mimic_error, mimic_log};
use shared::ipc::{AuthenticodeInfo, HeuristicResults, IpcMessage, MlPrediction, SignatureMatch};
use shared::{GalateaEvent, GalateaVerdict};

mod authenticode;
mod heuristics;

mod packers;
pub use packers::PackerSignatureEngine;

mod ml;
pub use ml::MlEngine;

use crate::STATIC_RESULT_CACHE;
use crate::cache::static_analyzer_cache::StaticResultCache;
use crate::engine::correlation::correlate_and_broadcast;
use crate::{
    CODE_SIGN_FORGIVENESS, CODE_SIGN_REVOKED, CODE_SIGN_UNTRUSTED, HOOK_FILE_NAME, ML_CERTENTY_MAL,
    ML_MALICIOUS,
    analyzer::authenticode::verify_signature,
    db::{self, DbPool, IOCTYPE},
    driver::{DriverHandle, io::send_verdict},
    injector::inject_dll,
    utils::calc_md5,
};

pub struct AnalysisResult {
    pub event: GalateaEvent,
    pub threat_score: i32,
    pub md5_hash: Option<String>,
    pub signature_match: Option<SignatureMatch>,
    pub authenticode: Option<AuthenticodeInfo>,
    pub heuristics: Option<HeuristicResults>,
    pub ml_prediction: Option<MlPrediction>,
    pub verdict_allow: bool,
    pub size: u64,
    pub mod_time: SystemTime,
    pub skip_cache: bool,
}

pub fn analyze_event(
    event: GalateaEvent,
    driver: DriverHandle,
    db_pool: DbPool,
    pack_engine: Arc<PackerSignatureEngine>,
    ml_engine: Arc<MlEngine>,
    ipc_sender: Option<Sender<IpcMessage>>,
) {
    let raw_path = String::from_utf16_lossy(&event.image_path)
        .trim_matches(char::from(0))
        .to_string();
    let image_path = match dunce::canonicalize(&raw_path) {
        Ok(path) => path.to_string_lossy().to_string(),
        Err(_) => raw_path,
    };

    if event.frozen {
        // Check against cache
        let (last_write, file_size) = match fs::metadata(&image_path) {
            Ok(meta) => {
                let time = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                let size = meta.len();

                (time, size)
            }
            Err(_) => (SystemTime::UNIX_EPOCH, 0),
        };

        if file_size > 0 {
            let cache = STATIC_RESULT_CACHE.get_or_init(|| StaticResultCache::new());
            if let Some(cache_data) = cache.retrieve_result(&image_path, last_write, file_size) {
                let allow = cache_data.threat_score <= crate::STAT_BLOCK_THRESHOLD;
                let result = AnalysisResult {
                    event,
                    threat_score: cache_data.threat_score,
                    md5_hash: cache_data.md5_hash,
                    signature_match: cache_data.signature_match,
                    authenticode: cache_data.authenticode,
                    heuristics: cache_data.heuristics,
                    ml_prediction: cache_data.ml_prediction,
                    verdict_allow: allow,
                    size: file_size,
                    mod_time: last_write,
                    skip_cache: true,
                };
                mimic_log!("Found cached result");
                correlate_and_broadcast(result, driver, ipc_sender.as_ref());
                return;
            }
        }

        let mut static_score = 0;
        let mut sig_match: Option<SignatureMatch> = None;
        let mut auth_info: Option<AuthenticodeInfo> = None;
        let mut heur_info: Option<HeuristicResults> = None;
        let mut ml_info: Option<MlPrediction> = None;

        mimic_log!(
            "[SCAN] PID: {:<6} | Image: {}",
            event.process_id,
            image_path
        );

        //md5 known bad
        let hash_md5 = match calc_md5(&image_path) {
            Ok(h) => h,
            Err(e) => {
                mimic_log!("[WARN] Failed to hash {}: {:?}", image_path, e);
                String::new()
            }
        };

        if !hash_md5.is_empty() {
            // TODO: Adjust to allow for less severe sightings (PUPs)
            if let Some(sig) = db::check_signature(&db_pool, &hash_md5)
                && sig.ioc_type == IOCTYPE::Md5Hash
            {
                mimic_log!("[ALERT] Known Malicious File Detected!");
                mimic_log!("        File: {}", image_path);
                mimic_log!("        Hash: {}", sig.hash);
                mimic_log!("        Meta: {}", sig.meta);
                mimic_log!("        Score: {}", sig.verdict);

                sig_match = Some(SignatureMatch {
                    hash: sig.hash.clone(),
                    verdict_score: sig.verdict,
                    metadata: sig.meta.clone(),
                });

                if block_on_highscore(sig.verdict, &event, &driver) {
                    // Blocked - send to correlation with blocked verdict
                    let result = AnalysisResult {
                        event,
                        threat_score: sig.verdict,
                        md5_hash: Some(hash_md5),
                        signature_match: sig_match,
                        authenticode: None,
                        heuristics: None,
                        ml_prediction: None,
                        verdict_allow: false,
                        size: file_size,
                        mod_time: last_write,
                        skip_cache: false,
                    };
                    correlate_and_broadcast(result, driver, ipc_sender.as_ref());
                    return;
                }
                static_score += sig.verdict;
            }
        }

        //authenticode

        let sig = verify_signature(&image_path);
        if sig.is_signed {
            if sig.is_trusted {
                mimic_log!("       [!] Signed and trusted: {:?}", sig.signer);
                static_score += CODE_SIGN_FORGIVENESS;
                auth_info = Some(AuthenticodeInfo {
                    is_signed: true,
                    is_trusted: true,
                    is_revoked: false,
                    signer: sig.signer.clone(),
                    score_modifier: CODE_SIGN_FORGIVENESS,
                });
            } else if sig.is_revoked {
                mimic_log!("       [!] Revoked Cert: {:?}", sig.signer);
                static_score += CODE_SIGN_REVOKED;
                auth_info = Some(AuthenticodeInfo {
                    is_signed: true,
                    is_trusted: false,
                    is_revoked: true,
                    signer: sig.signer.clone(),
                    score_modifier: CODE_SIGN_REVOKED,
                });
            } else {
                mimic_log!("       [!] Signed and not trusted: {:?}", sig.signer);
                static_score += CODE_SIGN_UNTRUSTED;
                auth_info = Some(AuthenticodeInfo {
                    is_signed: true,
                    is_trusted: false,
                    is_revoked: false,
                    signer: sig.signer.clone(),
                    score_modifier: CODE_SIGN_UNTRUSTED,
                });
            }
        }
        if block_on_highscore(static_score, &event, &driver) {
            let result = AnalysisResult {
                event,
                threat_score: static_score,
                md5_hash: Some(hash_md5),
                signature_match: sig_match,
                authenticode: auth_info,
                heuristics: None,
                ml_prediction: None,
                verdict_allow: false,
                size: file_size,
                mod_time: last_write,
                skip_cache: false,
            };
            correlate_and_broadcast(result, driver, ipc_sender.as_ref());
            return;
        }

        // ml engine

        if let Ok(buffer) = std::fs::read(&image_path) {
            if let Ok(pe) = PE::parse(&buffer) {
                let features = heuristics::extract_ml_features(&pe, &buffer);
                let ml_prob = ml_engine.predict(&features);
                mimic_log!("       [ML] Malicious Probability: {:.4}", ml_prob);
                if ml_prob > ML_CERTENTY_MAL as f32 {
                    static_score += ML_MALICIOUS;
                    ml_info = Some(MlPrediction {
                        malicious_probability: ml_prob,
                        score_modifier: ML_MALICIOUS,
                    });
                }
            }
        }

        // heuristics

        if let Some(rep) = heuristics::analyze_pe(&image_path, &pack_engine) {
            static_score += rep.score_mod;
            mimic_log!("       [!] Threat modifier: {}", rep.score_mod);
            if rep.is_packed {
                let packer = rep.packer.clone().unwrap_or("Unknown".to_string());
                mimic_log!("       [!] Detected Binary Toolchain({})", packer);
            }
            if rep.has_rwx {
                mimic_log!("       [!] Dangerous RWX Section Detected");
            }
            if rep.high_entropy && !rep.is_packed {
                mimic_log!("       [!] High Entropy Detected (>7.2)");
            }
            if !rep.imphash.is_empty() {
                mimic_log!("       [i] Imphash: {}", rep.imphash);
                //TODO: check DB for imphash matches
            }

            heur_info = Some(HeuristicResults {
                is_packed: rep.is_packed,
                packer_name: rep.packer.clone(),
                has_rwx_sections: rep.has_rwx,
                high_entropy: rep.high_entropy,
                imphash: if !rep.imphash.is_empty() {
                    Some(rep.imphash.clone())
                } else {
                    None
                },
                score_modifier: rep.score_mod,
            });

            if block_on_highscore(static_score, &event, &driver) {
                let result = AnalysisResult {
                    event,
                    threat_score: static_score,
                    md5_hash: Some(hash_md5),
                    signature_match: sig_match,
                    authenticode: auth_info,
                    heuristics: heur_info,
                    ml_prediction: ml_info,
                    verdict_allow: false,
                    size: file_size,
                    mod_time: last_write,
                    skip_cache: false,
                };
                correlate_and_broadcast(result, driver, ipc_sender.as_ref());
                return;
            }
        }

        let current_exe = std::env::current_exe().map_err(|e| e.to_string()).unwrap();
        let current_dir = current_exe.parent().unwrap();
        let dll_path = current_dir.join(HOOK_FILE_NAME);
        match inject_dll(event.process_id as u64, dll_path.to_str().unwrap()) {
            Ok(_) => {
                mimic_log!("injected")
            }
            Err(e) => mimic_error!("Inject failed: {}", e),
        };

        // Allowed - send to correlation
        let result = AnalysisResult {
            event,
            threat_score: static_score,
            md5_hash: Some(hash_md5),
            signature_match: sig_match,
            authenticode: auth_info,
            heuristics: heur_info,
            ml_prediction: ml_info,
            verdict_allow: true,
            size: file_size,
            mod_time: last_write,
            skip_cache: false,
        };
        correlate_and_broadcast(result, driver, ipc_sender.as_ref());
    } else {
        mimic_log!(
            "[FAST] PID: {:<6} | Image: {}",
            event.process_id,
            image_path
        );
    }
}

fn block_on_highscore(score: i32, event: &GalateaEvent, driver: &DriverHandle) -> bool {
    if score > crate::STAT_BLOCK_THRESHOLD {
        let verdict = GalateaVerdict {
            process_id: event.process_id,
            allow: false,
            request_id: event.request_id,
        };

        send_verdict(driver.0, verdict);
        return true;
    }
    false
}
