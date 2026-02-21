use std::fs;
use std::sync::{Arc, mpsc::Sender};
use std::time::SystemTime;

use goblin::pe::PE;
use mimic_core::{mimic_error, mimic_log};
use galatea_shared::ipc::{AuthenticodeInfo, HeuristicResults, IpcMessage, MlPrediction, SignatureMatch};
use galatea_shared::GalateaEvent;

mod authenticode;
mod heuristics;

mod packers;
pub use packers::PackerSignatureEngine;

mod ml;
pub use ml::MlEngine;

use crate::{STATIC_RESULT_CACHE, ipc, utils};
use crate::cache::static_analyzer_cache::StaticResultCache;
use crate::engine::correlation::correlate_and_broadcast;
use crate::{
    CODE_SIGN_FORGIVENESS, CODE_SIGN_REVOKED, CODE_SIGN_UNTRUSTED, HOOK_FILE_NAME, ML_CERTAINTY_MAL,
    ML_MALICIOUS,
    analyzer::authenticode::verify_signature,
    db::{self, DbPool, IocType},
    injector::inject_dll,
    utils::hashing::calc_md5,
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

impl AnalysisResult {
    pub fn new(event: GalateaEvent) -> Self {
        Self {
            event,
            threat_score: 0,
            md5_hash: None,
            signature_match: None,
            authenticode: None,
            heuristics: None,
            ml_prediction: None,
            verdict_allow: true,
            size: 0,
            mod_time: SystemTime::UNIX_EPOCH,
            skip_cache: false,
        }
    }
}

enum StageOutcome {
    Continue,
    Block,
    Allow,
}

pub fn analyze_event(
    event: GalateaEvent,
    driver: ipc::SendHandle,
    db_pool: DbPool,
    pack_engine: Arc<PackerSignatureEngine>,
    ml_engine: Arc<Option<MlEngine>>,
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

        let mut ctx = AnalysisResult::new(event);
        ctx.size = file_size;
        ctx.mod_time = last_write;

        mimic_log!(
            "[SCAN] PID: {:<6} | Image: {}",
            ctx.event.process_id,
            image_path
        );

        let file_buffer = fs::read(&image_path).ok();
        let file_pe = file_buffer.as_ref().and_then(|buf| PE::parse(buf).ok());

        let stages: &[&dyn Fn(&mut AnalysisResult) -> StageOutcome] = &[
            &|ctx| stage_signature_check(ctx, &db_pool, &image_path),
            &|ctx| stage_authenticode_check(ctx, &image_path),
            &|ctx| stage_ml_check(ctx, &ml_engine, file_buffer.as_deref(), file_pe.as_ref()),
            &|ctx| {
                stage_heuristic_check(ctx, &pack_engine, file_buffer.as_deref(), file_pe.as_ref())
            },
        ];

        for stage in stages {
            match stage(&mut ctx) {
                StageOutcome::Block => {
                    ctx.verdict_allow = false;
                    break;
                }
                StageOutcome::Continue => continue,
                StageOutcome::Allow => break,
            }
        }

        // Inject hook DLL if process was allowed
        if ctx.verdict_allow {
            let current_dir = utils::exe_directory();
            let dll_path = current_dir.join(HOOK_FILE_NAME);
            match dll_path.to_str() {
                Some(path) => match inject_dll(ctx.event.process_id as u64, path) {
                    Ok(_) => mimic_log!("injected"),
                    Err(e) => mimic_error!("Inject failed: {}", e),
                },
                None => {
                    mimic_error!(
                        "Skipping hook injection due to non-UTF8 DLL path: {:?}",
                        dll_path
                    );
                }
            }
        }

        correlate_and_broadcast(ctx, driver, ipc_sender.as_ref());
    } else {
        mimic_log!(
            "[FAST] PID: {:<6} | Image: {}",
            event.process_id,
            image_path
        );
    }
}


fn stage_signature_check(
    ctx: &mut AnalysisResult,
    db_pool: &DbPool,
    image_path: &str,
) -> StageOutcome {
    let hash_md5 = match calc_md5(image_path) {
        Ok(h) => h,
        Err(e) => {
            mimic_log!("[WARN] Failed to hash {}: {:?}", image_path, e);
            String::new()
        }
    };

    if !hash_md5.is_empty() {
        ctx.md5_hash = Some(hash_md5.clone());

        // TODO: Adjust to allow for less severe sightings (PUPs)
        if let Some(sig) = db::check_signature(db_pool, &hash_md5)
            && sig.ioc_type == IocType::Md5Hash
        {
            mimic_log!("[ALERT] Known Malicious File Detected!");
            mimic_log!("        File: {}", image_path);
            mimic_log!("        Hash: {}", sig.hash);
            mimic_log!("        Meta: {}", sig.meta);
            mimic_log!("        Score: {}", sig.verdict);

            ctx.signature_match = Some(SignatureMatch {
                hash: sig.hash.clone(),
                verdict_score: sig.verdict,
                metadata: sig.meta.clone(),
            });

            ctx.threat_score += sig.verdict;

            if ctx.threat_score > crate::STAT_BLOCK_THRESHOLD {
                return StageOutcome::Block;
            }
        }
    }

    StageOutcome::Continue
}

fn stage_authenticode_check(ctx: &mut AnalysisResult, image_path: &str) -> StageOutcome {
    let sig = verify_signature(image_path);
    if sig.is_signed {
        if sig.is_trusted {
            mimic_log!("       [!] Signed and trusted: {:?}", sig.signer);
            ctx.threat_score += CODE_SIGN_FORGIVENESS;
            ctx.authenticode = Some(AuthenticodeInfo {
                is_signed: true,
                is_trusted: true,
                is_revoked: false,
                signer: sig.signer.clone(),
                score_modifier: CODE_SIGN_FORGIVENESS,
            });
        } else if sig.is_revoked {
            mimic_log!("       [!] Revoked Cert: {:?}", sig.signer);
            ctx.threat_score += CODE_SIGN_REVOKED;
            ctx.authenticode = Some(AuthenticodeInfo {
                is_signed: true,
                is_trusted: false,
                is_revoked: true,
                signer: sig.signer.clone(),
                score_modifier: CODE_SIGN_REVOKED,
            });
        } else {
            mimic_log!("       [!] Signed and not trusted: {:?}", sig.signer);
            ctx.threat_score += CODE_SIGN_UNTRUSTED;
            ctx.authenticode = Some(AuthenticodeInfo {
                is_signed: true,
                is_trusted: false,
                is_revoked: false,
                signer: sig.signer.clone(),
                score_modifier: CODE_SIGN_UNTRUSTED,
            });
        }
    }
    if ctx.threat_score > crate::STAT_BLOCK_THRESHOLD {
        return StageOutcome::Block;
    }

    StageOutcome::Continue
}

fn stage_heuristic_check(
    ctx: &mut AnalysisResult,
    pack_engine: &PackerSignatureEngine,
    file_buffer: Option<&[u8]>,
    file_pe: Option<&PE>,
) -> StageOutcome {
    let (Some(buffer), Some(pe)) = (file_buffer, file_pe) else {
        return StageOutcome::Continue;
    };

    if let Some(rep) = heuristics::analyze_pe(buffer, pe, pack_engine) {
        ctx.threat_score += rep.score_mod;
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

        ctx.heuristics = Some(HeuristicResults {
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

        if ctx.threat_score > crate::STAT_BLOCK_THRESHOLD {
            return StageOutcome::Block;
        }
    }
    StageOutcome::Continue
}

fn stage_ml_check(
    ctx: &mut AnalysisResult,
    ml_engine: &Option<MlEngine>,
    file_buffer: Option<&[u8]>,
    file_pe: Option<&PE>,
) -> StageOutcome {
    let Some(engine) = ml_engine else {
        return StageOutcome::Continue;
    };
    let (Some(buffer), Some(pe)) = (file_buffer, file_pe) else {
        return StageOutcome::Continue;
    };

    let features = ml::extract_ml_features(pe, buffer);
    let ml_prob = engine.predict(&features);
    mimic_log!("       [ML] Malicious Probability: {:.4}", ml_prob);
    if ml_prob > ML_CERTAINTY_MAL as f32 {
        ctx.threat_score += ML_MALICIOUS;
        ctx.ml_prediction = Some(MlPrediction {
            malicious_probability: ml_prob,
            score_modifier: ML_MALICIOUS,
        });
    }

    StageOutcome::Continue
}
