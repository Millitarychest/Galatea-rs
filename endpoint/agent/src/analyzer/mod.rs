use std::sync::Arc;

use goblin::pe::PE;
use mimic_core::{mimic_error, mimic_log};
use shared::{GalateaEvent, GalateaVerdict};


mod heuristics;
mod authenticode;

mod packers;
pub use packers::PackerSignatureEngine;

mod ml;
pub use ml::MlEngine;

use crate::{CODE_SIGN_FORGIVENESS, CODE_SIGN_REVOKED, CODE_SIGN_UNTRUSTED, HOOK_FILE_NAME, ML_CERTENTY_MAL, ML_MALICIOUS, analyzer::authenticode::verify_signature, db::{self, DbPool, IOCTYPE}, driver::{DriverHandle, io::send_verdict}, injector::inject_dll, utils::calc_md5};

pub fn analyze_event(
    event: GalateaEvent, 
    driver: DriverHandle, 
    db_pool: DbPool, 
    pack_engine: Arc<PackerSignatureEngine>,
    ml_engine: Arc<MlEngine>
) {
    let image_path = String::from_utf16_lossy(&event.image_path)
        .trim_matches(char::from(0))
        .to_string();

    if event.frozen{
        let mut static_score = 0;

        mimic_log!("[SCAN] PID: {:<6} | Image: {}", event.process_id, image_path);
        
        //md5 known bad
        let hash_md5 = match calc_md5(&image_path) {
            Ok(h) => h,
            Err(e) => {
                mimic_log!("[WARN] Failed to hash {}: {:?}", image_path, e);
                String::new()
            },
        };
        
        if !hash_md5.is_empty(){ // TODO: Adjust to allow for less severe sightings (PUPs)
            if let Some(sig) = db::check_signature(&db_pool, &hash_md5) && sig.ioc_type == IOCTYPE::Md5Hash{
                mimic_log!("[ALERT] Known Malicious File Detected!");
                mimic_log!("        File: {}", image_path);
                mimic_log!("        Hash: {}", sig.hash);
                mimic_log!("        Meta: {}", sig.meta);
                mimic_log!("        Score: {}", sig.verdict);

                if block_on_highscore(sig.verdict, &event, &driver) {return;}
                static_score += sig.verdict;
            }
        }

        //authenticode

        let sig = verify_signature(&image_path);
        if sig.is_signed {
            if sig.is_trusted {
                mimic_log!("       [!] Signed and trusted: {:?}", sig.signer);
                static_score += CODE_SIGN_FORGIVENESS;
            }
            else if sig.is_revoked {
                mimic_log!("       [!] Revoked Cert: {:?}", sig.signer);
                static_score += CODE_SIGN_REVOKED
            }
            else {
                mimic_log!("       [!] Signed and not trusted: {:?}", sig.signer);
                static_score += CODE_SIGN_UNTRUSTED
            }
        }
        if block_on_highscore(static_score, &event, &driver) {return;}

        // ml engine

        if let Ok(buffer) = std::fs::read(&image_path) {
            if let Ok(pe) = PE::parse(&buffer) {
                let features = heuristics::extract_ml_features(&pe, &buffer);
                let ml_prob = ml_engine.predict(&features);
                mimic_log!("       [ML] Malicious Probability: {:.4}", ml_prob);
                if ml_prob > ML_CERTENTY_MAL as f32 { 
                    static_score += ML_MALICIOUS
                }
            }
        }

        // heuristics

        if let Some(rep) = heuristics::analyze_pe(&image_path, &pack_engine){
            static_score += rep.score_mod;
            mimic_log!("       [!] Threat modifier: {}", rep.score_mod);
            if rep.is_packed {
                let packer = rep.packer.unwrap_or("Unknown".to_string());
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

            if block_on_highscore(static_score, &event, &driver) {return;}
        }

        let current_exe = std::env::current_exe().map_err(|e| e.to_string()).unwrap();
        let current_dir = current_exe.parent().unwrap();
        let dll_path = current_dir.join(HOOK_FILE_NAME);
        match inject_dll(event.process_id as u64, dll_path.to_str().unwrap()) {
            Ok(_) => {mimic_log!("injected")},
            Err(e) => mimic_error!("Inject failed: {}", e),
        };

        let verdict = GalateaVerdict{
            process_id: event.process_id,
            allow: true,
            request_id: event.request_id,
        };

        send_verdict(driver.0, verdict);
    }
    else {
        mimic_log!("[FAST] PID: {:<6} | Image: {}", event.process_id, image_path);
    }

    
}

fn block_on_highscore(score: i32, event: &GalateaEvent, driver: &DriverHandle) -> bool{
    if score > crate::STAT_BLOCK_THRESHOLD{
        let verdict = GalateaVerdict{
            process_id: event.process_id,
            allow: false,
            request_id: event.request_id,
        };

        send_verdict(driver.0, verdict);
        return true;
    }
    false
}