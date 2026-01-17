use std::sync::Arc;

use mimic_core::{mimic_log};
use shared::{GalateaEvent, GalateaVerdict};

mod heuristics;
mod packers;
pub use packers::PackerSignatureEngine;

use crate::{db::{self, DbPool, IOCTYPE}, driver::{DriverHandle, io::send_verdict}, utils::calc_md5};

pub fn analyze_event(event: GalateaEvent, driver: DriverHandle, db_pool: DbPool, pack_engine: Arc<PackerSignatureEngine>) {
    let image_path = String::from_utf16_lossy(&event.image_path)
        .trim_matches(char::from(0))
        .to_string();

    if event.frozen{
        mimic_log!("[SCAN] PID: {:<6} | Image: {}", event.process_id, image_path);
        
        //check md5 known bad
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

                let allowed = sig.verdict < crate::MAL_IOC_BLOCK_THRESHOLD;

                let verdict = GalateaVerdict{
                    process_id: event.process_id,
                    allow: allowed,
                    request_id: event.request_id,
                };

                send_verdict(driver.0, verdict);
                return;
            }
        }

        if let Some(rep) = heuristics::analyze_pe(&image_path, &pack_engine){
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
        }


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
