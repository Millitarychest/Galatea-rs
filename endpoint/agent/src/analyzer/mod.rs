use mimic_core::{mimic_log, mimic_success};
use shared::{GalateaEvent, GalateaVerdict};

mod heuristics;

use crate::{db::{self, DbPool, IOCTYPE}, driver::{DriverHandle, io::send_verdict}, utils::calc_md5};

pub fn analyze_event(event: GalateaEvent, driver: DriverHandle, db_pool: DbPool) {
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
        
        if !hash_md5.is_empty(){
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

        if let Some(rep) = heuristics::analyze_pe(&image_path){
            mimic_success!("{}", rep.imphash)
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
