use mimic_core::mimic_log;
use shared::{GalateaEvent, GalateaVerdict};

use crate::{db::DbPool, driver::{DriverHandle, io::send_verdict}};



pub fn analyze_event(event: GalateaEvent, driver: DriverHandle, _db: DbPool) {
    let image_path = String::from_utf16_lossy(&event.image_path)
        .trim_matches(char::from(0))
        .to_string();


    if event.frozen{
        mimic_log!("[SCAN] PID: {:<6} | Image: {}", event.process_id, image_path);
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