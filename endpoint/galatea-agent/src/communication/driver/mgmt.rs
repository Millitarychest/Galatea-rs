use std::path::Path;

use mimic_core::{mimic_error, mimic_log, mimic_success, shell};

pub fn service_exists(name: &str) -> bool {
    shell::run(&format!("sc query {}", name)).is_ok()
}

pub fn is_service_running(name: &str) -> bool {
    match shell::run(&format!("sc query {}", name)) {
        Ok(output) => output.contains("RUNNING"),
        Err(_) => false,
    }
}

pub fn install_driver_service(name: &str, path: &Path) -> Result<(), String> {
    let cmd = format!(
        "sc create {} type= kernel binPath= \"{}\"",
        name,
        path.to_string_lossy()
    );

    match shell::run(&cmd) {
        Ok(_) => {
            mimic_success!("Service Installed Successfully.");
            Ok(())
        }
        Err(e) => Err(format!("Failed to install service: {:?}. Cmd: {}", e, cmd)),
    }
}

pub fn start_driver_service(name: &str) -> Result<(), String> {
    match shell::run(&format!("sc start {}", name)) {
        Ok(_) => {
            mimic_success!("Driver Started.");
            Ok(())
        }
        Err(e) => Err(format!(
            "Failed to start service: {:?}. (Is TestSigning enabled?)",
            e
        )),
    }
}

#[expect(dead_code)] //Old function will probably be reworked but not sure yet
pub fn stop_driver_service(name: &str) -> Result<(), String> {
    mimic_log!("Stopping Service: {}", name);
    match shell::run(&format!("sc stop {}", name)) {
        Ok(_) => {
            mimic_success!("Service Stopped.");
            Ok(())
        }
        Err(e) => {
            mimic_error!("Could not stop service (might be already stopped): {:?}", e);
            Ok(())
        }
    }
}

#[expect(dead_code)] //Old function will probably be reworked but not sure yet
pub fn uninstall_driver_service(name: &str) -> Result<(), String> {
    mimic_log!("Removing Service: {}", name);
    match shell::run(&format!("sc delete {}", name)) {
        Ok(_) => {
            mimic_success!("Service Deleted.");
            Ok(())
        }
        Err(e) => Err(format!("Failed to delete service: {:?}", e)),
    }
}
