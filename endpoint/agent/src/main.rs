use std::{env, path::{Path, PathBuf}, thread, time::Duration};

use mimic_core::{error, mimic_error, mimic_log, mimic_success, privilege, shell};


const DRIVER_SERVICE_NAME: &str = "Galatea";
const DRIVER_FILE_NAME: &str = "driver.sys";

fn main() -> error::Result<()>{
    mimic_log!("Initializing Galatea Agent...");

    if cfg!(debug_assertions) {
        ctrlc::set_handler(move || {
            mimic_log!("[DEV] Ctrl+C Detected! Initiating cleanup...");
            
            // Run cleanup logic
            let _ = stop_driver_service(DRIVER_SERVICE_NAME);
            let _ = uninstall_driver_service(DRIVER_SERVICE_NAME);
            
            mimic_success!("[DEV] Cleanup Complete. Exiting.");
            std::process::exit(0);
        }).expect("Error setting Ctrl-C handler");
    }

    init()?;

    mimic_success!("Galatea Systems: Online");
    mimic_log!("(Press Ctrl+C to stop the agent)");

    loop {
        thread::sleep(Duration::from_secs(5));
    }
}

fn init()-> error::Result<()>{

    if !privilege::is_elevated() {
        mimic_error!("Elevation Required: Galatea Agent must run as Administrator to load drivers.");
        return Ok(());
    }

    let driver_path = resolve_driver_path()?;
    mimic_log!("Driver Artifact: {:?}", driver_path);

    if !service_exists(DRIVER_SERVICE_NAME) {
        install_driver_service(DRIVER_SERVICE_NAME, &driver_path)?;
    }

    if !is_service_running(DRIVER_SERVICE_NAME) {
        mimic_log!("Starting Driver Service...");
        start_driver_service(DRIVER_SERVICE_NAME)?;
    } else {
        mimic_success!("Driver is already active.");
    }

    Ok(())
}

fn resolve_driver_path() -> Result<PathBuf, String> {
    let current_exe = env::current_exe().map_err(|e| e.to_string())?;
    let current_dir = current_exe.parent().unwrap();

    let prod_path = current_dir.join(DRIVER_FILE_NAME);
    if prod_path.exists() {
        return Ok(prod_path);
    }

    Err(format!("Could not locate '{}'. Checked local dir and target/dist.", DRIVER_FILE_NAME))
}

fn service_exists(name: &str) -> bool {
    shell::run(&format!("sc query {}", name)).is_ok()
}

fn is_service_running(name: &str) -> bool {
    match shell::run(&format!("sc query {}", name)) {
        Ok(output) => output.contains("RUNNING"),
        Err(_) => false,
    }
}

fn install_driver_service(name: &str, path: &Path) -> Result<(), String> {
    let cmd = format!(
        "sc create {} type= kernel binPath= \"{}\"", 
        name, 
        path.to_string_lossy()
    );

    match shell::run(&cmd) {
        Ok(_) => {
            mimic_success!("Service Installed Successfully.");
            Ok(())
        },
        Err(e) => Err(format!("Failed to install service: {:?}. Cmd: {}", e, cmd))
    }
}

fn start_driver_service(name: &str) -> Result<(), String> {
    match shell::run(&format!("sc start {}", name)) {
        Ok(_) => {
            mimic_success!("Driver Started.");
            Ok(())
        },
        Err(e) => {
            Err(format!("Failed to start service: {:?}. (Is TestSigning enabled?)", e))
        }
    }
}

fn stop_driver_service(name: &str) -> Result<(), String> {
    mimic_log!("Stopping Service: {}", name);
    match shell::run(&format!("sc stop {}", name)) {
        Ok(_) => {
            mimic_success!("Service Stopped.");
            Ok(())
        },
        Err(e) => {
            mimic_error!("Could not stop service (might be already stopped): {:?}", e);
            Ok(())
        }
    }
}

fn uninstall_driver_service(name: &str) -> Result<(), String> {
    mimic_log!("Removing Service: {}", name);
    match shell::run(&format!("sc delete {}", name)) {
        Ok(_) => {
            mimic_success!("Service Deleted.");
            Ok(())
        },
        Err(e) => Err(format!("Failed to delete service: {:?}", e))
    }
}