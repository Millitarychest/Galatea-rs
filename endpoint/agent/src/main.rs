use std::{env, path::PathBuf, sync::atomic::{AtomicUsize, Ordering}};

use windows::{Win32::{Foundation::HANDLE, System::IO::CancelIoEx}, core::w};
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE};
use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING, FILE_SHARE_READ, FILE_SHARE_WRITE};
use windows::Win32::System::IO::DeviceIoControl;
use std::ffi::c_void;
use std::mem::size_of;

use mimic_core::{error, mimic_bail, mimic_error, mimic_log, mimic_success, privilege};
use shared::{GalateaEvent, GalateaVerdict, IOCTL_GET_EVENT};

use crate::driver::io::send_verdict;

mod driver;

const DRIVER_SERVICE_NAME: &str = "Galatea";
const DRIVER_FILE_NAME: &str = "driver.sys";

static GLOBAL_DEVICE_HANDLE: AtomicUsize = AtomicUsize::new(0);

fn main() -> error::Result<()>{
    mimic_log!("Initializing Galatea Agent...");

    if cfg!(debug_assertions) {
        ctrlc::set_handler(move || {
            mimic_log!("[DEV] Ctrl+C Detected! Initiating cleanup...");
            
            let handle_val = GLOBAL_DEVICE_HANDLE.load(Ordering::SeqCst);

            if handle_val != 0 {
                let handle = HANDLE(handle_val as *mut c_void);
                unsafe {
                    let _ = CancelIoEx(handle, None);
                }
            }
            
        }).expect("Error setting Ctrl-C handler");
    }

    init()?;

    // Event loop
    let device_name = w!("\\\\.\\Galatea");
    
    let device_handle = unsafe {
        CreateFileW(
            device_name,
            (GENERIC_READ | GENERIC_WRITE).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };

    let device_handle = match device_handle {
        Ok(h) => h,
        Err(e) => {
            mimic_error!("Failed to open handle to driver. Is the driver loaded?");
            mimic_error!("Error: {:?}", e);
            cleanup();
            mimic_bail!("Could not open driver handle");
        }
    };

    GLOBAL_DEVICE_HANDLE.store(device_handle.0 as usize, Ordering::SeqCst);

    mimic_success!("Galatea Systems: Online");
    mimic_log!("(Press Ctrl+C to stop the agent)");

    loop {
        let mut event: GalateaEvent = unsafe { std::mem::zeroed() };
        let mut bytes_returned: u32 = 0;

        let result = unsafe {
            DeviceIoControl(
                device_handle,
                IOCTL_GET_EVENT,
                None,
                0,
                Some(&mut event as *mut _ as *mut c_void),
                size_of::<GalateaEvent>() as u32,
                Some(&mut bytes_returned),
                None,
            )
        };

        match result {
            Ok(_) => {
                let image_path = String::from_utf16_lossy(&event.image_path)
                    .trim_matches(char::from(0))
                    .to_string();

                mimic_log!(
                    "[EVENT] PID: {:<6} | Image: {}", 
                    event.process_id, 
                    image_path
                );

                let verdict = GalateaVerdict{
                    process_id: event.process_id,
                    allow: true,
                };

                send_verdict(device_handle, verdict);
            },
            Err(e) => {
                eprintln!("DeviceIoControl failed: {:?}", e);
                break;
            }
        }
    }

    let _ = unsafe { CloseHandle(device_handle) };
    cleanup();
    Ok(())
}

fn cleanup(){
    let _ = driver::mgmt::stop_driver_service(DRIVER_SERVICE_NAME);
    let _ = driver::mgmt::uninstall_driver_service(DRIVER_SERVICE_NAME);
}

fn init()-> error::Result<()>{

    if !privilege::is_elevated() {
        mimic_error!("Elevation Required: Galatea Agent must run as Administrator to load drivers.");
        return Ok(());
    }

    let driver_path = resolve_driver_path()?;
    mimic_log!("Driver Artifact: {:?}", driver_path);

    if !driver::mgmt::service_exists(DRIVER_SERVICE_NAME) {
        driver::mgmt::install_driver_service(DRIVER_SERVICE_NAME, &driver_path)?;
    }

    if !driver::mgmt::is_service_running(DRIVER_SERVICE_NAME) {
        mimic_log!("Starting Driver Service...");
        driver::mgmt::start_driver_service(DRIVER_SERVICE_NAME)?;
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

