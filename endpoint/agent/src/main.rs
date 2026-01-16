use std::{env, path::PathBuf, sync::atomic::{AtomicUsize, Ordering}};

use threadpool::ThreadPool;
use windows::{Win32::{Foundation::HANDLE, System::IO::CancelIoEx}, core::w};
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE};
use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING, FILE_SHARE_READ, FILE_SHARE_WRITE};
use windows::Win32::System::IO::DeviceIoControl;
use std::ffi::c_void;
use std::mem::size_of;

use mimic_core::{error, mimic_bail, mimic_error, mimic_log, mimic_success, privilege};
use shared::{GalateaEvent, IOCTL_GET_EVENT};


mod driver;
mod db;
mod analyzer;
mod utils;

use crate::driver::DriverHandle;

const DRIVER_SERVICE_NAME: &str = "Galatea";
const DRIVER_FILE_NAME: &str = "driver.sys";
const DB_FILE_NAME: &str = "galatea_dataset.db";

const MAL_IOC_BLOCK_THRESHOLD: i32 = 50;

static GLOBAL_LISTENER_HANDLE: AtomicUsize = AtomicUsize::new(0);


fn main() -> error::Result<()>{
    mimic_log!("Initializing Galatea Agent...");

    if cfg!(debug_assertions) {
        ctrlc::set_handler(move || {
            mimic_log!("[DEV] Ctrl+C Detected! Initiating cleanup...");
            
            let handle_val = GLOBAL_LISTENER_HANDLE.load(Ordering::SeqCst);

            if handle_val != 0 {
                let handle = HANDLE(handle_val as *mut c_void);
                unsafe {
                    let _ = CancelIoEx(handle, None);
                }
            }
            
        }).expect("Error setting Ctrl-C handler");
    }

    init_driver()?;

    
    // Setup Database Connection
    let current_exe = env::current_exe().map_err(|e| e.to_string())?;
    let current_dir = current_exe.parent().unwrap();

    let db_path = current_dir.join(DB_FILE_NAME);
    let db_pool = db::init_db_pool(db_path.to_str().unwrap())?;
    mimic_success!("Knowledge Base (Signatures) Loaded.");

    // Setup worker threads
    let n_workers = 16; // Adjust
    let worker_pool = ThreadPool::new(n_workers);
    mimic_log!("Analysis Engine: {} Workers ready.", n_workers);


    // Event loop
    let device_name = w!("\\\\.\\Galatea");
    let listener_handle = unsafe {
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

    let listener_handle = match listener_handle {
        Ok(h) => h,
        Err(e) => {
            mimic_error!("Failed to open handle to driver. Is the driver loaded?");
            mimic_error!("Error: {:?}", e);
            cleanup();
            mimic_bail!("Could not open driver handle");
        }
    };

    let control_handle = unsafe {
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

    let control_handle = match control_handle {
        Ok(h) => h,
        Err(_) => {
            mimic_error!("Failed to open control handle.");
            unsafe { let _ = CloseHandle(listener_handle);};
            cleanup();
            mimic_bail!("Could not open control handle");
        }
    };

    GLOBAL_LISTENER_HANDLE.store(listener_handle.0 as usize, Ordering::SeqCst);

    if let Err(_) = driver::io::register_agent(control_handle) {
        mimic_error!("CRITICAL: Agent Registration Failed.");
        mimic_error!("This usually means another Agent instance is already running.");
        let _ = unsafe { CloseHandle(listener_handle) };
        let _ = unsafe { CloseHandle(control_handle) };
        cleanup();
        mimic_bail!("Registration Handshake Failed");
    }

    let safe_handle = DriverHandle(control_handle);

    mimic_success!("Galatea Systems: Online");
    mimic_log!("(Press Ctrl+C to stop the agent)");

    loop {
        let mut event: GalateaEvent = unsafe { std::mem::zeroed() };
        let mut bytes_returned: u32 = 0;

        let result = unsafe {
            DeviceIoControl(
                listener_handle,
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
                let worker_handle = safe_handle.clone();
                let worker_db = db_pool.clone();
                let worker_event = event;

                worker_pool.execute(move || {
                    analyzer::analyze_event(worker_event, worker_handle, worker_db);
                });
            },
            Err(e) => {
                eprintln!("DeviceIoControl failed: {:?}", e);
                break;
            }
        }
    }

    let _ = unsafe { CloseHandle(listener_handle) };
    let _ = unsafe { CloseHandle(control_handle) };
    cleanup();
    Ok(())
}

fn cleanup(){
    let _ = driver::mgmt::stop_driver_service(DRIVER_SERVICE_NAME);
    let _ = driver::mgmt::uninstall_driver_service(DRIVER_SERVICE_NAME);
}

fn init_driver()-> error::Result<()>{
    // increase process prio
    unsafe {
        let current_process = windows::Win32::System::Threading::GetCurrentProcess();
        let _ = windows::Win32::System::Threading::SetPriorityClass(
            current_process, 
            windows::Win32::System::Threading::HIGH_PRIORITY_CLASS
        );
    }

    //setup driver
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

