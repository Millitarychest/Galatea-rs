use std::{
    path::PathBuf,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use std::ffi::c_void;
use std::mem::size_of;
use threadpool::ThreadPool;
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::{
    Win32::{Foundation::HANDLE, System::IO::CancelIoEx},
    core::w,
};

use mimic_core::{error, mimic_bail, mimic_error, mimic_log, mimic_success, privilege};
use shared::{GalateaEvent, IOCTL_GET_EVENT};

mod analyzer;
mod cache;
mod config;
mod db;
mod driver;
mod engine;
mod injector;
mod ipc;
mod logger;
mod probes;
mod utils;
use crate::{
    analyzer::{MlEngine, PackerSignatureEngine}, ipc::SendHandle,
};
use crate::{cache::static_analyzer_cache::StaticResultCache, ipc::ipc_server::IpcServer};
pub use config::*;

static GLOBAL_LISTENER_HANDLE: AtomicUsize = AtomicUsize::new(0);
static STATIC_RESULT_CACHE: OnceLock<StaticResultCache> = OnceLock::new();

fn main() -> error::Result<()> {
    // Setup file logging
    
    let current_dir = utils::exe_directory();
    let log_path = current_dir.join(LOG_FILE);

    if let Ok(file_logger) = logger::FileLogger::new(log_path) {
        mimic_core::logger::set_logger(Box::new(file_logger));
    }

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
        })
        .expect("Error setting Ctrl-C handler");
    }

    init_driver()?;

    // Setup Database Connection
    let db_path = current_dir.join(DB_FILE_NAME);
    let db_pool = db::init_db_pool(db_path.to_str().unwrap())?;
    mimic_success!("Knowledge Base (Signatures) Loaded.");

    // Load Packer Signatures
    let mut sig_engine = PackerSignatureEngine::new();
    let sig_path = current_dir.join("userdb.txt");
    if sig_path.exists() {
        if let Err(e) = sig_engine.load(sig_path.to_str().unwrap()) {
            mimic_error!("Failed to load signatures: {}", e);
        }
    } else {
        mimic_log!("No external userdb.txt found. Using internal heuristics only.");
    }
    let sig_engine = Arc::new(sig_engine);

    // prepare Ml engine
    let ml_path = current_dir.join("model.onnx");
    let ml_engine = if ml_path.exists() {
        mimic_log!("Loading AI Model from: {:?}", ml_path);
        match MlEngine::new(ml_path.to_str().unwrap()) {
            Ok(engine) => {
                mimic_success!("AI Model Loaded Successfully.");
                Some(engine)
            }
            Err(e) => {
                mimic_error!("Failed to load AI Model: {}", e);
                None
            }
        }
    } else {
        mimic_error!("model.onnx not found! ML disabled.");
        None
    };
    let ml_engine = Arc::new(ml_engine);

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
            unsafe {
                let _ = CloseHandle(listener_handle);
            };
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

    let safe_handle = SendHandle::from(control_handle);

    // Initialize IPC server
    let ipc_sender = IpcServer::start();

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
                let worker_sig = sig_engine.clone();
                let worker_ml = ml_engine.clone();
                let worker_ipc = ipc_sender.clone();
                let worker_event = event;

                worker_pool.execute(move || {
                    analyzer::analyze_event(
                        worker_event,
                        worker_handle,
                        worker_db,
                        worker_sig,
                        worker_ml,
                        worker_ipc,
                    );
                });
            }
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

fn cleanup() {
    let _ = driver::mgmt::stop_driver_service(DRIVER_SERVICE_NAME);
    let _ = driver::mgmt::uninstall_driver_service(DRIVER_SERVICE_NAME);
}

fn init_driver() -> error::Result<()> {
    // increase process prio
    unsafe {
        let current_process = windows::Win32::System::Threading::GetCurrentProcess();
        let _ = windows::Win32::System::Threading::SetPriorityClass(
            current_process,
            windows::Win32::System::Threading::HIGH_PRIORITY_CLASS,
        );
    }

    //setup driver
    if !privilege::is_elevated() {
        mimic_error!(
            "Elevation Required: Galatea Agent must run as Administrator to load drivers."
        );
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
    let current_dir = utils::exe_directory();

    let prod_path = current_dir.join(DRIVER_FILE_NAME);
    if prod_path.exists() {
        return Ok(prod_path);
    }

    Err(format!(
        "Could not locate '{}'. Checked local dir and target/dist.",
        DRIVER_FILE_NAME
    ))
}
