use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    QueryFullProcessImageNameW,
};
use windows::core::PWSTR;


#[repr(C)]
struct ProcessBasicInformation {
    exit_status: isize,
    peb_base_address: *mut core::ffi::c_void,
    affinity_mask: usize,
    base_priority: i32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

unsafe extern "system" {
    fn NtQueryInformationProcess(
        process_handle: HANDLE,
        process_information_class: u32,
        process_information: *mut core::ffi::c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

static PROCESS_CACHE: OnceLock<Mutex<HashMap<u64, CachedProcessInfo>>> = OnceLock::new();

#[derive(Clone, Debug)]
pub struct CachedProcessInfo {
    pub name: String,
    pub path: String,
    pub parent_pid: Option<u64>,
    pub command_line: Option<String>,
    pub creation_time: Option<DateTime<Utc>>,
    pub cached_at: SystemTime,
}

const CACHE_DURATION_SECS: u64 = 60; 


pub fn get_process_info(pid: u64) -> Option<CachedProcessInfo> {
    let cache = PROCESS_CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    // Check cache first
    {
        let cache_guard = cache.lock().ok()?;
        if let Some(cached) = cache_guard.get(&pid) {
            if let Ok(elapsed) = cached.cached_at.elapsed() {
                if elapsed.as_secs() < CACHE_DURATION_SECS {
                    return Some(cached.clone());
                }
            }
        }
    }

    let info = query_process_info(pid)?;


    if let Ok(mut cache_guard) = cache.lock() {
        cache_guard.insert(pid, info.clone());

        if cache_guard.len() > 1000 {
            cache_guard.clear();
        }
    }

    Some(info)
}

fn query_process_info(pid: u64) -> Option<CachedProcessInfo> {
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .ok()?
    };

    let mut info = CachedProcessInfo {
        name: String::new(),
        path: String::new(),
        parent_pid: None,
        command_line: None,
        creation_time: None,
        cached_at: SystemTime::now(),
    };


    if let Some(path) = get_process_image_path(handle) {
        info.path = path.clone();
        if let Some(name) = std::path::Path::new(&path).file_name() {
            info.name = name.to_string_lossy().to_string();
        }
    }

    info.parent_pid = get_parent_pid(handle);
    info.command_line = get_command_line(handle);
    info.creation_time = get_process_creation_time(handle);

    unsafe {
        let _ = CloseHandle(handle);
    }

    Some(info)
}

fn get_process_image_path(handle: HANDLE) -> Option<String> {
    let mut buffer = vec![0u16; 260];
    let mut size = buffer.len() as u32;

    unsafe {
        if QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
        .is_ok()
        {
            let path = String::from_utf16_lossy(&buffer[..size as usize]);
            return Some(path);
        }
    }

    None
}

fn get_parent_pid(handle: HANDLE) -> Option<u64> {
    let mut pbi: ProcessBasicInformation = unsafe { std::mem::zeroed() };
    let mut return_length: u32 = 0;

    unsafe {
        let status = NtQueryInformationProcess(
            handle,
            0, // ProcessBasicInformation = 0
            &mut pbi as *mut _ as *mut _,
            std::mem::size_of::<ProcessBasicInformation>() as u32,
            &mut return_length,
        );

        if status == 0 {
            return Some(pbi.inherited_from_unique_process_id as u64);
        }
    }

    None
}

fn get_command_line(_handle: HANDLE) -> Option<String> {
    //TODO
    None
}

fn get_process_creation_time(handle: HANDLE) -> Option<DateTime<Utc>> {
    use windows::Win32::Foundation::FILETIME;

    let mut creation_time: FILETIME = unsafe { std::mem::zeroed() };
    let mut exit_time: FILETIME = unsafe { std::mem::zeroed() };
    let mut kernel_time: FILETIME = unsafe { std::mem::zeroed() };
    let mut user_time: FILETIME = unsafe { std::mem::zeroed() };

    unsafe {
        if GetProcessTimes(
            handle,
            &mut creation_time,
            &mut exit_time,
            &mut kernel_time,
            &mut user_time,
        )
        .is_ok()
        {
            // Convert FILETIME to DateTime<Utc>
            let filetime_u64 = ((creation_time.dwHighDateTime as u64) << 32)
                | (creation_time.dwLowDateTime as u64);
            // FILETIME is 100-nanosecond intervals since January 1, 1601
            // Unix epoch is January 1, 1970
            const FILETIME_TO_UNIX_EPOCH: u64 = 116444736000000000;

            if filetime_u64 > FILETIME_TO_UNIX_EPOCH {
                let unix_nanos = (filetime_u64 - FILETIME_TO_UNIX_EPOCH) * 100;
                let unix_secs = unix_nanos / 1_000_000_000;
                let nanos = (unix_nanos % 1_000_000_000) as u32;

                if let Some(dt) = DateTime::from_timestamp(unix_secs as i64, nanos) {
                    return Some(dt);
                }
            }
        }
    }

    None
}
