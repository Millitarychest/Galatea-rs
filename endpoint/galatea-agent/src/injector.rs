use std::ffi::{CString, c_void};

use mimic_core::{error, mimic_bail};

use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
};
use windows::core::s;

/// Injects a Dll into a given Process
//  Mostly intended for userland hooks
pub fn inject_dll(pid: u64, dll_path: &str) -> error::Result<()> {
    //-----------------------------
    // Aquire handle to target
    //-----------------------------

    let process_handle = unsafe {
        OpenProcess(
            PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_CREATE_THREAD
                | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            pid as u32,
        )
    }?;

    //-----------------------------
    // Resolve Paths and Function addrs
    //-----------------------------

    let dll_path_c = CString::new(dll_path)?;
    let path_len = dll_path_c.as_bytes_with_nul().len();

    let kernel32_handle = unsafe { GetModuleHandleA(s!("Kernel32.dll")) }?;
    let load_library_fn_address = unsafe { GetProcAddress(kernel32_handle, s!("LoadLibraryA")) };
    let load_library_fn_address = match load_library_fn_address {
        None => mimic_bail!("Bad LoadLibraryA ptr"),
        Some(address) => address as *const (),
    };

    //-----------------------------
    // Prepare target Process
    //-----------------------------

    let remote_buffer_addr = unsafe {
        VirtualAllocEx(
            process_handle,
            None,
            path_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if remote_buffer_addr.is_null() {
        mimic_bail!("Failed to alloc memory")
    }

    let mut bytes_written: usize = 0;
    let buff_result = unsafe {
        WriteProcessMemory(
            process_handle,
            remote_buffer_addr,
            dll_path_c.as_ptr() as *const _,
            path_len,
            Some(&mut bytes_written as *mut usize),
        )
    };

    if buff_result.is_err() {
        mimic_bail!("Failed to write Memory");
    }

    //-----------------------------
    // Get Remote process to load our dll
    //-----------------------------

    let load_library_fn_address: Option<unsafe extern "system" fn(*mut c_void) -> u32> =
        Some(unsafe { std::mem::transmute(load_library_fn_address) });

    let mut thread: u32 = 0;
    let h_thread = unsafe {
        CreateRemoteThread(
            process_handle,
            None,
            0,
            load_library_fn_address,
            Some(remote_buffer_addr),
            0,
            Some(&mut thread as *mut u32),
        )
    };

    if h_thread.is_err() {
        mimic_bail!("Failed to create remote Thread");
    }

    Ok(())
}
