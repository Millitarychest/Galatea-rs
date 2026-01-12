#![no_std]
#[allow(unused_imports)]
use core::panic::PanicInfo;

use wdk_sys::ntddk::*;
use wdk_sys::{NTSTATUS, PCUNICODE_STRING, PVOID,DRIVER_OBJECT,STATUS_SUCCESS,PEPROCESS,PS_CREATE_NOTIFY_INFO,STATUS_ACCESS_DENIED,UNICODE_STRING};

#[cfg(not(test))]
extern crate wdk_panic;

#[unsafe(no_mangle)]
pub extern "C" fn DriverEntry(
    driver_object: *mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    unsafe {
        DbgPrint(b"Galatea: Driver Loaded (via wdk-sys)\0".as_ptr() as *const i8);

        (*driver_object).DriverUnload = Some(driver_unload);

        let status = PsSetCreateProcessNotifyRoutineEx(Some(process_notify_routine), 0);

        if status == STATUS_SUCCESS {
            DbgPrint(b"Galatea: Process Monitor Registered.\0".as_ptr() as *const i8);
        } else {
            DbgPrint(b"Galatea: FAILED to register. Status: %x\0".as_ptr() as *const i8, status);
            return status;
        }
    }
    STATUS_SUCCESS
}

pub extern "C" fn driver_unload(_driver_object: *mut DRIVER_OBJECT) {
    unsafe {
        DbgPrint(b"Galatea: Unloading...\0".as_ptr() as *const i8);
        PsSetCreateProcessNotifyRoutineEx(Some(process_notify_routine), 1); 
    }
}

unsafe extern "C" fn process_notify_routine(
    process: PEPROCESS,
    process_id: PVOID,
    create_info: *mut PS_CREATE_NOTIFY_INFO,
) {
    unsafe {
        if let Some(info) = create_info.as_mut() {
                
                DbgPrint(
                    b"Galatea: [CREATE] PID: %p | Image: %wZ\0".as_ptr() as *const i8,
                    process_id,
                    info.ImageFileName
                );

                if !(*info.CommandLine).Buffer.is_null() {
                    DbgPrint(
                        b"         -> CmdLine: %wZ\0".as_ptr() as *const i8,
                        info.CommandLine
                    );
                }


                let target_name_u16 = w!("\\??\\C:\\Program Files\\WindowsApps\\Microsoft.WindowsNotepad_11.2508.38.0_x64__8wekyb3d8bbwe\\Notepad\\Notepad.exe");
                let mut target_unicode = UNICODE_STRING {
                    Length: (target_name_u16.len() * 2) as u16,
                    MaximumLength: (target_name_u16.len() * 2) as u16,
                    Buffer: target_name_u16.as_ptr() as *mut _,
                };
                let matched = RtlEqualUnicodeString(info.ImageFileName, &mut target_unicode, 1);

                if matched == 1 {
                    DbgPrint(
                        b"Galatea: [BLOCK] Notepad.exe detected. Blocking execution\0".as_ptr() as *const i8,
                    );
                    info.CreationStatus = STATUS_ACCESS_DENIED;
                }

        } else {
            DbgPrint(b"Galatea: [EXIT]  PID: %p\0".as_ptr() as *const i8, process_id);
        }
    }
}

// ------ Helpers

// --- Helper Macro for Wide Strings (L"notepad.exe") ---
#[macro_export]
macro_rules! w {
    ($s:expr) => {
        {
            const S: &[u16] = &{
                let bs = $s.as_bytes();
                let mut out = [0u16; $s.len()];
                let mut i = 0;
                while i < $s.len() {
                    out[i] = bs[i] as u16;
                    i += 1;
                }
                out
            };
            S
        }
    };
}


// ------ Stubs

#[allow(dead_code)]
fn main() {}



