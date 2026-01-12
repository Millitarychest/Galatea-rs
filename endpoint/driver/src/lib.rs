#![no_std]
#[allow(unused_imports)]
use core::panic::PanicInfo;

use wdk_sys::ntddk::*;
use wdk_sys::{NTSTATUS, PCUNICODE_STRING, PVOID,DRIVER_OBJECT,STATUS_SUCCESS,PEPROCESS,PS_CREATE_NOTIFY_INFO};

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
    if !create_info.is_null() {
        unsafe {
            let info = &*create_info;
            
            DbgPrint(
                b"Galatea: [CREATE] PID: %p | Image: %wZ\0".as_ptr() as *const i8,
                process_id,
                &info.ImageFileName
            );

            if !(*info.CommandLine).Buffer.is_null() {
                DbgPrint(
                    b"         -> CmdLine: %wZ\0".as_ptr() as *const i8,
                    &info.CommandLine
                );
            }
        }
    } else {
        DbgPrint(b"Galatea: [EXIT]  PID: %p\0".as_ptr() as *const i8, process_id);
    }
}

// ------ Stubs

#[allow(dead_code)]
fn main() {}

