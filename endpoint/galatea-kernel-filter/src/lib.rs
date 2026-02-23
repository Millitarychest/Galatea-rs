//! Galatea Kernel Filter — Filesystem minifilter driver.

#![no_std]
#![deny(missing_docs)]

extern crate alloc;
#[cfg(not(test))]
extern crate wdk_panic;

mod ffi;

use core::ffi::c_void;
use core::mem::zeroed;
use core::ptr::null_mut;

use wdk_sys::ntddk::DbgPrint;
use wdk_sys::{
    DRIVER_OBJECT, IRP_MJ_CREATE, IRP_MJ_SET_INFORMATION, IRP_MJ_WRITE, NTSTATUS, PCUNICODE_STRING,
    STATUS_SUCCESS,
};

use crate::ffi::flt::{
    FLT_CALLBACK_DATA, FLT_OPERATION_REGISTRATION, FLT_POSTOP_CALLBACK_STATUS,
    FLT_POSTOP_FINISHED_PROCESSING, FLT_PREOP_CALLBACK_STATUS, FLT_PREOP_SUCCESS_NO_CALLBACK,
    FLT_PREOP_SUCCESS_WITH_CALLBACK, FLT_REGISTRATION, FLT_REGISTRATION_VERSION,
    FLT_RELATED_OBJECTS, FltRegisterFilter, FltStartFiltering, FltUnregisterFilter,
    IRP_MJ_OPERATION_END, PFLT_FILTER,
};

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;
#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

// ---- Globals ----

/// Handle returned by `FltRegisterFilter`, needed for teardown.
// Safety: only written in `DriverEntry` (single-threaded at PASSIVE_LEVEL)
// and read/cleared in `filter_unload` (serialised by FltMgr).
static mut FILTER_HANDLE: PFLT_FILTER = null_mut();

// ---- Pre/Post operation callbacks ----

/// Pre-create callback: logs every file open and allows it.
///
/// Returns [`FLT_PREOP_SUCCESS_WITH_CALLBACK`] so that [`post_create`] fires.
unsafe extern "C" fn pre_create(
    _data: *mut FLT_CALLBACK_DATA,
    flt_objects: *const FLT_RELATED_OBJECTS,
    _completion_context: *mut *mut c_void,
) -> FLT_PREOP_CALLBACK_STATUS {
    // Safety: flt_objects and its file_object are guaranteed valid by FltMgr
    // for the duration of this callback.
    unsafe {
        let file_obj = (*flt_objects).file_object;
        if !file_obj.is_null() && !(*file_obj).FileName.Buffer.is_null() {
            DbgPrint(
                b"GalateaFlt: [CREATE] %wZ\n\0".as_ptr() as *const i8,
                &(*file_obj).FileName,
            );
        }
    }
    FLT_PREOP_SUCCESS_WITH_CALLBACK
}

/// Post-create callback: logs creates that completed.
unsafe extern "C" fn post_create(
    data: *mut FLT_CALLBACK_DATA,
    flt_objects: *const FLT_RELATED_OBJECTS,
    _completion_context: *mut c_void,
    _flags: u32,
) -> FLT_POSTOP_CALLBACK_STATUS {
    // Safety: data and flt_objects are valid for the lifetime of this callback.
    unsafe {
        let status = (*data).io_status.__bindgen_anon_1.Status;
        if status != STATUS_SUCCESS {
            let file_obj = (*flt_objects).file_object;
            if !file_obj.is_null() && !(*file_obj).FileName.Buffer.is_null() {
                DbgPrint(
                    b"GalateaFlt: [CREATE-FAIL] %wZ status=0x%08x\n\0".as_ptr() as *const i8,
                    &(*file_obj).FileName,
                    status,
                );
            }
        }
    }
    FLT_POSTOP_FINISHED_PROCESSING
}

/// Pre-write callback: logs write operations.
unsafe extern "C" fn pre_write(
    _data: *mut FLT_CALLBACK_DATA,
    flt_objects: *const FLT_RELATED_OBJECTS,
    _completion_context: *mut *mut c_void,
) -> FLT_PREOP_CALLBACK_STATUS {
    // Safety: flt_objects is valid for the lifetime of this callback.
    unsafe {
        let file_obj = (*flt_objects).file_object;
        if !file_obj.is_null() && !(*file_obj).FileName.Buffer.is_null() {
            DbgPrint(
                b"GalateaFlt: [WRITE] %wZ\n\0".as_ptr() as *const i8,
                &(*file_obj).FileName,
            );
        }
    }
    FLT_PREOP_SUCCESS_NO_CALLBACK
}

/// Pre-set-information callback: catches rename and delete operations.
///
/// `IRP_MJ_SET_INFORMATION` covers `FileRenameInformation`,
/// `FileDispositionInformation`, and similar file metadata changes.
unsafe extern "C" fn pre_set_info(
    _data: *mut FLT_CALLBACK_DATA,
    flt_objects: *const FLT_RELATED_OBJECTS,
    _completion_context: *mut *mut c_void,
) -> FLT_PREOP_CALLBACK_STATUS {
    // Safety: flt_objects is valid for the lifetime of this callback.
    unsafe {
        let file_obj = (*flt_objects).file_object;
        if !file_obj.is_null() && !(*file_obj).FileName.Buffer.is_null() {
            DbgPrint(
                b"GalateaFlt: [SET_INFO] %wZ\n\0".as_ptr() as *const i8,
                &(*file_obj).FileName,
            );
        }
    }
    FLT_PREOP_SUCCESS_NO_CALLBACK
}

// ---- Filter unload ----

/// Called by Filter Manager when the driver is being unloaded.
unsafe extern "C" fn filter_unload(_flags: u32) -> NTSTATUS {
    // Safety: FILTER_HANDLE was set in DriverEntry and is only cleared here.
    // FltMgr serialises unload — this cannot race with DriverEntry.
    unsafe {
        DbgPrint(b"GalateaFlt: Unloading filter...\n\0".as_ptr() as *const i8);
        if !FILTER_HANDLE.is_null() {
            FltUnregisterFilter(FILTER_HANDLE);
            FILTER_HANDLE = null_mut();
        }
    }
    STATUS_SUCCESS
}

// ---- Driver entry ----

/// Driver entry point invoked by the kernel at load time.
///
/// Builds the registration structure, registers with Filter Manager,
/// and starts filtering. On failure the filter is cleaned up.
#[unsafe(no_mangle)]
pub extern "C" fn DriverEntry(
    driver_object: *mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    // Safety: called by the kernel at PASSIVE_LEVEL, single-threaded.
    unsafe {
        DbgPrint(b"GalateaFlt: DriverEntry called\n\0".as_ptr() as *const i8);

        // operation registrations — must live until FltRegisterFilter returns
        let operations: [FLT_OPERATION_REGISTRATION; 4] = [
            FLT_OPERATION_REGISTRATION {
                major_function: IRP_MJ_CREATE as u8,
                flags: 0,
                pre_operation: Some(pre_create),
                post_operation: Some(post_create),
                reserved1: null_mut(),
            },
            FLT_OPERATION_REGISTRATION {
                major_function: IRP_MJ_WRITE as u8,
                flags: 0,
                pre_operation: Some(pre_write),
                post_operation: None,
                reserved1: null_mut(),
            },
            FLT_OPERATION_REGISTRATION {
                major_function: IRP_MJ_SET_INFORMATION as u8,
                flags: 0,
                pre_operation: Some(pre_set_info),
                post_operation: None,
                reserved1: null_mut(),
            },
            // Sentinel — end of array
            FLT_OPERATION_REGISTRATION {
                major_function: IRP_MJ_OPERATION_END,
                flags: 0,
                pre_operation: None,
                post_operation: None,
                reserved1: null_mut(),
            },
        ];

        let mut reg: FLT_REGISTRATION = zeroed();
        reg.size = core::mem::size_of::<FLT_REGISTRATION>() as u16;
        reg.version = FLT_REGISTRATION_VERSION;
        reg.filter_unload_callback = Some(filter_unload);
        reg.operation_registration = operations.as_ptr();

        let mut status: NTSTATUS = FltRegisterFilter(driver_object, &reg, &raw mut FILTER_HANDLE);

        if status != STATUS_SUCCESS {
            DbgPrint(
                b"GalateaFlt: FltRegisterFilter FAILED 0x%08x\n\0".as_ptr() as *const i8,
                status,
            );
            return status;
        }
        DbgPrint(b"GalateaFlt: Filter registered successfully\n\0".as_ptr() as *const i8);

        status = FltStartFiltering(FILTER_HANDLE);
        if status != STATUS_SUCCESS {
            DbgPrint(
                b"GalateaFlt: FltStartFiltering FAILED 0x%08x\n\0".as_ptr() as *const i8,
                status,
            );
            FltUnregisterFilter(FILTER_HANDLE);
            FILTER_HANDLE = null_mut();
            return status;
        }
        DbgPrint(
            b"GalateaFlt: Filtering started! Allowing everything, logging to DbgPrint.\n\0".as_ptr()
                as *const i8,
        );

        STATUS_SUCCESS
    }
}

// ---- Stubs ----

#[allow(dead_code)]
fn main() {}
