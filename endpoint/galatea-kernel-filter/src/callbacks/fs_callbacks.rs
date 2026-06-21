use crate::ffi::flt::{
    FLT_CALLBACK_DATA, FLT_POSTOP_FINISHED_PROCESSING, FLT_PREOP_SUCCESS_NO_CALLBACK,
    FLT_PREOP_SUCCESS_WITH_CALLBACK, FLT_RELATED_OBJECTS, FltPostopCallbackStatus,
    FltPreopCallbackStatus,
};
use crate::io::filter_port::{is_agent_process, send_fs_telemetry};

use core::ffi::c_void;
use galatea_shared::filter_port::{FSEventType, GalateaFSEvent};
use wdk_sys::STATUS_SUCCESS;
use wdk_sys::ntddk::{DbgPrint, PsGetCurrentProcessId, PsGetProcessStartKey};

/// Pre-create callback: logs every file open and allows it.
///
/// Returns [`FLT_PREOP_SUCCESS_WITH_CALLBACK`] so that [`post_create`] fires.
pub unsafe extern "C" fn pre_create(
    _data: *mut FLT_CALLBACK_DATA,
    flt_objects: *const FLT_RELATED_OBJECTS,
    _completion_context: *mut *mut c_void,
) -> FltPreopCallbackStatus {
    // Safety: flt_objects and its file_object are guaranteed valid by FltMgr
    // for the duration of this callback.
    unsafe {
        let file_obj = (*flt_objects).file_object;
        if !file_obj.is_null() && !(*file_obj).FileName.Buffer.is_null() {
            //DbgPrint(b"GalateaFlt: [CREATE] %wZ\n\0".as_ptr() as *const i8,&(*file_obj).FileName,);
        }
    }
    FLT_PREOP_SUCCESS_WITH_CALLBACK
}

/// Post-create callback: logs creates that completed.
pub unsafe extern "C" fn post_create(
    data: *mut FLT_CALLBACK_DATA,
    flt_objects: *const FLT_RELATED_OBJECTS,
    _completion_context: *mut c_void,
    _flags: u32,
) -> FltPostopCallbackStatus {
    // Safety: data and flt_objects are valid for the lifetime of this callback.
    unsafe {
        let status = (*data).io_status.__bindgen_anon_1.Status;
        if status != STATUS_SUCCESS {
            let file_obj = (*flt_objects).file_object;
            if !file_obj.is_null() && !(*file_obj).FileName.Buffer.is_null() {
                //DbgPrint(b"GalateaFlt: [CREATE-FAIL] %wZ status=0x%08x\n\0".as_ptr() as *const i8,&(*file_obj).FileName,status,);
            }
        }
    }
    FLT_POSTOP_FINISHED_PROCESSING
}

/// Pre-write callback: logs write operations.
pub unsafe extern "C" fn pre_write(
    _data: *mut FLT_CALLBACK_DATA,
    flt_objects: *const FLT_RELATED_OBJECTS,
    _completion_context: *mut *mut c_void,
) -> FltPreopCallbackStatus {
    // Safety: flt_objects is valid for the lifetime of this callback.
    unsafe {
        if is_agent_process() {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        let file_obj = (*flt_objects).file_object;
        if !file_obj.is_null() && !(*file_obj).FileName.Buffer.is_null() {
            let file_name = &(*file_obj).FileName;
            let copy_len = ((file_name.Length as usize) / 2).min(259);
            let mut file_path = [0u16; 260];
            core::ptr::copy_nonoverlapping(file_name.Buffer, file_path.as_mut_ptr(), copy_len);
            
            let event = GalateaFSEvent {
                // Potentially send PsGetProcessStartKey aswell for better correlation? 
                // would need adjustment of other sensors aswell tho
                process_id: PsGetCurrentProcessId() as usize as u64,
                request_id: 0,
                event_type: FSEventType::FileWrite,
                file_path,
                process_start_key: PsGetProcessStartKey(PsGetCurrentProcess()),
                file_index: query_file_index((*flt_objects).instance, file_obj),
            };

            send_fs_telemetry(&raw const event);
        }
    }
    FLT_PREOP_SUCCESS_NO_CALLBACK
}

/// Pre-set-information callback: catches rename and delete operations.
///
/// `IRP_MJ_SET_INFORMATION` covers `FileRenameInformation`,
/// `FileDispositionInformation`, and similar file metadata changes.
pub unsafe extern "C" fn pre_set_info(
    _data: *mut FLT_CALLBACK_DATA,
    flt_objects: *const FLT_RELATED_OBJECTS,
    _completion_context: *mut *mut c_void,
) -> FltPreopCallbackStatus {
    // Safety: flt_objects is valid for the lifetime of this callback.
    unsafe {
        let file_obj = (*flt_objects).file_object;
        if !file_obj.is_null() && !(*file_obj).FileName.Buffer.is_null() {
            //DbgPrint( b"GalateaFlt: [SET_INFO] %wZ\n\0".as_ptr() as *const i8, &(*file_obj).FileName,);
        }
    }
    FLT_PREOP_SUCCESS_NO_CALLBACK
}


/// Helper: Queries the NTFS file index for the file object
/// currently being processed by the filter manager.
///
/// Returns the index on success, or `0` as a sentinel when the query fails
unsafe fn query_file_index(
    instance: *const c_void,
    file_object: *mut wdk_sys::FILE_OBJECT,
) -> u64 {
    /// # Safety
    /// `instance` and `file_object` must be the values received from the active
    /// `FLT_RELATED_OBJECTS` pointer during a Filter Manager callback — they are
    /// guaranteed valid for the callback lifetime.
    let mut info = FILE_INTERNAL_INFORMATION { index_number: 0 };
    let mut length_returned: u32 = 0;

    let status = unsafe {
        FltQueryInformationFile(
            instance,
            file_object,
            &raw mut info as *mut c_void,
            core::mem::size_of::<FILE_INTERNAL_INFORMATION>() as u32,
            FILE_INTERNAL_INFORMATION_CLASS,
            &raw mut length_returned,
        )
    };

    if status >= 0 {
        info.index_number as u64
    } else {
        // 0 is used as "unavailable" sentinel; valid NTFS indices start at 1.
        0
    }
}
