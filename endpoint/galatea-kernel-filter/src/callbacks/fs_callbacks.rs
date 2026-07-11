use crate::ffi::flt::{
    FILE_INTERNAL_INFORMATION, FILE_INTERNAL_INFORMATION_CLASS, FILE_RENAME_INFORMATION, FILE_RENAME_INFORMATION_BYPASS_ACCESS_CHECK_CLASS, FILE_RENAME_INFORMATION_CLASS, FILE_RENAME_INFORMATION_EX_BYPASS_ACCESS_CHECK_CLASS, FILE_RENAME_INFORMATION_EX_CLASS, FILE_RENAME_REPLACE_IF_EXISTS, FLT_CALLBACK_DATA, FLT_POSTOP_FINISHED_PROCESSING, FLT_PREOP_SUCCESS_NO_CALLBACK, FLT_PREOP_SUCCESS_WITH_CALLBACK, FLT_RELATED_OBJECTS, FltPostopCallbackStatus, FltPreopCallbackStatus, FltQueryInformationFile,
};
use crate::io::filter_port::{is_agent_process, send_fs_telemetry};

use core::ffi::c_void;
use core::mem::{offset_of, size_of};
use galatea_shared::filter_port::{FSEventType, FSModOperation, GalateaFSEvent, RenameMeta};
use wdk_sys::STATUS_SUCCESS;
use wdk_sys::ntddk::{IoGetCurrentProcess, PsGetCurrentProcessId, PsGetProcessStartKey, DbgPrint};

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

            let pid = PsGetCurrentProcessId() as usize as u64;

            //early exit for main system procs? I think it caused a few crashes / hangs by messing with ntuser.dat writes? It shouldnt but ig ill try it
            if pid <= 4 {
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }

            let event = GalateaFSEvent {
                // Potentially send PsGetProcessStartKey aswell for better correlation?
                // would need adjustment of other sensors aswell tho
                process_id: pid,
                request_id: 0, //TODO: Actually add request ID stuff, where needed
                event_type: FSEventType::FileWrite,
                file_path,
                process_start_key: PsGetProcessStartKey(IoGetCurrentProcess()),
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
    data: *mut FLT_CALLBACK_DATA,
    flt_objects: *const FLT_RELATED_OBJECTS,
    _completion_context: *mut *mut c_void,
) -> FltPreopCallbackStatus {
    // Safety: data and flt_objects are valid for the lifetime of this callback.
    unsafe {
        if is_agent_process() {//|| data.is_null() || flt_objects.is_null() {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        //DbgPrint( b"GalateaFlt: [SET_INFO] Something\n\0".as_ptr() as *const i8);
        'op_eval: {
            if  !( data.is_null() || flt_objects.is_null()) {
                //DbgPrint( b"GalateaFlt: [SET_INFO] 1\n\0".as_ptr() as *const i8);
                let iopb = (*data).iopb;
                if !iopb.is_null() {
                    let set_info = (*iopb).parameters.set_file_information;

                    //DbgPrint( b"GalateaFlt: [SET_INFO] 2\n\0".as_ptr() as *const i8);

                    match set_info.file_information_class {
                        FILE_RENAME_INFORMATION_CLASS | FILE_RENAME_INFORMATION_EX_CLASS | FILE_RENAME_INFORMATION_BYPASS_ACCESS_CHECK_CLASS | FILE_RENAME_INFORMATION_EX_BYPASS_ACCESS_CHECK_CLASS => {
                            //DbgPrint( b"GalateaFlt: [SET_INFO] 3a\n\0".as_ptr() as *const i8);
                            let rename_name_offset = offset_of!(FILE_RENAME_INFORMATION, file_name);
                            if (set_info.length as usize) < rename_name_offset + size_of::<u16>() { break 'op_eval; }
        
                            let rename_info =
                                core::ptr::read_unaligned(set_info.info_buffer.cast::<FILE_RENAME_INFORMATION>());
                            let requested_name_bytes = rename_info.file_name_length as usize;
                            let available_name_bytes = (set_info.length as usize) - rename_name_offset;
                            if requested_name_bytes > available_name_bytes || requested_name_bytes % size_of::<u16>() != 0 { break 'op_eval; }
                            
                            let file_obj = (*flt_objects).file_object;
                            if !file_obj.is_null() && !(*file_obj).FileName.Buffer.is_null() {
                                let file_name = &(*file_obj).FileName;
                                let copy_len = ((file_name.Length as usize) / 2).min(259);
                                let mut file_path = [0u16; 260];
                                core::ptr::copy_nonoverlapping(file_name.Buffer, file_path.as_mut_ptr(), copy_len);

                                let pid = PsGetCurrentProcessId() as usize as u64;
                                //early exit for main system procs? I think it caused a few crashes / hangs by messing with ntuser.dat writes? It shouldnt but ig ill try it
                                if pid <= 4 { return FLT_PREOP_SUCCESS_NO_CALLBACK;}

                                let new_path_len = (requested_name_bytes / size_of::<u16>()).min(259);
                                let mut new_file_path = [0u16; 260];

                                let new_path_buffer = set_info.info_buffer.cast::<u8>()
                                    .add(rename_name_offset).cast::<u16>();
                                core::ptr::copy_nonoverlapping(
                                    new_path_buffer,
                                    new_file_path.as_mut_ptr(),
                                    new_path_len,
                                );

                                let flags = if set_info.file_information_class == FILE_RENAME_INFORMATION_CLASS {
                                    if set_info.argument.rename_or_eof.replace_if_exists != 0 {
                                        FILE_RENAME_REPLACE_IF_EXISTS
                                    } else { 0 }
                                } else {
                                    rename_info.flags.flags
                                };
                                //DbgPrint( b"GalateaFlt: [SET_INFO] %wZ\n\0".as_ptr() as *const i8, &(*file_obj).FileName,);
                                let event = GalateaFSEvent {
                                    process_id: pid,
                                    process_start_key: PsGetProcessStartKey(IoGetCurrentProcess()),
                                    request_id: 0, //TODO: Actually add request ID stuff, where needed
                                    event_type: FSEventType::FileModify(FSModOperation::Rename(RenameMeta {
                                        flags,
                                        new_file_path,
                                    })),
                                    file_path,
                                    file_index: query_file_index((*flt_objects).instance, file_obj),
                                };

                                send_fs_telemetry(&raw const event);

                            }
                        },
                        _ => {
                            let file_obj = (*flt_objects).file_object;
                            if !file_obj.is_null() && !(*file_obj).FileName.Buffer.is_null() {
                                let file_name = &(*file_obj).FileName;
                                let copy_len = ((file_name.Length as usize) / 2).min(259);
                                let mut file_path = [0u16; 260];
                                core::ptr::copy_nonoverlapping(file_name.Buffer, file_path.as_mut_ptr(), copy_len);
                                //DbgPrint( b"GalateaFlt: [SET_INFO] %wZ\n\0".as_ptr() as *const i8, &(*file_obj).FileName,);
                            }
                            //DbgPrint( b"GalateaFlt: [SET_INFO] 3b (%d)\n\0".as_ptr() as *const i8, set_info.file_information_class);
                        }
                    }
                }
            }    
        //DbgPrint( b"GalateaFlt: [SET_INFO] %wZ\n\0".as_ptr() as *const i8, &(*file_obj).FileName,);
        }
    
        //DbgPrint( b"GalateaFlt: [SET_INFO] Exit\n\0".as_ptr() as *const i8);
    }
    FLT_PREOP_SUCCESS_NO_CALLBACK
}

/// Helper: Queries the NTFS file index for the file object
/// currently being processed by the filter manager.
///
/// Returns the index on success, or `0` as a sentinel when the query fails
unsafe fn query_file_index(instance: *const c_void, file_object: *mut wdk_sys::FILE_OBJECT) -> u64 {
    // Safety: `instance` and `file_object` must be the values received from the
    // active `FLT_RELATED_OBJECTS` pointer during a Filter Manager callback.
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
