use wdk_sys::{
    KLOCK_QUEUE_HANDLE,IO_NO_INCREMENT,STATUS_ACCESS_DENIED,PS_CREATE_NOTIFY_INFO,PVOID,
    STATUS_SUCCESS, UNICODE_STRING, PEPROCESS
};
use wdk_sys::ntddk::{
    IofCompleteRequest,
    KeAcquireInStackQueuedSpinLock,
    KeReleaseInStackQueuedSpinLock,
    DbgPrint,
    RtlEqualUnicodeString
};

use shared::GalateaEvent;
use crate::ioctl::{io_get_current_irp_stack_location,io_set_cancel_routine};
use crate::{PENDING_IRP, EVENT_LOCK, w};

pub unsafe extern "C" fn process_notify_routine(
    _process: PEPROCESS,
    process_id: PVOID,
    create_info: *mut PS_CREATE_NOTIFY_INFO,
) {
    unsafe {
        let info = match create_info.as_mut() {
            Some(i) => i,
            None => {
                DbgPrint(b"Galatea: [EXIT]  PID: %p\0".as_ptr() as *const i8, process_id);
                return;
            }
        };

        if info.ImageFileName.is_null() {
            return;
        }

        DbgPrint(
            b"Galatea: [CREATE] PID: %p | Image: %wZ\0".as_ptr() as *const i8,
            process_id,
            info.ImageFileName
        );

        if !info.CommandLine.is_null() && !(*info.CommandLine).Buffer.is_null() {
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

        // --- Event Notification Logic ---

        let mut lock_handle: KLOCK_QUEUE_HANDLE = core::mem::zeroed();
        KeAcquireInStackQueuedSpinLock(&raw mut EVENT_LOCK, &mut lock_handle);

        if !PENDING_IRP.is_null() {
            let irp = PENDING_IRP;
            
            if io_set_cancel_routine(irp, None).is_some() {
                PENDING_IRP = core::ptr::null_mut();
                
                let stack = io_get_current_irp_stack_location(irp);
                let output_len = (*stack).Parameters.DeviceIoControl.OutputBufferLength as usize;

                if output_len >= core::mem::size_of::<GalateaEvent>() {
                    let dst_event = &mut *((*irp).AssociatedIrp.SystemBuffer as *mut GalateaEvent);

                    core::ptr::write_bytes(dst_event as *mut GalateaEvent, 0, 1);
                    dst_event.process_id = process_id as u64;
                    let src_buffer = (*info.ImageFileName).Buffer;

                    if !src_buffer.is_null() {
                        let src_len = ((*info.ImageFileName).Length / 2) as usize;
                        let max_len = dst_event.image_path.len() - 1;
                        let copy_len = if src_len > max_len { max_len } else { src_len };

                        core::ptr::copy_nonoverlapping(
                            src_buffer, 
                            dst_event.image_path.as_mut_ptr(), 
                            copy_len
                        );
                    }

                    (*irp).IoStatus.Information = core::mem::size_of::<GalateaEvent>() as u64;
                    (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
                } else {
                    (*irp).IoStatus.Information = 0;
                    (*irp).IoStatus.__bindgen_anon_1.Status = wdk_sys::STATUS_BUFFER_TOO_SMALL;
                }

                KeReleaseInStackQueuedSpinLock(&mut lock_handle);
                IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
                return;
            }
        }
        KeReleaseInStackQueuedSpinLock(&mut lock_handle);
    }
}