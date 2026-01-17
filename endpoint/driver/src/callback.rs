use core::sync::atomic::Ordering;
use core::ptr::addr_of_mut;
use wdk_sys::{
    BOOLEAN, HANDLE, IO_NO_INCREMENT, KLOCK_QUEUE_HANDLE, PCUNICODE_STRING, PEPROCESS, PS_CREATE_NOTIFY_INFO, PVOID, STATUS_SUCCESS,
};
use wdk_sys::ntddk::{
    IofCompleteRequest,
    KeAcquireInStackQueuedSpinLock,
    KeReleaseInStackQueuedSpinLock,
    DbgPrint,
};

use shared::GalateaEvent;
use crate::ioctl::{io_get_current_irp_stack_location,io_set_cancel_routine};
use crate::utils::is_allowlisted_static;
use crate::{PENDING_IRP, PENDING_IRP_LOCK, REQUEST_ID_COUNTER, TARGET_LOCK, TARGET_PIDS, QUEUE_LOCK, EVENT_QUEUE,apc};

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

        /* Test blocking 
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
         */
        
        let req_id = REQUEST_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
        let fastpass = is_allowlisted_static(info.ImageFileName);
        // PREP FOR SCAN
        if !fastpass {
            let mut lock: KLOCK_QUEUE_HANDLE = core::mem::zeroed();
            KeAcquireInStackQueuedSpinLock(&raw mut TARGET_LOCK, &mut lock);

            let ptr = core::ptr::addr_of_mut!(TARGET_PIDS);
            if let Some(list) = (*ptr).as_mut() {
                list.push(crate::TargetProcess { pid: process_id as u64, request_id: req_id });
            }
            KeReleaseInStackQueuedSpinLock(&mut lock);
        }
        else {
            DbgPrint(b"Galatea: Allowed System Process (No Freeze): %wZ\0".as_ptr() as *const i8, info.ImageFileName);
        }

        // Agent IO
        notify_agent(process_id as u64, req_id ,info.ImageFileName, !fastpass);
    }
}

pub unsafe extern "C" fn thread_notify_routine(
    process_id: HANDLE,
    thread_id: HANDLE,
    create: BOOLEAN,
) {
    if create == 0 { return;}
    unsafe {
        let pid = process_id as u64;
        let found_req_id = {
            let mut lock: KLOCK_QUEUE_HANDLE = core::mem::zeroed();
            let mut id = None;

            KeAcquireInStackQueuedSpinLock(&raw mut TARGET_LOCK, &mut lock);
            let ptr = core::ptr::addr_of_mut!(TARGET_PIDS);
            if let Some(list) = (*ptr).as_mut() {
                if let Some(idx) = list.iter().position(|x| x.pid == pid) {
                    let item =list.remove(idx); 
                    id = Some(item.request_id)
                }
            }
            KeReleaseInStackQueuedSpinLock(&mut lock);
            id
        };

        if let Some(rid) = found_req_id {
            DbgPrint(b"Galatea: Injecting APC into PID %p\0".as_ptr() as *const i8, process_id);
            apc::inject_freeze_apc(thread_id, pid, rid);
        }
    }
}


// Helpers

unsafe fn notify_agent(pid: u64, rid: u64, image: PCUNICODE_STRING, frozen: bool){
    unsafe {
        let mut event = GalateaEvent {
            process_id: pid,
            request_id: rid,
            image_path: [0; 260],
            frozen,
        };

        if !image.is_null() && !(*image).Buffer.is_null() {
            let src = core::slice::from_raw_parts((*image).Buffer, ((*image).Length / 2) as usize);
            let len = core::cmp::min(src.len(), 259);
            event.image_path[..len].copy_from_slice(&src[..len]);
        }

        {
            let mut lock_handle: KLOCK_QUEUE_HANDLE = core::mem::zeroed();
            KeAcquireInStackQueuedSpinLock(&raw mut PENDING_IRP_LOCK, &mut lock_handle);

            if !PENDING_IRP.is_null() {
                let irp = PENDING_IRP;
                
                if io_set_cancel_routine(irp, None).is_some() {
                    PENDING_IRP = core::ptr::null_mut();
                    
                    let stack = io_get_current_irp_stack_location(irp);
                    let output_len = (*stack).Parameters.DeviceIoControl.OutputBufferLength as usize;

                    if output_len >= core::mem::size_of::<GalateaEvent>() {
                        let buffer = (*irp).AssociatedIrp.SystemBuffer as *mut GalateaEvent;
                        *buffer = event;

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
        
        {
            let mut lock_handle: KLOCK_QUEUE_HANDLE = core::mem::zeroed();
            KeAcquireInStackQueuedSpinLock(addr_of_mut!(QUEUE_LOCK), &mut lock_handle);
            if let Some(q) = (*addr_of_mut!(EVENT_QUEUE)).as_mut() {
                if q.len() < 1000 {
                    q.push(event);
                } else {
                    DbgPrint(b"Galatea: Event Queue Full! Dropping event.\0".as_ptr() as *const i8);
                }
            }
            KeReleaseInStackQueuedSpinLock(&mut lock_handle);
        }
        
    }
}