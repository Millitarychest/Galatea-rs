use wdk_sys::{DEVICE_OBJECT, IO_NO_INCREMENT, IO_STACK_LOCATION, IRP, KLOCK_QUEUE_HANDLE, NTSTATUS, SL_PENDING_RETURNED, STATUS_ACCESS_DENIED, STATUS_INVALID_DEVICE_REQUEST, STATUS_PENDING, STATUS_SUCCESS, STATUS_UNSUCCESSFUL
};
use wdk_sys::ntddk::{DbgPrint, IoGetCurrentProcess, IoReleaseCancelSpinLock, IofCompleteRequest, KeAcquireInStackQueuedSpinLock, KeReleaseInStackQueuedSpinLock, ObfReferenceObject, ObfDereferenceObject
};

use core::ptr::addr_of_mut;
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};

use shared::{GalateaEvent, GalateaVerdict, IOCTL_GET_EVENT, IOCTL_REGISTER_AGENT, IOCTL_SEND_VERDICT};
use crate::{PENDING_IRP_LOCK,PENDING_IRP,AGENT_PROCESS};

pub unsafe extern "C" fn dispatch_create_close(_device: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    unsafe {
        (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
        (*irp).IoStatus.Information = 0;
        IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
        STATUS_SUCCESS
    }
}

pub unsafe extern "C" fn dispatch_device_control(_device: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    unsafe {
        let stack = io_get_current_irp_stack_location(irp);
        let control_code = (*stack).Parameters.DeviceIoControl.IoControlCode;

        // validate agent
        if control_code != IOCTL_REGISTER_AGENT {
            let registered = AGENT_PROCESS.load(Ordering::SeqCst);
            let caller = IoGetCurrentProcess() as *mut c_void;

            if registered.is_null() || registered != caller {
                (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_ACCESS_DENIED;
                (*irp).IoStatus.Information = 0;
                IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
                return STATUS_ACCESS_DENIED;
            }
        }

        match control_code {
            IOCTL_GET_EVENT => {
                let mut irp_lock_handle: KLOCK_QUEUE_HANDLE = core::mem::zeroed();
                let mut queue_lock_handle: KLOCK_QUEUE_HANDLE = core::mem::zeroed();
                let mut queued_event: Option<GalateaEvent> = None;

                KeAcquireInStackQueuedSpinLock(&raw mut PENDING_IRP_LOCK, &mut irp_lock_handle);

                if !PENDING_IRP.is_null() {
                    KeReleaseInStackQueuedSpinLock(&mut irp_lock_handle);
                    (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_UNSUCCESSFUL;
                    (*irp).IoStatus.Information = 0;
                    IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
                    return STATUS_UNSUCCESSFUL;
                }

                KeAcquireInStackQueuedSpinLock(addr_of_mut!(crate::QUEUE_LOCK), &mut queue_lock_handle);
                if let Some(q) = (*addr_of_mut!(crate::EVENT_QUEUE)).as_mut() {
                    if !q.is_empty() {
                        queued_event = Some(q.remove(0));
                    }
                }
                KeReleaseInStackQueuedSpinLock(&mut queue_lock_handle);
                if let Some(evt) = queued_event {
                    KeReleaseInStackQueuedSpinLock(&mut irp_lock_handle);

                    let stack = io_get_current_irp_stack_location(irp);
                    let output_len = (*stack).Parameters.DeviceIoControl.OutputBufferLength as usize;
                    if output_len >= core::mem::size_of::<GalateaEvent>() {
                        let buffer = (*irp).AssociatedIrp.SystemBuffer as *mut GalateaEvent;
                        *buffer = evt;
                        (*irp).IoStatus.Information = core::mem::size_of::<GalateaEvent>() as u64;
                        (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
                    } else {
                        (*irp).IoStatus.__bindgen_anon_1.Status = wdk_sys::STATUS_BUFFER_TOO_SMALL;
                    }
                    IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
                    return STATUS_SUCCESS;
                }
                
                io_mark_irp_pending(irp);
                PENDING_IRP = irp;
                io_set_cancel_routine(irp, Some(cancel_routine));

                KeReleaseInStackQueuedSpinLock(&mut irp_lock_handle);
                return STATUS_PENDING;
            },
            IOCTL_SEND_VERDICT =>{
                let stack = io_get_current_irp_stack_location(irp);
                let input_len = (*stack).Parameters.DeviceIoControl.InputBufferLength as usize;

                if input_len < core::mem::size_of::<GalateaVerdict>() {
                    (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_UNSUCCESSFUL;
                    (*irp).IoStatus.Information = 0;
                    IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
                    return STATUS_UNSUCCESSFUL;
                }

                let verdict_data = &*((*irp).AssociatedIrp.SystemBuffer as *const GalateaVerdict);
                let pid = verdict_data.process_id;
                let rid = verdict_data.request_id;
                let allowed = verdict_data.allow;

                DbgPrint(b"Galatea: Received Verdict for PID: %d -> %d\0".as_ptr() as *const i8, pid, allowed as i32);
                let found = crate::apc::apply_verdict(pid, rid, allowed);

                let status = if found { STATUS_SUCCESS } else { STATUS_UNSUCCESSFUL };
                (*irp).IoStatus.__bindgen_anon_1.Status = status;
                (*irp).IoStatus.Information = 0;
                IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
                return status;
            
            
            },
            IOCTL_REGISTER_AGENT =>{
                let caller_process = IoGetCurrentProcess();
                ObfReferenceObject(caller_process as *mut _);
                let result = AGENT_PROCESS.compare_exchange(
                    core::ptr::null_mut(),
                    caller_process as *mut c_void,
                    Ordering::SeqCst,
                    Ordering::SeqCst
                );

                match result {
                    Ok(_) => {
                        DbgPrint(b"Galatea: Agent Registered Successfully.\0".as_ptr() as *const i8);
                        (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
                    },
                    Err(_) => {
                        DbgPrint(b"Galatea: Registration Rejected. Agent already active.\0".as_ptr() as *const i8);
                        ObfDereferenceObject(caller_process as *mut c_void);
                        (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_ACCESS_DENIED;
                    }
                }

                (*irp).IoStatus.Information = 0;
                IofCompleteRequest(irp, IO_NO_INCREMENT as i8);

                if (*irp).IoStatus.__bindgen_anon_1.Status == STATUS_SUCCESS {
                    STATUS_SUCCESS
                } else {
                    STATUS_ACCESS_DENIED
                }
            },
            _ => {
                (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_INVALID_DEVICE_REQUEST;
                (*irp).IoStatus.Information = 0;
                IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
                return STATUS_INVALID_DEVICE_REQUEST;
            }
        }
    }
}

pub unsafe extern "C" fn dispatch_cleanup(_device: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    unsafe {
        let mut irp_to_complete: *mut IRP = core::ptr::null_mut();
        {
            let mut lock_handle: KLOCK_QUEUE_HANDLE = core::mem::zeroed();
            KeAcquireInStackQueuedSpinLock(&raw mut PENDING_IRP_LOCK, &mut lock_handle);

            if !PENDING_IRP.is_null() {
                let pending = PENDING_IRP;

                if io_set_cancel_routine(pending, None).is_some() {
                    PENDING_IRP = core::ptr::null_mut();
                    irp_to_complete = pending;
                }
            }

            KeReleaseInStackQueuedSpinLock(&mut lock_handle);
        }

        if !irp_to_complete.is_null() {
            (*irp_to_complete).IoStatus.__bindgen_anon_1.Status = wdk_sys::STATUS_CANCELLED;
            (*irp_to_complete).IoStatus.Information = 0;
            IofCompleteRequest(irp_to_complete, IO_NO_INCREMENT as i8);
        }

        (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
        (*irp).IoStatus.Information = 0;
        IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
        
        STATUS_SUCCESS
    }
}

pub unsafe extern "C" fn cancel_routine(_device: *mut DEVICE_OBJECT, irp: *mut IRP) {
    unsafe {
        IoReleaseCancelSpinLock((*irp).CancelIrql);

        let mut irp_to_complete: *mut IRP = core::ptr::null_mut();
        let mut lock_handle: KLOCK_QUEUE_HANDLE = core::mem::zeroed();
        
        KeAcquireInStackQueuedSpinLock(&raw mut PENDING_IRP_LOCK, &mut lock_handle);

        if PENDING_IRP == irp {
            PENDING_IRP = core::ptr::null_mut();
            irp_to_complete = irp;
        }

        KeReleaseInStackQueuedSpinLock(&mut lock_handle);

        if !irp_to_complete.is_null() {
            (*irp_to_complete).IoStatus.__bindgen_anon_1.Status = wdk_sys::STATUS_CANCELLED;
            (*irp_to_complete).IoStatus.Information = 0;
            IofCompleteRequest(irp_to_complete, IO_NO_INCREMENT as i8);
        }
    }
}

//helpers

pub unsafe fn io_mark_irp_pending(irp: *mut IRP) {
    unsafe {
        let stack = io_get_current_irp_stack_location(irp);
        (*stack).Control |= SL_PENDING_RETURNED as u8;
    }
}

pub unsafe fn io_get_current_irp_stack_location(irp: *mut IRP) -> *mut IO_STACK_LOCATION {
    unsafe {
        let overlay = &mut (*irp).Tail.Overlay;
        overlay.__bindgen_anon_2.__bindgen_anon_1.CurrentStackLocation
    }
}

pub unsafe fn io_set_cancel_routine(irp: *mut IRP, routine: Option<unsafe extern "C" fn(*mut DEVICE_OBJECT, *mut IRP)>) -> Option<unsafe extern "C" fn(*mut DEVICE_OBJECT, *mut IRP)> {
    unsafe {
        let new_routine_ptr = match routine {
            Some(r) => r as *mut c_void,
            None => core::ptr::null_mut(),
        };

        let cancel_routine_atomic = &mut (*irp).CancelRoutine as *mut _ as *mut AtomicPtr<c_void>;
        let old_ptr = (*cancel_routine_atomic).swap(new_routine_ptr, Ordering::SeqCst);

        if old_ptr.is_null() {
            None
        } else {
            Some(core::mem::transmute(old_ptr))
        }
    }
}