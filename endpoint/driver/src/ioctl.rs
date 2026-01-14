use wdk_sys::{DEVICE_OBJECT,IRP,NTSTATUS,KLOCK_QUEUE_HANDLE,
    STATUS_SUCCESS,IO_NO_INCREMENT,STATUS_UNSUCCESSFUL,STATUS_PENDING,
    STATUS_INVALID_DEVICE_REQUEST, IO_STACK_LOCATION, SL_PENDING_RETURNED,
};
use wdk_sys::ntddk::{IofCompleteRequest,
    KeAcquireInStackQueuedSpinLock,
    KeReleaseInStackQueuedSpinLock,
    IoReleaseCancelSpinLock
};

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};

use shared::IOCTL_GET_EVENT;
use crate::{EVENT_LOCK,PENDING_IRP};

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

        match control_code {
            IOCTL_GET_EVENT => {
                let mut lock_handle: KLOCK_QUEUE_HANDLE = core::mem::zeroed();
                KeAcquireInStackQueuedSpinLock(&raw mut EVENT_LOCK, &mut lock_handle);

                if !PENDING_IRP.is_null() {
                    KeReleaseInStackQueuedSpinLock(&mut lock_handle);
                    (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_UNSUCCESSFUL;
                    (*irp).IoStatus.Information = 0;
                    IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
                    return STATUS_UNSUCCESSFUL;
                }

                io_mark_irp_pending(irp);
                PENDING_IRP = irp;

                io_set_cancel_routine(irp, Some(cancel_routine));

                KeReleaseInStackQueuedSpinLock(&mut lock_handle);
                return STATUS_PENDING;
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
        let mut lock_handle: KLOCK_QUEUE_HANDLE = core::mem::zeroed();
        KeAcquireInStackQueuedSpinLock(&raw mut EVENT_LOCK, &mut lock_handle);

        if !PENDING_IRP.is_null() {
            (*PENDING_IRP).IoStatus.__bindgen_anon_1.Status = wdk_sys::STATUS_CANCELLED;
            (*PENDING_IRP).IoStatus.Information = 0;
            IofCompleteRequest(PENDING_IRP, IO_NO_INCREMENT as i8);

            PENDING_IRP = core::ptr::null_mut();
        }

        KeReleaseInStackQueuedSpinLock(&mut lock_handle);

        (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
        (*irp).IoStatus.Information = 0;
        IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
        
        STATUS_SUCCESS
    }
}

pub unsafe extern "C" fn cancel_routine(_device: *mut DEVICE_OBJECT, irp: *mut IRP) {
    unsafe {
        IoReleaseCancelSpinLock((*irp).CancelIrql);

        let mut lock_handle: KLOCK_QUEUE_HANDLE = core::mem::zeroed();
        KeAcquireInStackQueuedSpinLock(&raw mut EVENT_LOCK, &mut lock_handle);

        if PENDING_IRP == irp {
            PENDING_IRP = core::ptr::null_mut();
            (*irp).IoStatus.__bindgen_anon_1.Status = wdk_sys::STATUS_CANCELLED;
            (*irp).IoStatus.Information = 0;
            IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
        }

        KeReleaseInStackQueuedSpinLock(&mut lock_handle);
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