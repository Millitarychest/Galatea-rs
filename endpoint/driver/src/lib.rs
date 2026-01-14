#![no_std]
extern crate alloc;

#[allow(unused_imports)]
use core::panic::PanicInfo;

use wdk_sys::ntddk::*;
use wdk_sys::{NTSTATUS, PCUNICODE_STRING, PVOID,DRIVER_OBJECT,STATUS_SUCCESS,PEPROCESS,PS_CREATE_NOTIFY_INFO,
    STATUS_ACCESS_DENIED,UNICODE_STRING,FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,DEVICE_OBJECT,
    IRP, IO_STACK_LOCATION, STATUS_PENDING, STATUS_INVALID_DEVICE_REQUEST, STATUS_UNSUCCESSFUL,
    KSPIN_LOCK, IO_NO_INCREMENT, DO_DEVICE_INITIALIZING, DO_BUFFERED_IO, IRP_MJ_CREATE,
    IRP_MJ_CLOSE, IRP_MJ_DEVICE_CONTROL, SL_PENDING_RETURNED, IRP_MJ_CLEANUP
};
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};
use shared::{IOCTL_GET_EVENT,GalateaEvent};
use wdk_sys::KLOCK_QUEUE_HANDLE;

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

static mut LOCAL_DEVICE_OBJECT: *mut DEVICE_OBJECT = core::ptr::null_mut();

static mut PENDING_IRP: *mut IRP = core::ptr::null_mut();
static mut EVENT_LOCK: KSPIN_LOCK = 0;

#[unsafe(no_mangle)]
pub extern "C" fn DriverEntry(
    driver_object: *mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    unsafe {
        DbgPrint(b"Galatea: Driver Loaded (via wdk-sys)\0".as_ptr() as *const i8);

        KeInitializeSpinLock(&raw mut EVENT_LOCK);

        (*driver_object).DriverUnload = Some(driver_unload);

        //ioctl dispatches
        (*driver_object).MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(dispatch_device_control);
        (*driver_object).MajorFunction[IRP_MJ_CREATE as usize] = Some(dispatch_create_close);
        (*driver_object).MajorFunction[IRP_MJ_CLOSE as usize] = Some(dispatch_create_close);
        (*driver_object).MajorFunction[IRP_MJ_CLEANUP as usize] = Some(dispatch_cleanup);

        //Device + Symlink
        let name_u16 = w!("\\Device\\Galatea");
        let mut dev_name = UNICODE_STRING {
            Length: (name_u16.len() * 2) as u16,
            MaximumLength: (name_u16.len() * 2) as u16,
            Buffer: name_u16.as_ptr() as *mut _,
        };

        let mut device_obj: *mut DEVICE_OBJECT = core::ptr::null_mut();
        let mut status = IoCreateDevice(
            driver_object,
            0,
            &mut dev_name,
            FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN,
            0,
            &mut device_obj,
        );
        if status != STATUS_SUCCESS {
            return status;
        }

        (*device_obj).Flags |= DO_BUFFERED_IO;

        let link_u16 = w!("\\DosDevices\\Galatea");
        let mut link_name = UNICODE_STRING {
            Length: (link_u16.len() * 2) as u16,
            MaximumLength: (link_u16.len() * 2) as u16,
            Buffer: link_u16.as_ptr() as *mut _,
        };
        status = IoCreateSymbolicLink(&mut link_name, &mut dev_name);
        if status != STATUS_SUCCESS {
            return status;
        }

        LOCAL_DEVICE_OBJECT = device_obj;
        (*device_obj).Flags &= !DO_DEVICE_INITIALIZING;

        // callbacks
        status = PsSetCreateProcessNotifyRoutineEx(Some(process_notify_routine), 0);

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
        let _ = PsSetCreateProcessNotifyRoutineEx(Some(process_notify_routine), 1); 

        let link_u16 = w!("\\DosDevices\\Galatea");
        let mut link_name = UNICODE_STRING { Length: 36, MaximumLength: 36, Buffer: link_u16.as_ptr() as *mut _ };
        let _ = IoDeleteSymbolicLink(&mut link_name);
        
        if !LOCAL_DEVICE_OBJECT.is_null() { IoDeleteDevice(LOCAL_DEVICE_OBJECT); }
    }
}


// Callbacks
unsafe extern "C" fn process_notify_routine(
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

// IOCTL Dispatches
unsafe extern "C" fn dispatch_create_close(_device: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    unsafe {
        (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
        (*irp).IoStatus.Information = 0;
        IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
        STATUS_SUCCESS
    }
}
unsafe extern "C" fn dispatch_device_control(_device: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
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
unsafe extern "C" fn dispatch_cleanup(_device: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
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
unsafe extern "C" fn cancel_routine(_device: *mut DEVICE_OBJECT, irp: *mut IRP) {
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

unsafe fn io_mark_irp_pending(irp: *mut IRP) {
    unsafe {
        let stack = io_get_current_irp_stack_location(irp);
        (*stack).Control |= SL_PENDING_RETURNED as u8;
    }
}

unsafe fn io_get_current_irp_stack_location(irp: *mut IRP) -> *mut IO_STACK_LOCATION {
    unsafe {
        let overlay = &mut (*irp).Tail.Overlay;
        overlay.__bindgen_anon_2.__bindgen_anon_1.CurrentStackLocation
    }
}

unsafe fn io_set_cancel_routine(irp: *mut IRP, routine: Option<unsafe extern "C" fn(*mut DEVICE_OBJECT, *mut IRP)>) -> Option<unsafe extern "C" fn(*mut DEVICE_OBJECT, *mut IRP)> {
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

// ------ Stubs

#[allow(dead_code)]
fn main() {}

unsafe extern "C" {
    pub fn KeAcquireInStackQueuedSpinLock(
        SpinLock: *mut KSPIN_LOCK,
        LockHandle: *mut KLOCK_QUEUE_HANDLE,
    );

    pub fn KeReleaseInStackQueuedSpinLock(
        LockHandle: *mut KLOCK_QUEUE_HANDLE,
    );
}

