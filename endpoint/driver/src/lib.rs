#![no_std]
extern crate alloc;
use core::sync::atomic::Ordering;
use core::ptr::addr_of_mut;
use alloc::vec::Vec;

use wdk_sys::{DEVICE_OBJECT, DO_BUFFERED_IO, DO_DEVICE_INITIALIZING, DRIVER_OBJECT, 
    FILE_DEVICE_SECURE_OPEN, FILE_DEVICE_UNKNOWN, IRP, IRP_MJ_CLEANUP, IRP_MJ_CLOSE, 
    IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, KEVENT, KLOCK_QUEUE_HANDLE, 
    KSPIN_LOCK, LARGE_INTEGER, NTSTATUS, PCUNICODE_STRING, STATUS_SUCCESS, 
    UNICODE_STRING, _MODE
};
use wdk_sys::ntddk::{
    IoDeleteDevice,
    IoDeleteSymbolicLink,
    PsSetCreateProcessNotifyRoutineEx,
    PsSetCreateThreadNotifyRoutine,
    PsRemoveCreateThreadNotifyRoutine,
    DbgPrint,
    IoCreateDevice,
    IoCreateSymbolicLink,
    KeInitializeSpinLock,
    KeDelayExecutionThread,
    KeReleaseInStackQueuedSpinLock,
    KeAcquireInStackQueuedSpinLock,
    KeSetEvent
};

mod ioctl;
mod callback;
mod apc;

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;

use crate::apc::APC_COUNT;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;
static mut LOCAL_DEVICE_OBJECT: *mut DEVICE_OBJECT = core::ptr::null_mut();

// Inverted Agent IOCTL 
static mut PENDING_IRP: *mut IRP = core::ptr::null_mut();
static mut PENDING_IRP_LOCK: KSPIN_LOCK = 0;

// Scan List
#[repr(C)]
struct PendingScan {
    pid: u64,
    event_ptr: *mut KEVENT,
    verdict: NTSTATUS,
}
static mut PENDING_SCANS: Option<Vec<PendingScan>> = None;
static mut PENDING_SCANS_LOCK: KSPIN_LOCK = 0;

// Intermediet Buffer of new Processes
static mut TARGET_PIDS: Option<Vec<u64>> = None;
static mut TARGET_LOCK: KSPIN_LOCK = 0;

#[unsafe(no_mangle)]
pub extern "C" fn DriverEntry(
    driver_object: *mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    unsafe {
        DbgPrint(b"Galatea: Driver Loaded (via wdk-sys)\0".as_ptr() as *const i8);

        KeInitializeSpinLock(&raw mut PENDING_IRP_LOCK);
        KeInitializeSpinLock(addr_of_mut!(TARGET_LOCK));
        KeInitializeSpinLock(addr_of_mut!(PENDING_SCANS_LOCK));

        *addr_of_mut!(TARGET_PIDS) = Some(Vec::new());
        *addr_of_mut!(PENDING_SCANS) = Some(Vec::new());

        (*driver_object).DriverUnload = Some(driver_unload);

        //ioctl dispatches
        (*driver_object).MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(ioctl::dispatch_device_control);
        (*driver_object).MajorFunction[IRP_MJ_CREATE as usize] = Some(ioctl::dispatch_create_close);
        (*driver_object).MajorFunction[IRP_MJ_CLOSE as usize] = Some(ioctl::dispatch_create_close);
        (*driver_object).MajorFunction[IRP_MJ_CLEANUP as usize] = Some(ioctl::dispatch_cleanup);

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
        status = PsSetCreateProcessNotifyRoutineEx(Some(callback::process_notify_routine), 0);
        if status == STATUS_SUCCESS {
            DbgPrint(b"Galatea: Process Monitor Registered.\0".as_ptr() as *const i8);
        } else {
            DbgPrint(b"Galatea: FAILED to register. Status: %x\0".as_ptr() as *const i8, status);
            return status;
        }

        status = PsSetCreateThreadNotifyRoutine(Some(callback::thread_notify_routine));
        if status == STATUS_SUCCESS {
            DbgPrint(b"Galatea: Thread Monitor Registered.\0".as_ptr() as *const i8);
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
        DbgPrint(b"Galatea: Unregistering Callbacks...\0".as_ptr() as *const i8);
        let _ = PsSetCreateProcessNotifyRoutineEx(Some(callback::process_notify_routine), 1); 
        let _ = PsRemoveCreateThreadNotifyRoutine(Some(callback::thread_notify_routine));

        DbgPrint(b"Galatea: Waking pending threads...\0".as_ptr() as *const i8);
        {
            let mut lock_handle: KLOCK_QUEUE_HANDLE = core::mem::zeroed();
            KeAcquireInStackQueuedSpinLock(addr_of_mut!(PENDING_SCANS_LOCK), &mut lock_handle);

            if let Some(list) = (*addr_of_mut!(PENDING_SCANS)).as_mut() {
                for item in list.iter() {
                    KeSetEvent(item.event_ptr, 0, 0);
                }
                list.clear();
            }
            KeReleaseInStackQueuedSpinLock(&mut lock_handle);
        }
        let mut count = APC_COUNT.load(Ordering::SeqCst);
        let mut interval = LARGE_INTEGER { QuadPart: -1_000_000 };

        while count > 0 {
            DbgPrint(b"Galatea: Waiting for %d APCs to finish...\0".as_ptr() as *const i8, count);
            let _ = KeDelayExecutionThread(
                _MODE::KernelMode as i8, 
                0, 
                &mut interval
            );    
            count = APC_COUNT.load(Ordering::SeqCst);
        }
        DbgPrint(b"Galatea: All APCs finished. Safe to unload.\0".as_ptr() as *const i8);

        DbgPrint(b"Galatea: Unregistering Device...\0".as_ptr() as *const i8);
        let link_u16 = w!("\\DosDevices\\Galatea");
        let mut link_name = UNICODE_STRING { Length: 36, MaximumLength: 36, Buffer: link_u16.as_ptr() as *mut _ };
        let _ = IoDeleteSymbolicLink(&mut link_name);
        
        if !LOCAL_DEVICE_OBJECT.is_null() { IoDeleteDevice(LOCAL_DEVICE_OBJECT); }
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
