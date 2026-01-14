#![no_std]
extern crate alloc;

use wdk_sys::{NTSTATUS, PCUNICODE_STRING, DRIVER_OBJECT, STATUS_SUCCESS,
    UNICODE_STRING,FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,DEVICE_OBJECT,
    IRP,KSPIN_LOCK, DO_DEVICE_INITIALIZING, DO_BUFFERED_IO, IRP_MJ_CREATE,
    IRP_MJ_CLOSE, IRP_MJ_DEVICE_CONTROL, IRP_MJ_CLEANUP
};
use wdk_sys::ntddk::{
    IoDeleteDevice,
    IoDeleteSymbolicLink,
    PsSetCreateProcessNotifyRoutineEx,
    DbgPrint,
    IoCreateDevice,
    IoCreateSymbolicLink,
    KeInitializeSpinLock,
};

mod ioctl;
mod callback;

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
    }
    STATUS_SUCCESS
}

pub extern "C" fn driver_unload(_driver_object: *mut DRIVER_OBJECT) {
    unsafe {
        DbgPrint(b"Galatea: Unloading...\0".as_ptr() as *const i8);
        let _ = PsSetCreateProcessNotifyRoutineEx(Some(callback::process_notify_routine), 1); 

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
