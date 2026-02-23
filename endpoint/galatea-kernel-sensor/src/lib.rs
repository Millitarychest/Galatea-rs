//! Galatea kernel sensor driver — process creation monitoring and APC-based process freezing.
#![no_std]
#![deny(missing_docs)]
#![expect(
    unsafe_op_in_unsafe_fn,
    reason = "Kernel driver: all unsafe fn have SAFETY comments; explicit inner blocks would add noise without safety benefit."
)]
#![expect(
    unused_doc_comments,
    reason = "rustdoc cannot document extern blocks; /// is kept for IDE hover support."
)]

extern crate alloc;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr::addr_of_mut;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::Ordering;

use wdk_sys::ntddk::{
    DbgPrint, IoCreateSymbolicLink, IoDeleteDevice, IoDeleteSymbolicLink,
    KeAcquireInStackQueuedSpinLock, KeDelayExecutionThread, KeInitializeSpinLock,
    KeReleaseInStackQueuedSpinLock, KeSetEvent, ObfDereferenceObject,
    PsRemoveCreateThreadNotifyRoutine, PsSetCreateProcessNotifyRoutineEx,
    PsSetCreateThreadNotifyRoutine,
};
use wdk_sys::{
    _MODE, DEVICE_OBJECT, DO_BUFFERED_IO, DO_DEVICE_INITIALIZING, DRIVER_OBJECT,
    FILE_DEVICE_SECURE_OPEN, FILE_DEVICE_UNKNOWN, IRP, IRP_MJ_CLEANUP, IRP_MJ_CLOSE, IRP_MJ_CREATE,
    IRP_MJ_DEVICE_CONTROL, KEVENT, KLOCK_QUEUE_HANDLE, KSPIN_LOCK, LARGE_INTEGER, NTSTATUS,
    PCUNICODE_STRING, STATUS_SUCCESS, UNICODE_STRING,
};

use galatea_shared::GalateaEvent;

mod apc;
mod callback;
mod ffi;
mod ioctl;
mod utils;

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
    request_id: u64,
    pid: u64,
    event_ptr: *mut KEVENT,
    verdict: NTSTATUS,
}
static mut PENDING_SCANS: Option<Vec<PendingScan>> = None;
static mut PENDING_SCANS_LOCK: KSPIN_LOCK = 0;

// Intermediate Buffer of new Processes

/// A process that has been intercepted and is pending a scan verdict.
pub struct TargetProcess {
    /// The OS process ID.
    pub pid: u64,
    /// The unique request ID assigned to this scan.
    pub request_id: u64,
}

static mut TARGET_PIDS: Option<Vec<TargetProcess>> = None;
static mut TARGET_LOCK: KSPIN_LOCK = 0;

/// Monotonically increasing counter used to assign unique request IDs to each scan event.
pub static REQUEST_ID_COUNTER: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(1);

// Event Buffer:
static mut EVENT_QUEUE: Option<Vec<GalateaEvent>> = None;
static mut QUEUE_LOCK: KSPIN_LOCK = 0;

// VerdictBuffer
#[derive(Clone, Copy)]
struct CachedVerdict {
    request_id: u64,
    allowed: bool,
    timestamp: u64,
}

static mut VERDICT_CACHE: Option<Vec<CachedVerdict>> = None;
static mut CACHE_LOCK: KSPIN_LOCK = 0;

/// Maximum number of verdict cache entries before the oldest is evicted.
pub const MAX_VERDICT_CACHE_SIZE: usize = 1024;

/// Time-to-live for verdict cache entries in 100-nanosecond kernel time units (10 seconds).
pub const MAX_VERDICT_CACHE_TTL: u64 = 10 * 10_000_000;

/// Atomic pointer to the registered agent's EPROCESS object, used to restrict IOCTL access.
pub static AGENT_PROCESS: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

/// Driver Entry Point
#[unsafe(no_mangle)]
pub extern "C" fn DriverEntry(
    driver_object: *mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    // SAFETY: DriverEntry is called once by the kernel at load time with a valid DRIVER_OBJECT.
    // All spin locks are initialised before use. Static muts are accessed exclusively here
    // during single-threaded initialisation.
    unsafe {
        DbgPrint(b"Galatea: Driver Loaded (via wdk-sys)\0".as_ptr() as *const i8);

        KeInitializeSpinLock(&raw mut PENDING_IRP_LOCK);
        KeInitializeSpinLock(addr_of_mut!(TARGET_LOCK));
        KeInitializeSpinLock(addr_of_mut!(PENDING_SCANS_LOCK));
        KeInitializeSpinLock(addr_of_mut!(CACHE_LOCK));
        KeInitializeSpinLock(addr_of_mut!(QUEUE_LOCK));

        *addr_of_mut!(TARGET_PIDS) = Some(Vec::new());
        *addr_of_mut!(PENDING_SCANS) = Some(Vec::new());
        *addr_of_mut!(VERDICT_CACHE) = Some(Vec::new());
        *addr_of_mut!(EVENT_QUEUE) = Some(Vec::new());

        (*driver_object).DriverUnload = Some(driver_unload);

        //ioctl dispatches
        (*driver_object).MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] =
            Some(ioctl::dispatch_device_control);
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

        let sddl = w![r"D:P(A;;GA;;;SY)(A;;GA;;;BA)"];
        let guid = &wdk_sys::GUID::default();

        let mut sddl_unicode = UNICODE_STRING {
            Length: (sddl.len() * 2) as u16,
            MaximumLength: (sddl.len() * 2) as u16,
            Buffer: sddl.as_ptr() as *mut _,
        };

        let mut status = ffi::WdmlibIoCreateDeviceSecure(
            driver_object,
            0,
            &mut dev_name,
            FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN,
            0,
            &mut sddl_unicode,
            guid,
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
            DbgPrint(
                b"Galatea: FAILED to register. Status: %x\0".as_ptr() as *const i8,
                status,
            );
            return status;
        }

        status = PsSetCreateThreadNotifyRoutine(Some(callback::thread_notify_routine));
        if status == STATUS_SUCCESS {
            DbgPrint(b"Galatea: Thread Monitor Registered.\0".as_ptr() as *const i8);
        } else {
            DbgPrint(
                b"Galatea: FAILED to register. Status: %x\0".as_ptr() as *const i8,
                status,
            );
            return status;
        }
    }
    STATUS_SUCCESS
}

/// Driver Exit — unregisters callbacks, wakes pending scan threads, and deletes the device.
pub extern "C" fn driver_unload(_driver_object: *mut DRIVER_OBJECT) {
    // SAFETY: Called once by the kernel during unload. All operations are guarded by
    // spin locks. PENDING_SCANS events are signalled before the Vec is cleared to
    // prevent frozen threads from waiting forever. The AGENT_PROCESS reference is
    // released here as the driver is the sole owner of that reference.
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
        let mut interval = LARGE_INTEGER {
            QuadPart: -1_000_000,
        };

        while count > 0 {
            DbgPrint(
                b"Galatea: Waiting for %d APCs to finish...\0".as_ptr() as *const i8,
                count,
            );
            let _ = KeDelayExecutionThread(_MODE::KernelMode as i8, 0, &mut interval);
            count = APC_COUNT.load(Ordering::SeqCst);
        }
        DbgPrint(b"Galatea: All APCs finished.\0".as_ptr() as *const i8);

        let agent = AGENT_PROCESS.load(Ordering::SeqCst);
        if !agent.is_null() {
            DbgPrint(b"Galatea: Releasing reference to Agent process...\0".as_ptr() as *const i8);
            ObfDereferenceObject(agent);
            AGENT_PROCESS.store(core::ptr::null_mut(), Ordering::SeqCst);
        }

        DbgPrint(b"Galatea: Unregistering Device...\0".as_ptr() as *const i8);
        let link_u16 = w!("\\DosDevices\\Galatea");
        let mut link_name = UNICODE_STRING {
            Length: 36,
            MaximumLength: 36,
            Buffer: link_u16.as_ptr() as *mut _,
        };
        let _ = IoDeleteSymbolicLink(&mut link_name);

        if !LOCAL_DEVICE_OBJECT.is_null() {
            IoDeleteDevice(LOCAL_DEVICE_OBJECT);
        }
    }
}

// ------ Stubs

#[expect(dead_code, reason = "Stub required for wdk build harness linking")]
fn main() {}
