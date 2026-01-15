use alloc::boxed::Box;
use core::ptr::addr_of_mut;
use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

use wdk_sys::_KWAIT_REASON::Suspended;
use wdk_sys::_MODE::{KernelMode, UserMode};
use wdk_sys::{_EVENT_TYPE, HANDLE, KAPC, KEVENT, KLOCK_QUEUE_HANDLE, KPROCESSOR_MODE, PETHREAD, PVOID, STATUS_ACCESS_DENIED, STATUS_SUCCESS, LARGE_INTEGER};
use wdk_sys::ntddk::{DbgPrint, KeAcquireInStackQueuedSpinLock, KeInitializeEvent, KeReleaseInStackQueuedSpinLock, KeSetEvent, KeWaitForSingleObject, ObfDereferenceObject, PsLookupThreadByThreadId, ZwTerminateProcess};

use crate::{PENDING_SCANS_LOCK,PENDING_SCANS, PendingScan};

pub static APC_COUNT: AtomicUsize = AtomicUsize::new(0);

//Freeze APC: Stops process execution until agent allows
#[repr(C)]
struct FreezeApcCtx{
    apc: KAPC,
    event: KEVENT,
    pid: u64,
}


pub unsafe fn inject_freeze_apc(thread_id: HANDLE, pid: u64) {
    unsafe {
        let mut thread_obj: PETHREAD = core::ptr::null_mut();
        let status = PsLookupThreadByThreadId(thread_id, &mut thread_obj);
        if status != STATUS_SUCCESS { return; }

        APC_COUNT.fetch_add(1, Ordering::SeqCst);

        let mut ctx = Box::new(FreezeApcCtx{
            apc: core::mem::zeroed(),
            event: core::mem::zeroed(),
            pid
        });

        KeInitializeEvent(&mut ctx.event, _EVENT_TYPE::NotificationEvent, 0);

        {
            let mut lock_handle: KLOCK_QUEUE_HANDLE = core::mem::zeroed();
            KeAcquireInStackQueuedSpinLock(addr_of_mut!(PENDING_SCANS_LOCK), &mut lock_handle);

            if let Some(list) = (*addr_of_mut!(PENDING_SCANS)).as_mut() {
                list.push(PendingScan {
                    pid,
                    event_ptr: &mut ctx.event,
                    verdict: STATUS_ACCESS_DENIED,
                });
            }

            KeReleaseInStackQueuedSpinLock(&mut lock_handle);
        }

        let ctx_ptr = Box::into_raw(ctx);

        KeInitializeApc(
            &mut (*ctx_ptr).apc,
            thread_obj,
            0,
            Some(apc_kernel_routine),
            Some(apc_rundown_routine),
            Some(apc_normal_routine),
            KernelMode as i8,
            ctx_ptr as *mut c_void,
        );

        let inserted = KeInsertQueueApc(
            &mut (*ctx_ptr).apc,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            0,
        );

        if inserted == 0 {
            let _ = Box::from_raw(ctx_ptr);

            {
                let mut lock_handle: KLOCK_QUEUE_HANDLE = core::mem::zeroed();
                KeAcquireInStackQueuedSpinLock(addr_of_mut!(PENDING_SCANS_LOCK), &mut lock_handle);

                if let Some(list) = (*addr_of_mut!(PENDING_SCANS)).as_mut() {
                    if let Some(idx) = list.iter().position(|x| x.pid == pid) {
                        list.remove(idx);
                    }
                }

                KeReleaseInStackQueuedSpinLock(&mut lock_handle);
            }

            APC_COUNT.fetch_sub(1, Ordering::SeqCst);
        }

        ObfDereferenceObject(thread_obj as PVOID);
    }
}

unsafe extern "C" fn apc_rundown_routine(apc: *mut KAPC){
    unsafe {
        let ctx_ptr = apc as *mut FreezeApcCtx;
        let _ = Box::from_raw(ctx_ptr);

        APC_COUNT.fetch_sub(1, Ordering::SeqCst);
        DbgPrint(b"Galatea: APC Rundown (Thread died early).\0".as_ptr() as *const i8);
    }
}

unsafe extern "C" fn apc_kernel_routine(
    _apc: *mut KAPC,
    _normal_routine: *mut *mut c_void,
    _normal_context: *mut *mut c_void,
    _sys_arg1: *mut *mut c_void,
    _sys_arg2: *mut *mut c_void,
) {

}

unsafe extern "C" fn apc_normal_routine(
    normal_context: *mut c_void,
    _sys_arg1: *mut c_void,
    _sys_arg2: *mut c_void,
) {
    unsafe {
        let ctx_ptr = normal_context as *mut FreezeApcCtx;
        let ctx = &mut *ctx_ptr;

        //TIMEOUT
        let mut timeout = LARGE_INTEGER { QuadPart: -50_000_000 };

        DbgPrint(b"Galatea: PID %d Frozen. Waiting for verdict...\0".as_ptr() as *const i8, ctx.pid);
        
        let status = KeWaitForSingleObject(
            &mut ctx.event as *mut _ as PVOID,
            Suspended,
            UserMode as i8, // UserMode allows the wait to be alertable if needed
            0, 
            &mut timeout
        );

        let mut verdict = STATUS_ACCESS_DENIED;

        {
            let mut lock_handle: KLOCK_QUEUE_HANDLE = core::mem::zeroed();
            KeAcquireInStackQueuedSpinLock(addr_of_mut!(PENDING_SCANS_LOCK), &mut lock_handle);
            
            if let Some(list) = (*addr_of_mut!(PENDING_SCANS)).as_mut() {
                if let Some(idx) = list.iter().position(|x| x.pid == ctx.pid) {
                    let item = list.remove(idx);
                    verdict = item.verdict;
                }
            }
            KeReleaseInStackQueuedSpinLock(&mut lock_handle);
        }

        if status == wdk_sys::STATUS_TIMEOUT {
            DbgPrint(b"Galatea: Timeout waiting for agent. Terminating.\0".as_ptr() as *const i8);
            // TODO: Make dependen on agent status (If agent is registered fail-> block else allow so task manager etc or the agent can start)
            //ZwTerminateProcess(core::ptr::null_mut(), STATUS_ACCESS_DENIED);
        } else if verdict != STATUS_SUCCESS {
            DbgPrint(b"Galatea: BLOCK verdict received. Terminating.\0".as_ptr() as *const i8);            
            let _ = ZwTerminateProcess(core::ptr::null_mut(), STATUS_ACCESS_DENIED);
        } else {
            DbgPrint(b"Galatea: ALLOW verdict received. Resuming.\0".as_ptr() as *const i8);
        }

        let _ = Box::from_raw(ctx_ptr);
        APC_COUNT.fetch_sub(1, Ordering::SeqCst);
    }
}

// helpers
pub unsafe fn apply_verdict(pid: u64, allow: bool) -> bool {
    unsafe {
        let mut found = false;
        let mut lock_handle: KLOCK_QUEUE_HANDLE = core::mem::zeroed();

        KeAcquireInStackQueuedSpinLock(addr_of_mut!(crate::PENDING_SCANS_LOCK), &mut lock_handle);

        if let Some(list) = (*addr_of_mut!(crate::PENDING_SCANS)).as_mut() {
            if let Some(item) = list.iter_mut().find(|x| x.pid == pid) {
                item.verdict = if allow { STATUS_SUCCESS } else { STATUS_ACCESS_DENIED };
                KeSetEvent(item.event_ptr, 0, 0);
                found = true;
            }
        }

        KeReleaseInStackQueuedSpinLock(&mut lock_handle);
        found
    }
}


//stubs 
unsafe extern "C" {
    pub fn KeInitializeApc(
        Apc: *mut KAPC,
        Thread: PETHREAD, 
        Environment: u8,
        KernelRoutine: Option<unsafe extern "C" fn(*mut KAPC, *mut *mut c_void, *mut *mut c_void, *mut *mut c_void, *mut *mut c_void)>,
        RundownRoutine: Option<unsafe extern "C" fn(*mut KAPC)>,
        NormalRoutine: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void)>,
        ProcessorMode: KPROCESSOR_MODE,
        NormalContext: *mut c_void,
    );

    pub fn KeInsertQueueApc(
        Apc: *mut KAPC,
        SystemArgument1: *mut c_void,
        SystemArgument2: *mut c_void,
        Increment: u32,
    ) -> u8;
}