use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
            Thread32Next,
        },
        Threading::{
            GetCurrentProcessId, GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread,
            THREAD_SUSPEND_RESUME,
        },
    },
};

use crate::error::HookError;

/// RAII guard that automatically resumes all suspended threads and closes their handles upon drop.
pub struct ThreadSuspensionGuard {
    handles: Vec<HANDLE>,
}

impl Drop for ThreadSuspensionGuard {
    fn drop(&mut self) {
        for &handle in &self.handles {
            unsafe {
                let _ = ResumeThread(handle);
                let _ = CloseHandle(handle);
            }
        }
    }
}

/// Suspend all threads in the current process except for the thread executing our EDR setup (i.e. the current thread).
///
/// Returns a `ThreadSuspensionGuard` that automatically resumes all suspended threads when dropped.
pub fn suspend_all_threads() -> Result<ThreadSuspensionGuard, HookError> {
    let thread_ids = get_thread_ids().map_err(|()| HookError::ThreadSnapshotFailed)?;

    let mut suspended_handles: Vec<HANDLE> = Vec::with_capacity(thread_ids.len());
    for id in thread_ids {
        let h = unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, id) };
        if let Ok(handle) = h {
            unsafe {
                let _ = SuspendThread(handle);
            }
            suspended_handles.push(handle);
        }
    }

    Ok(ThreadSuspensionGuard {
        handles: suspended_handles,
    })
}

/// Enumerate all threads in the current process except the current thread.
pub fn get_thread_ids() -> Result<Vec<u32>, ()> {
    let pid = unsafe { GetCurrentProcessId() };
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid) };
    let snapshot = match snapshot {
        Ok(s) => s,
        Err(_) => return Err(()),
    };

    let mut thread_ids: Vec<u32> = Vec::new();
    let current_thread = unsafe { GetCurrentThreadId() };

    let mut thread_entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    if unsafe { Thread32First(snapshot, &mut thread_entry) }.is_ok() {
        loop {
            if thread_entry.th32OwnerProcessID == pid && thread_entry.th32ThreadID != current_thread {
                thread_ids.push(thread_entry.th32ThreadID);
            }

            if unsafe { Thread32Next(snapshot, &mut thread_entry) }.is_err() {
                break;
            }
        }
    }

    let _ = unsafe { CloseHandle(snapshot) };

    Ok(thread_ids)
}
