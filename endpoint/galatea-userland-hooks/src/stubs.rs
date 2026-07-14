use std::{arch::asm, ffi::c_void};

use windows::{
    Win32::{
        Foundation::HANDLE,
        System::{
            Diagnostics::Debug::OutputDebugStringA,
            Threading::{GetCurrentProcessId, GetProcessId},
            WindowsProgramming::CLIENT_ID,
        },
    },
    core::PCSTR,
};

use crate::{etw::events, ssn::SYSCALL_NUMBER};

/// Injected stub for ZwOpenProcess and NtOpenProcess
pub fn nt_open_process(
    process_handle: HANDLE,
    desired_access: u32,
    object_attrs: *mut c_void,
    client_id: *mut CLIENT_ID,
) {
    if !client_id.is_null() {
        let target_pid = unsafe { (*client_id).UniqueProcess.0 } as u32;
        let pid = unsafe { GetCurrentProcessId() };

        // Currently only interested in foreign process handles..
        if target_pid != pid {
            println!("PID: {pid}, target: {target_pid}");
        }
        
        events().etw_process_handle_opened(None, pid, target_pid);

    }

    let msg = "Open Process Hook!\n\0";
    unsafe {
        OutputDebugStringA(PCSTR(msg.as_ptr()));
    }

    let ssn = *SYSCALL_NUMBER
        .get("ZwOpenProcess")
        .expect("failed to find function hook for ZwOpenProcess");

    unsafe {
        asm!(
            "mov r10, rcx",
            "syscall",
            in("rax") ssn,
            in("rcx") process_handle.0,
            in("rdx") desired_access,
            in("r8") object_attrs,
            in("r9") client_id,

            options(nostack, preserves_flags)
        );
    }
}

/// Syscall hook for ZwAllocateVirtualMemory
#[allow(asm_sub_register)]
pub fn virtual_alloc_ex(
    process_handle: HANDLE,
    base_address: *mut c_void,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) {
    let pid = unsafe { GetCurrentProcessId() };
    let remote_pid = unsafe { GetProcessId(process_handle) };

    // send telemetry in the case of a remote allocation
    if pid != remote_pid {
        let _region_size_checked = if region_size.is_null() {
            0
        } else {
            // SAFETY: Null pointer checked above
            unsafe { *region_size }
        };
    }

    let msg = "NTalloc!\n\0";
    unsafe {
        OutputDebugStringA(PCSTR(msg.as_ptr()));
    }

    // proceed with the syscall
    let ssn = *SYSCALL_NUMBER
        .get("ZwAllocateVirtualMemory")
        .expect("[hook] failed to find function hook for ZwAllocateVirtualMemory");

    #[allow(unused_assignments)]
    let mut result: u32 = 999;
    unsafe {
        asm!(
            "sub rsp, 0x30",            // reserve shadow space + 8 byte ptr as it expects a stack of that size
            "mov [rsp + 0x30], {1}",    // 8 byte ptr + 32 byte shadow space + 8 bytes offset from 5th arg
            "mov [rsp + 0x28], {0}",    // 8 byte ptr + 32 byte shadow space
            "mov r10, rcx",
            "syscall",
            "add rsp, 0x30",

            in(reg) allocation_type,
            in(reg) protect,
            inout("rax") ssn => result,
            in("rcx") process_handle.0,
            in("rdx") base_address,
            in("r8") zero_bits,
            in("r9") region_size,
            options(nostack),
        );

        if result != 0 {
            println!("[hook] [i] Result of ntallocvm: {result}")
        }
    }
}
