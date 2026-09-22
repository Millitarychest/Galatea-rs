use std::ffi::c_void;

use windows::Win32::{
    Foundation::{GetLastError, HINSTANCE, STATUS_SUCCESS},
    System::{
        Memory::{PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtect},
        SystemServices::DLL_PROCESS_ATTACH,
        Threading::{CreateThread, GetCurrentProcessId, THREAD_CREATION_FLAGS},
    },
};

mod addresses;
mod error;
mod etw;
mod identity;
mod ssn;
mod stubs;
mod threads;

use crate::{
    addresses::StubAddresses,
    error::HookError,
    identity::{current_ga_pid, ga_pid_parts},
    threads::suspend_all_threads,
};

fn try_init_hooks() -> Result<(), HookError> {
    let _guard = suspend_all_threads()?;

    // Force SSN resolution BEFORE patching ntdll in memory.
    // If deferred, the LazyLock would read our own patched trampoline bytes (NOPs/jmp)
    // instead of the original syscall preambles (0xb8d18b4c).
    let _ = std::sync::LazyLock::force(&ssn::SYSCALL_NUMBER);

    let stub_addresses = StubAddresses::new()?;
    let _ = current_ga_pid();
    patch(&stub_addresses)?;

    Ok(())
}

fn report_error(err: HookError) {
    let pid = unsafe { GetCurrentProcessId() };
    let (ga_pid_lo, ga_pid_hi) = match current_ga_pid() {
        Some(ga_pid) => ga_pid_parts(&ga_pid),
        None => (0, 0),
    };
    etw::events().etw_hook_init_failed(None, ga_pid_lo, ga_pid_hi, pid, err.error_code());
}

// init
unsafe extern "system" fn init_hooks(_: *mut c_void) -> u32 {
    if let Err(err) = try_init_hooks() {
        report_error(err);
    }

    STATUS_SUCCESS.0 as _
}

/// DLL entry point called by the Windows loader.
///
/// # Safety
///
/// Invoked directly by the Windows dynamic linker (`ntdll.dll`).
/// The caller guarantees `hinstance` and `reason` are valid loader parameters.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    _hinstance: HINSTANCE,
    reason: u32,
    _reserved: *mut c_void,
) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            let _ = CreateThread(
                None,
                0,
                Some(init_hooks),
                None,
                THREAD_CREATION_FLAGS(0),
                None,
            );
        }
    }
    1
}

#[unsafe(no_mangle)]
fn patch(addresses: &StubAddresses) -> Result<(), HookError> {
    for item in addresses.addresses.values() {
        let buffer: &[u8] = &[
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90,
        ];

        let mut old_protect: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS::default();
        if unsafe {
            VirtualProtect(
                item.ntdll as *const _,
                buffer.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )
        }
        .is_err()
        {
            return Err(HookError::VirtualProtectFailed(unsafe { GetLastError().0 }));
        }

        let addr = buffer.as_ptr();
        let len = buffer.len();

        unsafe { std::ptr::copy_nonoverlapping(addr, item.ntdll as *mut _, len) };

        let mob_abs_rax: [u8; 2] = [0x48, 0xB8];
        unsafe {
            std::ptr::copy_nonoverlapping(
                mob_abs_rax.as_ptr(),
                item.ntdll as *mut _,
                mob_abs_rax.len(),
            )
        };

        let mut addr_bytes = [0u8; 8]; // 8 for ptr, 2 for call
        let addr64 = item.edr as u64; // ensure we are 8-byte aligned
        for (i, b) in addr_bytes.iter_mut().enumerate() {
            *b = ((addr64 >> (i * 8)) & 0xFF) as u8;
        }

        unsafe {
            std::ptr::copy_nonoverlapping(
                addr_bytes.as_ptr(),
                (item.ntdll + 2) as *mut _,
                addr_bytes.len(),
            )
        };

        let jmp_bytes: &[u8] = &[0xFF, 0xE0];
        unsafe {
            std::ptr::copy_nonoverlapping(
                jmp_bytes.as_ptr(),
                (item.ntdll + 10) as *mut _,
                jmp_bytes.len(),
            )
        };

        // revert the protection
        if unsafe {
            VirtualProtect(
                item.ntdll as *const _,
                buffer.len(),
                old_protect,
                &mut old_protect,
            )
        }
        .is_err()
        {
            return Err(HookError::VirtualProtectFailed(unsafe { GetLastError().0 }));
        }
    }

    Ok(())
}
