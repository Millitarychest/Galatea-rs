use std::{ffi::c_void};
use windows::Win32::{
    Foundation::{GetLastError, HINSTANCE, STATUS_SUCCESS}, 
    System::{
        Memory::{PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtect},
        Threading::{CreateThread, THREAD_CREATION_FLAGS}
    },
};
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH};

mod addresses;
mod stubs;
mod ssn;
mod threads;
use crate::{addresses::StubAddresses, ssn::SYSCALL_NUMBER, threads::{resume_all_threads, suspend_all_threads}};
// init
unsafe extern "system" fn init_hooks(_: *mut c_void) -> u32{
    let suspended_handels = suspend_all_threads();
    
    let stub_addresses = StubAddresses::new();

    patch(&stub_addresses);

    resume_all_threads(suspended_handels);
    return STATUS_SUCCESS.0 as _;
}


#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    _hinstance: HINSTANCE,
    reason: u32,
    _reserved: *mut c_void,
) -> i32 {
    match reason {
        DLL_PROCESS_ATTACH => {
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
        _ => {}
    }
    1
}

#[unsafe(no_mangle)]
fn patch(addresses: &StubAddresses) {
    SYSCALL_NUMBER.get("ZwOpenProcess").unwrap();

    for (_, item) in &addresses.addresses {
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
            panic!("[-] Failed to change protection. {}", unsafe {
                GetLastError().0
            }) // todo should not panic
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
            panic!("[-] Failed to change protection. {}", unsafe {
                GetLastError().0
            }) // todo should not panic
        }
    }
}