use std::{collections::BTreeMap, mem, sync::LazyLock};

use windows::{
    Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress},
    core::{PCSTR, s},
};

/// Automated syscall number repository
pub static SYSCALL_NUMBER: LazyLock<BTreeMap<&'static str, u32>> = LazyLock::new(|| {
    let mut syscall_num_repo = BTreeMap::new();

    static NT_FUNC_NAMES: [&str; 5] = [
        "ZwOpenProcess\0",
        "ZwAllocateVirtualMemory\0",
        "NtWriteVirtualMemory\0",
        "NtProtectVirtualMemory\0",
        "NtCreateThreadEx\0",
    ];

    if let Ok(h_ntdll) = unsafe { GetModuleHandleA(s!("Ntdll.dll")) } {
        for name in NT_FUNC_NAMES {
            if let Some(ntfunc) = unsafe { GetProcAddress(h_ntdll, PCSTR::from_raw(name.as_ptr())) }
            {
                let funcaddr = unsafe { mem::transmute::<_, *const u8>(ntfunc) };

                #[cfg(target_arch = "x86_64")]
                {
                    if unsafe { (funcaddr as *const u32).read_unaligned() } == 0xb8d18b4c {
                        let num = (unsafe { (funcaddr as *const u64).read_unaligned() } >> 32)
                            as u32
                            & 0xfff;

                        // eliminate the last trailing '\0' to make a normal rust str
                        syscall_num_repo.insert(&name[0..name.len() - 1], num);
                    }
                }

                #[cfg(target_arch = "x86")]
                {
                    if unsafe { funcaddr.read_unaligned() } == 0xb8 {
                        let num = unsafe {
                            ((funcaddr as *const u64).add(1) as *const u32).read_unaligned()
                        } & 0xfff;

                        syscall_num_repo.insert(&name[0..name.len() - 1], num);
                    }
                }
            } else {
                println!("[-] Could not find function");
            }
        }
    }

    if syscall_num_repo.len() != NT_FUNC_NAMES.len() {
        println!(
            "[-] Could not resolve all required SSN's. {:?}",
            syscall_num_repo
        );
    }

    syscall_num_repo
});
