use std::collections::BTreeMap;

use windows::{
    Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress},
    core::s,
};

use crate::{
    error::HookError,
    stubs::{nt_open_process, virtual_alloc_ex},
};

pub struct StubAddresses<'a> {
    pub addresses: BTreeMap<&'a str, Addresses>,
}

pub struct Addresses {
    pub edr: usize,
    pub ntdll: usize,
}

impl<'a> StubAddresses<'a> {
    pub fn new() -> Result<Self, HookError> {
        let h_ntdll = unsafe { GetModuleHandleA(s!("Ntdll.dll")) }
            .map_err(|_| HookError::NtdllNotFound)?;

        // ZwOpenProcess
        let zwop = unsafe { GetProcAddress(h_ntdll, s!("ZwOpenProcess")) }
            .ok_or(HookError::FunctionNotFound("ZwOpenProcess"))? as *const () as usize;

        // ZwAllocateVirtualMemory
        let zwavm = unsafe { GetProcAddress(h_ntdll, s!("ZwAllocateVirtualMemory")) }
            .ok_or(HookError::FunctionNotFound("ZwAllocateVirtualMemory"))? as *const () as usize;

        let mut hm: BTreeMap<&str, Addresses> = BTreeMap::new();
        hm.insert(
            "NtOpenProcess",
            Addresses {
                edr: nt_open_process as *const () as usize,
                ntdll: zwop,
            },
        );
        hm.insert(
            "NtAllocateVirtualMemory",
            Addresses {
                edr: virtual_alloc_ex as *const () as usize,
                ntdll: zwavm,
            },
        );

        Ok(Self { addresses: hm })
    }
}
