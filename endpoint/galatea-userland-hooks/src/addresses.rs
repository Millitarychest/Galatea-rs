use std::collections::BTreeMap;

use windows::{
    Win32::{
        System::LibraryLoader::{GetModuleHandleA, GetProcAddress},
        UI::WindowsAndMessaging::{MB_OK, MessageBoxA},
    },
    core::s,
};

use crate::stubs::{nt_open_process, virtual_alloc_ex};

pub struct StubAddresses<'a> {
    pub addresses: BTreeMap<&'a str, Addresses>,
}
pub struct Addresses {
    pub edr: usize,
    pub ntdll: usize,
}

impl<'a> StubAddresses<'a> {
    pub fn new() -> Self {
        let h_ntdll = unsafe { GetModuleHandleA(s!("Ntdll.dll")) };
        let h_ntdll = match h_ntdll {
            Ok(h) => h,
            Err(_) => todo!(),
        };

        // ZwOpenProcess
        let zwop = unsafe { GetProcAddress(h_ntdll, s!("ZwOpenProcess")) };
        let zwop = match zwop {
            None => {
                unsafe {
                    MessageBoxA(
                        None,
                        s!("Could not get fn addr"),
                        s!("Could not get fn addr"),
                        MB_OK,
                    )
                };
                panic!("Oh no :("); // todo dont panic a process?
            }
            Some(address) => address as *const (),
        } as usize;

        // ZwAllocateVirtualMemory
        let zwavm = unsafe { GetProcAddress(h_ntdll, s!("ZwAllocateVirtualMemory")) };
        let zwavm = match zwavm {
            None => {
                unsafe {
                    MessageBoxA(
                        None,
                        s!("Could not get fn addr"),
                        s!("Could not get fn addr"),
                        MB_OK,
                    )
                };
                panic!("Oh no :("); // todo dont panic a process?
            }
            Some(address) => address as *const (),
        } as usize;

        let mut hm: BTreeMap<&str, Addresses> = BTreeMap::new();
        hm.insert(
            "NtOpenProcess",
            Addresses {
                edr: nt_open_process as usize,
                ntdll: zwop,
            },
        );
        hm.insert(
            "NtAllocateVirtualMemory",
            Addresses {
                edr: virtual_alloc_ex as usize,
                ntdll: zwavm,
            },
        );

        Self { addresses: hm }
    }
}
