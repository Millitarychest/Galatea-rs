///! Module describes helper functions for communicating with Kernel mode, 
///! mainly targeting the Galatea FS filter and Kernel Sensor
///! public interfaces should be prefixed with "kf_" for kernel filter or
///! public interfaces should be prefixed with "ks_" for kernel sensor

use std::ffi::c_void;

use mimic_core::{mimic_error, mimic_success};
use galatea_shared::{GalateaVerdict, IOCTL_REGISTER_AGENT, IOCTL_SEND_VERDICT};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        Storage::InstallableFileSystems::{FilterConnectCommunicationPort, FilterSendMessage},
        System::IO::DeviceIoControl,
    },
    core::w,
};

const GALATEA_FILTER_PORT_NAME: windows::core::PCWSTR = w!("\\GalateaFilterPort");
const GALATEA_FILTER_POC_MESSAGE: &[u8] = b"galatea-filter-poc";

pub fn ks_send_verdict(handle: HANDLE, mut verdict: GalateaVerdict){
    let mut bytes_verdict: u32 = 0;
    let verdict_result = unsafe {
        DeviceIoControl(
            handle, 
            IOCTL_SEND_VERDICT, 
            Some(&mut verdict as *mut _ as *mut c_void), 
            size_of::<GalateaVerdict>() as u32, 
            None, 
            0, 
            Some(&mut bytes_verdict), 
            None
        )
    };

    match verdict_result {
        Ok(_) => mimic_success!(" -> Verdict sent: {:?}", verdict.allow),
        Err(e) => mimic_error!(" -> Failed to submit Verdict: {:?}", e),
    }
}

pub fn ks_register_agent(handle: HANDLE) -> Result<(), String>{
    let mut bytes_returned: u32 = 0;
    let result = unsafe {
        DeviceIoControl(
            handle, 
            IOCTL_REGISTER_AGENT, 
            None, 
            0, 
            None, 
            0, 
            Some(&mut bytes_returned), 
            None
        )
    };
    
    match result {
        Ok(_) => {
            mimic_success!("Agent Registered with Kernel Driver.");
            Ok(())
        }
        Err(e) => {
            mimic_error!("Failed to Register Agent (Access Denied?): {:?}", e);
            Err(format!("{:?}", e))
        },
    }
}


pub fn kf_connect() -> Result<(), String> {
    let port_handle = unsafe {
        FilterConnectCommunicationPort(GALATEA_FILTER_PORT_NAME, 0, None, 0, None)
    };

    let port_handle = match port_handle {
        Ok(handle) => handle,
        Err(e) => {
            mimic_error!("Failed to connect to filter communication port: {:?}", e);
            return Err(format!("{e:?}"));
        }
    };

    let mut bytes_returned = 0;
    let send_result = unsafe {
        FilterSendMessage(
            port_handle,
            GALATEA_FILTER_POC_MESSAGE.as_ptr() as *const c_void,
            GALATEA_FILTER_POC_MESSAGE.len() as u32,
            None,
            0,
            &mut bytes_returned,
        )
    };

    let close_result = unsafe { CloseHandle(port_handle) };
    if let Err(e) = close_result {
        mimic_error!("Failed to close filter communication port handle: {:?}", e);
    }

    match send_result {
        Ok(_) => {
            mimic_success!("Filter port PoC message sent.");
            Ok(())
        }
        Err(e) => {
            mimic_error!("Failed to send PoC message to filter port: {:?}", e);
            Err(format!("{e:?}"))
        }
    }
}
