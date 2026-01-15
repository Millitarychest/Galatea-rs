use std::ffi::c_void;

use mimic_core::{mimic_error, mimic_success};
use shared::{GalateaVerdict, IOCTL_SEND_VERDICT};
use windows::Win32::{Foundation::HANDLE, System::IO::DeviceIoControl};

pub fn send_verdict(handle: HANDLE, mut verdict: GalateaVerdict){
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