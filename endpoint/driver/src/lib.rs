#![no_std]

use core::panic::PanicInfo;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
pub extern "system" fn driver_entry(driver_object: *mut u8, registry_path: *mut u8) -> u32 {
    0 /* STATUS_SUCCESS */
}

fn main() {}
