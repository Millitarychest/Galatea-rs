#![no_std]

pub const IOCTL_GET_EVENT: u32 = 0x80002000;
pub const IOCTL_SEND_VERDICT: u32 = 0x80002004;

#[repr(C)]
pub struct GalateaEvent {
    pub process_id: u64,
    pub image_path: [u16; 260], // MAX_PATH
}

#[repr(C)]
pub struct GalateaVerdict {
    pub process_id: u32,
    pub allow: bool,
}