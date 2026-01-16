#![no_std]

pub const IOCTL_GET_EVENT: u32 = 0x80002000;
pub const IOCTL_SEND_VERDICT: u32 = 0x80002004;
pub const IOCTL_REGISTER_AGENT: u32 = 0x80002008;

#[repr(C)]
pub struct GalateaEvent {
    pub process_id: u64,
    pub request_id: u64,
    pub frozen: bool,
    pub image_path: [u16; 260],
}

#[repr(C)]
pub struct GalateaVerdict {
    pub process_id: u64,
    pub request_id: u64,
    pub allow: bool,
}