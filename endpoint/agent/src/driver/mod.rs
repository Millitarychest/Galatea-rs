use windows::Win32::Foundation::HANDLE;

pub mod mgmt;
pub mod io;

#[derive(Debug, Clone, Copy)]
pub struct DriverHandle(pub HANDLE);

unsafe impl Send for DriverHandle {}
unsafe impl Sync for DriverHandle {}