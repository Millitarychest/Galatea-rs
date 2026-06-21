use windows::Win32::Foundation::HANDLE;

pub mod ipc_server;

/// Wrapper to make HANDLE Send-safe for thread communication
#[derive(Debug, Clone, Copy)]
pub struct SendHandle(HANDLE);
unsafe impl Send for SendHandle {}

impl From<HANDLE> for SendHandle {
    fn from(h: HANDLE) -> Self {
        SendHandle(h)
    }
}

impl From<SendHandle> for HANDLE {
    fn from(sh: SendHandle) -> Self {
        sh.0
    }
}
