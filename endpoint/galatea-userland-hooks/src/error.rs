/// Errors that can occur during userland hook initialization and patching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookError {
    /// Failed to obtain module handle to Ntdll.dll.
    NtdllNotFound,
    /// Failed to locate an expected exported function in Ntdll.dll.
    FunctionNotFound(&'static str),
    /// Failed to create a snapshot of process threads.
    ThreadSnapshotFailed,
    /// Failed to change memory protection flags on the hook target.
    VirtualProtectFailed(u32),
}

impl HookError {
    /// Numerical code used for ETW telemetry reporting.
    pub fn error_code(&self) -> u32 {
        match self {
            Self::NtdllNotFound => 1,
            Self::FunctionNotFound(_) => 2,
            Self::ThreadSnapshotFailed => 3,
            Self::VirtualProtectFailed(code) => 0x8000_0000 | (code & 0xFFFF),
        }
    }
}
