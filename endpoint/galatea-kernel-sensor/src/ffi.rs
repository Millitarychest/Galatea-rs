use wdk_sys::{
    DEVICE_OBJECT, DRIVER_OBJECT, GUID, NTSTATUS, PCUNICODE_STRING, PEPROCESS, PUNICODE_STRING,
    UNICODE_STRING,
};

/// FFI binding to `ntoskrnl` for the process image name lookup, which `wdk-sys` does not
/// cover. The symbol resolves against `ntoskrnl.lib`, which `wdk-build` already links.
unsafe extern "system" {
    /// Retrieves the image path of a process from its process object.
    ///
    /// On success, `*pImageFileName` receives a `UNICODE_STRING` allocated from paged
    /// pool whose `Buffer` is also paged-pool allocated. The caller must free both
    /// with `ExFreePool` once done.
    pub fn SeLocateProcessImageName(
        Process: PEPROCESS,
        pImageFileName: *mut PUNICODE_STRING,
    ) -> NTSTATUS;
}


/// FFI bindings to `wdmsec.lib` for secure device creation.
#[link(name = "wdmsec", kind = "static")]
unsafe extern "C" {
    /// Creates a named device object with an explicit SDDL security descriptor,
    /// as an alternative to `IoCreateDevice` + a separate security call.
    pub fn WdmlibIoCreateDeviceSecure(
        DriverObject: *mut DRIVER_OBJECT,
        DeviceExtensionSize: u32,
        DeviceName: *mut UNICODE_STRING,
        DeviceType: u32,
        DeviceCharacteristics: u32,
        Exclusive: u8,
        DefaultSDDLString: PCUNICODE_STRING,
        DeviceClassGuid: *const GUID,
        DeviceObject: *mut *mut DEVICE_OBJECT,
    ) -> NTSTATUS;
}
