use wdk_sys::{DEVICE_OBJECT, DRIVER_OBJECT, GUID, NTSTATUS, PCUNICODE_STRING, UNICODE_STRING};

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
