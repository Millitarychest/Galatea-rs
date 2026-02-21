use wdk_sys::{GUID, PCUNICODE_STRING,UNICODE_STRING,DRIVER_OBJECT,DEVICE_OBJECT,NTSTATUS};

#[link(name = "wdmsec", kind = "static")]
unsafe extern "C" {
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