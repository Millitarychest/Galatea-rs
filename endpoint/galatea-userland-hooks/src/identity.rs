use std::{ffi::c_void, sync::OnceLock};

use windows::Win32::{Foundation::{FILETIME, HANDLE}, System::Threading::{GetCurrentProcess, GetCurrentProcessId, GetProcessTimes}};

const PROCESS_IMAGE_FILE_NAME: u32 = 27;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
static CURRENT_GA_PID: OnceLock<galatea_shared::id::GA_PID> = OnceLock::new();

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

unsafe extern "system" {
    fn NtQueryInformationProcess(
        process_handle: HANDLE,
        process_information_class: u32,
        process_information: *mut c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

/// Returns the immutable Galatea identity of the process hosting this DLL.
pub(crate) fn current_ga_pid() -> Option<galatea_shared::id::GA_PID> {
    if let Some(ga_pid) = CURRENT_GA_PID.get() {
        return Some(*ga_pid);
    }

    let process = unsafe { GetCurrentProcess() };
    let mut creation_time = FILETIME::default();
    let mut exit_time = FILETIME::default();
    let mut kernel_time = FILETIME::default();
    let mut user_time = FILETIME::default();

    unsafe {
        GetProcessTimes(
            process,
            &mut creation_time,
            &mut exit_time,
            &mut kernel_time,
            &mut user_time,
        )
        .ok()?;
    }

    // FILETIME is the same 100-nanosecond, 1601-epoch value returned by
    // PsGetProcessCreateTimeQuadPart in the kernel callback.
    let creation_ticks =
        (u64::from(creation_time.dwHighDateTime) << 32) | u64::from(creation_time.dwLowDateTime);

    let mut required_length = 0u32;
    let sizing_status = unsafe {
        NtQueryInformationProcess(
            process,
            PROCESS_IMAGE_FILE_NAME,
            core::ptr::null_mut(),
            0,
            &mut required_length,
        )
    };
    if sizing_status != STATUS_INFO_LENGTH_MISMATCH
        || required_length < size_of::<UnicodeString>() as u32
    {
        return None;
    }

    // usize storage gives the returned UNICODE_STRING header its required alignment.
    let mut query_buffer = vec![0usize; (required_length as usize).div_ceil(size_of::<usize>())];
    let status = unsafe {
        NtQueryInformationProcess(
            process,
            PROCESS_IMAGE_FILE_NAME,
            query_buffer.as_mut_ptr().cast(),
            required_length,
            &mut required_length,
        )
    };
    if status != 0 {
        return None;
    }

    // SAFETY: NtQueryInformationProcess succeeded and wrote a UNICODE_STRING to the aligned
    // query buffer. Its buffer remains valid for the lifetime of query_buffer.
    let image = unsafe { &*query_buffer.as_ptr().cast::<UnicodeString>() };
    if image.buffer.is_null() || image.length > image.maximum_length {
        return None;
    }

    // Match the kernel by hashing the native UTF-16 image-path bytes without a terminator.
    let image_bytes =
        unsafe { core::slice::from_raw_parts(image.buffer.cast::<u8>(), image.length as usize) };
    let ga_pid = galatea_shared::id::generate_process_id(
        unsafe { GetCurrentProcessId() } as u64,
        image_bytes,
        creation_ticks,
    );

    let _ = CURRENT_GA_PID.set(ga_pid);
    CURRENT_GA_PID.get().copied()
}