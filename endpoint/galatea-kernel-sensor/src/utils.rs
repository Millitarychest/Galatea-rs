use wdk_sys::{LARGE_INTEGER, PCUNICODE_STRING, PEPROCESS, PUNICODE_STRING};

/// Converts an ASCII string literal into a `&[u16]` wide-string slice at compile time.
///
/// Equivalent to the C `L"..."` wide-string prefix. Only ASCII characters are supported.
#[macro_export]
macro_rules! w {
    ($s:expr) => {{
        const S: &[u16] = &{
            let bs = $s.as_bytes();
            let mut out = [0u16; $s.len()];
            let mut i = 0;
            while i < $s.len() {
                out[i] = bs[i] as u16;
                i += 1;
            }
            out
        };
        S
    }};
}

/// Returns the current kernel system time as a 100-nanosecond tick count.
pub unsafe fn get_kernel_time() -> u64 {
    // SAFETY: KeQuerySystemTimePrecise writes into the caller-provided LARGE_INTEGER.
    // The pointer is valid for the duration of the call.
    let mut time = LARGE_INTEGER { QuadPart: 0 };
    wdk_sys::ntddk::KeQuerySystemTimePrecise(&mut time);
    time.QuadPart as u64
}

//TODO: not very secure.
/// PoC implementation of excluding system binaries from static scans.
///
/// Returns `true` if the image path begins with a known Windows system directory prefix,
/// indicating the process should bypass the APC freeze flow.
pub unsafe fn is_allowlisted_static(image_name: PCUNICODE_STRING) -> bool {
    if image_name.is_null() {
        return false;
    }

    // SAFETY: image_name is a non-null PCUNICODE_STRING. We trust the kernel to provide a
    // valid buffer and length. The slice lifetime is bounded to this stack frame.
    let len = ((*image_name).Length / 2) as usize;
    let slice = core::slice::from_raw_parts((*image_name).Buffer, len);

    let sys32_c = w!("\\??\\C:\\Windows\\System32\\");
    let syswow_c = w!("\\??\\C:\\Windows\\SysWOW64\\");
    let sys32_root = w!("\\SystemRoot\\System32\\");
    let syswow_root = w!("\\SystemRoot\\SysWOW64\\");

    // Inner helpers inlined: uppercase-compare a u16 char, then zip-check prefix match.
    starts_with_ignore_case(slice, sys32_c)
        || starts_with_ignore_case(slice, syswow_c)
        || starts_with_ignore_case(slice, sys32_root)
        || starts_with_ignore_case(slice, syswow_root)
}

fn starts_with_ignore_case(haystack: &[u16], needle: &[u16]) -> bool {
    if haystack.len() < needle.len() {
        return false;
    }
    haystack
        .iter()
        .zip(needle.iter())
        .all(|(h, n)| to_upper(*h) == to_upper(*n))
}

fn to_upper(c: u16) -> u16 {
    if c >= b'a' as u16 && c <= b'z' as u16 {
        c - 32
    } else {
        c
    }
}

/// Retrieves the image path of a process whose process object is still alive.
///
/// Used by the process-exit notification, where the create info (and its
/// `ImageFileName`) is gone but the `PEPROCESS` is still referenced. Returns the
/// same UTF-16 NT device path the create callback hashed, so the identity
/// generated on exit matches the one generated on creation.
///
/// The returned image name is allocated from paged pool and must be released with
/// [`release_process_image_name`]. Returns null when the lookup fails; callers
/// should then fall back to hashing without an image path.
pub unsafe fn locate_process_image_name(process: PEPROCESS) -> PUNICODE_STRING {
    let mut image: PUNICODE_STRING = core::ptr::null_mut();

    // SAFETY: process is a valid, referenced PEPROCESS for the duration of the call
    // and image points to a valid stack location. Called at PASSIVE_LEVEL, which
    // SeLocateProcessImageName requires (paged-pool allocation).
    let status = crate::ffi::SeLocateProcessImageName(process, &mut image);
    if status < 0 || image.is_null() {
        return core::ptr::null_mut();
    }
    image
}

/// Frees an image name returned by [`locate_process_image_name`].
pub unsafe fn release_process_image_name(image: PUNICODE_STRING) {
    if image.is_null() {
        return;
    }

    // SAFETY: the UNICODE_STRING and its Buffer were allocated from paged pool by
    // SeLocateProcessImageName and are not accessed after this call.
    if !(*image).Buffer.is_null() {
        wdk_sys::ntddk::ExFreePool((*image).Buffer.cast());
    }
    wdk_sys::ntddk::ExFreePool(image.cast());
}

