use wdk_sys::{LARGE_INTEGER, PCUNICODE_STRING};

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
