use wdk_sys::{LARGE_INTEGER, PCUNICODE_STRING};

// --- Helper Macro for Wide Strings (L"notepad.exe") ---
#[macro_export]
macro_rules! w {
    ($s:expr) => {
        {
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
        }
    };
}

pub unsafe fn get_kernel_time() -> u64 {
    unsafe {
        let mut time = LARGE_INTEGER { QuadPart: 0 };
        wdk_sys::ntddk::KeQuerySystemTimePrecise(&mut time);
        time.QuadPart as u64
    }
}


//TODO: not very secure. 
/// POC implementation of excluding system bin from static scans 
pub unsafe fn is_allowlisted_static(image_name: PCUNICODE_STRING) -> bool{
    if image_name.is_null(){
        return false;
    }

    unsafe {
        let len = ((*image_name).Length / 2) as usize;
        let slice = core::slice::from_raw_parts((*image_name).Buffer, len);

        let sys32_c = w!("\\??\\C:\\Windows\\System32\\");
        let syswow_c = w!("\\??\\C:\\Windows\\SysWOW64\\");
        let sys32_root = w!("\\SystemRoot\\System32\\");
        let syswow_root = w!("\\SystemRoot\\SysWOW64\\");

        fn to_upper(c: u16) -> u16 {
            if c >= b'a' as u16 && c <= b'z' as u16 {
                c - 32
            } else {
                c
            }
        }

        fn starts_with_ignore_case(haystack: &[u16], needle: &[u16]) -> bool {
            if haystack.len() < needle.len() {
                return false;
            }

            haystack.iter()
                .zip(needle.iter())
                .all(|(h, n)| to_upper(*h) == to_upper(*n))
        }

        starts_with_ignore_case(slice, sys32_c) || starts_with_ignore_case(slice, syswow_c) || starts_with_ignore_case(slice, sys32_root) || starts_with_ignore_case(slice, syswow_root)
    }

}