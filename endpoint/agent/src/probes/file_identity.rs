use std::path::Path;

#[cfg(windows)]
pub fn get_file_index(path: &str) -> Option<u64> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Foundation::GENERIC_READ;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, GetFileInformationByHandle,
        OPEN_EXISTING,
    };
    use windows::core::HSTRING;

    let p = Path::new(path);
    if !p.exists() {
        return None;
    }

    unsafe {
        let hstring = HSTRING::from(path);
        let handle = CreateFileW(
            &hstring,
            GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .ok()?;

        let mut info = std::mem::zeroed();
        let result = GetFileInformationByHandle(handle, &mut info);
        let _ = CloseHandle(handle);

        if result.is_ok() {
            let index = ((info.nFileIndexHigh as u64) << 32) | (info.nFileIndexLow as u64);
            Some(index)
        } else {
            None
        }
    }
}

#[cfg(unix)]
pub fn get_file_index(path: &str) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).ok()?;
    Some(meta.ino())
}
