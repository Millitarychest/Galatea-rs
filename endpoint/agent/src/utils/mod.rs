use std::{env, path::PathBuf};

pub mod math;
pub mod hashing;

pub fn exe_directory() -> PathBuf {
    exe_directory_try().unwrap_or_else(|_| {
        env::current_dir().unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")))
    })
}

pub fn exe_directory_try() -> Result<PathBuf, String> {
    let current_exe = env::current_exe().map_err(|e| format!("Failed to locate current executable: {e}"))?;
    let parent = current_exe
        .parent()
        .ok_or_else(|| format!("Executable has no parent directory: {}", current_exe.display()))?;
    Ok(parent.to_path_buf())
}
