use std::{env, path::PathBuf};

pub mod math;
pub mod hashing;

pub fn exe_directory() -> PathBuf {
    env::current_exe().unwrap().parent().unwrap().to_path_buf()
}