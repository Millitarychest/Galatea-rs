use std::{fs::File, io};
use md5::{Digest, Md5};
use mimic_core::error;


pub fn calc_md5(file_path: &str) -> error::Result<String>{
    let mut file = File::open(file_path)?;
    let mut hasher = Md5::new();
    let _ = io::copy(&mut file, &mut hasher)?;
    let result = hasher.finalize();
    Ok(hex::encode(result))
}