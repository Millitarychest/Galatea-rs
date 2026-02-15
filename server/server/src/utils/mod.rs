pub mod fmt;

use rand::{RngExt, rng};

pub fn generate_passphrase(len: usize) -> String {
    if len == 0 {
        return String::new();
    }

    let words = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/static/orchard-street-medium.txt"
    ));
    let list: Vec<&str> = words.lines().filter(|line| !line.is_empty()).collect();
    if list.is_empty() {
        return String::new();
    }

    let mut rng = rng();
    let mut passphrase = String::new();
    for i in 0..len {
        if i > 0 {
            passphrase.push('-');
        }
        let index = rng.random_range(0..list.len());
        passphrase.push_str(list[index]);
    }

    passphrase
}
