use mimic_core::logger::{Level, LogTarget};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

pub struct FileLogger {
    file: Mutex<File>,
}

impl FileLogger {
    /// Create a new FileLogger that writes to the specified path
    pub fn new(log_path: PathBuf) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;

        Ok(FileLogger {
            file: Mutex::new(file),
        })
    }
}

impl LogTarget for FileLogger {
    fn log(&self, level: Level, args: &std::fmt::Arguments, _color: mimic_core::logger::Color) {
        let level_chunk = match level {
            Level::Error => "[!] ",
            Level::Info => "[+] ",
            Level::Warn => "[~]",
            Level::Debug => "[*]",
        };

        let log_line = format!("{}{}\n", level_chunk, args);

        if let Ok(mut file) = self.file.lock() {
            let _ = file.write_all(log_line.as_bytes());
            let _ = file.flush();
        }
    }

    fn error(&self, level: Level, args: &std::fmt::Arguments, color: mimic_core::logger::Color) {
        // For file logging, we treat errors the same as regular logs
        // (both go to the same file)
        self.log(level, args, color);
    }
}
