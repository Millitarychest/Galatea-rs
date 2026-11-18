use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use goblin::pe::PE;
use mimic_core::{error, mimic_log};

#[derive(Debug, Clone)]
pub struct PackSignature {
    pub name: String,
    pub pattern: Vec<Option<u8>>,
    pub ep_only: bool,
}

pub struct PackerSignatureEngine {
    signatures: Vec<PackSignature>,
}

impl PackerSignatureEngine {
    pub fn new() -> Self {
        Self {
            signatures: Vec::new(),
        }
    }

    /// Load signature base from file
    pub fn load(&mut self, path: &str) -> error::Result<()> {
        let file = File::open(path).map_err(|e| e.to_string())?;
        let reader = BufReader::new(file);

        let mut current_name = String::new();
        let mut current_pat = Vec::new();
        let mut current_ep_only = true;

        for line in reader.lines() {
            let line = line.map_err(|e| e.to_string())?;
            let text = line.trim();

            if text.is_empty() || text.starts_with(';') {
                continue;
            }

            if text.starts_with('[') && text.ends_with(']') {
                if !current_name.is_empty() && !current_pat.is_empty() {
                    self.signatures.push(PackSignature {
                        name: current_name.clone(),
                        pattern: current_pat.clone(),
                        ep_only: current_ep_only,
                    });
                }

                current_name = text[1..text.len() - 1].to_string();
                current_pat = Vec::new();
                current_ep_only = true;
                continue;
            }

            if let Some((key, value)) = text.split_once('=') {
                let key = key.trim().to_lowercase();
                let value = value.trim();

                match key.as_str() {
                    "signature" => {
                        current_pat = parse_pattern(value);
                    }
                    "ep_only" => {
                        current_ep_only = value.to_lowercase() == "true";
                    }
                    _ => {}
                }
            }
        }

        if !current_name.is_empty() && !current_pat.is_empty() {
            self.signatures.push(PackSignature {
                name: current_name,
                pattern: current_pat,
                ep_only: current_ep_only,
            });
        }

        mimic_log!("Loaded {} external signatures.", self.signatures.len());
        Ok(())
    }

    /// Check if the bin patterns of a file allign with a known packer
    pub fn scan(&self, pe: &PE, buffer: &[u8]) -> Option<String> {
        let ep_offset = match find_entry_point_offset(pe) {
            Some(o) => o,
            None => return None,
        };

        if ep_offset >= buffer.len() {
            return None;
        }

        let file_data = &buffer;
        let ep_data = &buffer[ep_offset..];

        for sig in &self.signatures {
            let target_slice = if sig.ep_only {
                if sig.pattern.len() > ep_data.len() {
                    continue;
                }
                ep_data
            } else {
                if sig.pattern.len() > file_data.len() {
                    continue;
                }
                file_data
            };

            if match_pattern(target_slice, &sig.pattern) {
                return Some(sig.name.clone());
            }
        }

        None
    }
}

fn parse_pattern(hex_str: &str) -> Vec<Option<u8>> {
    hex_str
        .split_whitespace()
        .map(|s| {
            if s == "??" {
                None
            } else {
                u8::from_str_radix(s, 16).ok()
            }
        })
        .collect()
}

fn match_pattern(data: &[u8], pattern: &[Option<u8>]) -> bool {
    if data.len() < pattern.len() {
        return false;
    }

    for (i, p_byte) in pattern.iter().enumerate() {
        match p_byte {
            Some(b) => {
                if data[i] != *b {
                    return false;
                }
            }
            None => continue,
        }
    }
    true
}

fn find_entry_point_offset(pe: &PE) -> Option<usize> {
    let entry_point_rva = pe.entry;

    for section in &pe.sections {
        let v_start = section.virtual_address as usize;
        let v_size = section.virtual_size as usize;

        if entry_point_rva as usize >= v_start && (entry_point_rva as usize) < v_start + v_size {
            let offset_in_section = (entry_point_rva as usize) - v_start;
            let raw_ptr = section.pointer_to_raw_data as usize;
            return Some(raw_ptr + offset_in_section);
        }
    }
    None
}
