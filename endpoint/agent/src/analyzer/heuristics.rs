use std::fs;

use goblin::pe::PE;
use md5::{Digest, Md5};

use crate::{HEUR_ENTROPY_SCORE, HEUR_ENTROPY_THRESHOLD, HEUR_HIDDEN_IMP_SCORE, HEUR_KNOWN_PACKER_SCORE, HEUR_RWX_SEC_SCORE, analyzer::PackerSignatureEngine};


#[derive(Debug,Clone)]
pub struct HeurReport {
    pub is_packed: bool,
    pub packer: Option<String>,
    pub has_rwx: bool,
    pub high_entropy: bool,
    pub imphash: String,
    pub score_mod: i32
}

impl HeurReport {
    pub fn new()-> Self{
        Self { is_packed: false, 
            packer: None, 
            has_rwx: false, 
            high_entropy: false, 
            imphash: String::new(), 
            score_mod: 0 
        }
    }
}

pub fn analyze_pe(path: &str, sig_engine: &PackerSignatureEngine) -> Option<HeurReport>{
    let buffer = match fs::read(path){
        Ok(b) => b,
        Err(_) => return None,
    };

    let pe = match PE::parse(&buffer) {
        Ok(p) => p,
        Err(_) => return None,
    };

    let mut report = HeurReport::new();

    let mut added_ent = false;
    let mut added_rwx = false;
    for section in &pe.sections {

        if let Some(packer_name) = sig_engine.scan(&pe, &buffer) {
            report.packer = Some(packer_name);
            report.is_packed = true;
        }

        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let end = start + size;

        if start < buffer.len() && end <= buffer.len() {
            let section_data = &buffer[start..end];
            let entropy = calculate_entropy(section_data);
        
            if entropy > HEUR_ENTROPY_THRESHOLD {
                report.high_entropy = true;

                if !added_ent {
                    if report.is_packed {
                        report.score_mod += HEUR_KNOWN_PACKER_SCORE;
                    }
                    report.score_mod += HEUR_ENTROPY_SCORE;
                    added_ent = true;
                }
            }
        }

        let characteristics = section.characteristics;
        if (characteristics & 0xE0000000) == 0xE0000000 {
            report.has_rwx = true;
            if !added_rwx && added_rwx {
                added_rwx = true;
                report.score_mod += HEUR_RWX_SEC_SCORE;
            }
        }

    }

    let mut import_list = Vec::new();
    
    for import in &pe.imports {
        let raw_dll = import.dll.to_lowercase();

        let dll_name = if raw_dll.ends_with(".dll") || raw_dll.ends_with(".sys") || raw_dll.ends_with(".ocx") {
             raw_dll.rsplitn(2, '.').last().unwrap_or(&raw_dll)
        } else {
             &raw_dll
        };

        let func_part = if !import.name.is_empty() {
            import.name.to_lowercase()
        } else {
            format!("ord{}", import.ordinal)
        };

        import_list.push(format!("{}.{}", dll_name, func_part));
    }
    
    if !import_list.is_empty() {
        if import_list.len() < 3 {
            if report.is_packed{
                let chg = HEUR_HIDDEN_IMP_SCORE - 10;
                report.score_mod += chg;
            }
            else {
                report.score_mod += HEUR_HIDDEN_IMP_SCORE;
            }
        }
        let joined_imports = import_list.join(",");
        let mut hasher = Md5::new();
        hasher.update(joined_imports.as_bytes());
        let result = hasher.finalize();
        report.imphash = hex::encode(result);
    } else {
        if report.is_packed{
            let chg = HEUR_HIDDEN_IMP_SCORE - 10;
            report.score_mod += chg;
        }
        else {
            report.score_mod += HEUR_HIDDEN_IMP_SCORE;
        }
    }

    Some(report)
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequency = [0usize; 256];
    for &byte in data {
        frequency[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &frequency {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}