use std::sync::Mutex;
use goblin::pe::PE;
use ndarray::Array2;
use ort::{session::{Session, builder::{GraphOptimizationLevel, SessionBuilder}}, value::Value};
use mimic_core::{error, mimic_error};

use crate::utils::math::calculate_entropy;


pub struct MlEngine {
    session: Mutex<Session>,
}

impl MlEngine {
    pub fn new(model_path: &str) -> error::Result<Self> {
        ort::init().with_name("GalateaCortex").commit();

        let session = SessionBuilder::new()
            .map_err(|e| e.to_string())?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(|e| e.to_string())?
            .with_intra_threads(1)
            .map_err(|e| e.to_string())?
            .commit_from_file(model_path)
            .map_err(|e| format!("Failed to load model from {}: {}", model_path, e))?;

        Ok(Self { session: Mutex::new(session) })
    }

    pub fn predict(&self, features: &Vec<f32>) -> f32 {
        let input_array = Array2::from_shape_vec((1, features.len()), features.clone())
            .unwrap_or_else(|_| Array2::zeros((1, features.len())));

        let input_tensor = match Value::from_array(input_array) {
            Ok(t) => t,
            Err(e) => {
                mimic_error!("Failed to create input tensor: {}", e);
                return 0.0;
            }
        };

        let mut session = match self.session.lock() {
            Ok(s) => s,
            Err(e) => {
                mimic_error!("Failed to acquire ML lock: {}", e);
                return 0.0;
            }
        };

        let outputs = match session.run(ort::inputs!["float_input" => input_tensor]) {
            Ok(o) => o,
            Err(e) => {
                mimic_error!("ML Inference Failed: {}", e);
                return 0.0;
            }
        };

        if let Some(output_val) = outputs.get("probabilities").or(outputs.get("output_probability")) {
            if let Ok((_shape, data)) = output_val.try_extract_tensor::<f32>() {
                if data.len() >= 2 {
                    return data[1];
                }
            }
        }

        if let Some(output_val) = outputs.get("label") {
             if let Ok((_, data)) = output_val.try_extract_tensor::<i64>() {
                 if let Some(lbl) = data.first() {
                     return *lbl as f32; 
                 }
             }
        }

        0.0
    }
}


pub fn extract_ml_features(pe: &PE, buffer: &[u8]) -> Vec<f32> {
    let mut features = Vec::with_capacity(27);
    let opt = pe.header.optional_header;

    features.push(pe.header.coff_header.machine as f32);
    features.push(pe.header.coff_header.size_of_optional_header as f32);
    features.push(pe.header.coff_header.characteristics as f32);

    if let Some(o) = opt {
        features.push(o.standard_fields.major_linker_version as f32); // 4
        features.push(o.standard_fields.minor_linker_version as f32); // 5
        features.push(o.standard_fields.size_of_code as f32);        // 6
        features.push(o.standard_fields.size_of_initialized_data as f32); // 7
        features.push(o.standard_fields.size_of_uninitialized_data as f32); // 8
        features.push(o.standard_fields.address_of_entry_point as f32); // 9
        features.push(o.standard_fields.base_of_code as f32);        // 10
        features.push(o.windows_fields.image_base as f32);           // 11
        features.push(o.windows_fields.section_alignment as f32);    // 12
        features.push(o.windows_fields.file_alignment as f32);       // 13
        features.push(o.windows_fields.major_operating_system_version as f32); // 14
        features.push(o.windows_fields.minor_operating_system_version as f32); // 15
        features.push(o.windows_fields.size_of_image as f32);        // 16
        features.push(o.windows_fields.size_of_headers as f32);      // 17
        features.push(o.windows_fields.check_sum as f32);            // 18
        features.push(o.windows_fields.subsystem as f32);            // 19
        features.push(o.windows_fields.dll_characteristics as f32);  // 20
    } else {
        // Fill zeros if optional header is missing (rare for valid PE)
        for _ in 0..17 { features.push(0.0); }
    }

    let mut entropies = Vec::new();
    for section in &pe.sections {
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        if start + size <= buffer.len() {
            let data = &buffer[start..start+size];
            entropies.push(calculate_entropy(data));
        } else {
            entropies.push(0.0);
        }
    }

    let mean_ent = if !entropies.is_empty() { entropies.iter().sum::<f64>() / entropies.len() as f64 } else { 0.0 };
    let min_ent = entropies.iter().fold(f64::INFINITY, |a, &b| a.min(b));
    let max_ent = entropies.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
    let min_ent = if min_ent == f64::INFINITY { 0.0 } else { min_ent };
    let max_ent = if max_ent == f64::NEG_INFINITY { 0.0 } else { max_ent };

    features.push(pe.sections.len() as f32);
    // 22. SectionsMeanEntropy
    features.push(mean_ent as f32);
    // 23. SectionsMinEntropy
    features.push(min_ent as f32);
    // 24. SectionsMaxEntropy
    features.push(max_ent as f32);

    features.push(pe.libraries.len() as f32); // 25. ImportsNbDLL
    features.push(pe.imports.len() as f32);   // 26. ImportsNb
    features.push(pe.exports.len() as f32);   // 27. ExportNb

    features
}