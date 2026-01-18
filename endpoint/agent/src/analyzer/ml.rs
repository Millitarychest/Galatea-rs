use std::sync::Mutex;
use ndarray::Array2;
use ort::{session::{Session, builder::{GraphOptimizationLevel, SessionBuilder}}, value::Value};
use mimic_core::{error, mimic_error};


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