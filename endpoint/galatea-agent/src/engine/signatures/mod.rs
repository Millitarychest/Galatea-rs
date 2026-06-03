pub mod file_signatures;
pub mod process_signatures;

// standardize oublic api for signature handling
pub trait ThreatSiganture {
    fn get_tid();
    fn get_common_name();
    fn get_description();

    fn eval_on_context(); // check against matching context type: FileContext for File sigantures and ProcessContext for Process signatures
}
