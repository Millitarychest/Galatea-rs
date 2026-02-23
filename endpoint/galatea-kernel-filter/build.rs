fn main() -> Result<(), wdk_build::ConfigError> {
    // fltMgr.lib provides Filter Manager exports (FltRegisterFilter, etc.)
    // that are not linked by the default WDK WDM build configuration.
    println!("cargo:rustc-link-lib=fltMgr");
    wdk_build::configure_wdk_binary_build()
}
