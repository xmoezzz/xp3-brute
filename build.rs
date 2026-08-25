fn main() {
    println!("cargo:rerun-if-changed=magic/krkr");
    #[cfg(feature = "python")]
    pyo3_build_config::add_extension_module_link_args();
}
