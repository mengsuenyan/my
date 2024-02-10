fn main() {
    if cfg!(target_arch = "x86")
        || cfg!(target_arch = "x86_64")
        || std::arch::is_x86_feature_detected!("aes")
    {
        println!("cargo:rustc-cfg=target_feature=\"aes\"");
    }
}
