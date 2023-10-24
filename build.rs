use chrono::{DateTime, Local};
use std::time::SystemTime;

fn main() {
    println!(
        "cargo:rustc-env=MY_VERSION_INFO={}-{}",
        env!("CARGO_PKG_VERSION"),
        DateTime::<Local>::from(SystemTime::now()).format("%Y/%m/%d-%H:%M:%S:%Z")
    );
}
