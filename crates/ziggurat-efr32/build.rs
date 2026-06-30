use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Make memory.x available to cortex-m-rt's link.x.
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(out.join("memory.x"), include_bytes!("memory.x")).unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
}
