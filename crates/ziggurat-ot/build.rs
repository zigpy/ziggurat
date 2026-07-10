fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    // Explicit triggers: the default "any package file changed" would re-run on
    // the include/ziggurat.h write below, rebuilding forever.
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/platform.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");

    cbindgen::generate(&crate_dir)
        .unwrap()
        .write_to_file(format!("{crate_dir}/include/ziggurat.h"));
}
