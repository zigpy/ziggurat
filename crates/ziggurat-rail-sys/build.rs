use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// The Simplicity SDK 2026.6.0 conan package: source of the C glue, headers, and the
// precompiled RAIL library. Fetched once and cached. Bump both together on an SDK update;
// SDK_REV doubles as the cache key so a bump re-downloads.
const SDK_URL: &str = "https://conan.silabs.net/v2/conans/simplicity-sdk/2026.6.0/silabs/_/revisions/d82063f9e47c75ac02812efeee2ac4e2/packages/aba2da4388b60e756ce70b12d6c63f3c69e22ef9/revisions/48dca41e2c905fbd226c80e428b5da12/files/conan_package.tgz";
const SDK_REV: &str = "48dca41e2c905fbd226c80e428b5da12";

// Resolve the SDK root: an explicit pre-extracted tree (fast local dev — point at the
// extracted package or a ~/.silabs install), else the download cache.
fn sdk_root() -> PathBuf {
    if let Ok(tree) = env::var("ZIGGURAT_SDK_TREE") {
        return PathBuf::from(tree);
    }
    let cache = env::var("ZIGGURAT_SDK_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env::var("HOME").unwrap()).join(".cache/ziggurat-rail-sdk"));
    let sdk_dir = cache.join(SDK_REV);
    let marker = sdk_dir.join(".extracted");
    if !marker.exists() {
        fs::create_dir_all(&sdk_dir).unwrap();
        let tgz = cache.join(format!("{SDK_REV}.tgz"));
        if !tgz.exists() {
            let ok = Command::new("curl")
                .args(["-fSL", "--retry", "3", "-o"])
                .arg(&tgz)
                .arg(SDK_URL)
                .status()
                .unwrap()
                .success();
            assert!(ok, "failed to download Simplicity SDK from {SDK_URL}");
        }
        let ok = Command::new("tar")
            .arg("-xzf")
            .arg(&tgz)
            .arg("-C")
            .arg(&sdk_dir)
            .status()
            .unwrap()
            .success();
        assert!(ok, "failed to extract Simplicity SDK package");
        fs::write(&marker, SDK_URL).unwrap();
    }
    sdk_dir
}

// clang (with --target) doesn't know the arm-none-eabi newlib/gcc header locations the
// way gcc does, so ask gcc for its system include search paths and feed them to bindgen.
fn gcc_system_includes() -> Vec<String> {
    let out = Command::new("arm-none-eabi-gcc")
        .args(["-E", "-Wp,-v", "-xc", "/dev/null"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let mut args = Vec::new();
    let mut in_section = false;
    for line in stderr.lines() {
        if line.contains("#include <...> search starts here") {
            in_section = true;
        } else if line.contains("End of search list") {
            break;
        } else if in_section {
            // Canonicalize first: the newlib dir is reported with `..` segments that pass
            // literally through `lib/gcc`. After resolving, keep newlib's headers
            // (string.h, …) but skip GCC's own include dirs — their arm_acle.h/arm_mve.h
            // use GCC __builtin_arm_* intrinsics clang rejects; clang ships its own.
            let dir = fs::canonicalize(line.trim()).unwrap_or_else(|_| PathBuf::from(line.trim()));
            // The GCC-internal dirs canonicalize to `.../lib/gcc/...`; newlib's headers
            // (string.h, …) live at `.../arm-none-eabi/include` with no `lib/gcc` segment.
            if !dir.to_string_lossy().contains("/lib/gcc/") {
                args.push(format!("-isystem{}", dir.display()));
            }
        }
    }
    args
}

fn read_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

fn main() {
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let recipe = crate_dir.join("recipe");
    let vendor = crate_dir.join("vendor");
    let sdk = sdk_root();

    // Include dirs (SDK-relative + the vendored SLC config/autogen) and defines, shared
    // between the cc glue compile and bindgen. The `defines.txt` entry whose value was
    // quote-mangled in the manifest is dropped there and re-added correctly here.
    let mut include_dirs: Vec<PathBuf> = read_lines(&recipe.join("sdk_includes.txt"))
        .iter()
        .map(|i| sdk.join(i))
        .collect();
    include_dirs.push(vendor.join("config"));
    include_dirs.push(vendor.join("autogen"));

    let mut defines: Vec<(String, Option<String>)> = read_lines(&recipe.join("defines.txt"))
        .into_iter()
        .filter(|d| !d.ends_with('\\'))
        .map(|d| match d.split_once('=') {
            Some((k, v)) => (k.to_owned(), Some(v.to_owned())),
            None => (d, None),
        })
        .collect();
    defines.push((
        "CMSIS_NVIC_VIRTUAL_HEADER_FILE".into(),
        Some("\"cmsis_nvic_virtual.h\"".into()),
    ));

    let mut build = cc::Build::new();
    build.compiler("arm-none-eabi-gcc");
    build.warnings(false);

    // Exact compile flags from the generated project (LTO dropped — normal compile;
    // dead code is pruned by --gc-sections at the final binary link).
    for flag in [
        "-mcpu=cortex-m33",
        "-mthumb",
        "-mfpu=fpv5-sp-d16",
        "-mfloat-abi=hard",
        "-mcmse",
        "-Os",
        "-fdata-sections",
        "-ffunction-sections",
        "-fomit-frame-pointer",
        "-fno-strict-aliasing",
        "--specs=nano.specs",
        "-std=gnu11",
    ] {
        build.flag(flag);
    }
    for inc in &include_dirs {
        build.include(inc);
    }
    for (k, v) in &defines {
        build.define(k, v.as_deref());
    }
    // Glue translation units (platform_core + rail_library), relative to the SDK root.
    for src in read_lines(&recipe.join("sdk_sources.txt")) {
        build.file(sdk.join(src));
    }
    // Minimal RADIOAES management (replaces the SDK's PSA-heavy sli_radioaes_management.c).
    build.file(vendor.join("sli_radioaes_stub.c"));
    // Accessors exposing the board's compile-time RF config macros to Rust.
    build.file(vendor.join("ziggurat_board.c"));
    build.compile("ziggurat_rail_glue");

    // Generate Rust FFI for the public RAIL API. `-fshort-enums` matches the ARM EABI
    // (and the precompiled blob's) enum sizing — a mismatch here is silent ABI corruption.
    let mut clang_args: Vec<String> = vec![
        "--target=thumbv8m.main-none-eabihf".into(),
        "-fshort-enums".into(),
    ];
    clang_args.extend(gcc_system_includes());
    clang_args.extend(include_dirs.iter().map(|i| format!("-I{}", i.display())));
    clang_args.extend(defines.iter().map(|(k, v)| match v {
        Some(v) => format!("-D{k}={v}"),
        None => format!("-D{k}"),
    }));

    let bindings = bindgen::Builder::default()
        .header(crate_dir.join("wrapper.h").to_str().unwrap())
        .clang_args(&clang_args)
        .use_core()
        .ctypes_prefix("core::ffi")
        .allowlist_function("(sl_rail|RAIL)_.*")
        .allowlist_function("sl_clock_manager_.*")
        .allowlist_function("sli_(ccm|aes|protocol_crypto)_.*")
        .allowlist_function("ziggurat_.*")
        .allowlist_type("(sl_rail|RAIL|sli_rail)_.*")
        .allowlist_var("(SL_RAIL|RAIL)_.*")
        // The blob's built-in RX FIFO/packet-queue backing store (lowercase, so not
        // covered by the SL_RAIL_ var pattern above).
        .allowlist_var("sl_rail_builtin_.*")
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .generate()
        .expect("bindgen failed to generate RAIL FFI");
    bindings
        .write_to_file(PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs"))
        .unwrap();
    println!("cargo:rerun-if-changed=wrapper.h");

    // The one prebuilt library: the RAIL blob, taken from the SDK package.
    println!(
        "cargo:rustc-link-search=native={}",
        sdk.join("rail_library/autogen/librail_release").display()
    );
    println!("cargo:rustc-link-lib=static=rail_efr32xg24_gcc_release");

    println!("cargo:rerun-if-env-changed=ZIGGURAT_SDK_TREE");
    println!("cargo:rerun-if-env-changed=ZIGGURAT_SDK_CACHE");
    println!("cargo:rerun-if-changed=recipe");
    println!("cargo:rerun-if-changed=vendor");
}
