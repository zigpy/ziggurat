use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

// The EFR32MG24 SVD lives inside the Silicon Labs CMSIS DFP pack (a zip). We fetch the
// pack once, extract the single SVD entry, and generate the PAC with svd2rust at build
// time — nothing derived is committed. Bump URL + REV together on an SVD update.
const PACK_URL: &str = "https://www.silabs.com/documents/public/cmsis-packs/SiliconLabs.GeckoPlatform_EFR32MG24_DFP.2025.12.1.pack";
const PACK_REV: &str = "2025.12.1";
const SVD_ENTRY: &str = "SVD/EFR32MG24/EFR32MG24A420F1536IM40.svd";

fn svd_xml() -> String {
    if let Ok(p) = env::var("ZIGGURAT_EFR32_SVD") {
        return fs::read_to_string(p).unwrap();
    }
    let cache = env::var("ZIGGURAT_EFR32_PAC_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env::var("HOME").unwrap()).join(".cache/ziggurat-efr32-pac")
        });
    let svd = cache.join(format!("{PACK_REV}.svd"));
    if !svd.exists() {
        fs::create_dir_all(&cache).unwrap();
        let pack = cache.join(format!("{PACK_REV}.pack"));
        if !pack.exists() {
            let ok = Command::new("curl")
                .args(["-fSL", "--retry", "3", "-o"])
                .arg(&pack)
                .arg(PACK_URL)
                .status()
                .unwrap()
                .success();
            assert!(ok, "failed to download DFP pack from {PACK_URL}");
        }
        // `unzip -p` streams the single SVD entry to stdout — no full extraction.
        let out = Command::new("unzip")
            .args(["-p"])
            .arg(&pack)
            .arg(SVD_ENTRY)
            .output()
            .unwrap();
        assert!(
            out.status.success() && !out.stdout.is_empty(),
            "failed to extract {SVD_ENTRY} from the DFP pack"
        );
        fs::write(&svd, &out.stdout).unwrap();
    }
    fs::read_to_string(&svd).unwrap()
}

// The public Gecko DFP SVD deliberately omits the radio peripheral interrupts (AGC, FRC,
// MODEM, PROTIMER, RAC_*, SYNTH, RFECA*, ...). Their NVIC vector slots (IRQ 30-39, 70-71)
// therefore come out `Reserved` in the generated vector table, so the RAIL blob's radio
// ISRs can never be wired in — a radio IRQ would vector to address 0 and hard fault.
// Inject the missing interrupts (real IRQ numbers from the EFR32MG24 CMSIS header) so
// svd2rust emits real vector slots + `PROVIDE(<name> = DefaultHandler)` weak aliases that
// a binary can override with the blob's `*_IRQHandler`.
fn inject_radio_interrupts(svd: String) -> String {
    // (name, IRQ number). HOSTMAILBOX (38) and SYSRTC_SEQ (68) are already in the SVD.
    const RADIO_IRQS: &[(&str, u32)] = &[
        ("AGC", 30),
        ("BUFC", 31),
        ("FRC_PRI", 32),
        ("FRC", 33),
        ("MODEM", 34),
        ("PROTIMER", 35),
        ("RAC_RSM", 36),
        ("RAC_SEQ", 37),
        ("SYNTH", 39),
        ("RFECA0", 70),
        ("RFECA1", 71),
    ];
    let mut xml = String::new();
    for (name, value) in RADIO_IRQS {
        xml.push_str(&format!(
            "<interrupt><name>{name}</name><description>Radio {name} (injected)</description><value>{value}</value></interrupt>"
        ));
    }
    // svd2rust aggregates <interrupt> elements across all peripherals into one vector
    // table indexed by value, so attaching them to the first peripheral is sufficient.
    let anchor = "</peripheral>";
    let pos = svd.find(anchor).expect("no <peripheral> in SVD");
    let mut out = String::with_capacity(svd.len() + xml.len());
    out.push_str(&svd[..pos]);
    out.push_str(&xml);
    out.push_str(&svd[pos..]);
    out
}

// svd2rust emits crate-level inner attributes (#![no_std], #![allow(...)], …) at the
// top. Those can't survive being `include!`d at the crate root, so strip the leading
// inner-attr run (string-literal-aware: the `doc` attr contains `]`); lib.rs re-declares
// the crate attributes itself.
fn strip_leading_inner_attrs(s: &str) -> &str {
    let b = s.as_bytes();
    let mut i = 0;
    loop {
        let mut j = i;
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if b.get(j) != Some(&b'#') {
            break;
        }
        j += 1;
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if b.get(j) != Some(&b'!') {
            break; // an outer attribute or a real item — done stripping
        }
        j += 1;
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if b.get(j) != Some(&b'[') {
            break;
        }
        let mut depth = 0;
        let mut in_str = false;
        while j < b.len() {
            let c = b[j];
            if in_str {
                match c {
                    b'\\' => j += 1,
                    b'"' => in_str = false,
                    _ => {}
                }
            } else {
                match c {
                    b'"' => in_str = true,
                    b'[' => depth += 1,
                    b']' => {
                        depth -= 1;
                        if depth == 0 {
                            j += 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            j += 1;
        }
        i = j;
    }
    &s[i..]
}

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());

    let mut config = svd2rust::Config::default();
    config.target = svd2rust::Target::CortexM;
    let svd = inject_radio_interrupts(svd_xml());
    let generated = svd2rust::generate(&svd, &config).expect("svd2rust generation failed");

    fs::write(out.join("pac.rs"), strip_leading_inner_attrs(&generated.lib_rs)).unwrap();

    // device.x carries the interrupt vector table; only needed (and only INCLUDEd by
    // cortex-m-rt's link.x) under the `rt` feature.
    if env::var_os("CARGO_FEATURE_RT").is_some() {
        if let Some(ds) = generated.device_specific {
            fs::write(out.join("device.x"), ds.device_x).unwrap();
            println!("cargo:rustc-link-search={}", out.display());
        }
    }

    println!("cargo:rerun-if-env-changed=ZIGGURAT_EFR32_SVD");
    println!("cargo:rerun-if-env-changed=ZIGGURAT_EFR32_PAC_CACHE");
    println!("cargo:rerun-if-changed=build.rs");
}
