//! Board-support glue shared by RAIL-based binaries: the heap, clock bring-up, and the
//! radio interrupt trampolines. This is the runtime environment `ziggurat_phy_efr32::Efr32Phy`
//! expects to already be in place (it owns only the RAIL logic, not the board init).

use embedded_alloc::LlffHeap as Heap;
use ziggurat_rail_sys as rail;

#[global_allocator]
static HEAP: Heap = Heap::empty();

/// Silabs `ApplicationProperties_t` (bootloader/application_properties.h). Commander scans the
/// image for its magic to build the GBL, and the Gecko bootloader reads it for OTA version
/// checks. Unsigned (`signature_type = 0`), Zigbee application type.
#[repr(C)]
struct ApplicationData {
    type_: u32,
    version: u32,
    capabilities: u32,
    product_id: [u8; 16],
}
#[repr(C)]
struct ApplicationProperties {
    magic: [u8; 16],
    struct_version: u32,
    signature_type: u32,
    signature_location: u32,
    app: ApplicationData,
    long_token_section_address: usize,
    decrypt_key: [u8; 16],
}
unsafe impl Sync for ApplicationProperties {}

#[used]
#[no_mangle]
static sl_app_properties: ApplicationProperties = ApplicationProperties {
    magic: [
        0x13, 0xb7, 0x79, 0xfa, 0xc9, 0x25, 0xdd, 0xb7, 0xad, 0xf3, 0xcf, 0xe0, 0xf1, 0xb6, 0x14,
        0xb8,
    ],
    struct_version: 0x0201, // APPLICATION_PROPERTIES_VERSION (major 1, minor 2)
    signature_type: 0,      // APPLICATION_SIGNATURE_NONE
    signature_location: 0,
    app: ApplicationData {
        type_: 1, // APPLICATION_TYPE_ZIGBEE
        version: 0,
        capabilities: 0,
        product_id: [0; 16],
    },
    long_token_section_address: 0,
    decrypt_key: [0; 16],
};

/// Heap for the `alloc` types the PHY and stack use (Vec/String in frames, config). Sized
/// generously for a first bring-up; a real network needs re-measuring.
const HEAP_BYTES: usize = 64 * 1024;

/// Point VTOR at our vector table. The Gecko bootloader jumps to the app (linked at
/// 0x08006000, see memory.x) without updating VTOR, so interrupts would otherwise vector
/// through the bootloader's table at 0x08000000. Must run before any interrupt is enabled.
pub fn init_vtor() {
    const APP_FLASH_ORIGIN: u32 = 0x0800_6000;
    unsafe { (*cortex_m::peripheral::SCB::PTR).vtor.write(APP_FLASH_ORIGIN) };
}

/// Initialize the global allocator. Must run before any allocation.
pub fn init_heap() {
    use core::mem::MaybeUninit;
    static mut ARENA: [MaybeUninit<u8>; HEAP_BYTES] = [MaybeUninit::uninit(); HEAP_BYTES];
    unsafe { HEAP.init(core::ptr::addr_of_mut!(ARENA) as usize, HEAP_BYTES) }
}

/// Bring up the clock tree (HFXO for the radio) via the SDK clock manager — the safe
/// enable-wait-switch path. Must run before the UART (it repoints EM01GRPCCLK) and RAIL.
pub fn init_clocks() {
    unsafe {
        rail::sl_clock_manager_init();
        rail::sl_clock_manager_runtime_init();
    }
}

// Route the PAC's radio interrupt vector slots to the RAIL blob's `<PERIPH>_IRQHandler`.
// Without these, radio IRQs vector to DefaultHandler and RAIL's state machine never advances.
macro_rules! radio_irq {
    ($($vector:ident => $handler:ident,)*) => {
        extern "C" { $(fn $handler();)* }
        $(
            #[no_mangle]
            extern "C" fn $vector() { unsafe { $handler() } }
        )*
    };
}

radio_irq! {
    AGC => AGC_IRQHandler,
    BUFC => BUFC_IRQHandler,
    FRC => FRC_IRQHandler,
    FRC_PRI => FRC_PRI_IRQHandler,
    MODEM => MODEM_IRQHandler,
    PROTIMER => PROTIMER_IRQHandler,
    RAC_RSM => RAC_RSM_IRQHandler,
    RAC_SEQ => RAC_SEQ_IRQHandler,
    SYNTH => SYNTH_IRQHandler,
    RFECA0 => RFECA0_IRQHandler,
    RFECA1 => RFECA1_IRQHandler,
}
