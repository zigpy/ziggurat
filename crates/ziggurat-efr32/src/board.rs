//! Board-support glue shared by RAIL-based binaries: the heap, clock bring-up, and the
//! radio interrupt trampolines. This is the runtime environment `ziggurat_phy_efr32::Efr32Phy`
//! expects to already be in place (it owns only the RAIL logic, not the board init).

use embedded_alloc::LlffHeap as Heap;
use ziggurat_rail_sys as rail;

#[global_allocator]
static HEAP: Heap = Heap::empty();

/// Heap for the `alloc` types the PHY and stack use (Vec/String in frames, config). Sized
/// generously for a first bring-up; a real network needs re-measuring.
const HEAP_BYTES: usize = 64 * 1024;

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
