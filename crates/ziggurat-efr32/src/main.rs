#![no_std]
#![no_main]

use cortex_m_rt::entry;
use panic_halt as _;

#[entry]
fn main() -> ! {
    // Phase 3 link probe: reference a representative slice of the RAIL API so the linker
    // pulls in the blob's reachable closure (and surfaces whatever glue/ISR symbols are
    // still unresolved). Not a functional bring-up yet.
    core::hint::black_box(ziggurat_rail_sys::sl_rail_init as *const ());
    core::hint::black_box(ziggurat_rail_sys::sl_rail_ieee802154_init as *const ());
    core::hint::black_box(ziggurat_rail_sys::sl_rail_start_tx as *const ());
    core::hint::black_box(ziggurat_rail_sys::sl_rail_start_rx as *const ());
    loop {}
}
