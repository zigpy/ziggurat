#![no_std]
#![no_main]

mod uart;

use core::fmt::Write;

use cortex_m::asm;
use cortex_m_rt::entry;
use panic_halt as _;

use uart::Vcom;

// SYSCLK runs from FSRCO (20 MHz) out of reset, so this is roughly one second.
const CYCLES_PER_SECOND: u32 = 20_000_000;

#[entry]
fn main() -> ! {
    let p = ziggurat_efr32_pac::Peripherals::take().unwrap();
    let mut vcom = Vcom::new(&p.cmu_s, &p.gpio_s, p.eusart0_s);

    let mut counter: u32 = 0;
    loop {
        let _ = writeln!(vcom, "Hello from EFR32MG24! #{counter}");
        counter = counter.wrapping_add(1);
        asm::delay(CYCLES_PER_SECOND);
    }
}
