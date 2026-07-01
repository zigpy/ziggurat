#![no_std]
#![no_main]

#[path = "../uart.rs"]
mod uart;
#[path = "../rail.rs"]
mod rail;

use core::fmt::Write;

use cortex_m_rt::entry;
use panic_halt as _;

use uart::Vcom;

const CHANNEL: u16 = 25;

#[entry]
fn main() -> ! {
    let p = ziggurat_efr32_pac::Peripherals::take().unwrap();

    // Bring up the clock tree (HFXO for the radio) FIRST: the clock manager repoints the
    // EM01GRPCCLK branch, so the UART must be initialized afterwards — Vcom re-pins that
    // branch to the always-on FSRCO with a matching divider, giving a stable 115200 baud.
    let (init, runtime) = rail::init_clocks();

    let mut vcom = Vcom::new(&p.cmu_s, &p.gpio_s, p.eusart0_s);
    writeln!(vcom, "\r\n=== EFR32MG24 RAIL RX demo ===").ok();
    writeln!(vcom, "clock_manager: init={init:#x} runtime={runtime:#x}").ok();

    let radio = rail::Radio::new();
    writeln!(vcom, "RAIL initialized").ok();

    let status = radio.start_rx(CHANNEL);
    writeln!(vcom, "start_rx(ch {CHANNEL}) status={status:#x}; listening...").ok();

    let mut buf = [0u8; 256];
    loop {
        if let Some(len) = rail::take_packet(&mut buf) {
            let shown = core::cmp::min(len, buf.len());
            write!(vcom, "RX len={len}:").ok();
            for byte in &buf[..shown] {
                write!(vcom, " {byte:02x}").ok();
            }
            writeln!(vcom).ok();
        }
    }
}
