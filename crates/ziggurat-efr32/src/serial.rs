//! Bidirectional EUSART0 for the JSON API (VCOM: TX PA05, RX PA06, 115200 8N1).
//!
//! RX is interrupt-driven: the EUSART0_RX ISR drains the hardware FIFO into a ring buffer
//! and signals the async reader. This is essential under load — the earlier poll-based RX
//! dropped inbound bytes (corrupting commands) whenever the executor was busy, and its
//! `yield_now` busy-loop kept the core from ever sleeping, starving the radio/capture tasks.
//! TX stays blocking (poll TXFL), which is fine for the writer task.
//!
//! (460800 from FSRCO is out of reach cleanly on this VCOM; 115200 is reliable.)

use core::cell::RefCell;

use critical_section::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use heapless::Deque;
use ziggurat_efr32_pac::{CmuS, Eusart0S, GpioS, Interrupt};

const REF_HZ: u32 = 20_000_000; // FSRCO clocking EM01GRPCCLK -> EUSART0
const BAUD: u32 = 115_200;
const OVS: u32 = 16;
const CLKDIV: u32 = ((32 * REF_HZ) + (BAUD * OVS) / 2) / (BAUD * OVS) - 32;

const RX_RING_BYTES: usize = 512;

static RX_RING: Mutex<RefCell<Deque<u8, RX_RING_BYTES>>> = Mutex::new(RefCell::new(Deque::new()));
static RX_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();

fn eusart() -> &'static ziggurat_efr32_pac::eusart0_s::RegisterBlock {
    unsafe { &*Eusart0S::ptr() }
}

/// Configure EUSART0 for bidirectional VCOM, enable the RX interrupt, and return the split
/// handles.
pub fn init(cmu: &CmuS, gpio: &GpioS, _eusart: Eusart0S) -> (SerialTx, SerialRx) {
    cmu.clken0().modify(|_, w| w.gpio().set_bit());
    cmu.clken1().modify(|_, w| w.eusart0().set_bit());
    cmu.em01grpcclkctrl().write(|w| w.clksel().fsrco());
    cmu.eusart0clkctrl().write(|w| w.clksel().em01grpcclk());

    gpio.porta_model()
        .modify(|_, w| w.mode5().pushpull().mode6().input());
    gpio.eusart0_txroute()
        .write(|w| unsafe { w.port().bits(0).pin().bits(5) });
    gpio.eusart0_rxroute()
        .write(|w| unsafe { w.port().bits(0).pin().bits(6) });
    gpio.eusart0_routeen()
        .write(|w| w.txpen().set_bit().rxpen().set_bit());

    let e = eusart();
    e.framecfg()
        .write(|w| w.databits().eight().stopbits().one().parity().none());
    e.clkdiv().write(|w| unsafe { w.div().bits(CLKDIV) });
    e.en().write(|w| w.en().set_bit());
    e.cmd().write(|w| w.txen().set_bit().rxen().set_bit());

    // Interrupt when the RX FIFO has data; the ISR drains it into RX_RING.
    e.ien().write(|w| w.rxfl().set_bit());
    unsafe { cortex_m::peripheral::NVIC::unmask(Interrupt::EUSART0_RX) };

    (SerialTx, SerialRx)
}

/// EUSART0 RX FIFO interrupt: drain every available byte into the ring, then wake the reader.
#[no_mangle]
extern "C" fn EUSART0_RX() {
    let e = eusart();
    critical_section::with(|cs| {
        let mut ring = RX_RING.borrow_ref_mut(cs);
        while e.status().read().rxfl().bit_is_set() {
            let byte = e.rxdata().read().rxdata().bits() as u8;
            let _ = ring.push_back(byte); // drop on overflow rather than wedge
        }
    });
    // IF.RXFL is latched; clear it via the Silabs CLR alias (reg + PER_REG_BLOCK_CLR_OFFSET
    // = 0x2000), or the interrupt re-fires forever and wedges the core.
    let if_clr = (e.if_().as_ptr() as usize + 0x2000) as *mut u32;
    unsafe { core::ptr::write_volatile(if_clr, 0xFFFF_FFFF) };
    RX_SIGNAL.signal(());
}

pub struct SerialTx;

impl SerialTx {
    pub fn write_all(&mut self, bytes: &[u8]) {
        let e = eusart();
        for &byte in bytes {
            while e.status().read().txfl().bit_is_clear() {}
            e.txdata().write(|w| unsafe { w.txdata().bits(u16::from(byte)) });
        }
    }
}

pub struct SerialRx;

impl SerialRx {
    /// Await the next received byte from the interrupt-fed ring buffer.
    pub async fn read_byte(&mut self) -> u8 {
        loop {
            if let Some(byte) = critical_section::with(|cs| RX_RING.borrow_ref_mut(cs).pop_front()) {
                return byte;
            }
            RX_SIGNAL.wait().await;
        }
    }
}
