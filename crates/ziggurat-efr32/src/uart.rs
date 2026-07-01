//! Minimal blocking driver for EUSART0 in UART mode, wired to the xG24 Dev Kit
//! (BRD2601B) virtual COM port: EUSART0 TX on PA05, 115200 8N1.
//!
//! EM01GRPCCLK (and thus EUSART0) is sourced from the always-on 20 MHz FSRCO, so no
//! crystal or DPLL bring-up is needed.

use core::fmt;

use ziggurat_efr32_pac::{CmuS, Eusart0S, GpioS};

/// FSRCO frequency clocking EM01GRPCCLK → EUSART0.
const REF_HZ: u32 = 20_000_000;
const BAUD: u32 = 115_200;

/// 16x oversampling (CFG0.OVS reset value).
const OVS: u32 = 16;

/// CLKDIV.DIV fractional divider field value; mirrors the SDK's
/// `sl_hal_eusart_uart_calculate_clock_div` for the async 16x case.
const CLKDIV: u32 = (32 * REF_HZ) / (BAUD * OVS) - 32;

pub struct Vcom {
    eusart: Eusart0S,
}

impl Vcom {
    /// Bring up clocks, route EUSART0 TX to PA05, and enable the transmitter.
    pub fn new(cmu: &CmuS, gpio: &GpioS, eusart: Eusart0S) -> Self {
        // Peripheral clocks: GPIO and EUSART0.
        cmu.clken0().modify(|_, w| w.gpio().set_bit());
        cmu.clken1().modify(|_, w| w.eusart0().set_bit());

        // Clock EUSART0 from EM01GRPCCLK, itself sourced from FSRCO (20 MHz).
        cmu.em01grpcclkctrl().write(|w| w.clksel().fsrco());
        cmu.eusart0clkctrl().write(|w| w.clksel().em01grpcclk());

        // PA05 as push-pull output, driven by the EUSART0 TX signal.
        gpio.porta_model().modify(|_, w| w.mode5().pushpull());
        gpio.eusart0_txroute()
            .write(|w| unsafe { w.port().bits(0).pin().bits(5) });
        gpio.eusart0_routeen().write(|w| w.txpen().set_bit());

        // Frame format: 8 data bits, 1 stop bit, no parity. Must be set while the
        // module is disabled (it is, out of reset).
        eusart
            .framecfg()
            .write(|w| w.databits().eight().stopbits().one().parity().none());
        eusart.clkdiv().write(|w| unsafe { w.div().bits(CLKDIV) });

        // Enable the module, then the transmitter.
        eusart.en().write(|w| w.en().set_bit());
        eusart.cmd().write(|w| w.txen().set_bit());

        Self { eusart }
    }

    pub fn write_byte(&self, byte: u8) {
        // Wait until there is room in the TX FIFO.
        while self.eusart.status().read().txfl().bit_is_clear() {}
        self.eusart
            .txdata()
            .write(|w| unsafe { w.txdata().bits(byte as u16) });
    }
}

impl fmt::Write for Vcom {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.write_byte(byte);
        }
        Ok(())
    }
}
