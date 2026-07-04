//! [`LinkOps`] over the platform layer's radio operations.

use alloc::string::String;
use core::time::Duration;

use ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_phy::{RadioConfig, RadioError};
use ziggurat_phy_otlink::LinkOps;

use crate::platform::{self, ZigguratRadioConfig};

pub struct PlatformLinkOps;

pub static LINK_OPS: PlatformLinkOps = PlatformLinkOps;

fn check(status: i32, what: &str) -> Result<(), RadioError> {
    if status == 0 {
        Ok(())
    } else {
        Err(RadioError::Other(String::from(what)))
    }
}

impl LinkOps for PlatformLinkOps {
    fn configure(&self, config: &RadioConfig) -> Result<(), RadioError> {
        let raw = ZigguratRadioConfig {
            channel: config.channel,
            tx_power_dbm: config.tx_power,
            short_address: config.short_address.as_u16(),
            pan_id: config.pan_id.0,
            extended_address: config.extended_address.to_bytes(),
            promiscuous: config.promiscuous,
            rx_on_when_idle: config.rx_on_when_idle,
            // The PAN coordinator (Zigbee coordinator, always short address 0x0000) also
            // accepts frames with no destination address.
            pan_coordinator: config.short_address.as_u16() == 0,
        };
        check(
            unsafe { platform::ziggurat_platform_radio_configure(&raw) },
            "radio_configure failed",
        )
    }

    fn set_channel(&self, channel: u8) -> Result<(), RadioError> {
        check(
            unsafe { platform::ziggurat_platform_radio_set_channel(channel) },
            "radio_set_channel failed",
        )
    }

    fn set_promiscuous(&self, promiscuous: bool) -> Result<(), RadioError> {
        check(
            unsafe { platform::ziggurat_platform_radio_set_promiscuous(promiscuous) },
            "radio_set_promiscuous failed",
        )
    }

    fn set_frame_pending_table(
        &self,
        short: &[Nwk],
        extended: &[Eui64],
    ) -> Result<(), RadioError> {
        unsafe {
            platform::ziggurat_platform_radio_src_match_clear();
            for nwk in short {
                check(
                    platform::ziggurat_platform_radio_src_match_add_short(nwk.as_u16()),
                    "radio_src_match_add_short failed",
                )?;
            }
            for eui in extended {
                let bytes = eui.to_bytes();
                check(
                    platform::ziggurat_platform_radio_src_match_add_ext(bytes.as_ptr()),
                    "radio_src_match_add_ext failed",
                )?;
            }
        }
        Ok(())
    }

    fn transmit(
        &self,
        psdu: &[u8],
        channel: u8,
        csma_ca: bool,
        max_frame_retries: u8,
        max_csma_backoffs: u8,
    ) -> Result<(), RadioError> {
        check(
            unsafe {
                platform::ziggurat_platform_radio_transmit(
                    psdu.as_ptr(),
                    psdu.len(),
                    channel,
                    csma_ca,
                    max_frame_retries,
                    max_csma_backoffs,
                )
            },
            "radio_transmit failed",
        )
    }

    fn energy_scan(&self, channel: u8, duration: Duration) -> Result<(), RadioError> {
        check(
            unsafe {
                platform::ziggurat_platform_radio_energy_scan(channel, duration.as_millis() as u16)
            },
            "radio_energy_scan failed",
        )
    }
}
