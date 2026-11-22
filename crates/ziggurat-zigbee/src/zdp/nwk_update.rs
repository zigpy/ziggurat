//! Mgmt_NWK_Update_req on a router (spec 2.4.3.3.9.2): what the request asks for, or
//! why it is refused.

use alloc::vec::Vec;
use core::ops::RangeInclusive;
use core::time::Duration;
use ziggurat_ieee_802154::types::Nwk;

use super::{MgmtNwkUpdateNotify, MgmtNwkUpdateReq, ZdpStatus};

/// Channel page 0 holds the 2.4 GHz channels 11 to 26, one mask bit each (spec Table
/// 3-7). The five high bits of a mask hold the channel page.
const PAGE_0_CHANNELS: RangeInclusive<u8> = 11..=26;
const CHANNEL_PAGE_BITS: u32 = 0xF800_0000;
const CHANNEL_BITS: u32 = !CHANNEL_PAGE_BITS;

/// 802.15.4 `aBaseSuperframeDuration`, and the 2.4 GHz symbol period.
const BASE_SUPERFRAME_DURATION_SYMBOLS: u64 = 960;
const SYMBOL_PERIOD_MICROS: u64 = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NwkUpdate {
    /// Switch to the channel once the request had time to reach the whole network.
    ChangeChannel { channel: u8, update_id: u8 },
    /// Store a new channel mask and network manager.
    UpdateManager { channel_mask: u32, manager: Nwk },
    /// Measure the energy on each channel, `count` times, reporting each pass.
    EnergyScan {
        channels: Vec<u8>,
        duration: Duration,
        count: u8,
    },
    /// Refuse the request, reporting the status in a Mgmt_NWK_Update_notify.
    Reject(ZdpStatus),
}

impl NwkUpdate {
    /// What the request asks for. Scans and refusals are only for a request unicast to
    /// us: a broadcast one is dropped instead (spec 2.4.3.3.9.3).
    pub fn from_request(request: &MgmtNwkUpdateReq, unicast: bool) -> Option<Self> {
        let reject = || unicast.then_some(Self::Reject(ZdpStatus::InvRequestType));

        let channels: Vec<u8> = if request.scan_channels & CHANNEL_PAGE_BITS == 0 {
            PAGE_0_CHANNELS
                .filter(|channel| request.scan_channels & (1 << channel) != 0)
                .collect()
        } else {
            Vec::new()
        };

        match request.scan_duration {
            0xFE => {
                let requested = (request.scan_channels & CHANNEL_BITS).count_ones();

                // Exactly one channel, and one we support
                match channels[..] {
                    [channel] if requested == 1 => Some(Self::ChangeChannel {
                        channel,
                        update_id: request
                            .nwk_update_id
                            .expect("a channel change carries an update id"),
                    }),
                    _ => reject(),
                }
            }
            0xFF => Some(Self::UpdateManager {
                channel_mask: request.scan_channels,
                manager: request
                    .nwk_manager_addr
                    .expect("a manager update carries the manager"),
            }),
            exponent @ 0x00..=0x05 => {
                if !unicast {
                    return None;
                }

                if channels.is_empty() {
                    return reject();
                }

                let symbols = BASE_SUPERFRAME_DURATION_SYMBOLS * ((1 << exponent) + 1);
                Some(Self::EnergyScan {
                    channels,
                    duration: Duration::from_micros(symbols * SYMBOL_PERIOD_MICROS),
                    count: request
                        .scan_count
                        .expect("a scan request carries a scan count"),
                })
            }
            _ => reject(),
        }
    }
}

/// The notify refusing a request.
pub const fn rejection(status: ZdpStatus) -> MgmtNwkUpdateNotify {
    MgmtNwkUpdateNotify {
        status,
        scanned_channels: 0,
        total_transmissions: 0,
        transmission_failures: 0,
        energy_values: Vec::new(),
    }
}

/// The notify reporting one energy scan pass: one energy value per scanned channel,
/// in ascending channel order.
pub fn scan_report(
    channels: &[u8],
    energy_values: Vec<u8>,
    total_transmissions: u16,
) -> MgmtNwkUpdateNotify {
    MgmtNwkUpdateNotify {
        status: ZdpStatus::Success,
        scanned_channels: channels
            .iter()
            .fold(0, |mask, channel| mask | (1 << channel)),
        total_transmissions,
        // TODO: the spec sums the neighbor table's TransmitFailure counters here
        // (frequency agility annex). Ours are kept but never read, and zigpy ignores
        // this field: sum them, or drop the dead counters
        transmission_failures: 0,
        energy_values,
    }
}
