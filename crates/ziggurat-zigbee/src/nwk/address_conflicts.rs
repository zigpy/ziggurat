use alloc::vec::Vec;
use core::time::Duration;

use crate::Instant;
use crate::flat_map::FlatMap;

use ziggurat_ieee_802154::types::Nwk;

/// How an address conflict (spec 3.6.1.10.5) came to our attention: detected locally
/// from a received frame, or reported by another device's network status command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrConflictSource {
    Local,
    Network,
}

#[derive(Debug)]
struct Conflict {
    handled_at: Instant,
    heard_from_network: bool,
    /// When our own Network Status broadcast is due. `None` once sent, or when no
    /// report is owed because the conflict was learned from the network.
    report_at: Option<Instant>,
}

/// The network address conflicts being handled (spec 3.6.1.10.5).
///
/// Detection re-triggers on every frame from the conflicted devices, so a conflict is
/// handled once per delivery window. A conflict we detected ourselves is reported to
/// the network after a jitter, unless another device reports it first.
#[derive(Debug, Default)]
pub struct AddressConflicts {
    table: FlatMap<Nwk, Conflict>,
}

impl AddressConflicts {
    /// Digest a detected conflict on `address`. Returns true for a conflict that must
    /// now be resolved, and false for a repeat of one already handled within `window`.
    /// A locally detected conflict owes a report at `now + report_jitter`.
    pub fn detect(
        &mut self,
        address: Nwk,
        source: AddrConflictSource,
        now: Instant,
        window: Duration,
        report_jitter: Duration,
    ) -> bool {
        if let Some(conflict) = self.table.get_mut(&address)
            && now < conflict.handled_at + window
        {
            conflict.heard_from_network |= source == AddrConflictSource::Network;
            return false;
        }

        self.table
            .retain(|_, conflict| now < conflict.handled_at + 2 * window);
        self.table.insert(
            address,
            Conflict {
                handled_at: now,
                heard_from_network: source == AddrConflictSource::Network,
                report_at: (source == AddrConflictSource::Local).then(|| now + report_jitter),
            },
        );

        true
    }

    /// When the soonest owed report is due, or `None` when none is owed.
    pub fn next_report(&self) -> Option<Instant> {
        self.table
            .values()
            .filter_map(|conflict| conflict.report_at)
            .min()
    }

    /// The addresses whose report is due and must be broadcast now. A due report is
    /// dropped when another device reported the conflict during the jitter.
    pub fn take_due_reports(&mut self, now: Instant) -> Vec<Nwk> {
        let mut due = Vec::new();

        for (address, conflict) in self.table.iter_mut() {
            if conflict.report_at.is_none_or(|report_at| report_at > now) {
                continue;
            }
            conflict.report_at = None;

            if conflict.heard_from_network {
                tracing::debug!(
                    "Address conflict on {address:?} was already reported, not rebroadcasting"
                );
            } else {
                due.push(*address);
            }
        }

        due
    }
}
