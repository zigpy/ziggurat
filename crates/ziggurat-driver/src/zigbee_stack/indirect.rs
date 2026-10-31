use crate::runtime::Runtime;
use crate::ziggurat_ieee_802154::{Ieee802154Address, Ieee802154CommandFrame};
use alloc::vec::Vec;
use ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_phy::{RadioError, RadioPhy};

use ziggurat_zigbee::nwk::commands::{NwkCommand, NwkLeaveCommand};

use super::{
    Confirm, DeviceLeaveReason, Frame, NwkSecurityMode, TxPolicy, ZigbeeNotification, ZigbeeStack,
};

impl<P: RadioPhy, R: Runtime> ZigbeeStack<P, R> {
    /// 802.15.4 spec 6.7.3: a MAC Data Request extracts the oldest frame awaiting the
    /// polling device. The poll doubles as the child keepalive (spec 3.6.10.4).
    pub(super) fn handle_data_request(&self, command_frame: &Ieee802154CommandFrame) {
        // Polls during association use extended addressing (the device has no short
        // address yet); joined children poll with their short address
        let poll_source = command_frame.header.src_address;

        let (source_eui64, source_nwk) = match poll_source {
            Some(Ieee802154Address::Eui64(eui64)) => {
                let nwk = self.core().nib.address_map.nwk_for(eui64);

                (Some(eui64), nwk)
            }
            Some(Ieee802154Address::Nwk(nwk)) => {
                let eui64 = self.core().nib.address_map.eui64_for(nwk);

                (eui64, Some(nwk))
            }
            _ => return,
        };

        // Spec 3.6.10.4: a poll from a known device refreshes its keepalive deadline
        let known_device = self.core().nib.neighbors.refresh_child_timeout(
            source_eui64,
            source_nwk,
            self.core_now(),
        );

        // The RCP only told the device to keep listening (frame-pending=1 in the
        // poll's auto-ACK) if the poll's source address was already written to the
        // source address match table. If that write is still in flight, the device is
        // asleep again by now: everything stays queued for the next poll instead of
        // being transmitted into the void.
        let fp_advertised =
            poll_source.is_some_and(|address| self.src_match_written.lock().contains(address));

        let now = self.core_now();
        let delivered = fp_advertised && {
            let mut core = self.core();
            let (queued, actions) = core.sends.poll(source_eui64, source_nwk, now);
            self.commit_sends(core, actions);
            queued
        };

        if delivered {
            tracing::debug!("Delivering queued indirect frame to {poll_source:?}");
        }

        // Spec 3.6.10.4: polls from devices without a neighbor table entry are
        // answered with an indirectly delivered leave, steering the stale child
        // toward a rejoin
        if !known_device
            && !delivered
            && let Some(nwk) = source_nwk
        {
            self.queue_leave_for_stale_child(nwk);
        }
    }

    /// Fail every frame awaiting a device's poll: it is no longer a child.
    pub(super) fn drop_indirect_transactions(&self, eui64: Option<Eui64>, nwk: Nwk) {
        let mut core = self.core();
        let actions = core.sends.drop_indirect_unicasts(eui64, nwk);
        self.commit_sends(core, actions);
    }

    /// Spec 3.6.10.4: a poll from a device with no neighbor table entry is answered
    /// with an indirectly delivered leave (request=1, rejoin=1), telling the stale
    /// child to re-attach through the rejoin path.
    fn queue_leave_for_stale_child(&self, nwk: Nwk) {
        let destination = Ieee802154Address::Nwk(nwk);

        // One queued leave at a time, or every poll until extraction would add one
        if self.core().sends.has_unicast_awaiting_poll(destination) {
            return;
        }

        tracing::info!("Poll from unknown device {nwk:?}, queueing a leave request");

        // Spec 3.6.10.4.1: no destination IEEE address is included
        let mut nwk_frame = self
            .nwk_command_frame(
                nwk,
                NwkCommand::Leave(NwkLeaveCommand {
                    rejoin: true,
                    request: true,
                    remove_children: false,
                }),
            )
            .with_radius(1);
        nwk_frame.nwk_header.sequence_number = self.next_nwk_sequence_number();

        // Fire-and-forget: an expiry (the stale child never polled again) is only
        // worth a log line.
        let admitted = self.enqueue_unicast(
            Frame::nwk(nwk_frame, NwkSecurityMode::NetworkKey),
            TxPolicy::STACK_CRITICAL,
            Confirm::OnHandoff,
            nwk,
            Some(destination),
        );

        if let Err(err) = admitted {
            tracing::warn!("Not queueing a leave for {nwk:?}: {err}");
        }
    }

    /// Mirrors the devices with frames awaiting their poll into the RCP source address
    /// match table: auto-ACKs to MAC Data Requests carry frame-pending=1 exactly for the
    /// devices that have something queued.
    pub(super) async fn src_match_sync_task(&self) {
        loop {
            self.src_match_sync.notified().await;

            // Failures are not retried here: persistent spinel failures trigger the
            // reset recovery path, which rewrites the table with the rest of the
            // radio configuration
            if let Err(err) = self.write_src_match_table().await {
                tracing::error!("Failed to write the source address match table: {err}");
            }
        }
    }

    /// Replace the RCP source address match table with the addresses of every device
    /// that has a frame awaiting its poll. An unchanged table is not rewritten.
    pub(super) async fn write_src_match_table(&self) -> Result<(), RadioError> {
        let table = {
            let core = self.core();
            core.sends.poll_addresses(core.nib.address_map.map())
        };

        if *self.src_match_written.lock() == table {
            return Ok(());
        }

        tracing::debug!(
            "Writing source address match table: {:?} {:?}",
            table.short_addresses,
            table.extended_addresses
        );

        let short: Vec<Nwk> = table.short_addresses.iter().copied().collect();
        let extended: Vec<Eui64> = table.extended_addresses.iter().copied().collect();
        self.radio
            .set_frame_pending_table(&short, &extended)
            .await?;

        *self.src_match_written.lock() = table;

        Ok(())
    }

    /// Evicts children whose keepalive deadline has lapsed (spec 3.6.10.1). Sleeps
    /// until the earliest deadline, woken early when a new or renegotiated child entry
    /// could move it closer; keepalive refreshes only push deadlines out and need no
    /// wake.
    pub(super) async fn child_timeout_task(&self) {
        loop {
            self.evict_timed_out_children();

            let next_timeout = self.core().nib.neighbors.next_child_timeout();
            match next_timeout {
                Some(deadline) => {
                    let _ = self
                        .timeout_at_core(deadline, self.maintenance_wake.notified())
                        .await;
                }
                None => self.maintenance_wake.notified().await,
            }
        }
    }

    fn evict_timed_out_children(&self) {
        let evicted = self
            .core()
            .nib
            .neighbors
            .evict_timed_out_children(self.core_now());

        for (eui64, nwk) in evicted {
            tracing::warn!("Child {eui64:?} ({nwk:?}) timed out without a keepalive, evicting");

            // The address map entry and any negotiated link key are kept so that the
            // device can rejoin later (mirrors `handle_leave`)
            self.drop_indirect_transactions(Some(eui64), nwk);
            self.core().nib.routing.remove_route(nwk);

            self.push_notification(ZigbeeNotification::DeviceLeft {
                nwk,
                ieee: Some(eui64),
                reason: DeviceLeaveReason::KeepaliveTimeout,
            });
        }
    }
}
