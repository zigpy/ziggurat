use crate::ieee_802154::{Ieee802154Address, Ieee802154CommandFrame, Ieee802154Frame};
use ieee_802154::types::{Eui64, Nwk};
use spinel::SpinelPropertyId;
use spinel::client::TxPriority;

use tokio::sync::oneshot;
use tokio::time::{Instant, timeout_at};
use zigbee::Command;
use zigbee::nwk::commands::NwkLeaveCommand;

use zigbee::indirect::Delivery;

use super::{
    IndirectCompletion, MAX_LOCK_DURATION, NwkSecurityMode, ZigbeeNotification, ZigbeeStack,
    ZigbeeStackError,
};

const fn set_frame_pending(frame: &mut Ieee802154Frame) {
    match frame {
        Ieee802154Frame::Data(f) => f.header.frame_control.frame_pending = true,
        Ieee802154Frame::Ack(f) => f.header.frame_control.frame_pending = true,
        Ieee802154Frame::Beacon(f) => f.header.frame_control.frame_pending = true,
        Ieee802154Frame::Command(f) => f.header.frame_control.frame_pending = true,
    }
}

impl ZigbeeStack {
    /// Queue a finished 802.15.4 frame for indirect delivery and wait for the
    /// destination to extract it with a MAC Data Request, or for the transaction to
    /// expire (802.15.4 spec 6.7.3). There is no retry loop here: the destination
    /// re-polling is the retry mechanism, expiry is the failure signal.
    pub(super) async fn queue_indirect_frame(
        &self,
        destination: Ieee802154Address,
        frame: Ieee802154Frame,
    ) -> Result<(), ZigbeeStackError> {
        let (completion, result_rx) = oneshot::channel();

        self.state
            .indirect_queue
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .push(destination, frame, completion, Instant::now().into_std());

        self.src_match_sync.notify_one();
        self.maintenance_wake.notify_one();

        // Every transaction is eventually resolved by delivery, the expiry sweep, or
        // child eviction; a dropped sender means the stack is shutting down
        result_rx
            .await
            .unwrap_or(Err(ZigbeeStackError::IndirectExpired { destination }))
    }

    /// 802.15.4 spec 6.7.3: a MAC Data Request extracts the oldest transaction queued
    /// for the polling device. The poll doubles as the child keepalive (spec 3.6.10.4).
    pub(super) fn handle_data_request(&self, command_frame: &Ieee802154CommandFrame) {
        let poll_received_at = Instant::now();
        // Polls during association use extended addressing (the device has no short
        // address yet); joined children poll with their short address
        let poll_source = command_frame.header.src_address;

        let (source_eui64, source_nwk) = match poll_source {
            Some(Ieee802154Address::Eui64(eui64)) => {
                let nwk = self
                    .state
                    .address_map
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap()
                    .nwk_for(eui64);

                (Some(eui64), nwk)
            }
            Some(Ieee802154Address::Nwk(nwk)) => {
                let eui64 = self
                    .state
                    .address_map
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap()
                    .eui64_for(nwk);

                (eui64, Some(nwk))
            }
            _ => return,
        };

        // Spec 3.6.10.4: a poll from a known device refreshes its keepalive deadline
        let known_device = self
            .state
            .neighbors
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .refresh_child_timeout(source_eui64, source_nwk, Instant::now().into_std());

        // The RCP only told the device to keep listening (frame-pending=1 in the
        // poll's auto-ACK) if the poll's source address was already written to the
        // source address match table. If that write is still in flight, the device is
        // asleep again by now: everything stays queued for the next poll instead of
        // being transmitted into the void.
        let fp_advertised = poll_source.is_some_and(|address| {
            self.src_match_written
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .contains(address)
        });

        let delivered = fp_advertised
            && self.deliver_indirect_transaction(source_eui64, source_nwk, poll_received_at);

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

    /// Pop and transmit the oldest live transaction queued under either of the polling
    /// device's addresses. Returns whether a transaction was found.
    fn deliver_indirect_transaction(
        &self,
        source_eui64: Option<Eui64>,
        source_nwk: Option<Nwk>,
        poll_received_at: Instant,
    ) -> bool {
        let outcome = self
            .state
            .indirect_queue
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .extract(source_eui64, source_nwk, Instant::now().into_std());

        for (destination, transaction) in outcome.expired {
            let _ = transaction
                .completion
                .send(Err(ZigbeeStackError::IndirectExpired { destination }));
        }

        let Some(delivery) = outcome.delivery else {
            return false;
        };

        tracing::debug!(
            "Delivering queued indirect frame to {:?}",
            delivery.destination
        );

        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        self.spawn_tracked(async move {
            arc_self
                .transmit_indirect_transaction(delivery, poll_received_at)
                .await;
        });

        true
    }

    async fn transmit_indirect_transaction(
        &self,
        delivery: Delivery<IndirectCompletion>,
        poll_received_at: Instant,
    ) {
        let Delivery {
            destination,
            transaction,
            more_pending,
        } = delivery;

        let mut frame = transaction.frame.clone();
        if more_pending {
            set_frame_pending(&mut frame);
        }

        // Poll-received to frame-handed-to-radio: the host-side turnaround that lock
        // contention or scheduling delay would inflate, against `macResponseWaitTime`.
        tracing::info!(
            target: "metrics",
            path = "rx_to_indirect_tx",
            latency_us = poll_received_at.elapsed().as_micros() as u64,
            destination = ?destination,
            "indirect delivery turnaround",
        );

        // Indirect delivery answers a sleepy child's poll within macResponseWaitTime — a
        // deadline-bound path, so it takes the radio ahead of the baseline backlog.
        match self
            .send_802154_frame(frame, TxPriority::STACK_CRITICAL)
            .await
        {
            Ok(()) => {
                let _ = transaction.completion.send(Ok(()));
                self.remove_indirect_queue_if_empty(destination);
            }
            // 802.15.4 spec 6.7.3: a transaction is only extracted once acknowledged,
            // so a failed transmit goes back to the head of the queue for the next poll
            Err(err) if Instant::now().into_std() < transaction.expires_at => {
                tracing::warn!("Indirect transmit to {destination:?} failed ({err}), requeueing");
                self.state
                    .indirect_queue
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap()
                    .requeue(destination, transaction);
            }
            Err(err) => {
                let _ = transaction.completion.send(Err(err));
                self.remove_indirect_queue_if_empty(destination);
            }
        }
    }

    fn remove_indirect_queue_if_empty(&self, destination: Ieee802154Address) {
        self.state
            .indirect_queue
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .remove_if_empty(destination);

        self.src_match_sync.notify_one();
    }

    /// Drop every transaction queued for a device that is no longer a child.
    pub(super) fn drop_indirect_transactions(&self, eui64: Option<Eui64>, nwk: Nwk) {
        let dropped = self
            .state
            .indirect_queue
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .drop_for(eui64, nwk);

        if dropped.is_empty() {
            return;
        }

        for (destination, transaction) in dropped {
            let _ = transaction
                .completion
                .send(Err(ZigbeeStackError::IndirectExpired { destination }));
        }

        self.src_match_sync.notify_one();
    }

    /// Spec 3.6.10.4: a poll from a device with no neighbor table entry is answered
    /// with an indirectly delivered leave (request=1, rejoin=1), telling the stale
    /// child to re-attach through the rejoin path.
    fn queue_leave_for_stale_child(&self, nwk: Nwk) {
        let destination = Ieee802154Address::Nwk(nwk);

        // One queued leave at a time, or every poll until extraction would add one
        if self
            .state
            .indirect_queue
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .has_queued(destination)
        {
            return;
        }

        tracing::info!("Poll from unknown device {nwk:?}, queueing a leave request");

        // Spec 3.6.10.4.1: no destination IEEE address is included
        let mut nwk_frame = self
            .nwk_command_frame(
                nwk,
                NwkLeaveCommand {
                    rejoin: true,
                    request: true,
                    remove_children: false,
                }
                .serialize()
                .unwrap(),
            )
            .with_radius(1);
        nwk_frame.nwk_header.sequence_number = self.next_nwk_sequence_number();

        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        self.spawn_tracked(async move {
            let frame =
                arc_self.finish_unicast_nwk_frame(nwk_frame, nwk, NwkSecurityMode::NetworkKey);

            if let Err(err) = arc_self.queue_indirect_frame(destination, frame).await {
                tracing::debug!("Queued leave to {nwk:?} was not extracted: {err}");
            }
        });
    }

    /// Mirrors the indirect queue keys into the RCP source address match table:
    /// auto-ACKs to MAC Data Requests carry frame-pending=1 exactly for the devices
    /// that have something queued.
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
    /// that has queued indirect transactions.
    pub(super) async fn write_src_match_table(&self) -> Result<(), ZigbeeStackError> {
        let table = {
            let queue = self
                .state
                .indirect_queue
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();
            let address_map = self
                .state
                .address_map
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();

            queue.queued_addresses(address_map.map())
        };

        tracing::debug!(
            "Writing source address match table: {:?} {:?}",
            table.short_addresses,
            table.extended_addresses
        );

        self.spinel
            .prop_value_set(
                SpinelPropertyId::MacSrcMatchShortAddresses,
                table
                    .short_addresses
                    .iter()
                    .flat_map(|nwk| nwk.to_bytes())
                    .collect(),
            )
            .await?;

        self.spinel
            .prop_value_set(
                SpinelPropertyId::MacSrcMatchExtendedAddresses,
                table
                    .extended_addresses
                    .iter()
                    .flat_map(|&eui64| spinel::eui64_to_spinel_bytes(eui64))
                    .collect(),
            )
            .await?;

        *self
            .src_match_written
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap() = table;

        Ok(())
    }

    /// Expires undelivered indirect transactions and evicts children whose keepalive
    /// deadline has lapsed (spec 3.6.10.1). Sleeps until the earliest pending
    /// deadline, woken early when a new transaction or child entry could move it
    /// closer; keepalive refreshes only push deadlines out and need no wake.
    pub(super) async fn indirect_maintenance_task(&self) {
        loop {
            self.expire_indirect_transactions();
            self.evict_timed_out_children();

            match self.next_maintenance_deadline() {
                Some(deadline) => {
                    let _ = timeout_at(deadline, self.maintenance_wake.notified()).await;
                }
                None => self.maintenance_wake.notified().await,
            }
        }
    }

    /// The earliest deadline the maintenance task has to act on: an indirect
    /// transaction expiry or a child keepalive timeout.
    fn next_maintenance_deadline(&self) -> Option<Instant> {
        let next_expiry = self
            .state
            .indirect_queue
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .next_expiry()
            .map(Instant::from_std);

        let next_eviction = self
            .state
            .neighbors
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .next_child_timeout()
            .map(Instant::from_std);

        [next_expiry, next_eviction].into_iter().flatten().min()
    }

    fn expire_indirect_transactions(&self) {
        let expired = self
            .state
            .indirect_queue
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .expire(Instant::now().into_std());

        if expired.is_empty() {
            return;
        }

        for (destination, transaction) in expired {
            tracing::warn!("Indirect transaction to {destination:?} expired without a poll");
            let _ = transaction
                .completion
                .send(Err(ZigbeeStackError::IndirectExpired { destination }));
        }

        self.src_match_sync.notify_one();
    }

    fn evict_timed_out_children(&self) {
        let evicted = self
            .state
            .neighbors
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .evict_timed_out_children(Instant::now().into_std());

        for (eui64, nwk) in evicted {
            tracing::warn!("Child {eui64:?} ({nwk:?}) timed out without a keepalive, evicting");

            // The address map entry and any negotiated link key are kept so that the
            // device can rejoin later (mirrors `handle_leave`)
            self.drop_indirect_transactions(Some(eui64), nwk);
            self.state
                .routing
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap()
                .remove_route(nwk);

            let _ = self.notification_tx.send(ZigbeeNotification::DeviceLeft {
                nwk,
                ieee: Some(eui64),
            });
        }
    }
}
