use crate::runtime::Runtime;
use crate::signal::{self, SignalWaiter};
use crate::ziggurat_ieee_802154::{Ieee802154Address, Ieee802154CommandFrame, Ieee802154Frame};
use ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_phy::RadioPhy;

use ziggurat_zigbee::Instant as CoreInstant;
use ziggurat_zigbee::nwk::commands::{NwkCommand, NwkLeaveCommand};
use ziggurat_zigbee::nwk::frame::EncryptedNwkFrame;

use ziggurat_zigbee::indirect::Delivery;

use super::{
    DeviceLeaveReason, NwkSecurityMode, SendKind, TxCompletion, TxPriority, ZigbeeNotification,
    ZigbeeStack, ZigbeeStackError,
};

impl<P: RadioPhy, R: Runtime> ZigbeeStack<P, R> {
    /// Queue a finished 802.15.4 frame for a polling device, resolving `completion` with
    /// the transmit result when the destination extracts it (802.15.4 spec 6.7.3), or
    /// with an error on expiry or eviction. There is no retry loop: the destination
    /// re-polling is the retry mechanism, expiry is the failure signal. Whoever wants the
    /// outcome — an awaiting unicast originator, or nobody — owns the completion's
    /// receiving half.
    pub(super) fn enqueue_indirect_frame(
        &self,
        destination: Ieee802154Address,
        frame: Ieee802154Frame<EncryptedNwkFrame>,
        completion: TxCompletion,
    ) {
        self.core()
            .mac
            .indirect_queue
            .push(destination, frame, completion, self.core_now());

        self.src_match_sync.notify_one();
        self.maintenance_wake.notify_one();
    }

    /// Queue a frame for a polling device without waiting on its delivery; the returned
    /// receiver resolves like [`Self::enqueue_indirect_frame`]'s completion. Fire-and-forget
    /// callers drop it.
    pub(super) fn push_indirect_frame(
        &self,
        destination: Ieee802154Address,
        frame: Ieee802154Frame<EncryptedNwkFrame>,
    ) -> SignalWaiter<Result<(), ZigbeeStackError>> {
        let (completion, result_rx) = signal::channel();
        self.enqueue_indirect_frame(destination, frame, completion);
        result_rx
    }

    pub(super) async fn queue_indirect_frame(
        &self,
        destination: Ieee802154Address,
        frame: Ieee802154Frame<EncryptedNwkFrame>,
    ) -> Result<(), ZigbeeStackError> {
        // Every transaction is eventually resolved by delivery, the expiry sweep, or
        // child eviction; a dropped sender means the stack is shutting down
        let waiter = self.push_indirect_frame(destination, frame);
        waiter
            .wait()
            .await
            .unwrap_or(Err(ZigbeeStackError::IndirectExpired { destination }))
    }

    /// 802.15.4 spec 6.7.3: a MAC Data Request extracts the oldest transaction queued
    /// for the polling device. The poll doubles as the child keepalive (spec 3.6.10.4).
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

        let delivered =
            fp_advertised && self.deliver_indirect_transaction(source_eui64, source_nwk);

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
    ) -> bool {
        let outcome =
            self.core()
                .mac
                .indirect_queue
                .extract(source_eui64, source_nwk, self.core_now());

        for (destination, transaction) in outcome.expired {
            transaction
                .completion
                .signal(Err(ZigbeeStackError::IndirectExpired { destination }));
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
            arc_self.transmit_indirect_transaction(delivery).await;
        });

        true
    }

    async fn transmit_indirect_transaction(&self, delivery: Delivery<TxCompletion>) {
        let Delivery {
            destination,
            transaction,
            more_pending,
        } = delivery;

        let mut frame = transaction.frame.clone();

        if more_pending {
            match frame {
                Ieee802154Frame::Data(ref mut f) => f.header.frame_control.frame_pending = true,
                Ieee802154Frame::Ack(ref mut f) => f.header.frame_control.frame_pending = true,
                Ieee802154Frame::Beacon(ref mut f) => f.header.frame_control.frame_pending = true,
                Ieee802154Frame::Command(ref mut f) => f.header.frame_control.frame_pending = true,
            }
        }

        // Indirect delivery answers a sleepy child's poll within `macResponseWaitTime`
        let raw_frame = Ieee802154Frame::from_bytes_without_fcs(&frame.to_bytes_without_fcs())
            .expect("a built indirect frame round-trips through bytes");

        match self
            .send(
                SendKind::Raw { frame: raw_frame },
                TxPriority::STACK_CRITICAL,
            )
            .await
        {
            Ok(()) => {
                transaction.completion.signal(Ok(()));
                self.remove_indirect_queue_if_empty(destination);
            }
            // 802.15.4 spec 6.7.3: a transaction is only extracted once acknowledged,
            // so a failed transmit goes back to the head of the queue for the next poll
            Err(err) if self.core_now() < transaction.expires_at => {
                tracing::warn!("Indirect transmit to {destination:?} failed ({err}), requeueing");
                self.core()
                    .mac
                    .indirect_queue
                    .requeue(destination, transaction);
            }
            Err(err) => {
                transaction.completion.signal(Err(err));
                self.remove_indirect_queue_if_empty(destination);
            }
        }
    }

    fn remove_indirect_queue_if_empty(&self, destination: Ieee802154Address) {
        self.core().mac.indirect_queue.remove_if_empty(destination);

        self.src_match_sync.notify_one();
    }

    /// Drop every transaction queued for a device that is no longer a child.
    pub(super) fn drop_indirect_transactions(&self, eui64: Option<Eui64>, nwk: Nwk) {
        let dropped = self.core().mac.indirect_queue.drop_for(eui64, nwk);

        if dropped.is_empty() {
            return;
        }

        for (destination, transaction) in dropped {
            transaction
                .completion
                .signal(Err(ZigbeeStackError::IndirectExpired { destination }));
        }

        self.src_match_sync.notify_one();
    }

    /// Spec 3.6.10.4: a poll from a device with no neighbor table entry is answered
    /// with an indirectly delivered leave (request=1, rejoin=1), telling the stale
    /// child to re-attach through the rejoin path.
    fn queue_leave_for_stale_child(&self, nwk: Nwk) {
        let destination = Ieee802154Address::Nwk(nwk);

        // One queued leave at a time, or every poll until extraction would add one
        if self.core().mac.indirect_queue.has_queued(destination) {
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
            let core = self.core();

            core.mac
                .indirect_queue
                .queued_addresses(core.nib.address_map.map())
        };

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
                    let _ = self
                        .timeout_at_core(deadline, self.maintenance_wake.notified())
                        .await;
                }
                None => self.maintenance_wake.notified().await,
            }
        }
    }

    /// The earliest deadline the maintenance task has to act on: an indirect
    /// transaction expiry or a child keepalive timeout.
    fn next_maintenance_deadline(&self) -> Option<CoreInstant> {
        let next_expiry = self.core().mac.indirect_queue.next_expiry();
        let next_eviction = self.core().nib.neighbors.next_child_timeout();

        [next_expiry, next_eviction].into_iter().flatten().min()
    }

    fn expire_indirect_transactions(&self) {
        let expired = self.core().mac.indirect_queue.expire(self.core_now());

        if expired.is_empty() {
            return;
        }

        for (destination, transaction) in expired {
            tracing::warn!("Indirect transaction to {destination:?} expired without a poll");
            transaction
                .completion
                .signal(Err(ZigbeeStackError::IndirectExpired { destination }));
        }

        self.src_match_sync.notify_one();
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
