use crate::ieee_802154::{Ieee802154Address, Ieee802154CommandFrame, Ieee802154Frame};
use crate::spinel::SpinelPropertyId;
use ieee_802154::types::{Eui64, Nwk};

use std::collections::HashSet;
use tokio::sync::oneshot;
use tokio::time::{Duration, Instant};
use zigbee_parts::Command;
use zigbee_parts::commands::NwkLeaveCommand;

use super::{
    MAX_LOCK_DURATION, NwkSecurityMode, PendingIndirectTransaction, SrcMatchTable,
    ZigbeeNotification, ZigbeeStack, ZigbeeStackError,
};

/// How often expired indirect transactions and timed-out children are swept.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(1);

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
            .entry(destination)
            .or_default()
            .push_back(PendingIndirectTransaction {
                frame,
                expires_at: Instant::now() + self.constants.transaction_persistence_time,
                completion,
            });

        self.src_match_sync.notify_one();

        // Every transaction is eventually resolved by delivery, the expiry sweep, or
        // child eviction; a dropped sender means the stack is shutting down
        result_rx
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
                let nwk = self
                    .state
                    .address_map
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap()
                    .get(&eui64)
                    .copied();

                (Some(eui64), nwk)
            }
            Some(Ieee802154Address::Nwk(nwk)) => {
                let eui64 = self
                    .state
                    .address_map
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap()
                    .iter()
                    .find_map(|(&eui64, &mapped)| (mapped == nwk).then_some(eui64));

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
            .refresh_child_timeout(source_eui64, source_nwk);

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
        let keys = source_eui64
            .map(Ieee802154Address::Eui64)
            .into_iter()
            .chain(source_nwk.map(Ieee802154Address::Nwk));

        let extracted = {
            let mut queue = self
                .state
                .indirect_queue
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();
            let now = Instant::now();
            let mut extracted = None;

            'keys: for key in keys {
                let Some(transactions) = queue.get_mut(&key) else {
                    continue;
                };

                while let Some(transaction) = transactions.pop_front() {
                    if transaction.expires_at <= now {
                        let _ = transaction
                            .completion
                            .send(Err(ZigbeeStackError::IndirectExpired { destination: key }));
                        continue;
                    }

                    // Further pending transactions are signaled in the delivered
                    // frame so the device keeps polling (802.15.4 spec 6.7.3)
                    let more_pending = !transactions.is_empty();
                    extracted = Some((key, transaction, more_pending));
                    break 'keys;
                }

                queue.remove(&key);
            }

            extracted
        };

        let Some((destination, transaction, more_pending)) = extracted else {
            return false;
        };

        log::info!("Delivering queued indirect frame to {destination:?}");

        let arc_self = self
            .self_weak
            .upgrade()
            .expect("Unable to upgrade self reference");

        self.spawn_tracked(async move {
            arc_self
                .transmit_indirect_transaction(destination, transaction, more_pending)
                .await;
        });

        true
    }

    async fn transmit_indirect_transaction(
        &self,
        destination: Ieee802154Address,
        transaction: PendingIndirectTransaction,
        more_pending: bool,
    ) {
        let mut frame = transaction.frame.clone();
        if more_pending {
            set_frame_pending(&mut frame);
        }

        match self.send_802154_frame(frame).await {
            Ok(()) => {
                let _ = transaction.completion.send(Ok(()));
                self.remove_indirect_queue_if_empty(destination);
            }
            // 802.15.4 spec 6.7.3: a transaction is only extracted once acknowledged,
            // so a failed transmit goes back to the head of the queue for the next poll
            Err(err) if Instant::now() < transaction.expires_at => {
                log::warn!("Indirect transmit to {destination:?} failed ({err}), requeueing");
                self.state
                    .indirect_queue
                    .try_lock_for(MAX_LOCK_DURATION)
                    .unwrap()
                    .entry(destination)
                    .or_default()
                    .push_front(transaction);
            }
            Err(err) => {
                let _ = transaction.completion.send(Err(err));
                self.remove_indirect_queue_if_empty(destination);
            }
        }
    }

    fn remove_indirect_queue_if_empty(&self, destination: Ieee802154Address) {
        {
            let mut queue = self
                .state
                .indirect_queue
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();

            if queue.get(&destination).is_some_and(|t| t.is_empty()) {
                queue.remove(&destination);
            }
        }

        self.src_match_sync.notify_one();
    }

    /// Drop every transaction queued for a device that is no longer a child.
    pub(super) fn drop_indirect_transactions(&self, eui64: Option<Eui64>, nwk: Nwk) {
        let keys = eui64
            .map(Ieee802154Address::Eui64)
            .into_iter()
            .chain([Ieee802154Address::Nwk(nwk)]);

        let mut dropped = false;
        {
            let mut queue = self
                .state
                .indirect_queue
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();

            for key in keys {
                if let Some(transactions) = queue.remove(&key) {
                    dropped = true;

                    for transaction in transactions {
                        let _ = transaction
                            .completion
                            .send(Err(ZigbeeStackError::IndirectExpired { destination: key }));
                    }
                }
            }
        }

        if dropped {
            self.src_match_sync.notify_one();
        }
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
            .contains_key(&destination)
        {
            return;
        }

        log::info!("Poll from unknown device {nwk:?}, queueing a leave request");

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
                log::debug!("Queued leave to {nwk:?} was not extracted: {err}");
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
                log::error!("Failed to write the source address match table: {err}");
            }
        }
    }

    /// Replace the RCP source address match table with the addresses of every device
    /// that has queued indirect transactions.
    pub(super) async fn write_src_match_table(&self) -> Result<(), ZigbeeStackError> {
        let mut short_addresses: HashSet<Nwk> = HashSet::new();
        let mut extended_addresses: HashSet<Eui64> = HashSet::new();

        {
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

            for key in queue.keys() {
                match key {
                    Ieee802154Address::Eui64(eui64) => {
                        extended_addresses.insert(*eui64);

                        // The device may poll with either of its addresses
                        if let Some(nwk) = address_map.get(eui64) {
                            short_addresses.insert(*nwk);
                        }
                    }
                    Ieee802154Address::Nwk(nwk) => {
                        short_addresses.insert(*nwk);
                    }
                }
            }
        }

        log::debug!(
            "Writing source address match table: {short_addresses:?} {extended_addresses:?}"
        );

        self.spinel
            .prop_value_set(
                SpinelPropertyId::MacSrcMatchShortAddresses,
                short_addresses
                    .iter()
                    .flat_map(|nwk| nwk.to_bytes())
                    .collect(),
            )
            .await?;

        self.spinel
            .prop_value_set(
                SpinelPropertyId::MacSrcMatchExtendedAddresses,
                extended_addresses
                    .iter()
                    .flat_map(|&eui64| super::eui64_to_spinel_bytes(eui64))
                    .collect(),
            )
            .await?;

        *self
            .src_match_written
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap() = SrcMatchTable {
            short_addresses,
            extended_addresses,
        };

        Ok(())
    }

    /// Expires undelivered indirect transactions and evicts children whose keepalive
    /// deadline has lapsed (spec 3.6.10.1).
    pub(super) async fn indirect_maintenance_task(&self) {
        loop {
            tokio::time::sleep(MAINTENANCE_INTERVAL).await;

            self.expire_indirect_transactions();
            self.evict_timed_out_children();
        }
    }

    fn expire_indirect_transactions(&self) {
        let now = Instant::now();
        let mut changed = false;

        {
            let mut queue = self
                .state
                .indirect_queue
                .try_lock_for(MAX_LOCK_DURATION)
                .unwrap();

            queue.retain(|destination, transactions| {
                // Transactions expire in arrival order: they are queued with a uniform
                // persistence time and requeued transmit failures keep their deadline
                while transactions
                    .front()
                    .is_some_and(|transaction| transaction.expires_at <= now)
                {
                    let transaction = transactions.pop_front().unwrap();
                    log::warn!("Indirect transaction to {destination:?} expired without a poll");
                    let _ = transaction
                        .completion
                        .send(Err(ZigbeeStackError::IndirectExpired {
                            destination: *destination,
                        }));
                    changed = true;
                }

                !transactions.is_empty()
            });
        }

        if changed {
            self.src_match_sync.notify_one();
        }
    }

    fn evict_timed_out_children(&self) {
        let evicted = self
            .state
            .neighbors
            .try_lock_for(MAX_LOCK_DURATION)
            .unwrap()
            .evict_timed_out_children();

        for (eui64, nwk) in evicted {
            log::warn!("Child {eui64:?} ({nwk:?}) timed out without a keepalive, evicting");

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
