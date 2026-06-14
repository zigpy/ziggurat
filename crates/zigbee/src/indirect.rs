use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use ieee_802154::types::{Eui64, Nwk};
use ieee_802154::{Ieee802154Address, Ieee802154Frame};

use crate::nwk::frame::EncryptedNwkFrame;

/// A finished 802.15.4 frame awaiting indirect delivery (802.15.4 spec 6.7.3).
///
/// The destination extracts it by polling with a MAC Data Request; the radio's
/// automatic ACK of that poll has its frame pending bit set (via the source address
/// match table), telling the device to keep listening.
#[derive(Debug)]
pub struct Transaction<C> {
    /// The frame as queued; the frame pending bit is applied to a copy at delivery
    /// time, based on whether more transactions remain.
    pub frame: Ieee802154Frame<EncryptedNwkFrame>,
    pub expires_at: Instant,
    /// The driver's completion token, resolved on delivery, expiry, or drop.
    pub completion: C,
}

/// A transaction extracted by a poll, ready for transmission.
#[derive(Debug)]
pub struct Delivery<C> {
    /// The queue key the transaction was extracted from
    pub destination: Ieee802154Address,
    pub transaction: Transaction<C>,
    /// Further transactions remain queued: the delivered frame's pending bit is set
    /// so the device keeps polling (802.15.4 spec 6.7.3)
    pub more_pending: bool,
}

/// What a poll extracted from the queue.
#[derive(Debug)]
pub struct PollOutcome<C> {
    /// Transactions that expired at the head of the queue, to be failed
    pub expired: Vec<(Ieee802154Address, Transaction<C>)>,
    /// The oldest live transaction, if any
    pub delivery: Option<Delivery<C>>,
}

/// The source address match table contents most recently written to the RCP, used to
/// tell whether the auto-ACK of a given poll advertised frame-pending=1.
#[derive(Debug, Default)]
pub struct SrcMatchTable {
    pub short_addresses: HashSet<Nwk>,
    pub extended_addresses: HashSet<Eui64>,
}

impl SrcMatchTable {
    pub fn contains(&self, address: Ieee802154Address) -> bool {
        match address {
            Ieee802154Address::Nwk(nwk) => self.short_addresses.contains(&nwk),
            Ieee802154Address::Eui64(eui64) => self.extended_addresses.contains(&eui64),
        }
    }
}

/// The indirect transaction queue: frames awaiting extraction by polling devices.
///
/// Transactions are kept in arrival order. Keys are whichever address form the frame
/// was queued under; a poll is matched against both its extended and short source
/// address.
#[derive(Debug)]
pub struct IndirectQueue<C> {
    /// How long a transaction awaits a poll before expiring
    persistence_time: Duration,
    queue: HashMap<Ieee802154Address, VecDeque<Transaction<C>>>,
}

impl<C> IndirectQueue<C> {
    pub fn new(persistence_time: Duration) -> Self {
        Self {
            persistence_time,
            queue: HashMap::new(),
        }
    }

    pub fn push(
        &mut self,
        destination: Ieee802154Address,
        frame: Ieee802154Frame<EncryptedNwkFrame>,
        completion: C,
        now: Instant,
    ) {
        self.queue
            .entry(destination)
            .or_default()
            .push_back(Transaction {
                frame,
                expires_at: now + self.persistence_time,
                completion,
            });
    }

    /// 802.15.4 spec 6.7.3: a transaction is only extracted once acknowledged, so a
    /// failed transmit goes back to the head of the queue for the next poll, keeping
    /// its original deadline.
    pub fn requeue(&mut self, destination: Ieee802154Address, transaction: Transaction<C>) {
        self.queue
            .entry(destination)
            .or_default()
            .push_front(transaction);
    }

    pub fn has_queued(&self, destination: Ieee802154Address) -> bool {
        self.queue.contains_key(&destination)
    }

    /// Match a poll against the queue: pop the oldest live transaction queued under
    /// either of the polling device's addresses, also popping any expired
    /// transactions found ahead of it.
    pub fn extract(
        &mut self,
        eui64: Option<Eui64>,
        nwk: Option<Nwk>,
        now: Instant,
    ) -> PollOutcome<C> {
        let keys = eui64
            .map(Ieee802154Address::Eui64)
            .into_iter()
            .chain(nwk.map(Ieee802154Address::Nwk));

        let mut expired = Vec::new();

        for key in keys {
            let Some(transactions) = self.queue.get_mut(&key) else {
                continue;
            };

            while let Some(transaction) = transactions.pop_front() {
                if transaction.expires_at <= now {
                    expired.push((key, transaction));
                    continue;
                }

                // The deque is intentionally kept (even when empty) until the
                // delivery resolves: the device keeps polling with frame-pending=1
                // while its transaction is in flight, and a failed transmit requeues
                let more_pending = !transactions.is_empty();

                return PollOutcome {
                    expired,
                    delivery: Some(Delivery {
                        destination: key,
                        transaction,
                        more_pending,
                    }),
                };
            }

            self.queue.remove(&key);
        }

        PollOutcome {
            expired,
            delivery: None,
        }
    }

    /// Remove the destination's queue once a resolved delivery leaves it empty.
    /// Returns whether the set of queued addresses changed.
    pub fn remove_if_empty(&mut self, destination: Ieee802154Address) -> bool {
        if self.queue.get(&destination).is_some_and(VecDeque::is_empty) {
            self.queue.remove(&destination);
            return true;
        }

        false
    }

    /// Drop every transaction queued under either of a device's addresses, returning
    /// them for resolution. Used when the device is no longer a child.
    pub fn drop_for(
        &mut self,
        eui64: Option<Eui64>,
        nwk: Nwk,
    ) -> Vec<(Ieee802154Address, Transaction<C>)> {
        let keys = eui64
            .map(Ieee802154Address::Eui64)
            .into_iter()
            .chain([Ieee802154Address::Nwk(nwk)]);

        let mut dropped = Vec::new();

        for key in keys {
            if let Some(transactions) = self.queue.remove(&key) {
                dropped.extend(
                    transactions
                        .into_iter()
                        .map(|transaction| (key, transaction)),
                );
            }
        }

        dropped
    }

    /// Pop every transaction whose deadline has passed, returning them for
    /// resolution. Transactions expire in arrival order: they are queued with a
    /// uniform persistence time and requeued transmit failures keep their deadline.
    pub fn expire(&mut self, now: Instant) -> Vec<(Ieee802154Address, Transaction<C>)> {
        let mut expired = Vec::new();

        self.queue.retain(|&destination, transactions| {
            while transactions
                .front()
                .is_some_and(|transaction| transaction.expires_at <= now)
            {
                expired.push((destination, transactions.pop_front().unwrap()));
            }

            !transactions.is_empty()
        });

        expired
    }

    /// The earliest transaction deadline, for scheduling the expiry sweep. Each
    /// queue's front is its earliest deadline.
    pub fn next_expiry(&self) -> Option<Instant> {
        self.queue
            .values()
            .filter_map(|transactions| transactions.front())
            .map(|transaction| transaction.expires_at)
            .min()
    }

    /// The source address match table the RCP should hold: every device with queued
    /// transactions, under both its address forms (the device may poll with either).
    pub fn queued_addresses(&self, address_map: &HashMap<Eui64, Nwk>) -> SrcMatchTable {
        let mut table = SrcMatchTable::default();

        for key in self.queue.keys() {
            match key {
                Ieee802154Address::Eui64(eui64) => {
                    table.extended_addresses.insert(*eui64);

                    if let Some(nwk) = address_map.get(eui64) {
                        table.short_addresses.insert(*nwk);
                    }
                }
                Ieee802154Address::Nwk(nwk) => {
                    table.short_addresses.insert(*nwk);
                }
            }
        }

        table
    }
}
