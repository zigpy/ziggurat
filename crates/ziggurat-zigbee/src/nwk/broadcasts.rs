use alloc::vec::Vec;
use core::time::Duration;

use crate::flat_map::{FlatMap, FlatSet};

use crate::Instant;

use ziggurat_ieee_802154::types::Nwk;

#[derive(Debug)]
struct Transaction {
    expiration_time: Instant,
    /// The router neighbors that were the transmission's audience, snapshotted when
    /// the transaction is created. A passive acknowledgment is expected only from
    /// audience members that are still live neighbors: routers that became
    /// neighbors later owe no ack, and routers that ceased being neighbors can
    /// never give one
    expected_relayers: Vec<Nwk>,
    /// Neighbors heard relaying this broadcast: their passive acknowledgments
    /// (spec 3.6.6)
    heard_from: FlatSet<Nwk>,
}

/// The NWK broadcast transaction table: deduplication of received broadcasts and
/// passive acknowledgment accounting (spec 3.6.6).
#[derive(Debug, Default)]
pub struct Broadcasts {
    table: FlatMap<(Nwk, u8), Transaction>,
}

impl Broadcasts {
    /// Digest a received broadcast. Returns true for a known transaction, which also
    /// records the sender's passive acknowledgment: the frame is a duplicate and must
    /// be filtered. An unknown broadcast creates a transaction expecting passive acks
    /// from the routers `audience` returns, and returns false: the frame is fresh and
    /// must be processed.
    pub fn filter_received(
        &mut self,
        source: Nwk,
        sequence_number: u8,
        sender: Nwk,
        audience: impl FnOnce() -> Vec<Nwk>,
        now: Instant,
        delivery_time: Duration,
    ) -> bool {
        self.table.retain(|_, entry| entry.expiration_time > now);

        if let Some(transaction) = self.table.get_mut(&(source, sequence_number)) {
            // Spec 3.6.6: a neighbor relaying a broadcast we know about is its
            // passive acknowledgment of that broadcast
            transaction.heard_from.insert(sender);
            return true;
        }

        self.table.insert(
            (source, sequence_number),
            Transaction {
                expiration_time: now + delivery_time,
                expected_relayers: audience(),
                // Whoever delivered the frame to us has already broadcast it
                heard_from: FlatSet::from([sender]),
            },
        );

        false
    }

    /// Record a broadcast we originate, so that copies relayed back to us by
    /// neighbors are filtered instead of re-processed (spec 3.6.6).
    pub fn record_transmission(
        &mut self,
        source: Nwk,
        sequence_number: u8,
        audience: Vec<Nwk>,
        now: Instant,
        delivery_time: Duration,
    ) {
        self.table.insert(
            (source, sequence_number),
            Transaction {
                expiration_time: now + delivery_time,
                expected_relayers: audience,
                heard_from: FlatSet::new(),
            },
        );
    }

    /// Spec 3.6.6: whether enough neighbors were heard relaying the broadcast.
    /// Only expected relayers that are still good neighbors count. We need `quorum`
    /// of them, or all of them if there are fewer. With none, the broadcast is never
    /// acked. An expired transaction is always acked.
    pub fn passively_acked(
        &self,
        source: Nwk,
        sequence_number: u8,
        is_live_relayer: impl Fn(Nwk) -> bool,
        quorum: usize,
    ) -> bool {
        self.table
            .get(&(source, sequence_number))
            .is_none_or(|transaction| {
                let mut audience = 0;
                let mut heard = 0;
                for &nwk in &transaction.expected_relayers {
                    if is_live_relayer(nwk) {
                        audience += 1;
                        heard += usize::from(transaction.heard_from.contains(&nwk));
                    }
                }

                audience > 0 && heard >= audience.min(quorum)
            })
    }
}
