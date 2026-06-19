use std::collections::HashMap;

use ieee_802154::types::{Eui64, Key};

#[derive(Debug)]
enum NetworkKeyType {
    Standard = 1,
}

#[derive(Debug)]
struct NwkSecurityDescriptor {
    key_seq_number: u8,
    outgoing_frame_counter: u32,
    incoming_frame_counter_set: HashMap<Eui64, u32>,
    key: Key,
    #[allow(dead_code)]
    network_key_type: NetworkKeyType,
}

/// The outcome of advancing the outgoing NWK security frame counter.
#[derive(Debug)]
#[must_use = "the advanced counter must be written into the frame and persisted when \
    requested; dropping it risks reusing a counter or a rollback on restart"]
pub struct CounterAdvance {
    pub value: u32,
    /// The client's persisted copy of the counter should be refreshed: a rollback
    /// after a restart would make every device silently reject our frames
    pub should_persist: bool,
}

/// The NWK security material: the network key, its outgoing frame counter, and the
/// per-relayer incoming frame counters used for replay protection (spec 4.3.1.2).
#[derive(Debug)]
pub struct NwkSecurity {
    primary: NwkSecurityDescriptor,
    /// Key rotation is not yet implemented; the alternate material is a placeholder
    #[allow(dead_code)]
    alternate: NwkSecurityDescriptor,
    active_key_seq_number: u8,
    /// Indicates whether incoming NWK frames SHALL be all checked for freshness when
    /// the memory for incoming frame counts is exceeded.
    #[allow(dead_code)]
    all_fresh: bool,
    /// Every this many outgoing frames, a counter advance asks to be persisted
    persist_interval: u32,
}

impl NwkSecurity {
    pub fn new(
        key: Key,
        key_seq_number: u8,
        outgoing_frame_counter: u32,
        persist_interval: u32,
    ) -> Self {
        Self {
            primary: NwkSecurityDescriptor {
                key_seq_number,
                outgoing_frame_counter,
                incoming_frame_counter_set: HashMap::new(),
                key,
                network_key_type: NetworkKeyType::Standard,
            },
            alternate: NwkSecurityDescriptor {
                key_seq_number: 0,
                outgoing_frame_counter: 0,
                incoming_frame_counter_set: HashMap::new(),
                key: Key::from_hex("00000000000000000000000000000000"),
                network_key_type: NetworkKeyType::Standard,
            },
            active_key_seq_number: key_seq_number,
            all_fresh: false,
            persist_interval,
        }
    }

    pub fn network_key(&self) -> Key {
        self.primary.key.clone()
    }

    pub const fn key_seq_number(&self) -> u8 {
        self.primary.key_seq_number
    }

    pub const fn active_key_seq_number(&self) -> u8 {
        self.active_key_seq_number
    }

    pub const fn outgoing_frame_counter(&self) -> u32 {
        self.primary.outgoing_frame_counter
    }

    /// Advance the outgoing security frame counter. The counter must never wrap:
    /// that would reuse a CCM* nonce. The spec's remedy near the end of the counter
    /// space is key rotation, which is not yet implemented.
    pub const fn next_outgoing_frame_counter(&mut self) -> CounterAdvance {
        self.primary.outgoing_frame_counter =
            self.primary.outgoing_frame_counter.checked_add(1).unwrap();

        let value = self.primary.outgoing_frame_counter;

        CounterAdvance {
            value,
            should_persist: value.is_multiple_of(self.persist_interval),
        }
    }

    /// Validate an inbound secured frame's auxiliary header against the active
    /// security material, returning the key to decrypt it with. `None` rejects the
    /// frame: an unknown key sequence number, or a frame counter that rolled
    /// backward for the relaying device (replay protection, spec 4.3.1.2).
    pub fn inbound_network_key(
        &self,
        sender: Eui64,
        key_sequence_number: u8,
        frame_counter: u32,
    ) -> Option<Key> {
        if key_sequence_number != self.active_key_seq_number {
            tracing::debug!("Ignoring frame, key sequence number is unknown");
            return None;
        }

        // Spec 4.3.1.2 step 1: a frame counter at its maximum value is rejected
        // outright; the sender must rotate the network key before it wraps.
        if frame_counter == u32::MAX {
            tracing::debug!("Ignoring frame, frame counter is at its maximum value");
            return None;
        }

        match self.primary.incoming_frame_counter_set.get(&sender) {
            None => {
                tracing::debug!("Unknown sender, not validating frame counter");
            }
            Some(&last_stored_frame_counter) => {
                if frame_counter <= last_stored_frame_counter {
                    tracing::debug!(
                        "Ignoring frame, frame counter has rolled backward from \
                         {last_stored_frame_counter} to {frame_counter}"
                    );
                    return None;
                }
            }
        }

        Some(self.primary.key.clone())
    }

    /// Store the security frame counter of a successfully decrypted frame for its
    /// relaying device, the baseline for future replay checks.
    pub fn note_inbound_frame_counter(&mut self, sender: Eui64, frame_counter: u32) -> Option<u32> {
        self.primary
            .incoming_frame_counter_set
            .insert(sender, frame_counter)
    }
}
