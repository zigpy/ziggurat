use std::collections::HashMap;

use ieee_802154::types::{Eui64, Nwk};

use crate::nwk::neighbors::Neighbors;

/// The EUI64-to-network-address map (the spec's `nwkAddressMap`), with the invariant
/// that a network address has a single owner.
#[derive(Debug)]
pub struct AddressMap {
    own_address: Nwk,
    map: HashMap<Eui64, Nwk>,
}

impl AddressMap {
    /// The map is seeded with our own mapping: relayed copies of our own frames
    /// carry our extended source and must not read as address conflicts.
    pub fn new(own_address: Nwk, own_eui64: Eui64) -> Self {
        Self {
            own_address,
            map: HashMap::from([(own_eui64, own_address)]),
        }
    }

    pub fn nwk_for(&self, eui64: Eui64) -> Option<Nwk> {
        self.map.get(&eui64).copied()
    }

    pub fn eui64_for(&self, nwk: Nwk) -> Option<Eui64> {
        self.map
            .iter()
            .find_map(|(&eui64, &mapped)| (mapped == nwk).then_some(eui64))
    }

    /// Record a mapping learned from a frame. Returns true when the network address
    /// is already claimed by a second IEEE address — an address conflict
    /// (spec 3.6.1.10.2); the mapping is left untouched in that case.
    pub fn update_mapping(&mut self, eui64: Eui64, nwk: Nwk) -> bool {
        if self.map.get(&eui64) == Some(&nwk) {
            return false;
        }

        if self.claimed_by_other(nwk, eui64) {
            return true;
        }

        match self.map.insert(eui64, nwk) {
            None => tracing::debug!("Added new address mapping: {eui64:?} -> {nwk:?}"),
            Some(old_nwk) => {
                tracing::warn!("Updated address mapping: {eui64:?} -> {nwk:?} (was {old_nwk:?})")
            }
        }

        false
    }

    /// Whether the network address belongs to a device other than the given one,
    /// including ourselves.
    pub fn claimed_by_other(&self, nwk: Nwk, eui64: Eui64) -> bool {
        nwk == self.own_address
            || self
                .map
                .iter()
                .any(|(&other_eui64, &other_nwk)| other_nwk == nwk && other_eui64 != eui64)
    }

    /// The network address for a joining device: its previous one if it has joined
    /// before, otherwise a fresh unused one.
    pub fn allocate(
        &self,
        eui64: Eui64,
        neighbors: &Neighbors,
        candidates: impl Iterator<Item = Nwk>,
    ) -> Nwk {
        self.nwk_for(eui64)
            .unwrap_or_else(|| self.generate_unused(neighbors, candidates))
    }

    /// The first candidate address that lies in the assigned range (0x0001-0xFFF7)
    /// and is not in use by us, the map, or the neighbor table. The candidate stream
    /// is the caller's randomness.
    pub fn generate_unused(
        &self,
        neighbors: &Neighbors,
        mut candidates: impl Iterator<Item = Nwk>,
    ) -> Nwk {
        candidates
            .find(|&candidate| {
                candidate.as_u16() != 0x0000
                    && candidate.as_u16() < 0xFFF8
                    && candidate != self.own_address
                    && !self.map.values().any(|&nwk| nwk == candidate)
                    && !neighbors.has_network_address(candidate)
            })
            .expect("Candidate address stream ended")
    }

    /// A device announced its address authoritatively: mappings of that address to
    /// any other IEEE address no longer have "a known valid 16-bit NWK address"
    /// and are evicted; the announcer's mapping is recorded.
    pub fn claim(&mut self, eui64: Eui64, nwk: Nwk) {
        self.evict_other_owners(nwk, eui64);
        self.map.insert(eui64, nwk);
    }

    /// Forget every mapping to a network address, e.g. one made ambiguous by an
    /// address conflict.
    pub fn forget_address(&mut self, nwk: Nwk) {
        self.map.retain(|_, &mut mapped| mapped != nwk);
    }

    fn evict_other_owners(&mut self, nwk: Nwk, owner: Eui64) {
        self.map.retain(|&eui64, &mut mapped| {
            let stale = mapped == nwk && eui64 != owner;
            if stale {
                tracing::info!(
                    "Forgetting stale address mapping {eui64:?} -> {nwk:?}, \
                     the address now belongs to {owner:?}"
                );
            }

            !stale
        });
    }

    /// The raw mapping, e.g. for completing indirect queue keys with the device's
    /// other address form.
    pub const fn map(&self) -> &HashMap<Eui64, Nwk> {
        &self.map
    }
}
