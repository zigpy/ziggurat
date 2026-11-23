//! The PHYs a node sends and receives on: the radio, and secondary PHYs such as a
//! backbone over IP.

/// The PHY a frame came in on or goes out on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PhyIndex {
    Radio,
    /// An index into the driver's secondary PHYs
    Secondary(u8),
}

/// A set of PHYs: bit 0 is the radio, bit `n + 1` is secondary PHY `n`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhySet(u32);

impl PhySet {
    /// The most secondary PHYs a set can hold.
    pub const MAX_SECONDARY: usize = 31;

    const fn bit(phy: PhyIndex) -> u32 {
        match phy {
            PhyIndex::Radio => 1,
            PhyIndex::Secondary(index) => 1 << (index + 1),
        }
    }

    /// The radio and `count` secondary PHYs: every PHY of a node.
    pub const fn radio_and_secondary(count: usize) -> Self {
        assert!(count <= Self::MAX_SECONDARY);
        Self(u32::MAX >> (Self::MAX_SECONDARY - count))
    }

    pub const fn only(phy: PhyIndex) -> Self {
        Self(Self::bit(phy))
    }

    pub const fn without(self, phy: PhyIndex) -> Self {
        Self(self.0 & !Self::bit(phy))
    }

    pub const fn contains(self, phy: PhyIndex) -> bool {
        self.0 & Self::bit(phy) != 0
    }

    /// The PHYs in the set, the radio first.
    pub fn iter(self) -> impl Iterator<Item = PhyIndex> {
        (0..=Self::MAX_SECONDARY as u8)
            .filter(move |&bit| self.0 & (1 << bit) != 0)
            .map(|bit| match bit {
                0 => PhyIndex::Radio,
                bit => PhyIndex::Secondary(bit - 1),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn test_phy_set() {
        let all = PhySet::radio_and_secondary(2);
        assert_eq!(
            all.iter().collect::<Vec<_>>(),
            vec![
                PhyIndex::Radio,
                PhyIndex::Secondary(0),
                PhyIndex::Secondary(1)
            ]
        );

        let relay = all.without(PhyIndex::Secondary(0));
        assert!(!relay.contains(PhyIndex::Secondary(0)));
        assert!(relay.contains(PhyIndex::Secondary(1)));

        assert_eq!(
            PhySet::radio_and_secondary(0),
            PhySet::only(PhyIndex::Radio)
        );
        assert_eq!(PhySet::radio_and_secondary(31).iter().count(), 32);
    }
}
