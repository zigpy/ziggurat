//! Simulation radio backend.
//!
//! [`SimPhy`] implements [`ziggurat_phy::RadioPhy`] over a socket to a medium server
//! (`ziggurat-sim-server`): transmits are sent to the server, which fans them out to the
//! other nodes listening on the same channel. Lets many Ziggurat processes share a
//! virtual radio with no hardware.

pub mod proto;

mod phy;

pub use phy::SimPhy;
