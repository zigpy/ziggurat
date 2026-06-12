pub mod addresses;
pub mod broadcasts;
pub mod commands;
pub mod frame;
pub mod neighbors;
pub mod routing;
pub mod security;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NwkDeviceType {
    Coordinator = 0x00,
    Router = 0x01,
    EndDevice = 0x02,
}
