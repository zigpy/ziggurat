use wire_format::{u1, u2, u3, u4, zigbee_bytes};

/// Zigbee spec compressed: 3.4.8.3
#[zigbee_bytes]
// #[derive(Debug, Clone, PartialEq)]
pub struct NwkLinkStatusCommand {
    reserved: u4,
    pub is_first_frame: bool,
    pub is_last_frame: bool,
    reserved: u1,
    pub link_statuses: Vec<NwkLinkStatus>,
}

#[zigbee_bytes]
// #[derive(Debug, Clone, PartialEq)]
pub struct NwkLinkStatus {
    address: Nwk,
    incoming_cost: u3,
    reserved: u1,
    outgoing_cost: u3,
    reserved: u1,
}


#[zigbee_bytes]
// #[derive(Debug, Eq, Hash, Copy, Clone, PartialEq)]
pub struct Nwk(pub u16);


#[zigbee_bytes]
struct Test {
    list: Vec<u8>,
}

// #[test]
// fn main() {
//
// }
