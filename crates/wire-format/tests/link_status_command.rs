use wire_format::zigbee_bytes;

// #[wire_format::zigbee_bytes]
// #[derive(Debug, Clone, PartialEq)]
// pub struct Eui64(pub [u8; 8]);

/// Zigbee spec compressed: 3.4.8.3
#[zigbee_bytes]
#[derive(Debug, Clone, PartialEq)]
pub struct NwkLinkStatusCommand {
    #[wire_format(length_of = link_statuses)]
    reserved: u5,
    pub is_first_frame: bool,
    pub is_last_frame: bool,
    reserved: u1,
    pub link_statuses: Vec<u8>, // edit for testing sake
}

// /// Zigbee spec 3.4.1
// #[zigbee_bytes]
// #[derive(Debug, Clone, PartialEq)]
// pub struct NwkRouteRequestCommand {
//     reserved: u3,
//     pub many_to_one: NwkRouteRequestManyToOne,
//     #[wire_format(controls = destination_eui64)]
//     reserved: bool,
//     reserved: u2,
//     pub route_request_identifier: u8,
//     pub destination_address: Nwk,
//     pub path_cost: u8,
//     pub destination_eui64: Option<Eui64>,
//     pub tlvs: Vec<u8>,
// }
//
// #[derive(Debug, Clone, Copy, PartialEq)]
// #[wire_format::zigbee_bytes(bits=2)]
// #[repr(u8)]
// pub enum NwkRouteRequestManyToOne {
//     NotManyToOne = 0,
//     ManyToOneSenderSupportsRouteRecordTable = 1,
//     ManyToOneSenderDoesntSupportRouteRecordTable = 2,
//     Reserved = 3,
// }

// #[wire_format::zigbee_bytes]
// struct TestEnum {
//     reserved: u3,
//     thing: NwkRouteRequestManyToOne,
//     reserved: u5,
// }

// #[wire_format::zigbee_bytes]
// #[derive(Debug, Clone, PartialEq)]
// pub struct NwkRouteReplyCommand {
//     reserved: u3,
//     #[wire_format(controls = originator_eui64)]
//     reserved: bool,
//     #[wire_format(controls = responder_eui64)]
//     reserved: bool,
//     reserved: u3,
//
//     pub multicast: bool,
//     pub route_request_identifier: u8,
//     pub originator_nwk: Nwk,
//     pub responder_nwk: Nwk,
//     pub path_cost: u8,
//     pub originator_eui64: Option<Eui64>,
//     pub responder_eui64: Option<Eui64>,
//     pub tlvs: Vec<u8>,
// }
//
// #[zigbee_bytes]
// #[derive(Debug, Clone, PartialEq)]
// pub struct Eui64(u64);

// /// Zigbee spec compressed: 3.4.8.3
// #[zigbee_bytes]
// // #[derive(Debug, Clone, PartialEq)]
// pub struct NwkLinkStatusCommand {
//     reserved: u4,
//     pub is_first_frame: bool,
//     pub is_last_frame: bool,
//     reserved: u1,
//     pub link_statuses: Vec<NwkLinkStatus>,
// }
//
// #[zigbee_bytes]
// // #[derive(Debug, Clone, PartialEq)]
// pub struct NwkLinkStatus {
//     address: Nwk,
//     incoming_cost: u3,
//     reserved: u1,
//     outgoing_cost: u3,
//     reserved: u1,
// }

#[zigbee_bytes]
#[derive(Debug, Clone, PartialEq)]
pub struct Nwk(pub u16);

// #[zigbee_bytes]
// struct Test {
//     list: Vec<u8>,
// }

// #[test]
// fn main() {
//
// }
