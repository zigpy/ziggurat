use crate::types::{Eui64, Nwk};
use crate::Command;

use super::commands::*;
use hex_literal::hex;

#[test]
fn test_nwk_route_request_command() {
    let bytes = hex!("0100dea30501").to_vec();
    let command = NwkRouteRequestCommand::deserialize(&bytes).unwrap();

    assert_eq!(
        command,
        NwkRouteRequestCommand {
            many_to_one: NwkRouteRequestManyToOne::NotManyToOne,
            route_request_identifier: 222,
            destination_address: Nwk(0x05A3),
            path_cost: 1,
            destination_eui64: None,
        }
    );

    assert_eq!(command.serialize(), Ok(bytes));
}

#[test]
fn test_nwk_route_reply_command() {
    let bytes = hex!("02305f375f0a93037138210501881700aed31f0b01881700").to_vec();
    let command = NwkRouteReplyCommand::deserialize(&bytes).unwrap();

    assert_eq!(
        command,
        NwkRouteReplyCommand {
            route_request_identifier: 95,
            originator_nwk: Nwk(0x5F37),
            responder_nwk: Nwk(0x930A),
            path_cost: 3,
            originator_eui64: Some(Eui64::from_hex("00:17:88:01:05:21:38:71")),
            responder_eui64: Some(Eui64::from_hex("00:17:88:01:0b:1f:d3:ae")),
        }
    );

    assert_eq!(command.serialize(), Ok(bytes));
}

#[test]
fn test_nwk_route_record_command_empty() {
    let bytes = hex!("0500").to_vec();
    let command = NwkRouteRecordCommand::deserialize(&bytes).unwrap();

    assert_eq!(command, NwkRouteRecordCommand { relays: vec![] });

    assert_eq!(command.serialize(), Ok(bytes));
}

#[test]
fn test_nwk_route_record_command() {
    let bytes = hex!("0501eb1c").to_vec();
    let command = NwkRouteRecordCommand::deserialize(&bytes).unwrap();

    assert_eq!(
        command,
        NwkRouteRecordCommand {
            relays: vec![Nwk(0x1CEB)],
        }
    );

    assert_eq!(command.serialize(), Ok(bytes));
}

#[test]
fn test_nwk_link_status_command() {
    let bytes = hex!("0862e73c120ac711").to_vec();
    let command = NwkLinkStatusCommand::deserialize(&bytes).unwrap();

    assert_eq!(
        command,
        NwkLinkStatusCommand {
            is_first_frame: true, // byte 0x62 -> 0b01100010
            is_last_frame: true,
            link_statuses: vec![
                NwkLinkStatus {
                    address: Nwk(0x3CE7), // e7 3c
                    incoming_cost: 2,     // 12 -> 0b00010010 (inc=2, out=1)
                    outgoing_cost: 1,
                },
                NwkLinkStatus {
                    address: Nwk(0xC70A), // 0a c7
                    incoming_cost: 1,     // 11 -> 0b00010001 (inc=1, out=1)
                    outgoing_cost: 1,
                },
            ],
        }
    );

    assert_eq!(command.serialize(), Ok(bytes));
}

#[test]
fn test_nwk_leave_command() {
    let bytes = hex!("0400").to_vec();
    let command = NwkLeaveCommand::deserialize(&bytes).unwrap();

    assert_eq!(
        command,
        NwkLeaveCommand {
            rejoin: false,
            request: false,
            remove_children: false,
        }
    );

    assert_eq!(command.serialize(), Ok(bytes));
}

#[test]
fn test_nwk_end_device_timeout_request_command() {
    let bytes = hex!("0b0300").to_vec();
    let command = NwkEndDeviceTimeoutRequestCommand::deserialize(&bytes).unwrap();

    assert_eq!(
        command,
        NwkEndDeviceTimeoutRequestCommand {
            request_timeout_enum: EndDeviceTimeout::Minutes8,
        }
    );

    assert_eq!(command.serialize(), Ok(bytes));
}

#[test]
fn test_nwk_end_device_timeout_response_command() {
    let bytes = hex!("0c0003").to_vec();
    let command = NwkEndDeviceTimeoutResponseCommand::deserialize(&bytes).unwrap();

    assert_eq!(
        command,
        NwkEndDeviceTimeoutResponseCommand {
            status: NwkEndDeviceTimeoutResponseStatus::Success,
            mac_data_poll_keepalive_supported: true,
            end_device_timeout_request_keepalive_supported: true,
            power_negotation_support: false,
        }
    );

    assert_eq!(command.serialize(), Ok(bytes));
}
