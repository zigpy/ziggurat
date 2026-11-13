use super::*;
use alloc::vec;
use hex_literal::hex;
use rand::Rng;
use rand::RngExt;
use rand::SeedableRng;
use rand::rngs::StdRng;

const NOW: Duration = Duration::from_secs(100);

// A parsed response waits in the client until its command runs. Another request
// made in between must not get the same transaction id.
#[test]
fn test_transaction_id_is_not_reused_until_its_request_is_released() {
    let mut protocol = SpinelProtocol::new();
    let tid = protocol.allocate_tid(NOW).unwrap();
    let header = SpinelHeader {
        flag: 0b10,
        network_link_id: 0,
        transaction_id: tid,
    };

    let mut events = Vec::new();
    protocol.handle_inbound_frame(header, SpinelCommandId::PropValueIs, &[], &mut events);
    assert_eq!(events, [SpinelEvent::Response(tid)]);

    for _ in 0..12 {
        let other = protocol.allocate_tid(NOW).unwrap();
        assert_ne!(other, tid);
        protocol.release_request(other);
    }

    assert!(matches!(
        protocol.release_request(tid),
        Transaction::Answered(_)
    ));
    let reused = (0..7).any(|_| {
        let other = protocol.allocate_tid(NOW).unwrap();
        protocol.release_request(other);
        other == tid
    });
    assert!(reused);
}

#[test]
fn test_no_transaction_id_is_given_while_all_seven_are_in_use() {
    let mut protocol = SpinelProtocol::new();
    let mut tids: Vec<u8> = (0..7)
        .map(|_| protocol.allocate_tid(NOW).unwrap())
        .collect();
    tids.sort_unstable();
    assert_eq!(tids, [1, 2, 3, 4, 5, 6, 7]);

    assert_eq!(protocol.allocate_tid(NOW), None);

    protocol.release_request(4);
    assert_eq!(protocol.allocate_tid(NOW), Some(4));
}

/// A status notification that announces a reset.
fn reset_notification() -> (SpinelHeader, Vec<u8>) {
    let header = SpinelHeader {
        flag: 0b10,
        network_link_id: 0,
        transaction_id: 0,
    };
    let mut payload = packed_uint21_to_bytes(SpinelPropertyId::LastStatus as u32);
    payload.extend(packed_uint21_to_bytes(SpinelStatus::ResetPowerOn as u32));

    (header, payload)
}

// A response that already arrived survives the reset: its command still takes it.
#[test]
fn test_reset_cancels_the_requests_without_a_response() {
    let mut protocol = SpinelProtocol::new();
    let queued = protocol.allocate_tid(NOW).unwrap();
    let written = protocol.allocate_tid(NOW).unwrap();
    let answered = protocol.allocate_tid(NOW).unwrap();
    protocol.request_written(written);
    protocol.request_written(answered);

    let mut events = Vec::new();
    let response = SpinelProtocol::request_frame(answered, SpinelCommandId::PropValueIs, vec![]);
    protocol.handle_inbound_frame(response.header, response.command_id, &[], &mut events);

    let (header, payload) = reset_notification();
    protocol.handle_inbound_frame(header, SpinelCommandId::PropValueIs, &payload, &mut events);
    assert_eq!(
        events,
        [
            SpinelEvent::Response(answered),
            SpinelEvent::Reset(SpinelStatus::ResetPowerOn)
        ]
    );

    assert_eq!(protocol.release_request(queued), Transaction::Cancelled);
    assert_eq!(protocol.release_request(written), Transaction::Cancelled);
    assert!(matches!(
        protocol.release_request(answered),
        Transaction::Answered(_)
    ));
}

/// Whether a transaction id is among the next seven given out.
fn is_given_out(protocol: &mut SpinelProtocol, tid: u8, now: Duration) -> bool {
    let given: Vec<u8> = core::iter::from_fn(|| protocol.allocate_tid(now)).collect();
    for other in &given {
        protocol.release_request(*other);
    }

    given.contains(&tid)
}

// The response to an abandoned request must not reach a later command, so its
// transaction id is not given out until that response arrives.
#[test]
fn test_abandoned_transaction_id_returns_with_its_response() {
    let mut protocol = SpinelProtocol::new();
    let tid = protocol.allocate_tid(NOW).unwrap();
    protocol.request_written(tid);
    protocol.abandon_request(tid, NOW + Duration::from_secs(2));
    assert!(!is_given_out(&mut protocol, tid, NOW));

    let mut events = Vec::new();
    let response = SpinelProtocol::request_frame(tid, SpinelCommandId::PropValueIs, vec![]);
    protocol.handle_inbound_frame(response.header, response.command_id, &[], &mut events);

    assert_eq!(events, [SpinelEvent::LateResponse(tid)]);
    assert!(is_given_out(&mut protocol, tid, NOW));
}

#[test]
fn test_abandoned_transaction_id_returns_when_no_response_comes() {
    let mut protocol = SpinelProtocol::new();
    let tid = protocol.allocate_tid(NOW).unwrap();
    protocol.request_written(tid);

    let until = NOW + Duration::from_secs(2);
    protocol.abandon_request(tid, until);
    assert_eq!(protocol.next_abandoned_expiry(), Some(until));

    assert!(!is_given_out(
        &mut protocol,
        tid,
        until - Duration::from_millis(1)
    ));
    assert!(is_given_out(&mut protocol, tid, until));
    assert_eq!(protocol.next_abandoned_expiry(), None);
}

#[test]
fn test_reset_frees_an_abandoned_transaction_id() {
    let mut protocol = SpinelProtocol::new();
    let tid = protocol.allocate_tid(NOW).unwrap();
    protocol.request_written(tid);
    protocol.abandon_request(tid, NOW + Duration::from_secs(2));

    let (header, payload) = reset_notification();
    let mut events = Vec::new();
    protocol.handle_inbound_frame(header, SpinelCommandId::PropValueIs, &payload, &mut events);

    assert!(is_given_out(&mut protocol, tid, NOW));
}

#[test]
fn test_response_to_no_request_is_dropped() {
    let mut protocol = SpinelProtocol::new();
    let mut events = Vec::new();

    // Transaction ids 8 to 15 fit the header but we never use them
    for tid in [1, 15] {
        let response = SpinelProtocol::request_frame(tid, SpinelCommandId::PropValueIs, vec![]);
        protocol.handle_inbound_frame(response.header, response.command_id, &[], &mut events);
    }

    assert_eq!(events, []);
    assert_eq!(*protocol.transaction(1), Transaction::Free);
}

#[test]
fn test_uint21_to_bytes() {
    assert_eq!(packed_uint21_to_bytes(0x1FD7FC), hex!("fcaf7f").to_vec());
}

#[test]
fn test_uint21_deserialize() {
    let data = hex!("fcaf7fabcd");
    let (value, remaining) = packed_uint21_deserialize(&data).unwrap();

    assert_eq!(value, 0x1FD7FC);
    assert_eq!(remaining, hex!("abcd").to_vec());
}

#[test]
fn test_uint21_stress() {
    for value in 0..U21_MAX {
        let mut serialized = packed_uint21_to_bytes(value);
        serialized.extend(hex!("abcd"));

        let (parsed_value, remaining) = packed_uint21_deserialize(&serialized).unwrap();

        assert_eq!(value, parsed_value);
        assert_eq!(remaining, hex!("abcd").to_vec());
    }
}

#[test]
fn test_hdlc_lite_frame() {
    let frame = HdlcLiteFrame {
        // Special bytes interleaved with 00
        data: hex!("00 7E 00 7D 00 11 00 13 00 F8 00").to_vec(),
    };

    assert_eq!(
        frame.to_bytes(),
        hex!("00 7D5E 00 7D5D 00 7D31 00 7D33 00 7DD8 00 2881")
    );

    let parsed_frame = HdlcLiteFrame::from_bytes(&frame.to_bytes()).unwrap();
    assert_eq!(frame, parsed_frame);
}

#[test]
fn test_hdlc_lite_frame_vectors() {
    assert_eq!(
        HdlcLiteFrame {
            data: hex!("810243").to_vec()
        }
        .to_bytes(),
        hex!("810243d3d3")
    );

    assert_eq!(
        HdlcLiteFrame {
            data: hex!("8103367e7d").to_vec()
        }
        .to_bytes(),
        hex!("8103367d5e7d5d6af9")
    );
}

#[test]
fn test_hdlc_lite_frame_stress() {
    let mut rng = StdRng::seed_from_u64(0);

    for _ in 0..1000 {
        let len = rng.random_range(1..1000);
        let mut data = Vec::new();

        for _ in 0..len {
            data.push((rng.next_u32() & 0xFF) as u8);
        }

        let frame = HdlcLiteFrame { data: data.clone() };
        let parsed_frame = HdlcLiteFrame::from_bytes(&frame.to_bytes()).unwrap();

        assert_eq!(frame, parsed_frame);
    }
}

#[test]
fn test_spinel_header_parsing() {
    let data = hex!("81");
    let header = SpinelHeader::from_bytes(&data).unwrap();

    assert_eq!(
        header,
        SpinelHeader {
            flag: 0b10,
            network_link_id: 0,
            transaction_id: 1
        }
    );

    assert_eq!(header.to_bytes(), data);
}

#[test]
fn test_spinel_parsing_bulk() {
    let data = hex!("7E   81 02 02 5E 80   7E 7E   7E 81 02 02 5E 80  7E 81 02 02 5E 80 7E");
    let mut protocol = SpinelProtocol::new();

    let frames = protocol.parse_frames_from_bytes(&data);

    assert_eq!(
        frames,
        vec![
            SpinelFrame {
                header: SpinelHeader {
                    flag: 0b10,
                    network_link_id: 0,
                    transaction_id: 1
                },
                command_id: SpinelCommandId::PropValueGet,
                payload: vec![2]
            },
            SpinelFrame {
                header: SpinelHeader {
                    flag: 0b10,
                    network_link_id: 0,
                    transaction_id: 1
                },
                command_id: SpinelCommandId::PropValueGet,
                payload: vec![2]
            },
            SpinelFrame {
                header: SpinelHeader {
                    flag: 0b10,
                    network_link_id: 0,
                    transaction_id: 1
                },
                command_id: SpinelCommandId::PropValueGet,
                payload: vec![2]
            }
        ]
    );
}

#[test]
fn test_spinel_parsing_byte_by_byte() {
    let data = hex!("7E   81 02 02 5E 80   7E 7E   7E 81 02 02 5E 80  7E 81 02 02 5E 80 7E");

    let mut protocol = SpinelProtocol::new();
    let mut frames = Vec::new();

    for byte in data {
        frames.extend(protocol.parse_frames_from_bytes(&[byte]));
    }

    assert_eq!(
        frames,
        vec![
            SpinelFrame {
                header: SpinelHeader {
                    flag: 0b10,
                    network_link_id: 0,
                    transaction_id: 1
                },
                command_id: SpinelCommandId::PropValueGet,
                payload: vec![2]
            },
            SpinelFrame {
                header: SpinelHeader {
                    flag: 0b10,
                    network_link_id: 0,
                    transaction_id: 1
                },
                command_id: SpinelCommandId::PropValueGet,
                payload: vec![2]
            },
            SpinelFrame {
                header: SpinelHeader {
                    flag: 0b10,
                    network_link_id: 0,
                    transaction_id: 1
                },
                command_id: SpinelCommandId::PropValueGet,
                payload: vec![2]
            }
        ]
    );
}

#[test]
fn test_spinel_sending_request() {
    let mut protocol = SpinelProtocol::new();

    // Simulate sending a request. This transaction was taken from a universal-silabs-flasher
    // session with a real device.
    protocol.next_tid = 3;

    let request = SpinelProtocol::request_frame(
        protocol.allocate_tid(NOW).unwrap(),
        SpinelCommandId::PropValueGet,
        packed_uint21_to_bytes(SpinelPropertyId::NcpVersion as u32),
    );
    assert_eq!(
        request,
        SpinelFrame {
            header: SpinelHeader {
                flag: 0b10,
                network_link_id: 0,
                transaction_id: 3,
            },
            command_id: SpinelCommandId::PropValueGet,
            payload: packed_uint21_to_bytes(SpinelPropertyId::NcpVersion as u32)
        }
    );

    // Receive a response
    let mut events = Vec::new();
    protocol.handle_inbound_bytes(
        b"~\x83\x06\x02SL-OPENTHREAD/2.4.4.0_GitHub-7074a43e4; EFR32; Oct 21 2024 1",
        &mut events,
    );
    protocol.handle_inbound_bytes(b"4:40:57\x00\x81\xf7~", &mut events);

    assert_eq!(events, [SpinelEvent::Response(3)]);
    assert_eq!(
        protocol.release_request(3),
        Transaction::Answered(SpinelFrame {
            header: SpinelHeader {
                flag: 0b10,
                network_link_id: 0,
                transaction_id: 3,
            },
            command_id: SpinelCommandId::PropValueIs,
            payload: b"\x02SL-OPENTHREAD/2.4.4.0_GitHub-7074a43e4; EFR32; Oct 21 2024 14:40:57\x00"
                .to_vec()
        })
    );
}
