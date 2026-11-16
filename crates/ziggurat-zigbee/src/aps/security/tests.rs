use ziggurat_ieee_802154::types::{Eui64, Key};

use crate::aps::frame::{
    ApsCommandFrameCommand, ApsDeliveryMode, ApsFrameControl, ApsFrameType,
    ApsRequestKeyCommandFrame, ApsRequestKeyType,
};
use crate::nwk::frame::Nsdu;

use super::*;

const PERSIST_INTERVAL: u32 = 100;

fn security() -> ApsSecurity {
    ApsSecurity::new(
        Key([0; 16]),
        Eui64::from_be_bytes([0; 8]),
        None,
        PERSIST_INTERVAL,
    )
}

/// Encrypt `frames` frames, as far as the counter is concerned.
fn advance(security: &mut ApsSecurity, frames: u32) {
    for _ in 0..frames {
        security.next_outgoing_frame_counter();
    }
}

#[test]
fn test_counter_is_persisted_once_per_interval() {
    let mut security = security();

    advance(&mut security, PERSIST_INTERVAL - 1);
    assert_eq!(security.take_counter_to_persist(), None);

    advance(&mut security, 1);
    assert_eq!(security.take_counter_to_persist(), Some(PERSIST_INTERVAL));
    assert_eq!(security.take_counter_to_persist(), None);
}

// A caller that did not ask in time still gets the value, and the next one is a full
// interval after it.
#[test]
fn test_missed_call_persists_the_counter_at_the_next_one() {
    let mut security = security();

    advance(&mut security, PERSIST_INTERVAL + 30);
    assert_eq!(
        security.take_counter_to_persist(),
        Some(PERSIST_INTERVAL + 30)
    );

    advance(&mut security, PERSIST_INTERVAL - 1);
    assert_eq!(security.take_counter_to_persist(), None);
}

// The restored value may be one the client never stored, such as its own margin on top
// of what it had. The first frame after it tells the client where the counter is.
#[test]
fn test_restored_counter_is_persisted_at_the_first_frame() {
    let mut security = security();
    security.restore_outgoing_frame_counter(12_345);

    advance(&mut security, 1);
    assert_eq!(security.take_counter_to_persist(), Some(12_346));
}

/// A device's trust center link key request, APS-secured with `key_id` and encrypted
/// with `key` (the raw key, not derived further here).
fn request_key_secured_with(key_id: NwkSecurityHeaderKeyId, key: &Key, source: Eui64) -> Nsdu {
    let command = ApsCommandFrame {
        frame_control: ApsFrameControl {
            frame_type: ApsFrameType::Command,
            delivery_mode: ApsDeliveryMode::Unicast,
            reserved1: 0b0,
            security: true,
            ack_request: false,
            extended_header: false,
        },
        counter: 1,
        command: ApsCommandFrameCommand::RequestKey(ApsRequestKeyCommandFrame {
            key_type: ApsRequestKeyType::TrustCenterLinkKey,
            partner_address: None,
        }),
    };

    command.encrypt(
        key,
        &ApsAuxHeader {
            security_control: NwkSecurityHeaderControlField {
                security_level: NwkSecurityLevel::NoSecurity,
                key_id,
                extended_nonce: true,
                require_verified_frame_counter: false,
            },
            frame_counter: 1,
            extended_source: Some(source),
            // Present exactly when the network key secures the frame
            key_sequence_number: (key_id == NwkSecurityHeaderKeyId::NetworkKey).then_some(0),
        },
    )
}

// Spec 4.7.3.8 step 2: a trust center link key request must be secured with a key-pair
// entry. One secured with the network key decrypts, but must not count as a link key.
#[test]
fn test_request_key_under_the_network_key_is_not_link_key_secured() {
    const REQUESTER: Eui64 = Eui64::from_be_bytes([0x20; 8]);
    const NETWORK_KEY: Key = Key([0x11; 16]);
    let mut security = security();

    let frame =
        request_key_secured_with(NwkSecurityHeaderKeyId::NetworkKey, &NETWORK_KEY, REQUESTER);
    let frame = EncryptedApsCommandFrame::from_bytes(&frame).unwrap();
    let (_, applied) = security
        .decrypt_command(REQUESTER, &frame, &NETWORK_KEY)
        .unwrap();
    assert_eq!(applied, AppliedKey::Network);
    assert!(!applied.is_link_key());

    // The same request under the well-known link key is secured with a key-pair entry
    let frame = request_key_secured_with(NwkSecurityHeaderKeyId::DataKey, &Key([0; 16]), REQUESTER);
    let frame = EncryptedApsCommandFrame::from_bytes(&frame).unwrap();
    let (_, applied) = security
        .decrypt_command(REQUESTER, &frame, &NETWORK_KEY)
        .unwrap();
    assert_eq!(applied, AppliedKey::Global);
    assert!(applied.is_link_key());
    assert!(AppliedKey::Device.is_link_key());
}
