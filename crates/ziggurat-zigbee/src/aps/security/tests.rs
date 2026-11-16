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

const OLD_KEY: Key = Key([0x11; 16]);
const NEW_KEY: Key = Key([0x22; 16]);

fn device() -> Eui64 {
    Eui64::from_be_bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
}

/// Receive a frame from `device()` secured with `key` and carrying `frame_counter`;
/// whether it was accepted.
fn receive(security: &mut ApsSecurity, key: &Key, frame_counter: u32) -> bool {
    let aux_header = ApsAuxHeader {
        security_control: NwkSecurityHeaderControlField {
            security_level: NwkSecurityLevel::NoSecurity,
            key_id: NwkSecurityHeaderKeyId::DataKey,
            extended_nonce: true,
            require_verified_frame_counter: false,
        },
        frame_counter,
        extended_source: Some(device()),
        key_sequence_number: None,
    };

    security
        .decrypt_frame(device(), &aux_header, &Key([0xFF; 16]), |candidate| {
            (candidate == key).then_some(())
        })
        .is_some()
}

/// A device with a verified key whose frames we have seen up to a high counter.
fn device_with_used_key() -> ApsSecurity {
    let mut security = security();
    security.restore_device_key(device(), OLD_KEY);
    security.restore_incoming_frame_counter(device(), 4097);
    security
}

#[test]
fn test_same_key_replay_is_rejected() {
    let mut security = device_with_used_key();

    assert!(!receive(&mut security, &OLD_KEY, 4096));
    assert!(receive(&mut security, &OLD_KEY, 4097));
    assert!(!receive(&mut security, &OLD_KEY, 4097));
    assert_eq!(security.incoming_frame_counter(device()), Some(4098));
}

// Spec 4.4.8.1.3 step 6: frames under a newly verified key start their own counter.
#[test]
fn test_verified_new_key_resets_incoming_counter() {
    let mut security = device_with_used_key();

    security.issue_device_key(device(), NEW_KEY);
    assert_eq!(
        security.verify_device_key(device(), &verify_key_hash(&NEW_KEY)),
        Some(true)
    );
    assert_eq!(security.incoming_frame_counter(device()), None);

    assert!(receive(&mut security, &NEW_KEY, 5));
    assert!(!receive(&mut security, &NEW_KEY, 5));
}

// A factory-new device counts its frames from scratch.
#[test]
fn test_fresh_join_resets_incoming_counter() {
    let mut security = device_with_used_key();

    assert_eq!(security.begin_join(device()), None);
    assert_eq!(security.incoming_frame_counter(device()), None);

    security.issue_device_key(device(), NEW_KEY);
    assert_eq!(
        security.verify_device_key(device(), &verify_key_hash(&NEW_KEY)),
        Some(true)
    );
    assert!(receive(&mut security, &NEW_KEY, 5));
}

// Verify-Key is sent unencrypted and its hash never changes for a key, so a replayed
// one must not reset the replay protection of the key it verifies.
#[test]
fn test_reverified_key_keeps_incoming_counter() {
    let mut security = device_with_used_key();

    assert_eq!(
        security.verify_device_key(device(), &verify_key_hash(&OLD_KEY)),
        Some(true)
    );
    assert_eq!(security.incoming_frame_counter(device()), Some(4097));
    assert!(!receive(&mut security, &OLD_KEY, 5));
}

// A TCLK seed issues the same key again, so its frame counter carries on.
#[test]
fn test_reissued_seed_key_keeps_incoming_counter() {
    let mut security = ApsSecurity::new(
        Key([0; 16]),
        Eui64::from_be_bytes([0; 8]),
        Some(TclkSeed {
            seed: Key([0x33; 16]),
            flavor: TclkFlavor::ZStack,
        }),
        PERSIST_INTERVAL,
    );
    let seed_key = security.device_link_key(device());
    security.restore_incoming_frame_counter(device(), 4097);

    let issued = security.issue_device_key(device(), NEW_KEY);
    assert_eq!(issued, seed_key);
    assert_eq!(
        security.verify_device_key(device(), &verify_key_hash(&issued)),
        Some(true)
    );
    assert_eq!(security.incoming_frame_counter(device()), Some(4097));
    assert!(!receive(&mut security, &seed_key, 5));
}

// A provisional install-code key survives a fresh join, its frame counter does not.
#[test]
fn test_fresh_join_keeps_provisional_key_and_resets_incoming_counter() {
    let mut security = security();
    security.set_provisional_key(device(), OLD_KEY);
    security.restore_incoming_frame_counter(device(), 4097);

    assert_eq!(security.begin_join(device()), Some(OLD_KEY));
    assert_eq!(security.incoming_frame_counter(device()), None);
    assert!(receive(&mut security, &OLD_KEY, 5));
}

// A seed-derived key is not stored, so a fresh join leaves nothing to keep.
#[test]
fn test_fresh_join_prunes_seed_device_counter() {
    let mut security = ApsSecurity::new(
        Key([0; 16]),
        Eui64::from_be_bytes([0; 8]),
        Some(TclkSeed {
            seed: Key([0x33; 16]),
            flavor: TclkFlavor::ZStack,
        }),
        PERSIST_INTERVAL,
    );
    security.restore_incoming_frame_counter(device(), 4097);

    assert_eq!(security.begin_join(device()), None);
    assert!(security.devices.get(&device()).is_none());
}
