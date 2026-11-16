use ziggurat_ieee_802154::types::{Eui64, Key};

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

const JOINER: Eui64 = Eui64::from_be_bytes([0x10; 8]);
const FIRST_KEY: Key = Key([0x31; 16]);
const SECOND_KEY: Key = Key([0x42; 16]);

#[test]
fn test_repeated_request_key_reissues_the_pending_key() {
    let mut security = security();

    // A retried Request-Key, or one crossing our Transport-Key in flight
    assert_eq!(
        security.issue_device_key(JOINER, FIRST_KEY, AppliedKey::Global),
        FIRST_KEY
    );
    assert_eq!(
        security.issue_device_key(JOINER, SECOND_KEY, AppliedKey::Global),
        FIRST_KEY
    );

    // The device installed the first key it was sent and verifies that one
    assert_eq!(
        security.verify_device_key(JOINER, &verify_key_hash(&FIRST_KEY)),
        Some(true)
    );
    assert_eq!(security.device_link_key(JOINER), FIRST_KEY);
}

#[test]
fn test_pending_key_is_not_resent_under_another_key() {
    const THIRD_KEY: Key = Key([0x53; 16]);
    let mut security = security();
    security.set_provisional_key(JOINER, Key([0x77; 16]));

    // Sent under the install-code key, so a request under the well-known key (which
    // anyone holding the network key can send) must not get the same key back
    assert_eq!(
        security.issue_device_key(JOINER, FIRST_KEY, AppliedKey::Device),
        FIRST_KEY
    );
    assert_eq!(
        security.issue_device_key(JOINER, SECOND_KEY, AppliedKey::Global),
        SECOND_KEY
    );

    // Nor does the device get back the key sent under the well-known key
    assert_eq!(
        security.issue_device_key(JOINER, THIRD_KEY, AppliedKey::Device),
        THIRD_KEY
    );
}

#[test]
fn test_different_provisional_key_drops_the_pending_key() {
    let mut security = security();
    security.set_provisional_key(JOINER, Key([0x77; 16]));
    security.issue_device_key(JOINER, FIRST_KEY, AppliedKey::Device);

    // Registering the same install code again changes nothing
    security.set_provisional_key(JOINER, Key([0x77; 16]));
    assert_eq!(
        security.issue_device_key(JOINER, SECOND_KEY, AppliedKey::Device),
        FIRST_KEY
    );

    // Sent under the old install-code key, so not reissued under the new one
    security.set_provisional_key(JOINER, Key([0x78; 16]));
    assert_eq!(
        security.issue_device_key(JOINER, SECOND_KEY, AppliedKey::Device),
        SECOND_KEY
    );
}

#[test]
fn test_different_restored_key_drops_the_pending_key() {
    let mut security = security();
    security.restore_device_key(JOINER, Key([0x77; 16]));
    security.issue_device_key(JOINER, FIRST_KEY, AppliedKey::Device);

    // Restoring the same key again changes nothing
    security.restore_device_key(JOINER, Key([0x77; 16]));
    assert_eq!(
        security.issue_device_key(JOINER, SECOND_KEY, AppliedKey::Device),
        FIRST_KEY
    );

    // Sent under the old key, so not reissued under the restored one
    security.restore_device_key(JOINER, Key([0x78; 16]));
    assert_eq!(
        security.issue_device_key(JOINER, SECOND_KEY, AppliedKey::Device),
        SECOND_KEY
    );
}

#[test]
fn test_fresh_join_drops_the_pending_key() {
    let mut security = security();

    security.issue_device_key(JOINER, FIRST_KEY, AppliedKey::Global);
    assert_eq!(security.begin_join(JOINER), None);

    assert_eq!(
        security.issue_device_key(JOINER, SECOND_KEY, AppliedKey::Global),
        SECOND_KEY
    );
    assert_eq!(
        security.verify_device_key(JOINER, &verify_key_hash(&FIRST_KEY)),
        Some(false)
    );
}

#[test]
fn test_request_key_after_verification_issues_a_new_key() {
    let mut security = security();

    security.issue_device_key(JOINER, FIRST_KEY, AppliedKey::Global);
    assert_eq!(
        security.verify_device_key(JOINER, &verify_key_hash(&FIRST_KEY)),
        Some(true)
    );

    assert_eq!(
        security.issue_device_key(JOINER, SECOND_KEY, AppliedKey::Global),
        SECOND_KEY
    );
}

#[test]
fn test_seed_derived_key_is_issued_on_every_request() {
    let seed = TclkSeed {
        seed: Key([0x5A; 16]),
        flavor: TclkFlavor::ZStack,
    };
    let derived = seed.derive(JOINER);
    let mut security = ApsSecurity::new(
        Key([0; 16]),
        Eui64::from_be_bytes([0; 8]),
        Some(seed),
        PERSIST_INTERVAL,
    );

    assert_eq!(
        security.issue_device_key(JOINER, FIRST_KEY, AppliedKey::Global),
        derived
    );
    assert_eq!(
        security.issue_device_key(JOINER, SECOND_KEY, AppliedKey::Global),
        derived
    );
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
