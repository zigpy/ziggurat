use super::*;
use ziggurat_driver::ziggurat_ieee_802154::types::Key;

const NETWORK_KEY: Key = Key([3; 16]);
const IEEE: Eui64 = Eui64([2; 8]);

/// A server whose radio transport is already open but never driven, which is all a
/// `configure` needs.
fn test_server() -> ZigguratServer {
    let server = ZigguratServer::new(SerialConfig {
        device: String::new(),
        baudrate: 0,
        flow_control: FlowControlMode::None,
        reconnect_timeout: Duration::ZERO,
        reconnect_on_unresponsive: false,
    });
    *server.phy.try_lock().unwrap() = Some(Arc::new(Phy::new()));
    server
}

fn payload(
    network_key: Key,
    ieee_address: Eui64,
    nwk_counter: u32,
    aps_counter: u32,
) -> proto::ConfigurePayload {
    proto::ConfigurePayload {
        role: proto::NodeRole::Coordinator,
        source_routing: false,
        state: proto::NetworkState {
            channel: 15,
            nwk_update_id: 0,
            pan_id: PanId(0x1234),
            extended_pan_id: Eui64([1; 8]),
            nwk_address: Nwk(0x0000),
            ieee_address,
            network_key,
            network_key_seq: 0,
            network_key_tx_counter: nwk_counter,
            tc_link_key: Key(*b"ZigBeeAlliance09"),
            has_tclk_seed: false,
            tclk_seed: Key([0; 16]),
            tclk_flavor: proto::TclkFlavorId::ZStack,
            tx_power: DEFAULT_TX_POWER,
            aps_frame_counter: aps_counter,
        },
    }
}

async fn configure(server: &ZigguratServer, payload: proto::ConfigurePayload) {
    assert!(server.handle_configure(payload).await.is_ok());
}

/// Advance the current stack's counters as five NWK frames and two APS-encrypted ones
/// would.
fn transmit(server: &ZigguratServer) {
    let stack = server.current_stack().unwrap();
    for _ in 0..5 {
        let _ = stack.next_nwk_frame_counter();
    }
    let mut core = stack.state.core.lock();
    let counter = core.aib.aps_security.outgoing_frame_counter();
    core.aib
        .aps_security
        .restore_outgoing_frame_counter(counter + 2);
    drop(core);
}

/// The current stack's outgoing (NWK, APS) frame counters.
fn counters(server: &ZigguratServer) -> (u32, u32) {
    let stack = server.current_stack().unwrap();
    let state = proto::network_info_payload(&*stack, false).state;
    (state.network_key_tx_counter, state.aps_frame_counter)
}

#[tokio::test]
async fn test_reconfiguring_the_same_network_keeps_the_live_counters() {
    let server = test_server();
    configure(&server, payload(NETWORK_KEY, IEEE, 1000, 500)).await;
    transmit(&server);

    // A restarted client configures the stack from the counters it read earlier
    configure(&server, payload(NETWORK_KEY, IEEE, 1000, 500)).await;

    assert_eq!(counters(&server), (1005, 502));
}

#[tokio::test]
async fn test_reconfiguring_keeps_higher_requested_counters() {
    let server = test_server();
    configure(&server, payload(NETWORK_KEY, IEEE, 1000, 500)).await;
    transmit(&server);

    configure(&server, payload(NETWORK_KEY, IEEE, 2000, 1500)).await;

    assert_eq!(counters(&server), (2000, 1500));
}

#[tokio::test]
async fn test_another_network_key_takes_only_the_aps_counter_over() {
    let server = test_server();
    configure(&server, payload(NETWORK_KEY, IEEE, 1000, 500)).await;
    transmit(&server);

    // The APS nonces depend on the link keys and our IEEE address, not on the network key
    configure(&server, payload(Key([4; 16]), IEEE, 0, 0)).await;

    assert_eq!(counters(&server), (0, 502));
}

#[tokio::test]
async fn test_another_ieee_address_takes_no_counter_over() {
    let server = test_server();
    configure(&server, payload(NETWORK_KEY, IEEE, 1000, 500)).await;
    transmit(&server);

    configure(&server, payload(NETWORK_KEY, Eui64([5; 8]), 0, 0)).await;

    assert_eq!(counters(&server), (0, 0));
}
