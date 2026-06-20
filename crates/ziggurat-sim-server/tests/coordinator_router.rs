//! End-to-end: a coordinator and a router, each a full `ZigbeeStack` on a `SimPhy`,
//! share one simulation medium. The router's active scan must surface the coordinator's
//! beacon — exercising both stacks and the medium with no hardware.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};
use tokio::time::{sleep, timeout};
use ziggurat_driver::zigbee_stack::{
    ApsAck, NetworkConfig, NwkDeviceType, Tunables, TxPriority, WELL_KNOWN_LINK_KEY,
    ZigbeeNotification, ZigbeeStack,
};
use ziggurat_driver::ziggurat_ieee_802154::types::{Eui64, Nwk, PanId};
use ziggurat_driver::ziggurat_zigbee::aps::frame::ApsDeliveryMode;
use ziggurat_radio_sim::SimPhy;
use ziggurat_radio_sim::proto::Position;
use ziggurat_sim_server::serve;

const CHANNEL: u8 = 15;

fn config(role: NwkDeviceType, network_address: Nwk, ieee_address: Eui64) -> NetworkConfig {
    NetworkConfig {
        role,
        channel: CHANNEL,
        update_id: 0,
        pan_id: PanId(0x1234),
        extended_pan_id: Eui64([0xaa; 8]),
        network_address,
        ieee_address,
        network_key: WELL_KNOWN_LINK_KEY.clone(),
        network_key_seq_number: 0,
        network_key_tx_counter: 0,
        tc_link_key: WELL_KNOWN_LINK_KEY.clone(),
        tclk_seed: None,
        tx_power: 8,
        source_routing: false,
    }
}

const fn fast_tunables() -> Tunables {
    Tunables {
        link_status_period: Duration::from_millis(200),
        ..Tunables::new()
    }
}

async fn spawn_stack(
    addr: std::net::SocketAddr,
    position: Position,
    config: NetworkConfig,
) -> (
    Arc<ZigbeeStack<SimPhy>>,
    broadcast::Receiver<ZigbeeNotification>,
) {
    let phy = Arc::new(SimPhy::connect(addr, position).await.unwrap());
    let (stack, notifications) = ZigbeeStack::new(phy, config, fast_tunables());
    stack.start_network().await.unwrap();

    let run_handle = Arc::clone(&stack);
    stack.spawn_tracked(async move { run_handle.run().await });
    (stack, notifications)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn router_hears_coordinator_beacon() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { serve(listener).await });

    let (_coordinator, _) = spawn_stack(
        addr,
        Position { x: 0.0, y: 0.0 },
        config(NwkDeviceType::Coordinator, Nwk(0x0000), Eui64([1; 8])),
    )
    .await;
    let (router, _) = spawn_stack(
        addr,
        Position { x: 10.0, y: 0.0 },
        config(NwkDeviceType::Router, Nwk(0x1234), Eui64([2; 8])),
    )
    .await;

    // Let both nodes' channel registrations reach the medium before scanning.
    sleep(Duration::from_millis(50)).await;

    let (found_tx, mut found_rx) = mpsc::channel(8);
    router
        .network_scan(&[CHANNEL], Duration::from_millis(300), found_tx)
        .await
        .unwrap();

    let beacon = timeout(Duration::from_secs(1), found_rx.recv())
        .await
        .expect("scan did not complete in time")
        .expect("expected a beacon from the coordinator");

    assert_eq!(beacon.source, Some(Nwk(0x0000)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn router_out_of_range_hears_nothing() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { serve(listener).await });

    let (_coordinator, _) = spawn_stack(
        addr,
        Position { x: 0.0, y: 0.0 },
        config(NwkDeviceType::Coordinator, Nwk(0x0000), Eui64([1; 8])),
    )
    .await;
    let (router, _) = spawn_stack(
        addr,
        Position { x: 500.0, y: 0.0 },
        config(NwkDeviceType::Router, Nwk(0x1234), Eui64([2; 8])),
    )
    .await;

    sleep(Duration::from_millis(50)).await;

    let (found_tx, mut found_rx) = mpsc::channel(8);
    router
        .network_scan(&[CHANNEL], Duration::from_millis(300), found_tx)
        .await
        .unwrap();

    assert!(found_rx.recv().await.is_none());
}

// Coordinator (0,0), relay (60,0), far node (130,0): the far node is out of the
// coordinator's direct range, so an APS unicast to it must be relayed via the middle
// router. Proves MAC-ack-driven routing across a multi-hop topology.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_hop_unicast_relays_to_far_node() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { serve(listener).await });

    let (coordinator, _) = spawn_stack(
        addr,
        Position { x: 0.0, y: 0.0 },
        config(NwkDeviceType::Coordinator, Nwk(0x0000), Eui64([1; 8])),
    )
    .await;
    let (_relay, _) = spawn_stack(
        addr,
        Position { x: 60.0, y: 0.0 },
        config(NwkDeviceType::Router, Nwk(0x0001), Eui64([2; 8])),
    )
    .await;
    let (_far, mut far_events) = spawn_stack(
        addr,
        Position { x: 130.0, y: 0.0 },
        config(NwkDeviceType::Router, Nwk(0x0002), Eui64([3; 8])),
    )
    .await;

    // Let several link-status rounds establish bidirectional neighbor costs.
    sleep(Duration::from_secs(2)).await;

    coordinator
        .send_aps_command(
            ApsDeliveryMode::Unicast,
            Nwk(0x0002),
            0x0104,
            0x0006,
            1,
            1,
            ApsAck::None,
            30,
            0,
            vec![0xab, 0xcd],
            None,
            TxPriority::USER_NORMAL,
        )
        .await
        .unwrap();

    let received = timeout(Duration::from_secs(5), async {
        loop {
            match far_events.recv().await {
                Ok(ZigbeeNotification::ReceivedApsCommand { source, data, .. }) => {
                    return (source, data);
                }
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => panic!("notifications closed"),
            }
        }
    })
    .await
    .expect("far node did not receive the relayed APS frame");

    assert_eq!(received.0, Nwk(0x0000));
    assert_eq!(received.1, vec![0xab, 0xcd]);
}
