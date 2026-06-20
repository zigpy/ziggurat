//! End-to-end: a coordinator and a router, each a full `ZigbeeStack` on a `SimPhy`,
//! share one simulation medium. The router's active scan must surface the coordinator's
//! beacon — exercising both stacks and the medium with no hardware.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use ziggurat_driver::zigbee_stack::{
    NetworkConfig, NwkDeviceType, Tunables, WELL_KNOWN_LINK_KEY, ZigbeeStack,
};
use ziggurat_driver::ziggurat_ieee_802154::types::{Eui64, Nwk, PanId};
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

async fn spawn_stack(
    addr: std::net::SocketAddr,
    position: Position,
    config: NetworkConfig,
) -> Arc<ZigbeeStack<SimPhy>> {
    let phy = Arc::new(SimPhy::connect(addr, position).await.unwrap());
    let (stack, _notifications) = ZigbeeStack::new(phy, config, Tunables::new());
    stack.start_network().await.unwrap();

    let run_handle = Arc::clone(&stack);
    stack.spawn_tracked(async move { run_handle.run().await });
    stack
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn router_hears_coordinator_beacon() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { serve(listener).await });

    let _coordinator = spawn_stack(
        addr,
        Position { x: 0.0, y: 0.0 },
        config(NwkDeviceType::Coordinator, Nwk(0x0000), Eui64([1; 8])),
    )
    .await;
    let router = spawn_stack(
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

    let _coordinator = spawn_stack(
        addr,
        Position { x: 0.0, y: 0.0 },
        config(NwkDeviceType::Coordinator, Nwk(0x0000), Eui64([1; 8])),
    )
    .await;
    let router = spawn_stack(
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
