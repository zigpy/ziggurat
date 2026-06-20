//! Stands up a grid of pre-provisioned nodes on one in-process medium. The coordinator
//! is a concentrator (source routing): nodes reach it via many-to-one routes, which
//! plants source routes the coordinator then uses to reach back. Run:
//! `cargo run --release -p ziggurat-sim-server --example mesh_demo [grid_side]` (default 10).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::time::sleep;
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
const SPACING: f32 = 70.0;

/// Records, per receiving node, which source addresses it has delivered an APS frame
/// from. A task drains each node's notifications into it continuously, so a delivery is
/// never missed to a lagging broadcast receiver.
type Deliveries = Arc<Mutex<HashSet<(u16, u16)>>>;

fn config(index: u16) -> NetworkConfig {
    NetworkConfig {
        role: if index == 0 {
            NwkDeviceType::Coordinator
        } else {
            NwkDeviceType::Router
        },
        channel: CHANNEL,
        update_id: 0,
        pan_id: PanId(0x1234),
        extended_pan_id: Eui64([0xaa; 8]),
        network_address: Nwk(index),
        ieee_address: Eui64([0, 0, 0, 0, 0, 0, (index >> 8) as u8, index as u8]),
        network_key: WELL_KNOWN_LINK_KEY.clone(),
        network_key_seq_number: 0,
        network_key_tx_counter: 0,
        tc_link_key: WELL_KNOWN_LINK_KEY.clone(),
        tclk_seed: None,
        tx_power: 8,
        source_routing: index == 0,
    }
}

fn drain(index: u16, mut events: broadcast::Receiver<ZigbeeNotification>, deliveries: Deliveries) {
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(ZigbeeNotification::ReceivedApsCommand { source, .. }) => {
                    deliveries.lock().insert((index, source.0));
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

async fn deliver(
    sender: &Arc<ZigbeeStack<SimPhy>>,
    destination: u16,
    expected_source: u16,
    aps_seq: u8,
    deliveries: &Deliveries,
) -> String {
    let started = Instant::now();
    let sent = sender
        .send_aps_command(
            ApsDeliveryMode::Unicast,
            Nwk(destination),
            0x0104,
            0x0006,
            1,
            1,
            ApsAck::None,
            30,
            aps_seq,
            vec![0xab, 0xcd],
            None,
            TxPriority::USER_NORMAL,
        )
        .await;
    if let Err(error) = sent {
        return format!("no route ({error})");
    }

    while started.elapsed() < Duration::from_secs(5) {
        if deliveries.lock().contains(&(destination, expected_source)) {
            return format!("delivered in {:?}", started.elapsed());
        }
        sleep(Duration::from_millis(25)).await;
    }
    "sent, no delivery observed".to_string()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let side: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(10);
    let count = side * side;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { serve(listener).await });

    let deliveries: Deliveries = Arc::new(Mutex::new(HashSet::new()));

    println!("Bringing up a {side}x{side} grid ({count} nodes), {SPACING} units apart...");
    let mut stacks = Vec::new();
    for index in 0..count as u16 {
        let position = Position {
            x: (index as usize % side) as f32 * SPACING,
            y: (index as usize / side) as f32 * SPACING,
        };
        let phy = Arc::new(SimPhy::connect(addr, position).await.unwrap());
        let tunables = Tunables {
            link_status_period: Duration::from_millis(1000),
            mtorr_min_interval: Duration::from_secs(2),
            mtorr_max_interval: Duration::from_secs(2),
            ..Tunables::new()
        };
        let (stack, events) = ZigbeeStack::new(phy, config(index), tunables);
        stack.start_network().await.unwrap();
        let run = Arc::clone(&stack);
        stack.spawn_tracked(async move { run.run().await });
        drain(index, events, Arc::clone(&deliveries));
        stacks.push(stack);
    }

    println!("Settling 15s for link status + many-to-one route advertisements...");
    sleep(Duration::from_secs(15)).await;

    let mut aps_seq = 0u8;
    for (gx, gy) in [(4, 0), (6, 0), (8, 0), (side - 1, side - 1)] {
        let index = (gy * side + gx) as u16;
        println!(
            "--- target 0x{index:04x} at ({gx},{gy}), ~{} hops ---",
            gx + gy
        );

        aps_seq = aps_seq.wrapping_add(1);
        let up = deliver(&stacks[index as usize], 0, index, aps_seq, &deliveries).await;
        println!("  node -> coordinator (many-to-one): {up}");

        aps_seq = aps_seq.wrapping_add(1);
        let down = deliver(&stacks[0], index, 0, aps_seq, &deliveries).await;
        println!("  coordinator -> node (source route): {down}");
    }
}
