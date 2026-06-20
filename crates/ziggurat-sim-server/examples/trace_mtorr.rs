//! A line of nodes (coordinator at one end, source routing on) so a single many-to-one
//! route advertisement floods deterministically hop by hop. Run with logging to follow
//! it: `RUST_LOG=ziggurat_driver::zigbee_stack::route=debug cargo run -p ziggurat-sim-server
//! --example trace_mtorr [line_len]`.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::time::{sleep, timeout};
use tracing_subscriber::EnvFilter;
use ziggurat_driver::zigbee_stack::{
    ApsAck, NetworkConfig, NwkDeviceType, Tunables, TxPriority, WELL_KNOWN_LINK_KEY,
    ZigbeeNotification, ZigbeeStack,
};
use ziggurat_driver::ziggurat_ieee_802154::types::{Eui64, Nwk, PanId};
use ziggurat_driver::ziggurat_zigbee::aps::frame::ApsDeliveryMode;
use ziggurat_radio_sim::SimPhy;
use ziggurat_radio_sim::proto::Position;
use ziggurat_sim_server::serve;

fn config(index: u16) -> NetworkConfig {
    NetworkConfig {
        role: if index == 0 {
            NwkDeviceType::Coordinator
        } else {
            NwkDeviceType::Router
        },
        channel: 15,
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

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let len: u16 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(6);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { serve(listener).await });

    let mut stacks = Vec::new();
    let mut events: Vec<broadcast::Receiver<ZigbeeNotification>> = Vec::new();
    for index in 0..len {
        let position = Position {
            x: f32::from(index) * 70.0,
            y: 0.0,
        };
        let phy = Arc::new(SimPhy::connect(addr, position).await.unwrap());
        let tunables = Tunables {
            link_status_period: Duration::from_millis(1000),
            mtorr_min_interval: Duration::from_secs(2),
            mtorr_max_interval: Duration::from_secs(2),
            ..Tunables::new()
        };
        let (stack, node_events) = ZigbeeStack::new(phy, config(index), tunables);
        stack.start_network().await.unwrap();
        let run = Arc::clone(&stack);
        stack.spawn_tracked(async move { run.run().await });
        stacks.push(stack);
        events.push(node_events);
    }

    eprintln!("Line of {len} nodes up; settling 12s...");
    sleep(Duration::from_secs(12)).await;

    let far = len - 1;
    eprintln!("Node 0x{far:04x} -> coordinator 0x0000 (upstream, {far} hops)...");
    let sent = stacks[far as usize]
        .send_aps_command(
            ApsDeliveryMode::Unicast,
            Nwk(0),
            0x0104,
            0x0006,
            1,
            1,
            ApsAck::None,
            30,
            1,
            vec![0xab, 0xcd],
            None,
            TxPriority::USER_NORMAL,
        )
        .await;
    eprintln!("send_aps result: {sent:?}");

    let got = timeout(Duration::from_secs(3), async {
        loop {
            match events[0].recv().await {
                Ok(ZigbeeNotification::ReceivedApsCommand { source, .. }) => return Some(source),
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
    .await;
    eprintln!("coordinator received from: {got:?}");
}
