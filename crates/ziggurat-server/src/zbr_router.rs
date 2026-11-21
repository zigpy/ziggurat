//! SPIKE (throwaway): Zigbee Border Router, router placement (spike B). Brings this
//! node up as a router of someone else's network, configured out-of-band from that
//! coordinator's Ziggurat API (as the ZLOE satellite spike does) instead of joining over
//! the air. The border router (`zbr`) then runs on top, with this node's own NWK address.

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use ziggurat_driver::ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_protocol::{self as proto};

use crate::ZigguratServer;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const REQUEST_ID: proto::RequestId = 1;

pub async fn bootstrap(server: &std::sync::Arc<ZigguratServer>, coordinator: &str) -> Result<(), BoxError> {
    tracing::info!("ZBR router: fetching network settings from {coordinator}");
    let info = fetch_network_info(coordinator).await?;
    let coord = &info.state;

    let phy = server.phy().await?;
    let ieee = phy.hw_address().await.map_err(|e| format!("{e:?}"))?;
    let nwk = derive_nwk(ieee);
    tracing::info!(
        "ZBR router: joining PAN {:?} (ext {:?}) on channel {} as router {nwk:?} / {ieee:?}",
        coord.pan_id,
        coord.extended_pan_id,
        coord.channel
    );

    let payload = proto::ConfigurePayload {
        role: proto::NodeRole::Router,
        source_routing: false,
        state: proto::NetworkState {
            nwk_address: nwk,
            ieee_address: ieee,
            // Restarts must not reuse counters: seed from the wall clock
            network_key_tx_counter: clock_counter(),
            aps_frame_counter: clock_counter(),
            has_tclk_seed: false,
            ..coord.clone()
        },
    };
    server.handle_configure(payload).await.map_err(|_| "configure failed")?;
    server
        .handle_start_network()
        .await
        .map_err(|_| "start_network failed")?;

    spawn_zdp_responder(server, nwk);
    announce(server, nwk, ieee);
    tracing::info!("ZBR router: up");
    Ok(())
}

async fn fetch_network_info(url: &str) -> Result<proto::NetworkInfoPayload, BoxError> {
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await?;

    let command = proto::RequestCommand::GetNetworkInfo as u8;
    let request = proto::envelope(proto::FrameType::Request, command, REQUEST_ID);
    ws.send(Message::Binary(request.into())).await?;

    while let Some(message) = ws.next().await {
        let Message::Binary(data) = message? else {
            continue;
        };
        let Some((header, consumed)) = proto::Header::parse(&data) else {
            continue;
        };
        if header.frame_type != proto::FrameType::Response || header.command != command {
            continue;
        }
        let body = &data[consumed..];
        if body.first() != Some(&(proto::Status::Ok as u8)) {
            return Err(format!("coordinator refused get_network_info: {body:02X?}").into());
        }
        let info: proto::NetworkInfoPayload =
            proto::parse(&body[1..]).ok_or("malformed network info")?;
        if !info.started {
            return Err("coordinator network is not started".into());
        }
        let _ = ws.close(None).await;
        return Ok(info);
    }
    Err("coordinator closed the connection".into())
}

/// A stable address from the EUI-64, outside 0x0000 and the reserved 0xFFF8.. range.
fn derive_nwk(ieee: Eui64) -> Nwk {
    let mut hash: u32 = 2_166_136_261;
    for byte in ieee.0 {
        hash = (hash ^ u32::from(byte)).wrapping_mul(16_777_619);
    }
    Nwk(((hash ^ (hash >> 16)) as u16) % 0xFFF7 + 1)
}

fn clock_counter() -> u32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    (secs.saturating_sub(1_767_225_600) * 10) as u32
}

/// Answer Node_Desc_req and Active_EP_req (no endpoints) for our own address, so the
/// network's controller can interview this router after its Device_annce.
fn spawn_zdp_responder(server: &std::sync::Arc<ZigguratServer>, own: Nwk) {
    use ziggurat_driver::zigbee_stack::{ApsAck, RouteDirective, TxPriority, ZigbeeNotification};

    let mut notifications = server.notification_tx.subscribe();
    let server = server.clone();
    tokio::spawn(async move {
        loop {
            let notification = match notifications.recv().await {
                Ok(n) => n,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return,
            };
            let ZigbeeNotification::ReceivedApsCommand {
                source,
                profile_id: 0x0000,
                cluster_id,
                dst_ep: 0,
                data,
                ..
            } = notification
            else {
                continue;
            };
            let [seq, lo, hi, ..] = data[..] else {
                continue;
            };
            if Nwk(u16::from_le_bytes([lo, hi])) != own {
                continue;
            }
            let Some(stack) = server.current_stack() else {
                continue;
            };
            let (rsp_cluster, rsp) = match cluster_id {
                // Router, 2.4 GHz, caps 0x8E, buffer 82, transfer 128, stack rev 22
                0x0002 => {
                    let server_mask: u16 = 22 << 9;
                    let mut rsp = vec![seq, 0x00, lo, hi, 0x01, 0x40, 0x8E, 0x00, 0x00, 0x52];
                    rsp.extend_from_slice(&128u16.to_le_bytes());
                    rsp.extend_from_slice(&server_mask.to_le_bytes());
                    rsp.extend_from_slice(&128u16.to_le_bytes());
                    rsp.push(0x00);
                    (0x8002, rsp)
                }
                0x0005 => (0x8005, vec![seq, 0x00, lo, hi, 0x00]),
                _ => continue,
            };
            let result = stack.send_aps_unicast(
                source,
                0x0000,
                rsp_cluster,
                0,
                0,
                ApsAck::None,
                None,
                30,
                rsp,
                None,
                false,
                TxPriority::StackCritical,
                RouteDirective::StackDecides,
            );
            tracing::info!(
                "ZBR router: ZDP {cluster_id:#06x} from {source:?} answered: {:?}",
                result.map(|_| ())
            );
        }
    });
}

/// ZDP Device_annce, as any router does after joining.
fn announce(server: &std::sync::Arc<ZigguratServer>, nwk: Nwk, ieee: Eui64) {
    use ziggurat_driver::zigbee_stack::TxPriority;

    let Some(stack) = server.current_stack() else {
        return;
    };
    let mut payload = vec![0x00];
    payload.extend_from_slice(&nwk.0.to_le_bytes());
    payload.extend_from_slice(&ieee.0);
    payload.push(0x8E);
    let result = stack.send_aps_broadcast(
        Nwk(0xFFFD),
        0x0000,
        0x0013,
        0,
        0,
        30,
        payload,
        TxPriority::StackCritical,
    );
    tracing::info!("ZBR router: Device_annce for {nwk:?}: {:?}", result.map(|_| ()));
}
