//! SPIKE (throwaway): bring a Ziggurat node up as a satellite router, configured
//! out-of-band from the coordinator's own Ziggurat API instead of joining over the air.

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use ziggurat_driver::ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_protocol::{self as proto};

use crate::ZigguratServer;

const REQUEST_ID: proto::RequestId = 1;

pub async fn bootstrap(
    server: &std::sync::Arc<ZigguratServer>,
    coordinator: &str,
    nwk: Option<Nwk>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!("Satellite: fetching network settings from {coordinator}");
    let info = fetch_network_info(coordinator).await?;
    start_router(server, &info, nwk).await
}

/// Find the coordinator on the (trusted) ZLOE backbone and fetch the settings from it.
pub async fn bootstrap_zloe(
    server: &std::sync::Arc<ZigguratServer>,
    epan: Option<Eui64>,
    nwk: Option<Nwk>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!("Satellite: looking for a coordinator on the ZLOE backbone");
    let phy = server.phy().await?;
    let bytes = phy
        .fetch_network(epan, std::time::Duration::from_secs(60))
        .await?;
    let info: proto::NetworkInfoPayload =
        proto::parse(&bytes).ok_or("malformed network settings from coordinator")?;
    start_router(server, &info, nwk).await
}

async fn start_router(
    server: &std::sync::Arc<ZigguratServer>,
    info: &proto::NetworkInfoPayload,
    nwk: Option<Nwk>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let coord = &info.state;

    let phy = server.phy().await?;
    let ieee = phy.inner().hw_address().await?;
    let nwk = nwk.unwrap_or_else(|| derive_nwk(ieee));

    tracing::info!(
        "Satellite: joining PAN {:?} (ext {:?}) on channel {} as router {nwk:?} / {ieee:?}",
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
            // Stateless, but restarts must not reuse counters (neighbours would drop
            // our frames as replays): seed from the wall clock, 10 frames/s of headroom
            network_key_tx_counter: clock_counter(),
            aps_frame_counter: clock_counter(),
            has_tclk_seed: false,
            ..coord.clone()
        },
    };

    server
        .handle_configure(payload)
        .await
        .map_err(|_| "configure failed")?;
    server
        .handle_start_network()
        .await
        .map_err(|_| "start_network failed")?;

    spawn_zdp_responder(server, nwk);
    announce(server, nwk, ieee);
    tracing::info!("Satellite: router is up");
    Ok(())
}

async fn fetch_network_info(
    url: &str,
) -> Result<proto::NetworkInfoPayload, Box<dyn std::error::Error + Send + Sync>> {
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
            continue; // the hello notification, other clients' traffic
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

/// A stable address from the EUI64, outside the reserved 0x0000 and 0xFFF8.. ranges.
/// No conflict check: the stack's address conflict detection will report one.
fn derive_nwk(ieee: Eui64) -> Nwk {
    let mut hash: u32 = 2_166_136_261;
    for byte in ieee.0 {
        hash = (hash ^ u32::from(byte)).wrapping_mul(16_777_619);
    }
    let nwk = ((hash ^ (hash >> 16)) as u16) % 0xFFF7 + 1;
    Nwk(nwk)
}

fn clock_counter() -> u32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    // Seconds since 2026-01-01, times 10: fits u32 for ~13 years
    (secs.saturating_sub(1_767_225_600) * 10) as u32
}

/// SPIKE: bring this node up as coordinator of a private test network, created on
/// first use and kept in `path` (`key=value` lines) so restarts keep the network.
pub async fn test_coordinator(
    server: &std::sync::Arc<ZigguratServer>,
    path: &str,
    channel: u8,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use ziggurat_driver::ziggurat_ieee_802154::types::{Key, PanId};

    if !std::path::Path::new(path).exists() {
        let mut random = [0u8; 26];
        std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom")?, &mut random)?;
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let pan = u16::from_le_bytes([random[0], random[1]]) % 0xFFF0 + 1;
        std::fs::write(
            path,
            format!(
                "channel={channel}\npan={pan:04x}\nepid={}\nkey={}\n",
                hex(&random[2..10]),
                hex(&random[10..26])
            ),
        )?;
        tracing::info!("Test network: created {path}");
    }

    let text = std::fs::read_to_string(path)?;
    let get = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .ok_or_else(|| format!("{path}: missing {k}"))
    };
    let mut key = [0u8; 16];
    let key_hex = get("key")?;
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&key_hex[i * 2..i * 2 + 2], 16)?;
    }

    let phy = server.phy().await?;
    let ieee = phy.inner().hw_address().await?;

    let payload = proto::ConfigurePayload {
        role: proto::NodeRole::Coordinator,
        source_routing: true,
        state: proto::NetworkState {
            channel: get("channel")?.parse()?,
            nwk_update_id: 0,
            pan_id: PanId::try_from_hex(get("pan")?)?,
            extended_pan_id: Eui64::try_from_hex(get("epid")?)?,
            nwk_address: Nwk(0x0000),
            ieee_address: ieee,
            network_key: Key(key),
            network_key_seq: 0,
            network_key_tx_counter: clock_counter(),
            tc_link_key: Key(*b"ZigBeeAlliance09"),
            has_tclk_seed: false,
            tclk_seed: Key([0; 16]),
            tclk_flavor: proto::TclkFlavorId::ZStack,
            tx_power: 8,
            aps_frame_counter: clock_counter(),
        },
    };
    tracing::info!("Test network: coordinator {ieee:?} from {path}");
    server
        .handle_configure(payload)
        .await
        .map_err(|_| "configure failed")?;
    server
        .handle_start_network()
        .await
        .map_err(|_| "start_network failed")?;
    tracing::info!("Test network: coordinator is up");
    spawn_zdp_responder(server, Nwk(0x0000));
    Ok(())
}

/// SPIKE: answer the ZDP requests of a device interview ourselves, for nodes without
/// a client to do it: the test-network coordinator (zigpy's job normally; ZBOSS joiners
/// leave when the coordinator's Node_Desc_req goes unanswered) and satellites (zigpy
/// interviews them after their Device_annce and gives up otherwise).
///
/// Answers Node_Desc_req and Active_EP_req (no endpoints) for our own address.
fn spawn_zdp_responder(server: &std::sync::Arc<ZigguratServer>, own: Nwk) {
    use ziggurat_driver::zigbee_stack::{ApsAck, RouteDirective, TxPriority, ZigbeeNotification};

    let coordinator = own == Nwk(0x0000);
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
                // Node descriptor: 2.4 GHz, buffer 82, transfer sizes 128, stack
                // compliance revision 22. Coordinator: logical type 0, MAC caps 0x8F,
                // server mask primary TC + network manager. Router: type 1, caps 0x8E
                0x0002 => {
                    let (logical_type, caps, mask) = if coordinator {
                        (0x00, 0x8F, 0x0001 | 0x0040)
                    } else {
                        (0x01, 0x8E, 0x0000)
                    };
                    let server_mask: u16 = mask | (22 << 9);
                    let mut rsp = vec![
                        seq,
                        0x00,
                        lo,
                        hi,
                        logical_type,
                        0x40,
                        caps,
                        0x00,
                        0x00,
                        0x52,
                    ];
                    rsp.extend_from_slice(&128u16.to_le_bytes());
                    rsp.extend_from_slice(&server_mask.to_le_bytes());
                    rsp.extend_from_slice(&128u16.to_le_bytes());
                    rsp.push(0x00);
                    (0x8002, rsp)
                }
                // Active endpoints: none
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
                "ZDP responder: answered {cluster_id:#06x} from {source:?}: {:?}",
                result.map(|_| ())
            );
        }
    });
}

/// ZDP Device_annce (spec 2.4.3.1.11), as any router does after (re)joining: maps our
/// EUI64 to our (possibly new) NWK address in every node's address and neighbor
/// tables, and lets the coordinator's client (ZHA) learn about the satellite.
fn announce(server: &std::sync::Arc<ZigguratServer>, nwk: Nwk, ieee: Eui64) {
    use ziggurat_driver::zigbee_stack::TxPriority;

    let Some(stack) = server.current_stack() else {
        return;
    };
    // Capability: router, mains powered, receiver on when idle, allocate address
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
    tracing::info!(
        "Satellite: Device_annce for {nwk:?}: {:?}",
        result.map(|_| ())
    );
}
