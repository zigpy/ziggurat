//! SPIKE (throwaway): poke a Ziggurat node's API for the ZLOE bench without ZHA.
//!
//! zloe-ctl <ws-url> permit <seconds>
//! zloe-ctl <ws-url> onoff <nwk-hex> <on|off|toggle> [endpoint, default 1]
//! zloe-ctl <ws-url> lqi <nwk-hex>          (Mgmt_Lqi_req, decodes the response)
//! zloe-ctl <ws-url> listen <seconds>     (print notifications)

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use ziggurat_driver::ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_protocol::{self as proto};

type Error = Box<dyn std::error::Error>;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [url, command, rest @ ..] = &args[..] else {
        return Err(
            "usage: zloe-ctl <ws-url> permit <s> | onoff <nwk> <on|off|toggle> | listen <s>".into(),
        );
    };
    let (mut ws, _) = tokio_tungstenite::connect_async(url.as_str()).await?;

    let (opcode, payload) = match (command.as_str(), rest) {
        ("permit", [secs]) => {
            let mut body = Vec::new();
            proto::append(
                &mut body,
                &proto::PermitJoinsPayload {
                    duration: secs.parse()?,
                    accept_direct_joins: true,
                },
            );
            (proto::RequestCommand::PermitJoins, body)
        }
        ("onoff", [nwk, action, ep @ ..]) => {
            let dst_ep: u8 = ep.first().map_or(Ok(1), |e| e.parse())?;
            let zcl_command = match action.as_str() {
                "off" => 0x00,
                "on" => 0x01,
                "toggle" => 0x02,
                _ => return Err("action must be on, off or toggle".into()),
            };
            // ZCL: cluster-specific, client->server, default response enabled
            let seq = (std::process::id() & 0xFF) as u8;
            let mut body = Vec::new();
            proto::append(
                &mut body,
                &proto::SendUnicastPayload {
                    flags: proto::SendUnicastFlags {
                        has_eui64: false,
                        aps_ack: true,
                        aps_encryption: false,
                        sleepy_destination: false,
                        force_aps_seq: false,
                    },
                    destination: Nwk::try_from_hex(nwk)?,
                    destination_eui64: Eui64([0; 8]),
                    profile_id: 0x0104,
                    cluster_id: 0x0006,
                    src_ep: 1,
                    dst_ep,
                    aps_seq: 0,
                    radius: 30,
                    priority: 0,
                    route: proto::RouteControl::StackDecides,
                    next_hop: None,
                    relays: None,
                    asdu: vec![0x01, seq, zcl_command],
                },
            );
            (proto::RequestCommand::SendUnicast, body)
        }
        ("lqi", [nwk]) => {
            let mut body = Vec::new();
            proto::append(
                &mut body,
                &proto::SendUnicastPayload {
                    flags: proto::SendUnicastFlags {
                        has_eui64: false,
                        aps_ack: false,
                        aps_encryption: false,
                        sleepy_destination: false,
                        force_aps_seq: false,
                    },
                    destination: Nwk::try_from_hex(nwk)?,
                    destination_eui64: Eui64([0; 8]),
                    profile_id: 0x0000,
                    cluster_id: 0x0031,
                    src_ep: 0,
                    dst_ep: 0,
                    aps_seq: 0,
                    radius: 30,
                    priority: 0,
                    route: proto::RouteControl::StackDecides,
                    next_hop: None,
                    relays: None,
                    asdu: vec![0x42, 0x00],
                },
            );
            (proto::RequestCommand::SendUnicast, body)
        }
        ("listen", [secs]) => {
            let deadline = std::time::Duration::from_secs(secs.parse()?);
            let _ = tokio::time::timeout(deadline, async {
                while let Some(Ok(Message::Binary(data))) = ws.next().await {
                    if let Some((header, _)) = proto::Header::parse(&data) {
                        println!(
                            "{:?} cmd={:#04x} {:02x?}",
                            header.frame_type,
                            header.command,
                            &data[3..data.len().min(40)]
                        );
                    }
                }
            })
            .await;
            return Ok(());
        }
        _ => return Err(format!("unknown command {command} {rest:?}").into()),
    };

    let started = std::time::Instant::now();
    let is_lqi = command == "lqi";
    let mut frame = proto::envelope(proto::FrameType::Request, opcode as u8, 1);
    frame.extend_from_slice(&payload);
    ws.send(Message::Binary(frame.into())).await?;

    // Print everything until the response (and, for sends, the send status) arrives
    let deadline =
        std::time::Duration::from_secs(if opcode == proto::RequestCommand::SendUnicast {
            15
        } else {
            5
        });
    let _ = tokio::time::timeout(deadline, async {
        while let Some(Ok(Message::Binary(data))) = ws.next().await {
            let Some((header, consumed)) = proto::Header::parse(&data) else {
                continue;
            };
            let body = &data[consumed..];
            let ms = started.elapsed().as_millis();
            let notification = header.frame_type == proto::FrameType::Notification;
            if notification && header.command == 0x10 {
                if let Some(aps) = proto::parse::<proto::ReceivedApsPayload>(body)
                    && aps.cluster_id == 0x8031
                {
                    print_lqi_rsp(&aps, ms);
                    if is_lqi {
                        break;
                    }
                }
                continue;
            }
            println!(
                "+{ms}ms {:?} cmd={:#04x} {:02x?}",
                header.frame_type, header.command, body
            );
            // 0x12 is the APS ack confirm: the end of a unicast's story
            let done = (header.frame_type == proto::FrameType::Response
                && header.command == opcode as u8
                && opcode != proto::RequestCommand::SendUnicast)
                || (notification && header.command == 0x12 && !is_lqi);
            if done {
                break;
            }
        }
    })
    .await;
    Ok(())
}

/// Mgmt_Lqi_rsp: seq, status, total, start, count, then 22-byte neighbor records.
fn print_lqi_rsp(aps: &proto::ReceivedApsPayload, ms: u128) {
    let d = &aps.data;
    if d.len() < 5 {
        return;
    }
    println!(
        "+{ms}ms Mgmt_Lqi_rsp from {:?}: status={} total={} start={} count={}",
        aps.source, d[1], d[2], d[3], d[4]
    );
    for rec in d[5..].as_chunks::<22>().0 {
        let nwk = u16::from_le_bytes([rec[16], rec[17]]);
        let kind = match rec[18] & 0x03 {
            0 => "coordinator",
            1 => "router",
            2 => "end device",
            _ => "unknown",
        };
        let relation = match (rec[18] >> 4) & 0x07 {
            0 => "parent",
            1 => "child",
            2 => "sibling",
            3 => "none",
            _ => "previous child",
        };
        println!(
            "  nwk={nwk:#06x} {kind:<11} {relation:<14} depth={} lqi={}",
            rec[20], rec[21]
        );
    }
}
