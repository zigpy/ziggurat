//! SPIKE (throwaway): poke a Ziggurat node's API for the ZLOE bench without ZHA.
//!
//! zloe-ctl <ws-url> permit <seconds>
//! zloe-ctl <ws-url> onoff <nwk-hex> <on|off|toggle>
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
        ("onoff", [nwk, action]) => {
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
                    dst_ep: 1,
                    aps_seq: 0,
                    radius: 0,
                    priority: 0,
                    route: proto::RouteControl::StackDecides,
                    next_hop: None,
                    relays: None,
                    asdu: vec![0x01, seq, zcl_command],
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
            println!(
                "{:?} cmd={:#04x} {:02x?}",
                header.frame_type, header.command, body
            );
            let done = header.frame_type == proto::FrameType::Response
                && header.command == opcode as u8
                && opcode != proto::RequestCommand::SendUnicast;
            if done {
                break;
            }
        }
    })
    .await;
    Ok(())
}
