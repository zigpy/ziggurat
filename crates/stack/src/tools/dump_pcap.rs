use std::fs::File;

use inline_colorization::*;
use pcap_parser::traits::PcapNGPacketBlock;
use pcap_parser::{PcapBlockOwned, PcapError, create_reader};
use shellexpand;

use ziggurat::ieee_802154::{Ieee802154Frame, Ieee802154FrameType};
use ziggurat::zigbee_nwk::NwkFrame;
use ziggurat::zigbee_parts::types::Key;

fn main() {
    let keys_path = shellexpand::tilde("~/.config/wireshark/zigbee_pc_keys").into_owned();
    let mut keys = Vec::<Key>::new();

    for line in std::fs::read_to_string(keys_path)
        .expect("Failed to read keys file")
        .lines()
    {
        if !line.starts_with('"') {
            continue;
        }

        let key_text = line
            .split(',')
            .nth(0)
            .expect("Line must have commas")
            .split("\"")
            .nth(1)
            .expect("Failed to parse key");
        let key = Key::from_hex(key_text);
        keys.push(key);
    }

    println!("Loaded {} keys from Wireshark", keys.len());

    let pcap = std::env::args().nth(1).expect("no pcap file given");
    let file = File::open(pcap).expect("failed to open pcap file");
    let mut reader = create_reader(65536, file).expect("LegacyPcapReader");

    let mut total_frames = 0;
    let mut nwk_frames = 0;
    let mut decrypted_frames_success = 0;
    let mut decrypted_frames_failure = 0;
    let mut fcs_present = None;

    loop {
        let (offset, block) = match reader.next() {
            Ok((offset, block)) => (offset, block),
            Err(PcapError::Incomplete(_)) => {
                reader.refill().unwrap();
                continue;
            }
            Err(PcapError::Eof) => break,
            Err(e) => panic!("error while reading: {:?}", e),
        };

        let frame_data = match block {
            PcapBlockOwned::Legacy(legacy_block) => legacy_block.data.to_vec(),
            PcapBlockOwned::NG(pcap_parser::Block::EnhancedPacket(packet)) => {
                packet.packet_data().to_vec()
            }
            PcapBlockOwned::NG(pcap_parser::Block::SimplePacket(packet)) => {
                packet.packet_data().to_vec()
            }
            _ => {
                reader.consume(offset);
                continue;
            }
        };

        reader.consume(offset);

        // Figure out if the FCS is present via the first frame
        if fcs_present.is_none() {
            fcs_present = match Ieee802154Frame::from_bytes(&frame_data.clone()) {
                Ok(_) => Some(true),
                Err(_) => {
                    Ieee802154Frame::from_bytes_without_fcs(&frame_data.clone())
                        .expect("Failed to determine FCS presence from first frame");
                    Some(false)
                }
            };

            println!("FCS present: {:?}", fcs_present.unwrap());
        }

        let frame = if fcs_present.unwrap() {
            Ieee802154Frame::from_bytes(&frame_data).expect("Failed to parse frame")
        } else {
            Ieee802154Frame::from_bytes_without_fcs(&frame_data).expect("Failed to parse frame")
        };

        total_frames += 1;

        // 802.15.4 encrypted frames can't be Zigbee NWK
        if frame.frame_control.security_enabled {
            continue;
        }

        if frame.frame_control.frame_type != Ieee802154FrameType::Data {
            continue;
        }

        let nwk_frame = match NwkFrame::from_bytes(&frame.payload) {
            Ok(nwk_frame) => nwk_frame,
            Err(_) => {
                println!(
                    "{color_red}Failed to parse frame, maybe not Zigbee NWK? {:?}{color_reset}",
                    frame.payload
                );
                continue;
            }
        };

        nwk_frames += 1;

        let mut decrypted: Option<NwkFrame> = None;

        if !nwk_frame.encrypted {
            decrypted = Some(nwk_frame.clone()); // Why clone??
        } else {
            for (index, key) in keys.iter().enumerate() {
                match nwk_frame.decrypt(&key) {
                    Ok(decrypted_frame) => {
                        // Swap the first key with this one for efficiency
                        keys.swap(0, index);
                        decrypted = Some(decrypted_frame);
                        break;
                    }
                    Err(_) => continue,
                }
            }
        }

        if decrypted.is_none() {
            decrypted_frames_failure += 1;
            //println!("{color_red}Failed to decrypt raw frame #{}: {:#?}{color_reset}", total_frames, frame_data);
            //println!("{color_red}Failed to decrypt 802.15.4 frame #{}: {:#?}{color_reset}", total_frames, frame);
            //println!("{color_red}Failed to decrypt frame #{}: {:#?}{color_reset}", total_frames, nwk_frame);
            //println!("\n\n\n\n\n==============================================================================================================================================================================\n\n\n\n\n");
        } else {
            decrypted_frames_success += 1;
            //println!("{color_green}Decrypted frame {}: {:#?}{color_reset}", total_frames, nwk_frame);
            //println!("\n\n\n\n\n==============================================================================================================================================================================\n\n\n\n\n");
        }
    }

    println!("Processed {} 802.15.4 frames", total_frames);
    println!("Processed {} Zigbee NWK frames", nwk_frames);
    println!(
        "Decrypted {} frames, with {} failures",
        decrypted_frames_success, decrypted_frames_failure
    );
}
