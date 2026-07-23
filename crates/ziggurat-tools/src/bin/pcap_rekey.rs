//! Rekey a Zigbee capture: rewrite every NWK frame secured with one network key so it is
//! secured with another, leaving frames from other networks untouched. Optionally prepend
//! a synthetic APS Transport-Key command so Wireshark learns the new key automatically.

use std::borrow::Cow;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::{Block, PcapNgReader, PcapNgWriter};

use ziggurat_ieee_802154::types::{Eui64, Key, Nwk, PanId};
use ziggurat_ieee_802154::{
    FrameBytes, Ieee802154Address, Ieee802154AddressingMode, Ieee802154DataFrame, Ieee802154Frame,
    Ieee802154FrameControl, Ieee802154FrameHeader, Ieee802154FrameType, Ieee802154FrameVersion,
};
use ziggurat_zigbee::aps::frame::{
    ApsAuxHeader, ApsCommandFrame, ApsCommandFrameCommand, ApsDeliveryMode, ApsFrameControl,
    ApsFrameType, ApsNetworkKeyDescriptor, ApsStandardKeyType, ApsTransportKeyCommandFrame,
    ApsTransportKeyDescriptor,
};
use ziggurat_zigbee::crypto::key_transport_key;
use ziggurat_zigbee::nwk::frame::{
    EncryptedNwkFrame, NwkFrameControl, NwkFrameType, NwkHeader, NwkRouteDiscovery,
    NwkSecurityHeaderControlField, NwkSecurityHeaderKeyId, NwkSecurityLevel,
};

/// The well-known default global Trust Center link key ("ZigBeeAlliance09"), which
/// Wireshark ships preconfigured. The synthetic transport-key command is protected with
/// the key derived from it so Wireshark can decrypt it out of the box.
const ZIGBEE_ALLIANCE_09: Key = Key::from_string(b"ZigBeeAlliance09");

#[derive(Parser)]
#[command(
    about = "Change the network key of a Zigbee pcap/pcapng capture",
    long_about = "Decrypts every NWK-secured frame protected by the current network key and \
re-encrypts it under the target key. Frames belonging to other networks (whose MIC does not \
verify) are left untouched, and the transform round-trips when the two keys are equal."
)]
struct Args {
    /// Input capture (.pcapng).
    input: PathBuf,

    /// Output capture (.pcapng).
    output: PathBuf,

    /// The current network key protecting the capture.
    #[arg(long, value_parser = parse_key)]
    old_key: Key,

    /// The network key to re-encrypt the capture with.
    #[arg(long, value_parser = parse_key)]
    new_key: Key,

    /// Do not prepend a synthetic Transport-Key command for the new key.
    #[arg(long)]
    no_transport_key: bool,

    /// The key sequence number the new key is announced with in the Transport-Key command.
    #[arg(long, default_value_t = 0)]
    key_sequence_number: u8,
}

fn parse_key(text: &str) -> Result<Key, String> {
    Key::try_from_hex(text).map_err(|e| e.to_string())
}

/// The 802.15.4 link-layer type of a capture's packets, which decides whether each
/// packet is prefixed by an IEEE 802.15.4 TAP pseudo-header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkType {
    /// LINKTYPE_IEEE802_15_4_TAP (283): a TAP pseudo-header precedes the PHY payload.
    Tap,
    /// LINKTYPE_IEEE802_15_4_WITHFCS (195) or _NOFCS: the packet is the raw PHY payload.
    Raw,
}

impl LinkType {
    const fn from_pcap_linktype(linktype: u16) -> Option<Self> {
        match linktype {
            283 => Some(Self::Tap),
            195 | 230 => Some(Self::Raw),
            _ => None,
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let reader = PcapNgReader::new(BufReader::new(
        File::open(&args.input).with_context(|| format!("opening {}", args.input.display()))?,
    ))
    .context("parsing pcapng input")?;

    let writer_file = BufWriter::new(
        File::create(&args.output)
            .with_context(|| format!("creating {}", args.output.display()))?,
    );
    let mut writer = PcapNgWriter::new(writer_file).context("initializing pcapng writer")?;

    // The link type of each interface, indexed by interface id, so packet blocks know
    // whether they carry a TAP pseudo-header.
    let mut link_types: Vec<Option<LinkType>> = Vec::new();
    let mut transport_key_injected = args.no_transport_key;

    let mut total = 0u64;
    let mut rekeyed = 0u64;

    let mut reader = reader;
    while let Some(block) = reader.next_block() {
        let block = block.context("reading pcapng block")?;

        match block {
            Block::InterfaceDescription(idb) => {
                link_types.push(LinkType::from_pcap_linktype(u32::from(idb.linktype) as u16));
                writer
                    .write_block(&Block::InterfaceDescription(idb.into_owned()))
                    .context("writing interface description")?;
            }
            Block::EnhancedPacket(packet) => {
                let interface_id = packet.interface_id as usize;
                let link_type = link_types.get(interface_id).copied().flatten();

                total += 1;

                let new_block = match link_type {
                    Some(link_type) => {
                        match rekey_packet(link_type, &packet.data, &args.old_key, &args.new_key) {
                            Some(new_data) => {
                                rekeyed += 1;

                                // The first frame we rekey identifies the network's PAN.
                                // Wireshark scopes a learned key to the PAN it saw the
                                // transport-key command on, so we emit that command on the
                                // same PAN, just before the frame it decrypts.
                                if !transport_key_injected
                                    && let Some(pan_id) = mac_pan_id(link_type, &packet.data)
                                {
                                    inject_transport_key(
                                        &mut writer,
                                        packet.interface_id,
                                        link_type,
                                        pan_id,
                                        &args.new_key,
                                        args.key_sequence_number,
                                    )?;
                                    transport_key_injected = true;
                                }

                                rekeyed_block(&packet, new_data)
                            }
                            None => Block::EnhancedPacket(packet.into_owned()),
                        }
                    }
                    None => Block::EnhancedPacket(packet.into_owned()),
                };

                writer.write_block(&new_block).context("writing packet")?;
            }
            other => {
                writer
                    .write_block(&other.into_owned())
                    .context("writing block")?;
            }
        }
    }

    eprintln!(
        "Rekeyed {rekeyed} of {total} packets ({} left untouched)",
        total - rekeyed
    );
    Ok(())
}

/// Rebuild an enhanced-packet block around rekeyed data of the same length.
fn rekeyed_block(original: &EnhancedPacketBlock, new_data: Vec<u8>) -> Block<'static> {
    Block::EnhancedPacket(EnhancedPacketBlock {
        interface_id: original.interface_id,
        timestamp: original.timestamp,
        original_len: new_data.len() as u32,
        data: Cow::Owned(new_data),
        options: original
            .options
            .iter()
            .map(|option| option.clone().into_owned())
            .collect(),
    })
}

fn inject_transport_key(
    writer: &mut PcapNgWriter<impl std::io::Write>,
    interface_id: u32,
    link_type: LinkType,
    pan_id: PanId,
    new_key: &Key,
    key_sequence_number: u8,
) -> Result<()> {
    let data = transport_key_packet(
        link_type,
        pan_id,
        new_key,
        key_sequence_number,
        &ZIGBEE_ALLIANCE_09,
    );

    let block = Block::EnhancedPacket(EnhancedPacketBlock {
        interface_id,
        timestamp: std::time::Duration::from_secs(0),
        original_len: data.len() as u32,
        data: Cow::Owned(data),
        options: Vec::new(),
    });

    writer
        .write_block(&block)
        .context("writing synthetic transport-key packet")?;
    Ok(())
}

/// Rekey one capture packet, given its link type. Returns `Some(new_packet)` when the
/// packet carried a NWK frame secured with `old_key` (re-encrypted under `new_key`), or
/// `None` when the packet should be emitted unchanged (a foreign network, an
/// unencrypted frame, or anything that does not parse).
fn rekey_packet(link_type: LinkType, data: &[u8], old_key: &Key, new_key: &Key) -> Option<Vec<u8>> {
    match link_type {
        LinkType::Raw => rekey_phy(data, old_key, new_key),
        LinkType::Tap => {
            let header_len = tap_header_len(data)?;
            let new_phy = rekey_phy(&data[header_len..], old_key, new_key)?;

            let mut out = data[..header_len].to_vec();
            out.extend(new_phy);
            Some(out)
        }
    }
}

/// The length of the IEEE 802.15.4 TAP pseudo-header (its little-endian length field),
/// or `None` if the buffer is too short to contain one.
fn tap_header_len(data: &[u8]) -> Option<usize> {
    if data.len() < 4 {
        return None;
    }

    let header_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    if header_len < 4 || header_len > data.len() {
        return None;
    }

    Some(header_len)
}

/// The destination PAN ID (falling back to the source PAN ID) of a capture packet's MAC
/// frame, used to scope the synthetic transport-key command to the right network.
fn mac_pan_id(link_type: LinkType, data: &[u8]) -> Option<PanId> {
    let phy = match link_type {
        LinkType::Raw => data,
        LinkType::Tap => &data[tap_header_len(data)?..],
    };

    let header = Ieee802154Frame::from_bytes(phy).ok()?;
    let header = header.header();
    header.dest_pan_id.or(header.src_pan_id)
}

/// Rekey a raw 802.15.4 PHY payload (including its FCS). See [`rekey_packet`].
fn rekey_phy(phy: &[u8], old_key: &Key, new_key: &Key) -> Option<Vec<u8>> {
    let Ieee802154Frame::Data(data_frame) = Ieee802154Frame::from_bytes(phy).ok()? else {
        return None;
    };

    let encrypted = EncryptedNwkFrame::from_bytes(&data_frame.payload).ok()?;

    // Only NWK frames secured with the network key are ours to rekey.
    if !encrypted.nwk_header.frame_control.security {
        return None;
    }
    let aux_header = encrypted.aux_header.as_ref()?;
    if aux_header.security_control.key_id != NwkSecurityHeaderKeyId::NetworkKey {
        return None;
    }

    // The CCM* nonce needs the originator's EUI64; without it we cannot re-encrypt.
    if aux_header.extended_source.is_none() && encrypted.nwk_header.source_ieee.is_none() {
        return None;
    }

    // A MIC mismatch means the frame belongs to another network: leave it untouched.
    let decrypted = encrypted.decrypt(old_key).ok()?;
    let reencrypted = decrypted.encrypt(new_key);

    let new_frame = Ieee802154Frame::Data(Ieee802154DataFrame {
        header: data_frame.header,
        payload: FrameBytes::from_slice(&reencrypted.to_bytes()).ok()?,
        fcs: 0,
    });

    Some(new_frame.to_bytes())
}

/// Build a synthetic capture packet carrying an APS Transport-Key command that transports
/// `network_key`, protected with the key-transport key derived from `link_key` (typically
/// [`ZIGBEE_ALLIANCE_09`]). Placed at the top of a capture, it lets Wireshark learn the
/// network key automatically, without the key being supplied out of band.
fn transport_key_packet(
    link_type: LinkType,
    pan_id: PanId,
    network_key: &Key,
    key_sequence_number: u8,
    link_key: &Key,
) -> Vec<u8> {
    // Fabricated addresses for the synthetic frame; only internal consistency matters.
    let coordinator = Eui64::from_hex("aa:aa:aa:aa:aa:aa:aa:aa");
    let joining_device = Eui64::from_hex("bb:bb:bb:bb:bb:bb:bb:bb");

    let aps_command = ApsCommandFrame {
        frame_control: ApsFrameControl {
            frame_type: ApsFrameType::Command,
            delivery_mode: ApsDeliveryMode::Unicast,
            reserved1: 0,
            security: true,
            ack_request: false,
            extended_header: false,
        },
        counter: 0,
        command: ApsCommandFrameCommand::TransportKey(ApsTransportKeyCommandFrame {
            standard_key_type: ApsStandardKeyType::StandardNetworkKey,
            key_descriptor: ApsTransportKeyDescriptor::NetworkKey(ApsNetworkKeyDescriptor {
                key: network_key.clone(),
                sequence_number: key_sequence_number,
                destination_address: joining_device,
                source_address: coordinator,
            }),
        }),
    };

    let aps_aux_header = ApsAuxHeader {
        security_control: NwkSecurityHeaderControlField {
            security_level: NwkSecurityLevel::NoSecurity,
            key_id: NwkSecurityHeaderKeyId::KeyTransportKey,
            extended_nonce: true,
            require_verified_frame_counter: false,
        },
        frame_counter: 0,
        extended_source: Some(coordinator),
        key_sequence_number: None,
    };

    let aps_bytes = aps_command
        .encrypt(&key_transport_key(link_key), &aps_aux_header)
        .to_bytes();

    // An unsecured NWK data frame carries the APS command (`EncryptedNwkFrame` with no
    // aux header and no NWK encryption is just a cleartext NWK frame on the wire).
    let nwk_frame = EncryptedNwkFrame {
        nwk_header: NwkHeader {
            frame_control: NwkFrameControl {
                frame_type: NwkFrameType::Data,
                protocol_version: 2,
                discover_route: NwkRouteDiscovery::Suppress,
                multicast: false,
                security: false,
                source_route: false,
                destination: false,
                extended_source: true,
                end_device_initiator: false,
                reserved1: 0,
            },
            destination: Nwk(0x1234),
            source: Nwk(0x0000),
            radius: 30,
            sequence_number: 0,
            destination_ieee: None,
            source_ieee: Some(coordinator),
            multicast_control: None,
            source_route: None,
        },
        aux_header: None,
        ciphertext: FrameBytes::from_slice(&aps_bytes).expect("APS command is frame-bounded"),
    };

    let mac_frame = Ieee802154Frame::Data(Ieee802154DataFrame {
        header: Ieee802154FrameHeader {
            frame_control: Ieee802154FrameControl {
                frame_type: Ieee802154FrameType::Data,
                security_enabled: false,
                frame_pending: false,
                ack_request: false,
                pan_id_compression: true,
                reserved1: false,
                sequence_number_suppression: false,
                information_elements_present: false,
                dest_addr_mode: Ieee802154AddressingMode::Short,
                frame_version: Ieee802154FrameVersion::Ieee2006,
                src_addr_mode: Ieee802154AddressingMode::Short,
            },
            sequence_number: Some(0),
            dest_pan_id: Some(pan_id),
            dest_address: Some(Ieee802154Address::Nwk(Nwk(0x1234))),
            src_pan_id: Some(pan_id),
            src_address: Some(Ieee802154Address::Nwk(Nwk(0x0000))),
        },
        payload: FrameBytes::from_slice(&nwk_frame.to_bytes()).expect("NWK frame is frame-bounded"),
        fcs: 0,
    });

    let phy = mac_frame.to_bytes();

    match link_type {
        LinkType::Raw => phy,
        LinkType::Tap => {
            // A 12-byte TAP header: 4-byte base plus one FCS-type TLV declaring a 16-bit
            // FCS is present, so Wireshark validates the CRC we emit.
            let mut out = vec![0x00, 0x00, 0x0C, 0x00];
            out.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]); // TLV type 0 (FCS type), len 1
            out.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // value 1 (16-bit FCS), padded
            out.extend(phy);
            out
        }
    }
}
