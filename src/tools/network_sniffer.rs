use log::LevelFilter;
use serial2::Settings;
use serial2_tokio::SerialPort;
use std::env;
use tokio::sync::mpsc;
use ziggurat::ieee_802154::Ieee802154Frame;
use ziggurat::spinel::SpinelPropertyId;
use ziggurat::spinel_client::{SpinelClient, SpinelRxFrame};
use ziggurat::types::{Eui64, Key, Nwk, PanId};
use ziggurat::zigbee_stack::ZigbeeStack;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder()
        .format_timestamp_micros()
        .filter(None, LevelFilter::Debug)
        .filter_module("ziggurat::spinel", LevelFilter::Info)
        .init();

    let args: Vec<String> = env::args().collect();
    let port = SerialPort::open(&args[1], |mut settings: Settings| {
        settings.set_raw();
        settings.set_baud_rate(460_800)?;
        Ok(settings)
    })?;

    let client = SpinelClient::new(port);
    client.spawn_reader();
    {
        let mut protocol = client.protocol.lock().await;
        protocol.next_tid = 3;
    }

    let ncp_version = client
        .get_ncp_version()
        .await
        .expect("Invalid UTF-8 string");

    println!("NCP Version: {:?}", ncp_version);

    client
        .prop_value_set(SpinelPropertyId::PhyEnabled as u32, vec![true as u8])
        .await
        .expect("Failed to enable the PHY");

    client
        .prop_value_set(SpinelPropertyId::MacPromiscuousMode as u32, vec![2])
        .await
        .expect("Failed to set the MAC promiscuous mode");

    client
        .prop_value_set(
            SpinelPropertyId::MacRawStreamEnabled as u32,
            vec![true as u8],
        )
        .await
        .expect("Failed to enable the RAW stream");

    let mut zigbee_stack = ZigbeeStack::new();
    zigbee_stack.nib.nwk_update_id = 0;
    zigbee_stack.nib.nwk_network_address = Nwk(0x0000);
    zigbee_stack.nib.nwk_extended_pan_id = Eui64::from_hex("fe:ed:fa:ce:de:ad:be:ef");
    zigbee_stack.nib.nwk_is_concentrator = true;
    zigbee_stack.nib.nwk_security_level = 5;
    zigbee_stack
        .nib
        .nwk_security_material_primary
        .key_seq_number = 0;
    zigbee_stack
        .nib
        .nwk_security_material_primary
        .outgoing_frame_counter = 16498716;
    zigbee_stack.nib.nwk_security_material_primary.key =
        Key::from_hex("37:66:8f:d6:4e:35:e0:33:42:e5:ef:9f:35:cc:f4:ab");
    zigbee_stack.nib.nwk_pan_id = PanId(0xBEEF);
    zigbee_stack.nib.nwk_ieee_address = Eui64::from_hex("00:12:4b:00:1c:a1:b8:46");

    let channel = 25;
    client
        .prop_value_set(SpinelPropertyId::PhyChan as u32, vec![channel])
        .await
        .expect("Failed to set the PHY");

    let (stream_raw_tx, mut stream_raw_rx) = mpsc::channel(32);

    {
        let mut guard = client.protocol.lock().await;
        guard.set_property_update_receiver(SpinelPropertyId::StreamRaw as u32, stream_raw_tx);
    }

    println!("Listening for packets...");

    while let Some(stream_raw_prop) = stream_raw_rx.recv().await {
        let packet = match SpinelRxFrame::from_bytes(&stream_raw_prop.value) {
            Ok(packet) => packet,
            Err(e) => {
                eprintln!("Error parsing packet: {:?}", e);
                continue;
            }
        };

        let ieee802154_frame =
            match Ieee802154Frame::from_bytes_without_fcs(&packet.psdu[..packet.psdu.len() - 2]) {
                Ok(frame) => frame,
                Err(e) => {
                    eprintln!("Error parsing IEEE 802.15.4 frame: {:?}", e);
                    continue;
                }
            };

        log::debug!("Received 802.15.4 frame: {:?}", ieee802154_frame);
        zigbee_stack.receive_802154_frame(&ieee802154_frame);
    }

    Ok(())
}
