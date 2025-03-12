use log::LevelFilter;
use serial2::Settings;
use serial2_tokio::SerialPort;
use std::env;
use ziggurat::ieee_802154::Ieee802154Frame;
use ziggurat::ieee_802154::{
    Ieee802154Address, Ieee802154AddressingMode, Ieee802154FrameControl, Ieee802154FrameType,
};
use ziggurat::spinel::SpinelPropertyId;
use ziggurat::spinel_client::{SpinelClient, SpinelTxFrame};
use ziggurat::types::{Nwk, PanId};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder()
        .format_timestamp_micros()
        .filter(None, LevelFilter::Debug)
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
        .prop_value_set(
            SpinelPropertyId::MacRawStreamEnabled as u32,
            vec![true as u8],
        )
        .await
        .expect("Failed to enable the RAW stream");

    let channel = 19;
    client
        .prop_value_set(SpinelPropertyId::PhyChan as u32, vec![channel])
        .await
        .expect("Failed to set the PHY");

    let mut last_time = std::time::Instant::now();

    let mut sequence = 1;

    loop {
        let now = std::time::Instant::now();
        // Print time since last packet with 8 decimal places
        println!(
            "=== Delta {:0.8}",
            now.duration_since(last_time).as_secs_f64()
        );
        last_time = now;

        let frame = SpinelTxFrame {
            psdu: Ieee802154Frame {
                frame_control: Ieee802154FrameControl {
                    frame_type: Ieee802154FrameType::Command,
                    security_enabled: false,
                    frame_pending: false,
                    ack_request: false,
                    pan_id_compression: false,
                    reserved: false,
                    sequence_number_suppression: false,
                    information_elements_present: false,
                    dest_addr_mode: Ieee802154AddressingMode::Short,
                    frame_version: 0,
                    src_addr_mode: Ieee802154AddressingMode::None,
                },
                sequence_number: Some(sequence),
                dest_pan_id: Some(PanId(0xffff)),
                dest_address: Some(Ieee802154Address::Nwk(Nwk(0xffff))),
                src_pan_id: None,
                src_address: None,
                payload: b"\x07".to_vec(),
                fcs: 0x0000, // It'll be recalculated
            }
            .to_bytes(),
            channel: channel,
            max_csma_backoffs: 1,
            max_frame_retries: 4,
            enable_csma_ca: true,
            is_header_updated: true,
            is_a_retransmit: false,
            is_security_processed: true,
            tx_delay: 0 as u32,
            tx_delay_base_time: 0 as u32,
            rx_channel_after_tx: channel,
            tx_power: 8,
        };

        sequence = (sequence + 1) % 255;

        match client.transmit_frame(&frame).await {
            Ok(status) => println!("Frame transmitted: {:?}", status),
            Err(e) => eprintln!("Error transmitting frame: {:?}", e),
        }
    }

    Ok(())
}
