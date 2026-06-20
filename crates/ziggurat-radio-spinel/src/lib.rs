//! [`RadioPhy`] implemented over an OpenThread RCP via Spinel.
//!
//! Translates the trait's semantic operations into Spinel property sets and frame
//! transmits, and bridges the RCP's unsolicited streams (received frames, energy-scan
//! results, reset notifications) onto the trait's sinks.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_phy::{
    RadioConfig, RadioError, RadioPhy, ResetEvent, RxFrame, TxFrame, TxPriority, TxResult,
};
use ziggurat_spinel::client::{
    SpinelClient, SpinelError, SpinelRxFrame, SpinelTxFrame, TxPriority as SpinelTxPriority,
};
use ziggurat_spinel::{
    SpinelFramePropValueIs, SpinelMacPromiscuousMode, SpinelMacScanState, SpinelPropertyId,
    SpinelResetReason, SpinelStatus,
};

/// Grace beyond the requested dwell for the RCP to report an energy-scan result.
const ENERGY_SCAN_RESULT_TIMEOUT: Duration = Duration::from_secs(2);

pub struct SpinelPhy {
    client: Arc<SpinelClient>,
    home_channel: Mutex<u8>,
    sinks: Mutex<Sinks>,
    energy_rx: AsyncMutex<mpsc::Receiver<SpinelFramePropValueIs>>,
    inbound: Mutex<Option<Inbound>>,
}

#[derive(Default)]
struct Sinks {
    rx: Option<mpsc::Sender<RxFrame>>,
    reset: Option<mpsc::Sender<ResetEvent>>,
}

/// The RCP receivers consumed once by [`RadioPhy::start`] to drive the forward tasks.
struct Inbound {
    raw: mpsc::Receiver<SpinelFramePropValueIs>,
    reset: mpsc::Receiver<SpinelStatus>,
}

impl SpinelPhy {
    pub fn new(client: Arc<SpinelClient>) -> Self {
        let (raw_tx, raw_rx) = mpsc::channel(64);
        let (energy_tx, energy_rx) = mpsc::channel(8);
        let (reset_tx, reset_rx) = mpsc::channel(8);

        client.set_property_update_receiver(SpinelPropertyId::StreamRaw, raw_tx);
        client.set_property_update_receiver(SpinelPropertyId::MacEnergyScanResult, energy_tx);
        client.set_reset_notification_receiver(reset_tx);

        Self {
            client,
            home_channel: Mutex::new(11),
            sinks: Mutex::new(Sinks::default()),
            energy_rx: AsyncMutex::new(energy_rx),
            inbound: Mutex::new(Some(Inbound {
                raw: raw_rx,
                reset: reset_rx,
            })),
        }
    }
}

fn map_err(err: SpinelError) -> RadioError {
    match err {
        SpinelError::Timeout => RadioError::Timeout,
        SpinelError::TransportClosed | SpinelError::CancelledByReset => RadioError::TransportClosed,
        other => RadioError::Other(other.to_string()),
    }
}

const fn map_status(status: SpinelStatus) -> TxResult {
    match status {
        SpinelStatus::Ok => TxResult::Acked,
        SpinelStatus::NoAck => TxResult::NoAck,
        SpinelStatus::CcaFailure => TxResult::ChannelAccessFailure,
        _ => TxResult::Failed,
    }
}

async fn set_prop(
    client: &SpinelClient,
    id: SpinelPropertyId,
    value: Vec<u8>,
) -> Result<(SpinelPropertyId, Vec<u8>), RadioError> {
    client.prop_value_set(id, value).await.map_err(map_err)
}

async fn write_frame_pending(
    client: &SpinelClient,
    short: &[Nwk],
    extended: &[Eui64],
) -> Result<(), RadioError> {
    let short_bytes: Vec<u8> = short.iter().flat_map(|nwk| nwk.to_bytes()).collect();
    set_prop(
        client,
        SpinelPropertyId::MacSrcMatchShortAddresses,
        short_bytes,
    )
    .await?;

    let extended_bytes: Vec<u8> = extended
        .iter()
        .flat_map(|eui64| ziggurat_spinel::eui64_to_spinel_bytes(*eui64))
        .collect();
    set_prop(
        client,
        SpinelPropertyId::MacSrcMatchExtendedAddresses,
        extended_bytes,
    )
    .await?;
    Ok(())
}

async fn apply_config(client: &SpinelClient, config: &RadioConfig) -> Result<(), RadioError> {
    set_prop(client, SpinelPropertyId::PhyEnabled, vec![1]).await?;
    set_prop(client, SpinelPropertyId::PhyChan, vec![config.channel]).await?;
    set_prop(
        client,
        SpinelPropertyId::PhyTxPower,
        vec![config.tx_power as u8],
    )
    .await?;

    let promiscuous = if config.promiscuous {
        SpinelMacPromiscuousMode::Full
    } else {
        SpinelMacPromiscuousMode::Off
    };
    set_prop(
        client,
        SpinelPropertyId::MacPromiscuousMode,
        vec![promiscuous as u8],
    )
    .await?;

    set_prop(
        client,
        SpinelPropertyId::Mac154Laddr,
        ziggurat_spinel::eui64_to_spinel_bytes(config.extended_address).to_vec(),
    )
    .await?;
    set_prop(
        client,
        SpinelPropertyId::Mac154Saddr,
        config.short_address.to_bytes().to_vec(),
    )
    .await?;
    set_prop(
        client,
        SpinelPropertyId::Mac154Panid,
        config.pan_id.to_bytes().to_vec(),
    )
    .await?;
    set_prop(
        client,
        SpinelPropertyId::MacRxOnWhenIdleMode,
        vec![config.rx_on_when_idle as u8],
    )
    .await?;
    set_prop(client, SpinelPropertyId::MacRawStreamEnabled, vec![1]).await?;
    set_prop(client, SpinelPropertyId::MacSrcMatchEnabled, vec![1]).await?;
    write_frame_pending(
        client,
        &config.frame_pending_short,
        &config.frame_pending_extended,
    )
    .await
}

fn tx_frame_to_spinel(frame: TxFrame, channel: u8) -> SpinelTxFrame {
    SpinelTxFrame {
        psdu: frame.psdu,
        channel: Some(frame.channel.unwrap_or(channel)),
        max_csma_backoffs: Some(frame.max_csma_backoffs),
        max_frame_retries: Some(frame.max_frame_retries),
        enable_csma_ca: Some(frame.csma_ca),
        is_header_updated: Some(true),
        is_a_retransmit: Some(false),
        is_security_processed: Some(frame.security_processed),
        tx_delay: None,
        tx_delay_base_time: None,
        rx_channel_after_tx: None,
        tx_power: None,
    }
}

impl RadioPhy for SpinelPhy {
    async fn reset(&self) -> Result<(), RadioError> {
        self.client
            .send_reset(SpinelResetReason::Stack)
            .await
            .map_err(map_err)
    }

    async fn reconfigure(&self, config: &RadioConfig) -> Result<(), RadioError> {
        let _radio = self.client.lock_radio().await;
        apply_config(&self.client, config).await?;
        *self.home_channel.lock() = config.channel;
        Ok(())
    }

    async fn set_channel(&self, channel: u8) -> Result<(), RadioError> {
        let _radio = self.client.lock_radio().await;
        let (response, value) =
            set_prop(&self.client, SpinelPropertyId::PhyChan, vec![channel]).await?;
        if response != SpinelPropertyId::PhyChan {
            return Err(RadioError::Rejected(format!(
                "channel change to {channel} rejected: {response:?}={value:02X?}"
            )));
        }
        *self.home_channel.lock() = channel;
        Ok(())
    }

    async fn set_frame_pending_table(
        &self,
        short: &[Nwk],
        extended: &[Eui64],
    ) -> Result<(), RadioError> {
        write_frame_pending(&self.client, short, extended).await
    }

    async fn transmit(&self, frame: TxFrame, priority: TxPriority) -> Result<TxResult, RadioError> {
        let home = *self.home_channel.lock();
        let spinel_frame = tx_frame_to_spinel(frame, home);
        let status = self
            .client
            .transmit_frame(&spinel_frame, SpinelTxPriority(priority.0))
            .await
            .map_err(map_err)?;
        Ok(map_status(status))
    }

    #[allow(clippy::significant_drop_tightening)]
    async fn energy_detect(&self, channel: u8, duration: Duration) -> Result<i8, RadioError> {
        let mut energy_rx = self.energy_rx.lock().await;
        while energy_rx.try_recv().is_ok() {}

        let scan_period_ms = u16::try_from(duration.as_millis()).unwrap_or(u16::MAX);

        let max_rssi = {
            let _radio = self.client.lock_radio().await;

            set_prop(&self.client, SpinelPropertyId::MacScanMask, vec![channel]).await?;
            set_prop(
                &self.client,
                SpinelPropertyId::MacScanPeriod,
                scan_period_ms.to_le_bytes().to_vec(),
            )
            .await?;

            let (response, value) = set_prop(
                &self.client,
                SpinelPropertyId::MacScanState,
                vec![SpinelMacScanState::Energy as u8],
            )
            .await?;
            if response != SpinelPropertyId::MacScanState {
                return Err(RadioError::Rejected(format!(
                    "energy scan of channel {channel} rejected: {response:?}={value:02X?}"
                )));
            }

            let update = timeout(duration + ENERGY_SCAN_RESULT_TIMEOUT, energy_rx.recv())
                .await
                .map_err(|_| RadioError::Timeout)?
                .ok_or(RadioError::TransportClosed)?;

            let [scanned_channel, max_rssi] = update.value[..] else {
                return Err(RadioError::Other(format!(
                    "malformed energy scan result: {:02X?}",
                    update.value
                )));
            };
            if scanned_channel != channel {
                return Err(RadioError::Other(format!(
                    "energy scan result for wrong channel: {scanned_channel} != {channel}"
                )));
            }
            max_rssi as i8
        };

        let home = *self.home_channel.lock();
        set_prop(&self.client, SpinelPropertyId::PhyChan, vec![home]).await?;
        Ok(max_rssi)
    }

    #[allow(clippy::significant_drop_tightening)]
    async fn active_scan(
        &self,
        channels: &[u8],
        beacon_request: &[u8],
        dwell: Duration,
    ) -> Result<(), RadioError> {
        let result = async {
            for &channel in channels {
                let radio = self.client.lock_radio().await;
                set_prop(&self.client, SpinelPropertyId::PhyChan, vec![channel]).await?;

                let frame = SpinelTxFrame {
                    psdu: beacon_request.to_vec(),
                    channel: Some(channel),
                    max_csma_backoffs: Some(4),
                    max_frame_retries: Some(0),
                    enable_csma_ca: Some(true),
                    is_header_updated: Some(true),
                    is_a_retransmit: Some(false),
                    is_security_processed: Some(true),
                    tx_delay: None,
                    tx_delay_base_time: None,
                    rx_channel_after_tx: None,
                    tx_power: None,
                };
                radio.transmit_frame(&frame).await.map_err(map_err)?;

                sleep(dwell).await;
            }
            Ok(())
        }
        .await;

        let home = *self.home_channel.lock();
        set_prop(&self.client, SpinelPropertyId::PhyChan, vec![home]).await?;
        result
    }

    fn set_rx_sink(&self, sink: mpsc::Sender<RxFrame>) {
        self.sinks.lock().rx = Some(sink);
    }

    fn set_reset_sink(&self, sink: mpsc::Sender<ResetEvent>) {
        self.sinks.lock().reset = Some(sink);
    }

    fn start(&self) {
        let Inbound { mut raw, mut reset } =
            self.inbound.lock().take().expect("start called twice");

        let rx_sink = self.sinks.lock().rx.clone().expect("rx sink not set");
        tokio::spawn(async move {
            while let Some(update) = raw.recv().await {
                let Ok(frame) = SpinelRxFrame::from_bytes(&update.value) else {
                    continue;
                };
                if frame.psdu.len() < 2 {
                    continue;
                }
                let psdu = frame.psdu[..frame.psdu.len() - 2].to_vec();
                let rx = RxFrame {
                    psdu,
                    channel: frame.channel,
                    rssi: frame.rssi,
                    lqi: frame.lqi,
                    timestamp_us: frame.timestamp_us,
                };
                if rx_sink.send(rx).await.is_err() {
                    break;
                }
            }
        });

        let reset_sink = self.sinks.lock().reset.clone().expect("reset sink not set");
        tokio::spawn(async move {
            while let Some(status) = reset.recv().await {
                let event = ResetEvent {
                    reason: format!("{status:?}"),
                };
                if reset_sink.send(event).await.is_err() {
                    break;
                }
            }
        });
    }
}
