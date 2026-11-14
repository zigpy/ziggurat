//! [`RadioPhy`] implemented over an OpenThread RCP via Spinel.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use embedded_io_async::{Read, Write};
use ziggurat_ieee_802154::types::{Eui64, Nwk};
use ziggurat_ieee_802154::{FCS_LENGTH, Ieee802154Frame, Msdu};
use ziggurat_phy::{
    ExclusiveRadio, RadioConfig, RadioError, RadioPhy, Receiver, ResetEvent, RxFrame, TxFrame,
    TxResult,
};
use ziggurat_runtime::runtime::Runtime;
use ziggurat_runtime::sync::{Mutex, Notify};
use ziggurat_spinel::client::{
    ExclusiveRadio as SpinelRadioGuard, SpinelClient, SpinelError, SpinelRxFrame, SpinelTxFrame,
};
use ziggurat_spinel::{
    SpinelEvent, SpinelFramePropValueIs, SpinelMacPromiscuousMode, SpinelMacScanState,
    SpinelPropertyId, SpinelResetReason, SpinelStatus,
};

const ENERGY_SCAN_RESULT_TIMEOUT: Duration = Duration::from_secs(2);

/// A bounded queue with one consumer. A push onto a full queue drops the item.
struct Queue<T> {
    state: Mutex<QueueState<T>>,
    ready: Notify,
    capacity: usize,
    /// What the items are, for the log.
    name: &'static str,
}

struct QueueState<T> {
    items: VecDeque<T>,
    closed: bool,
    /// Items dropped since the consumer last took one.
    dropped: u32,
}

impl<T> Queue<T> {
    fn new(name: &'static str, capacity: usize) -> Self {
        Self {
            state: Mutex::new(QueueState {
                items: VecDeque::with_capacity(capacity),
                closed: false,
                dropped: 0,
            }),
            ready: Notify::new(),
            capacity,
            name,
        }
    }

    fn push(&self, item: T) {
        {
            let mut state = self.state.lock();
            if state.items.len() == self.capacity {
                state.dropped += 1;
                return;
            }
            state.items.push_back(item);
        }
        self.ready.notify_one();
    }

    fn clear(&self) {
        let mut state = self.state.lock();
        state.items.clear();
        state.dropped = 0;
    }

    /// End the stream: `recv` returns `None` once the queued items are consumed.
    fn close(&self) {
        self.state.lock().closed = true;
        self.ready.notify_one();
    }

    async fn recv(&self) -> Option<T> {
        loop {
            let dropped = {
                let mut state = self.state.lock();
                if let Some(item) = state.items.pop_front() {
                    Some((item, core::mem::take(&mut state.dropped)))
                } else if state.closed {
                    return None;
                } else {
                    None
                }
            };

            // Logged once per burst, when the consumer catches up, not once per item
            if let Some((item, dropped)) = dropped {
                if dropped > 0 {
                    tracing::warn!(
                        "Dropped {dropped} {}: the queue of {} was full",
                        self.name,
                        self.capacity
                    );
                }
                return Some(item);
            }
            self.ready.notified().await;
        }
    }
}

/// A subscribed stream, returned by `subscribe_*` and pulled by the driver.
pub struct QueueRx<T>(Arc<Queue<T>>);

impl<T: Send> Receiver<T> for QueueRx<T> {
    async fn recv(&mut self) -> Option<T> {
        self.0.recv().await
    }
}

/// The queue of the currently-subscribed stream. `subscribe_*` swaps a fresh queue in
/// here and closes the previous one.
struct SlotState<T> {
    queue: Option<Arc<Queue<T>>>,
    /// The link ended. A later subscription gets a stream that has already ended.
    closed: bool,
}

type Slot<T> = Mutex<SlotState<T>>;

const fn new_slot<T>() -> Slot<T> {
    Mutex::new(SlotState {
        queue: None,
        closed: false,
    })
}

fn subscribe<T>(slot: &Slot<T>, name: &'static str, capacity: usize) -> QueueRx<T> {
    let queue = Arc::new(Queue::new(name, capacity));
    let (previous, closed) = {
        let mut slot = slot.lock();
        (slot.queue.replace(Arc::clone(&queue)), slot.closed)
    };
    if let Some(previous) = previous {
        previous.close();
    }
    if closed {
        queue.close();
    }
    QueueRx(queue)
}

fn close_slot<T>(slot: &Slot<T>) {
    let queue = {
        let mut slot = slot.lock();
        slot.closed = true;
        slot.queue.clone()
    };
    if let Some(queue) = queue {
        queue.close();
    }
}

/// Where the Spinel client's unsolicited events land.
struct Streams {
    rx: Slot<RxFrame>,
    reset: Slot<ResetEvent>,
    energy: Queue<SpinelFramePropValueIs>,
}

impl Streams {
    /// The link ended: every stream ends once its queued items are consumed.
    fn close(&self) {
        close_slot(&self.rx);
        close_slot(&self.reset);
        self.energy.close();
    }

    fn deliver(&self, event: SpinelEvent, value: &[u8]) {
        match event {
            SpinelEvent::PropertyUpdate(property_id) => match property_id {
                SpinelPropertyId::StreamRaw => self.deliver_rx(value),
                SpinelPropertyId::MacEnergyScanResult => {
                    self.energy.push(SpinelFramePropValueIs {
                        property_id,
                        value: value.to_vec(),
                    });
                }
                // Expected for e.g. the MacScanState=IDLE update at the end of each
                // scanned channel
                property_id => tracing::debug!("Ignoring property update: {property_id:?}"),
            },
            SpinelEvent::Reset(status) => {
                let queue = self.reset.lock().queue.clone();
                if let Some(queue) = queue {
                    queue.push(ResetEvent {
                        reason: format!("{status:?}"),
                    });
                }
            }
            SpinelEvent::Response(_) | SpinelEvent::LateResponse(_) => {
                unreachable!("responses stay inside the client")
            }
        }
    }

    fn deliver_rx(&self, value: &[u8]) {
        let Ok(frame) = SpinelRxFrame::from_bytes(value) else {
            return;
        };
        if frame.psdu.len() < 2 {
            return;
        }
        let queue = self.rx.lock().queue.clone();
        if let Some(queue) = queue {
            let mut psdu = frame.psdu;
            psdu.truncate(psdu.len() - FCS_LENGTH);
            queue.push(RxFrame {
                psdu,
                channel: frame.channel,
                rssi: frame.rssi,
                lqi: frame.lqi,
                timestamp_us: frame.timestamp_us,
            });
        }
    }
}

struct CloseStreamsOnDrop<'a>(&'a Streams);

impl Drop for CloseStreamsOnDrop<'_> {
    fn drop(&mut self) {
        self.0.close();
    }
}

pub struct SpinelPhy<R: Runtime> {
    client: SpinelClient<R>,
    home_channel: Mutex<u8>,
    streams: Arc<Streams>,
}

impl<R: Runtime> Default for SpinelPhy<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: Runtime> SpinelPhy<R> {
    pub fn new() -> Self {
        let streams = Arc::new(Streams {
            rx: new_slot(),
            reset: new_slot(),
            energy: Queue::new("energy scan results", 8),
        });
        let client_streams = Arc::clone(&streams);

        Self {
            client: SpinelClient::new(Box::new(move |event, value| {
                client_streams.deliver(event, value);
            })),
            home_channel: Mutex::new(11),
            streams,
        }
    }

    /// Drive the RCP link over its transport. Returns only when the transport fails;
    /// nothing else on this PHY makes progress unless this is running. Runs once per
    /// PHY: when it ends, returned or dropped, every stream ends too.
    pub async fn run<Rd: Read, Wr: Write>(&self, reader: Rd, writer: Wr) -> RadioError {
        let _closing = CloseStreamsOnDrop(&self.streams);
        map_err(self.client.run(reader, writer).await)
    }

    /// The radio's factory-programmed EUI64, readable before any network is configured.
    pub async fn hw_address(&self) -> Result<Eui64, RadioError> {
        self.client.get_hw_address().await.map_err(map_err)
    }
}

/// Exclusive radio access over the Spinel client.
pub struct SpinelExclusive<'a, R: Runtime> {
    phy: &'a SpinelPhy<R>,
    guard: SpinelRadioGuard<'a, R>,
}

impl<R: Runtime> ExclusiveRadio for SpinelExclusive<'_, R> {
    async fn set_channel(&self, channel: u8) -> Result<(), RadioError> {
        let (response, value) =
            set_spinel_prop(&self.phy.client, SpinelPropertyId::PhyChan, &[channel]).await?;
        if response != SpinelPropertyId::PhyChan {
            return Err(RadioError::Rejected(format!(
                "channel change to {channel} rejected: {response:?}={value:02X?}"
            )));
        }
        *self.phy.home_channel.lock() = channel;
        Ok(())
    }

    async fn transmit(&self, frame: TxFrame) -> Result<TxResult, RadioError> {
        let home = *self.phy.home_channel.lock();
        let spinel_frame = tx_frame_to_spinel(frame, home);
        let status = self
            .guard
            .transmit_frame(&spinel_frame)
            .await
            .map_err(map_err)?;
        Ok(map_status(status))
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

async fn set_spinel_prop<R: Runtime>(
    client: &SpinelClient<R>,
    id: SpinelPropertyId,
    value: &[u8],
) -> Result<(SpinelPropertyId, Vec<u8>), RadioError> {
    client.prop_value_set(id, value).await.map_err(map_err)
}

async fn write_frame_pending<R: Runtime>(
    client: &SpinelClient<R>,
    short: &[Nwk],
    extended: &[Eui64],
) -> Result<(), RadioError> {
    client
        .prop_value_set_with(SpinelPropertyId::MacSrcMatchShortAddresses, |value| {
            for nwk in short {
                value.extend(nwk.to_bytes());
            }
        })
        .await
        .map_err(map_err)?;

    client
        .prop_value_set_with(SpinelPropertyId::MacSrcMatchExtendedAddresses, |value| {
            for eui64 in extended {
                value.extend(eui64.to_be_bytes());
            }
        })
        .await
        .map_err(map_err)?;
    Ok(())
}

async fn apply_config<R: Runtime>(
    client: &SpinelClient<R>,
    config: &RadioConfig,
) -> Result<(), RadioError> {
    set_spinel_prop(client, SpinelPropertyId::PhyEnabled, &[1]).await?;
    set_spinel_prop(client, SpinelPropertyId::PhyChan, &[config.channel]).await?;
    set_spinel_prop(
        client,
        SpinelPropertyId::PhyTxPower,
        &[config.tx_power as u8],
    )
    .await?;

    let promiscuous = if config.promiscuous {
        SpinelMacPromiscuousMode::Full
    } else {
        SpinelMacPromiscuousMode::Off
    };
    set_spinel_prop(
        client,
        SpinelPropertyId::MacPromiscuousMode,
        &[promiscuous as u8],
    )
    .await?;

    set_spinel_prop(
        client,
        SpinelPropertyId::Mac154Laddr,
        &config.extended_address.to_be_bytes(),
    )
    .await?;
    set_spinel_prop(
        client,
        SpinelPropertyId::Mac154Saddr,
        &config.short_address.to_bytes(),
    )
    .await?;
    set_spinel_prop(
        client,
        SpinelPropertyId::Mac154Panid,
        &config.pan_id.to_bytes(),
    )
    .await?;
    set_spinel_prop(
        client,
        SpinelPropertyId::MacRxOnWhenIdleMode,
        &[config.rx_on_when_idle as u8],
    )
    .await?;
    set_spinel_prop(client, SpinelPropertyId::MacRawStreamEnabled, &[1]).await?;
    set_spinel_prop(client, SpinelPropertyId::MacSrcMatchEnabled, &[1]).await?;
    write_frame_pending(
        client,
        &config.frame_pending_short,
        &config.frame_pending_extended,
    )
    .await
}

fn tx_frame_to_spinel(frame: TxFrame, channel: u8) -> SpinelTxFrame {
    // The RCP's frame length must include the FCS.
    let mut psdu = frame.psdu;
    let fcs = Ieee802154Frame::<Msdu>::compute_fcs(&psdu).to_le_bytes();
    psdu.extend_from_slice(&fcs)
        .expect("the driver leaves room for the FCS");

    let tx_channel = frame.channel.unwrap_or(channel);

    // The fields are positional, so the receive channel needs the delay fields before
    // it. OT receives on the transmit channel after an off-channel frame unless told
    // otherwise; zero delay fields mean an untimed transmit.
    let (tx_delay, tx_delay_base_time, rx_channel_after_tx) = match frame.tx_at {
        Some(tx_at) => (
            Some(tx_at.delay_us),
            Some(tx_at.base_us as u32),
            Some(channel),
        ),
        None if tx_channel != channel => (Some(0), Some(0), Some(channel)),
        None => (None, None, None),
    };

    SpinelTxFrame {
        psdu,
        channel: Some(tx_channel),
        max_csma_backoffs: Some(frame.max_csma_backoffs),
        max_frame_retries: Some(frame.max_frame_retries),
        enable_csma_ca: Some(frame.csma_ca),
        is_header_updated: Some(true),
        is_a_retransmit: Some(false),
        is_security_processed: Some(frame.security_processed),
        tx_delay,
        tx_delay_base_time,
        rx_channel_after_tx,
        tx_power: None,
    }
}

impl<R: Runtime> RadioPhy for SpinelPhy<R> {
    type Exclusive<'a> = SpinelExclusive<'a, R>;
    type RxStream = QueueRx<RxFrame>;
    type ResetStream = QueueRx<ResetEvent>;

    async fn reset(&self) -> Result<(), RadioError> {
        self.client.send_reset(SpinelResetReason::Stack);
        Ok(())
    }

    async fn reconfigure(&self, config: &RadioConfig) -> Result<(), RadioError> {
        let _radio = self.client.lock_radio().await;
        apply_config(&self.client, config).await?;
        *self.home_channel.lock() = config.channel;
        Ok(())
    }

    async fn lock(&self) -> SpinelExclusive<'_, R> {
        let guard = self.client.lock_radio().await;
        SpinelExclusive { phy: self, guard }
    }

    async fn set_frame_pending_table(
        &self,
        short: &[Nwk],
        extended: &[Eui64],
    ) -> Result<(), RadioError> {
        write_frame_pending(&self.client, short, extended).await
    }

    async fn transmit(&self, frame: TxFrame) -> Result<TxResult, RadioError> {
        let home = *self.home_channel.lock();
        let spinel_frame = tx_frame_to_spinel(frame, home);
        let status = self
            .client
            .transmit_frame(&spinel_frame)
            .await
            .map_err(map_err)?;
        Ok(map_status(status))
    }

    async fn energy_detect(&self, channel: u8, duration: Duration) -> Result<i8, RadioError> {
        let scan_period_ms = u16::try_from(duration.as_millis()).unwrap_or(u16::MAX);

        let max_rssi = {
            // Lock the radio for the duration of the energy detect scan
            let _radio = self.client.lock_radio().await;
            self.streams.energy.clear();

            set_spinel_prop(&self.client, SpinelPropertyId::MacScanMask, &[channel]).await?;
            set_spinel_prop(
                &self.client,
                SpinelPropertyId::MacScanPeriod,
                &scan_period_ms.to_le_bytes(),
            )
            .await?;

            let (response, value) = set_spinel_prop(
                &self.client,
                SpinelPropertyId::MacScanState,
                &[SpinelMacScanState::Energy as u8],
            )
            .await?;
            if response != SpinelPropertyId::MacScanState {
                return Err(RadioError::Rejected(format!(
                    "energy scan of channel {channel} rejected: {response:?}={value:02X?}"
                )));
            }

            let update = R::timeout(
                duration + ENERGY_SCAN_RESULT_TIMEOUT,
                self.streams.energy.recv(),
            )
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
        set_spinel_prop(&self.client, SpinelPropertyId::PhyChan, &[home]).await?;
        Ok(max_rssi)
    }

    fn subscribe_rx(&self) -> QueueRx<RxFrame> {
        subscribe(&self.streams.rx, "received frames", 32)
    }

    fn subscribe_reset(&self) -> QueueRx<ResetEvent> {
        subscribe(&self.streams.reset, "reset events", 8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_queue_counts_what_it_drops() {
        let queue = Queue::new("items", 2);
        for item in 0..5 {
            queue.push(item);
        }

        let state = queue.state.lock();
        assert_eq!(state.items, [0, 1]);
        assert_eq!(state.dropped, 3);
    }
}
