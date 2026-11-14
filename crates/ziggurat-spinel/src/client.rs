use crate::{
    HdlcSpecial, SPINEL_FRAME_MAX_SIZE, SpinelCommandId, SpinelEvent, SpinelFrameParsingError,
    SpinelHeader, SpinelPropertyId, SpinelProtocol, SpinelResetReason, SpinelStatus, Transaction,
    hdlc_escape_into, packed_uint21_deserialize, packed_uint21_into,
};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::pin::pin;
use core::time::Duration;
use embedded_io_async::{Error as _, Read, Write};
use futures::future::{Either, select};
use thiserror::Error;
use ziggurat_ieee_802154::Psdu;
use ziggurat_ieee_802154::types::Eui64;
use ziggurat_runtime::runtime::{RtInstant, Runtime};
use ziggurat_runtime::sync::{AsyncMutex, AsyncMutexGuard, Mutex, Notify};

/// A local RCP link — serial, or Ethernet to a network-attached RCP — answers in
/// milliseconds; anything beyond this is a failure. Wi-Fi is not supported: its
/// latency variance can spuriously trip the consecutive-timeout limit and force a
/// reset-recovery against a perfectly healthy radio.
const TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SpinelTxFrame {
    pub psdu: Psdu,
    pub channel: Option<u8>,
    pub max_csma_backoffs: Option<u8>,
    pub max_frame_retries: Option<u8>,
    pub enable_csma_ca: Option<bool>,
    pub is_header_updated: Option<bool>,
    pub is_a_retransmit: Option<bool>,
    pub is_security_processed: Option<bool>,
    pub tx_delay: Option<u32>,
    pub tx_delay_base_time: Option<u32>,
    pub rx_channel_after_tx: Option<u8>,
    pub tx_power: Option<i8>,
}

/// The property id and value of a property response payload.
fn parse_property(response: &[u8]) -> Result<(SpinelPropertyId, &[u8]), SpinelError> {
    let (property_id, value) =
        packed_uint21_deserialize(response).map_err(SpinelError::U21ParsingError)?;
    let property_id = SpinelPropertyId::try_from(property_id)
        .map_err(|_| SpinelError::InvalidResponsePropertyId { property_id })?;

    Ok((property_id, value))
}

impl SpinelTxFrame {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        self.serialize_into(&mut result);
        result
    }

    /// Append the `STREAM_RAW` value: the PSDU and its transmit metadata.
    pub fn serialize_into(&self, result: &mut Vec<u8>) {
        result.extend_from_slice(&(self.psdu.len() as u16).to_le_bytes());
        result.extend_from_slice(&self.psdu);

        // TODO: These are not really optional per-field, they must be contiguous: if a
        // field is not provided, all subsequent fields must be omitted as well
        if let Some(channel) = self.channel {
            result.push(channel);
        }

        if let Some(max_csma_backoffs) = self.max_csma_backoffs {
            result.push(max_csma_backoffs);
        }

        if let Some(max_frame_retries) = self.max_frame_retries {
            result.push(max_frame_retries);
        }

        if let Some(enable_csma_ca) = self.enable_csma_ca {
            result.push(enable_csma_ca as u8);
        }

        if let Some(is_header_updated) = self.is_header_updated {
            result.push(is_header_updated as u8);
        }

        if let Some(is_a_retransmit) = self.is_a_retransmit {
            result.push(is_a_retransmit as u8);
        }

        if let Some(is_security_processed) = self.is_security_processed {
            result.push(is_security_processed as u8);
        }

        if let Some(tx_delay) = self.tx_delay {
            result.extend_from_slice(&tx_delay.to_le_bytes());
        }

        if let Some(tx_delay_base_time) = self.tx_delay_base_time {
            result.extend_from_slice(&tx_delay_base_time.to_le_bytes());
        }

        if let Some(rx_channel_after_tx) = self.rx_channel_after_tx {
            result.push(rx_channel_after_tx);
        }

        if let Some(tx_power) = self.tx_power {
            result.push(tx_power as u8);
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SpinelRxFrame {
    pub psdu: Psdu,
    pub rssi: i8,
    pub noise_floor: i8,
    pub flags: u32,
    pub channel: u8,
    pub lqi: u8,
    pub timestamp_us: u64,
    pub receive_error: u8,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SpinelRxFrameError {
    #[error("frame too short, expected at least {expected} bytes, got {got}")]
    TooShort { expected: usize, got: usize },
    #[error("PSDU too long to fit its frame bound, got {got} bytes")]
    PsduTooLong { got: usize },
}

impl SpinelRxFrame {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SpinelRxFrameError> {
        let mut offset = 0;

        // The 2-byte PSDU length prefix must be present before it can be read
        if bytes.len() < 2 {
            return Err(SpinelRxFrameError::TooShort {
                expected: 2,
                got: bytes.len(),
            });
        }
        let psdu_len = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;

        // The PSDU is followed by a fixed metadata trailer: rssi, noise floor, flags,
        // channel, lqi, timestamp, and receive error
        let expected = offset + psdu_len + (1 + 1 + 4 + 1 + 1 + 8 + 1);
        if expected > bytes.len() {
            return Err(SpinelRxFrameError::TooShort {
                expected,
                got: bytes.len(),
            });
        }

        let psdu = Psdu::from_slice(&bytes[offset..offset + psdu_len])
            .map_err(|_| SpinelRxFrameError::PsduTooLong { got: psdu_len })?;
        offset += psdu_len;

        let rssi = bytes[offset] as i8;
        offset += 1;

        let noise_floor = bytes[offset] as i8;
        offset += 1;

        let flags = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        offset += 4;

        let channel = bytes[offset];
        offset += 1;

        let lqi = bytes[offset];
        offset += 1;

        let timestamp_us = u64::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        offset += 8;

        // Any vendor-specific bytes after it are not read
        let receive_error = bytes[offset];

        Ok(Self {
            psdu,
            rssi,
            noise_floor,
            flags,
            channel,
            lqi,
            timestamp_us,
            receive_error,
        })
    }
}

#[derive(Error, Debug)]
pub enum SpinelError {
    #[error("io error: {0:?}")]
    Io(embedded_io_async::ErrorKind),
    #[error("command cancelled by an RCP reset")]
    CancelledByReset,
    #[error("the spinel transport closed")]
    TransportClosed,
    #[error("the spinel transport stopped accepting bytes")]
    WriteStalled,
    #[error("the RCP stopped answering")]
    Unresponsive,
    #[error("timeout")]
    Timeout,
    #[error("spinel U21 parsing error")]
    U21ParsingError(#[from] SpinelFrameParsingError),
    #[error("invalid property id {property_id} in response")]
    InvalidResponsePropertyId { property_id: u32 },
    #[error("NCP version is not valid UTF-8")]
    NcpVersionNotUtf8,
    #[error("invalid hardware address: {got:02X?}")]
    InvalidHardwareAddress { got: Vec<u8> },
    #[error("unexpected response property: expected {expected:?}, got {got:?}")]
    UnexpectedResponseProperty {
        expected: SpinelPropertyId,
        got: SpinelPropertyId,
    },
    #[error("response payload was empty")]
    EmptyResponse,
    #[error("invalid spinel status {status}")]
    InvalidStatus { status: u8 },
}

/// A frame waiting for the write loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outbound {
    /// The request of this transaction id, written in its transaction.
    Request(u8),
    /// A `CMD_RESET`, which has no transaction.
    Reset(SpinelResetReason),
}

struct State {
    protocol: SpinelProtocol,
    /// Frames waiting for the write loop.
    outbound: VecDeque<Outbound>,
    /// The transaction id of the request the write loop is writing right now.
    writing: Option<u8>,
    /// [`SpinelClient::run`] is running. It runs one link at a time.
    running: bool,
    /// How many times [`SpinelClient::run`] was called.
    runs: u32,
    /// [`SpinelClient::run`] returned and was not called again: nothing is read or
    /// written.
    closed: bool,
    /// Resets forwarded to the event handler, announced or not.
    resets: u64,
    /// End the link rather than forward a reset once requests keep timing out.
    close_when_unresponsive: bool,
    /// The link timed out too often and is to be closed.
    unresponsive: bool,
}

/// A command's hold on its transaction id. The id and a frame the write loop has not
/// reached yet are given back when the command returns or its future is dropped.
struct HeldTransaction<'a, R: Runtime> {
    client: &'a SpinelClient<R>,
    tid: u8,
}

impl<R: Runtime> HeldTransaction<'_, R> {
    /// Give the id back. A response is read with `read` before the id is released, as
    /// another command could otherwise overwrite it. Returns what `read` made of the
    /// response, or where the transaction stood if there was none.
    fn release<T>(&self, read: impl FnOnce(&[u8]) -> T) -> Result<T, Transaction> {
        let now = self.client.now();

        let released = {
            let mut state = self.client.state.lock();
            state
                .outbound
                .retain(|outbound| *outbound != Outbound::Request(self.tid));

            // The request went out, or is going out, and its response is still to
            // come. The id waits for it, so that it cannot reach a later command
            let response_due = *state.protocol.transaction(self.tid)
                == Transaction::AwaitingResponse
                || state.writing == Some(self.tid);

            let transaction = if response_due {
                state.protocol.abandon_request(self.tid, now + TIMEOUT)
            } else {
                state.protocol.release_request(self.tid)
            };

            match transaction {
                Transaction::Answered => Ok(read(state.protocol.response(self.tid))),
                transaction => Err(transaction),
            }
        };
        self.client.tid_released.notify_one();

        released
    }

    /// Give the id back, reading its response with `read` if it has one.
    fn finish<T>(self, read: impl FnOnce(&[u8]) -> T) -> Result<T, Transaction> {
        let released = self.release(read);
        // The id may already belong to another command: it must not be released twice
        core::mem::forget(self);

        released
    }
}

impl<R: Runtime> Drop for HeldTransaction<'_, R> {
    fn drop(&mut self) {
        let _ = self.release(|_| ());
    }
}

/// Closes the link when [`SpinelClient::run`] ends, also when its future is dropped.
/// The write loop may have taken a frame it will now never write, and its command
/// must not wait for it.
struct CloseOnDrop<'a, R: Runtime>(&'a SpinelClient<R>);

impl<R: Runtime> Drop for CloseOnDrop<'_, R> {
    fn drop(&mut self) {
        {
            let mut state = self.0.state.lock();
            state.closed = true;
            state.running = false;
        }
        self.0.wake_all_waiters();
    }
}

/// Receives the unsolicited events: property updates, with their value, and resets.
pub type EventHandler = Box<dyn Fn(SpinelEvent, &[u8]) + Send + Sync>;

/// The RCP link. Commands queue frames and wait for their responses; [`Self::run`] does
/// all the transport IO.
pub struct SpinelClient<R: Runtime> {
    state: Mutex<State>,
    /// Indexed by transaction id; woken when that transaction changes and when the
    /// link closes.
    transaction_changed: [Notify; 8],
    outbound_ready: Notify,
    /// Commands that found all seven transaction ids in use wait here, in order. Only
    /// the first of them waits on `tid_released`.
    tid_queue: AsyncMutex<()>,
    tid_released: Notify,
    /// Woken when the link timed out too often and is to be closed.
    link_unresponsive: Notify,
    on_event: EventHandler,
    /// Functional ownership of the radio (scan, reset recovery, channel retune), taken via
    /// [`Self::lock_radio`].
    exclusive_lock: AsyncMutex<()>,
    /// The fixed moment the protocol's clock counts from.
    epoch: R::Instant,
}

impl<R: Runtime> SpinelClient<R> {
    pub fn new(on_event: EventHandler) -> Self {
        Self {
            state: Mutex::new(State {
                protocol: SpinelProtocol::new(),
                outbound: VecDeque::new(),
                writing: None,
                running: false,
                runs: 0,
                closed: false,
                resets: 0,
                close_when_unresponsive: false,
                unresponsive: false,
            }),
            transaction_changed: core::array::from_fn(|_| Notify::new()),
            outbound_ready: Notify::new(),
            tid_queue: AsyncMutex::new(()),
            tid_released: Notify::new(),
            link_unresponsive: Notify::new(),
            on_event,
            exclusive_lock: AsyncMutex::new(()),
            epoch: R::now(),
        }
    }

    fn now(&self) -> Duration {
        R::now().saturating_duration_since(self.epoch)
    }

    /// Drive the link: parse inbound bytes and write queued frames. Returns only when
    /// the transport fails, or when the RCP stopped answering and
    /// [`Self::set_close_when_unresponsive`] is on. Commands that wait then fail with
    /// `TransportClosed`.
    ///
    /// Can be called again once it returned, with a new link to the same or another
    /// radio. That run first resets the RCP; the reset is forwarded like any other, so
    /// the radio is reconfigured. If the RCP does not announce it, a `ResetUnknown` is
    /// forwarded after [`TIMEOUT`].
    pub async fn run<Rd: Read, Wr: Write>(&self, reader: Rd, writer: Wr) -> SpinelError {
        let relinked = {
            let mut state = self.state.lock();
            assert!(!state.running, "the Spinel link runs one at a time");
            state.running = true;
            state.closed = false;
            state.unresponsive = false;
            state.runs += 1;

            let relinked = state.runs > 1;
            if relinked {
                state.protocol.link_restarted();
                state
                    .outbound
                    .push_front(Outbound::Reset(SpinelResetReason::Stack));
            }
            relinked
        };
        let _closing = CloseOnDrop(self);

        let read = pin!(self.read_loop(reader));
        let write = pin!(self.write_loop(writer));
        let watch = pin!(self.watch_link(relinked));

        match select(select(read, write), watch).await {
            Either::Left((Either::Left((error, _)) | Either::Right((error, _)), _))
            | Either::Right((error, _)) => error,
        }
    }

    /// Watch the link from the side: presume a reset if a new link brings no reset
    /// announcement, and end the link once it is unresponsive.
    async fn watch_link(&self, relinked: bool) -> SpinelError {
        if relinked {
            let seen = self.state.lock().resets;
            R::sleep(TIMEOUT).await;

            let presumed = {
                let mut state = self.state.lock();
                (state.resets == seen).then(|| state.protocol.presume_reset())
            };
            if let Some(reset) = presumed {
                tracing::warn!("The RCP announced no reset on the new link, presuming one");
                self.forward_reset(reset);
            }
        }

        loop {
            if self.state.lock().unresponsive {
                return SpinelError::Unresponsive;
            }
            self.link_unresponsive.notified().await;
        }
    }

    /// End the link, rather than forward a `ResponseTimeout` reset, once requests keep
    /// timing out. For links that can die without an error: a TCP peer that vanished,
    /// or a serial-to-TCP bridge whose serial port went away. Off by default.
    pub fn set_close_when_unresponsive(&self, close: bool) {
        self.state.lock().close_when_unresponsive = close;
    }

    /// Hand a reset to the event handler. The protocol already cancelled the requests.
    fn forward_reset(&self, reset: SpinelEvent) {
        self.state.lock().resets += 1;
        self.wake_all_waiters();
        (self.on_event)(reset, &[]);
    }

    async fn read_loop<Rd: Read>(&self, mut reader: Rd) -> SpinelError {
        let mut buffer = [0u8; 2048];
        // The value of the property update being handled. It keeps its capacity
        let mut update = Vec::new();

        loop {
            let n = match reader.read(&mut buffer).await {
                Ok(0) => return SpinelError::TransportClosed,
                Ok(n) => n,
                Err(e) => return SpinelError::Io(e.kind()),
            };

            self.state.lock().protocol.receive(&buffer[..n]);

            loop {
                // One frame at a time, so events are handled outside the lock
                let event = self.state.lock().protocol.next_event(&mut update);
                let Some(event) = event else {
                    break;
                };

                match event {
                    SpinelEvent::Response(tid) => {
                        self.transaction_changed[usize::from(tid)].notify_one();
                    }
                    SpinelEvent::LateResponse(_) => self.tid_released.notify_one(),
                    SpinelEvent::Reset(_) => self.forward_reset(event),
                    SpinelEvent::PropertyUpdate(_) => (self.on_event)(event, &update),
                }
            }
        }
    }

    async fn write_loop<Wr: Write>(&self, mut writer: Wr) -> SpinelError {
        // Frames go out one at a time, so two persistent buffers cover every TX
        let mut frame_scratch = Vec::with_capacity(SPINEL_FRAME_MAX_SIZE);
        // Worst-case HDLC escaping doubles the frame, plus two flags
        let mut hdlc_scratch = Vec::with_capacity(2 * SPINEL_FRAME_MAX_SIZE + 2);

        loop {
            if !self.next_outbound(&mut frame_scratch) {
                self.outbound_ready.notified().await;
                continue;
            }

            hdlc_scratch.clear();
            hdlc_scratch.push(HdlcSpecial::Flag as u8);
            hdlc_escape_into(&frame_scratch, &mut hdlc_scratch);
            hdlc_scratch.push(HdlcSpecial::Flag as u8);

            tracing::trace!("Writing {hdlc_scratch:02X?}");

            // A transport that takes this long to accept one frame is dead
            let write = pin!(writer.write_all(&hdlc_scratch));
            let stalled = pin!(R::sleep(TIMEOUT));
            match select(write, stalled).await {
                Either::Left((Ok(()), _)) => {}
                Either::Left((Err(e), _)) => return SpinelError::Io(e.kind()),
                Either::Right(_) => return SpinelError::WriteStalled,
            }

            // The command's response timeout starts here. One lock covers both steps: a
            // command dropped in between would find its request neither being written
            // nor sent, and free its id while the response is still to come
            let tid = {
                let mut state = self.state.lock();
                let tid = state.writing.take();
                if let Some(tid) = tid {
                    state.protocol.request_written(tid);
                }
                tid
            };
            if let Some(tid) = tid {
                self.transaction_changed[usize::from(tid)].notify_one();
            }
        }
    }

    /// Take the next frame waiting for the write loop into `frame`, cleared first, and
    /// mark its transaction as being written. Returns `false` when none waits.
    fn next_outbound(&self, frame: &mut Vec<u8>) -> bool {
        let mut state = self.state.lock();

        // A reset cancels the queued requests. Their commands remove their frames only
        // when they next run, and the reset RCP must not get them before then
        let outbound = loop {
            let outbound = state.outbound.pop_front();
            match outbound {
                Some(Outbound::Request(tid))
                    if *state.protocol.transaction(tid) == Transaction::Cancelled => {}
                _ => break outbound,
            }
        };

        frame.clear();
        state.writing = match outbound {
            Some(Outbound::Request(tid)) => {
                frame.extend_from_slice(state.protocol.request(tid));
                Some(tid)
            }
            Some(Outbound::Reset(reason)) => {
                let header = SpinelHeader {
                    flag: 0b10,
                    network_link_id: 0,
                    transaction_id: 0,
                };
                frame.extend(header.to_bytes());
                frame.push(SpinelCommandId::Reset as u8);
                frame.push(reason as u8);
                // Resets carry no transaction
                None
            }
            None => None,
        };

        outbound.is_some()
    }

    fn wake_all_waiters(&self) {
        for changed in &self.transaction_changed {
            changed.notify_one();
        }
        // A reset frees the abandoned transaction ids
        self.tid_released.notify_one();
    }

    /// `CMD_RESET` is acknowledged with an unsolicited `LastStatus = RESET_*`
    /// notification rather than a tid-matched response, so this only sends.
    pub fn send_reset(&self, reason: SpinelResetReason) {
        self.state
            .lock()
            .outbound
            .push_back(Outbound::Reset(reason));
        self.outbound_ready.notify_one();
    }

    /// Take a transaction id, waiting for one while all seven are in use.
    async fn allocate_tid(&self) -> u8 {
        let _queue = self.tid_queue.lock().await;

        loop {
            let now = self.now();
            let abandoned_until = {
                let mut state = self.state.lock();
                if let Some(tid) = state.protocol.allocate_tid(now) {
                    return tid;
                }
                state.protocol.next_abandoned_expiry()
            };

            // An abandoned id comes back by itself, with no release to wake us
            match abandoned_until {
                Some(until) => {
                    let _ =
                        R::timeout(until.saturating_sub(now), self.tid_released.notified()).await;
                }
                None => self.tid_released.notified().await,
            }
        }
    }

    /// Send a command whose payload `write` appends, and read its response payload
    /// with `read`.
    pub async fn send_command<T>(
        &self,
        command_id: SpinelCommandId,
        write: impl FnOnce(&mut Vec<u8>),
        read: impl FnOnce(&[u8]) -> T,
    ) -> Result<T, SpinelError> {
        let tid = self.allocate_tid().await;
        let transaction = HeldTransaction { client: self, tid };

        {
            let mut state = self.state.lock();
            if state.closed {
                return Err(SpinelError::TransportClosed);
            }
            state.protocol.write_request(tid, command_id, write);
            tracing::trace!("Sending frame {:02X?}", state.protocol.request(tid));
            state.outbound.push_back(Outbound::Request(tid));
        }
        self.outbound_ready.notify_one();

        // The timeout is for the RCP to answer, so it starts once the request is
        // written. A request reported as timed out must not go out afterwards: the
        // caller may send it again, and a transmit would then reach the air twice
        if R::timeout(TIMEOUT, self.request_left_queue(tid))
            .await
            .is_err()
        {
            // Removed under the lock that finds it, so the write loop cannot take it
            // in between
            let unsent = {
                let mut state = self.state.lock();
                let queued = state.outbound.len();
                state
                    .outbound
                    .retain(|outbound| *outbound != Outbound::Request(tid));
                state.outbound.len() != queued
            };

            if unsent {
                return Err(self.request_timed_out());
            }

            // The write loop is writing it. It finishes, or gives up and closes the
            // link, within its own timeout
            self.request_left_queue(tid).await;
        }

        let timed_out = R::timeout(TIMEOUT, self.request_settled(tid))
            .await
            .is_err();

        // Where the transaction stands decides the result, not the timer: a response
        // can arrive between the timeout firing and this line
        match transaction.finish(read) {
            Ok(response) => Ok(response),
            Err(Transaction::Answered) => unreachable!("an answered transaction is read"),
            Err(Transaction::Cancelled) => Err(SpinelError::CancelledByReset),
            Err(
                Transaction::Queued
                | Transaction::AwaitingResponse
                | Transaction::Free
                | Transaction::Abandoned { .. },
            ) => {
                if timed_out {
                    Err(self.request_timed_out())
                } else {
                    // Nothing settled it, so the link closed
                    Err(SpinelError::TransportClosed)
                }
            }
        }
    }

    /// Wait until the request `tid` is no longer queued: it was written or a reset
    /// cancelled it. Also returns when the link closes.
    async fn request_left_queue(&self, tid: u8) {
        loop {
            {
                let state = self.state.lock();
                if *state.protocol.transaction(tid) != Transaction::Queued || state.closed {
                    return;
                }
            }
            self.transaction_changed[usize::from(tid)].notified().await;
        }
    }

    /// Wait until the request `tid` has its response or a reset cancelled it. Also
    /// returns when the link closes.
    async fn request_settled(&self, tid: u8) {
        loop {
            {
                let state = self.state.lock();
                if matches!(
                    state.protocol.transaction(tid),
                    Transaction::Answered | Transaction::Cancelled
                ) || state.closed
                {
                    return;
                }
            }
            self.transaction_changed[usize::from(tid)].notified().await;
        }
    }

    /// Count a request that timed out, and start reset recovery once enough have.
    fn request_timed_out(&self) -> SpinelError {
        let reset = {
            let mut state = self.state.lock();
            let reset = state.protocol.request_timed_out();
            if reset.is_some() && state.close_when_unresponsive {
                state.unresponsive = true;
                None
            } else {
                reset
            }
        };

        match reset {
            Some(reset) => {
                tracing::error!("Triggering reset recovery");
                self.forward_reset(reset);
            }
            None if self.state.lock().unresponsive => {
                tracing::error!("Closing the RCP link");
                self.wake_all_waiters();
                self.link_unresponsive.notify_one();
            }
            None => {}
        }

        SpinelError::Timeout
    }

    pub async fn prop_value_get(
        &self,
        property_id: SpinelPropertyId,
    ) -> Result<Vec<u8>, SpinelError> {
        match self.prop_value_get_once(property_id).await {
            Err(SpinelError::Timeout) => self.prop_value_get_once(property_id).await,
            result => result,
        }
    }

    async fn prop_value_get_once(
        &self,
        property_id: SpinelPropertyId,
    ) -> Result<Vec<u8>, SpinelError> {
        self.send_command(
            SpinelCommandId::PropValueGet,
            |payload| packed_uint21_into(property_id as u32, payload),
            |response| {
                let (_, value) =
                    packed_uint21_deserialize(response).map_err(SpinelError::U21ParsingError)?;
                Ok(value.to_vec())
            },
        )
        .await?
    }

    pub async fn prop_value_set(
        &self,
        property_id: SpinelPropertyId,
        value: &[u8],
    ) -> Result<(SpinelPropertyId, Vec<u8>), SpinelError> {
        self.prop_value_set_with(property_id, |payload| payload.extend_from_slice(value))
            .await
    }

    /// Set a property to the value `write` appends.
    pub async fn prop_value_set_with(
        &self,
        property_id: SpinelPropertyId,
        write: impl Fn(&mut Vec<u8>) + Sync,
    ) -> Result<(SpinelPropertyId, Vec<u8>), SpinelError> {
        match self.prop_value_set_once(property_id, &write).await {
            Err(SpinelError::Timeout) => self.prop_value_set_once(property_id, &write).await,
            result => result,
        }
    }

    async fn prop_value_set_once(
        &self,
        property_id: SpinelPropertyId,
        write: impl FnOnce(&mut Vec<u8>),
    ) -> Result<(SpinelPropertyId, Vec<u8>), SpinelError> {
        let (rsp_property_id, value) = self
            .send_command(
                SpinelCommandId::PropValueSet,
                |payload| {
                    packed_uint21_into(property_id as u32, payload);
                    write(payload);
                },
                |response| {
                    parse_property(response)
                        .map(|(property_id, value)| (property_id, value.to_vec()))
                },
            )
            .await??;

        tracing::trace!("Set property {property_id:?}, result {rsp_property_id:?}={value:02X?}");

        Ok((rsp_property_id, value))
    }

    /// Take functional ownership of the radio, fencing out transmits for the life of the
    /// guard. The right tool for any operation that drives the radio across multiple
    /// commands: scans, channel retune, reset recovery. The guard can itself transmit —
    /// see [`ExclusiveRadio::transmit_frame`].
    pub async fn lock_radio(&self) -> ExclusiveRadio<'_, R> {
        ExclusiveRadio {
            client: self,
            _guard: self.exclusive_lock.lock().await,
        }
    }

    // Convenience method wrapping broad functionality are below
    pub async fn get_ncp_version(&self) -> Result<String, SpinelError> {
        let ncp_version_rsp = self.prop_value_get(SpinelPropertyId::NcpVersion).await?;

        let ncp_version_with_null =
            String::from_utf8(ncp_version_rsp).map_err(|_| SpinelError::NcpVersionNotUtf8)?;

        Ok(ncp_version_with_null
            .trim_matches(char::from(0x00))
            .to_string())
    }

    /// The radio's factory-programmed EUI64, a core property readable in any RCP state.
    pub async fn get_hw_address(&self) -> Result<Eui64, SpinelError> {
        let rsp = self.prop_value_get(SpinelPropertyId::Hwaddr).await?;

        let bytes: [u8; 8] = rsp
            .try_into()
            .map_err(|rsp: Vec<u8>| SpinelError::InvalidHardwareAddress { got: rsp })?;

        Ok(Eui64::from_be_bytes(bytes))
    }

    pub async fn transmit_frame(
        &self,
        tx_frame: &SpinelTxFrame,
    ) -> Result<SpinelStatus, SpinelError> {
        let _exclusive_lock = self.exclusive_lock.lock().await;
        self.transmit_frame_inner(tx_frame).await
    }

    /// Put a frame on the air, assuming the caller already holds the radio.
    async fn transmit_frame_inner(
        &self,
        tx_frame: &SpinelTxFrame,
    ) -> Result<SpinelStatus, SpinelError> {
        // No retry on timeout: a duplicate transmit is worse than a failed one, and the
        // NWK retry paths handle the failure
        self.send_command(
            SpinelCommandId::PropValueSet,
            |payload| {
                packed_uint21_into(SpinelPropertyId::StreamRaw as u32, payload);
                tx_frame.serialize_into(payload);
            },
            |response| {
                let (rsp_prop_id, value) = parse_property(response)?;

                if rsp_prop_id != SpinelPropertyId::LastStatus {
                    return Err(SpinelError::UnexpectedResponseProperty {
                        expected: SpinelPropertyId::LastStatus,
                        got: rsp_prop_id,
                    });
                }

                let &[status, ..] = value else {
                    return Err(SpinelError::EmptyResponse);
                };

                SpinelStatus::try_from(status).map_err(|_| SpinelError::InvalidStatus { status })
            },
        )
        .await?
    }
}

/// Functional ownership of the radio, handed out by [`SpinelClient::lock_radio`].
pub struct ExclusiveRadio<'a, R: Runtime> {
    client: &'a SpinelClient<R>,
    _guard: AsyncMutexGuard<'a, ()>,
}

impl<R: Runtime> ExclusiveRadio<'_, R> {
    /// Put a frame on the air while owning the radio.
    pub async fn transmit_frame(
        &self,
        tx_frame: &SpinelTxFrame,
    ) -> Result<SpinelStatus, SpinelError> {
        self.client.transmit_frame_inner(tx_frame).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HdlcLiteFrame, SpinelFrame, packed_uint21_to_bytes};
    use alloc::sync::Arc;
    use alloc::vec;
    use embedded_io_adapters::tokio_1::FromTokio;
    use std::sync::Mutex as StdMutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
    use tokio::task::JoinHandle;
    use ziggurat_runtime::runtime::TokioRuntime;

    type Client = SpinelClient<TokioRuntime>;
    type Link = (
        FromTokio<ReadHalf<DuplexStream>>,
        FromTokio<WriteHalf<DuplexStream>>,
    );

    /// The far end of a link, standing in for the RCP.
    struct Rcp {
        io: DuplexStream,
        parser: SpinelProtocol,
    }

    impl Rcp {
        /// The frames the client wrote, waiting up to `wait` for the first.
        async fn frames(&mut self, wait: Duration) -> Vec<SpinelFrame> {
            let mut buffer = [0u8; 512];
            match tokio::time::timeout(wait, self.io.read(&mut buffer)).await {
                Ok(Ok(n)) => self.parser.parse_frames_from_bytes(&buffer[..n]),
                _ => Vec::new(),
            }
        }

        async fn send(&mut self, tid: u8, command_id: SpinelCommandId, payload: Vec<u8>) {
            let frame = SpinelFrame {
                header: SpinelHeader {
                    flag: 0b10,
                    network_link_id: 0,
                    transaction_id: tid,
                },
                command_id,
                payload,
            };
            let bytes = HdlcLiteFrame {
                data: frame.to_bytes(),
            }
            .to_bytes_with_flags();
            self.io.write_all(&bytes).await.unwrap();
        }

        async fn announce_reset(&mut self) {
            let mut payload = packed_uint21_to_bytes(SpinelPropertyId::LastStatus as u32);
            payload.extend(packed_uint21_to_bytes(SpinelStatus::ResetSoftware as u32));
            self.send(0, SpinelCommandId::PropValueIs, payload).await;
        }

        /// Answer the next request, a property get, with `value`.
        async fn answer_get(&mut self, value: &[u8]) {
            let frames = self.frames(TIMEOUT).await;
            let request = frames
                .iter()
                .find(|frame| frame.command_id == SpinelCommandId::PropValueGet)
                .expect("a property get");
            let mut payload = request.payload.clone();
            payload.extend_from_slice(value);
            self.send(
                request.header.transaction_id,
                SpinelCommandId::PropValueIs,
                payload,
            )
            .await;
        }
    }

    fn link() -> (Link, Rcp) {
        let (client_side, rcp_side) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(client_side);
        let rcp = Rcp {
            io: rcp_side,
            parser: SpinelProtocol::new(),
        };
        ((FromTokio::new(reader), FromTokio::new(writer)), rcp)
    }

    fn client() -> (Arc<Client>, Arc<StdMutex<Vec<SpinelEvent>>>) {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::clone(&events);
        let client = Client::new(Box::new(move |event, _| {
            sink.lock().unwrap().push(event);
        }));
        (Arc::new(client), events)
    }

    fn run(client: &Arc<Client>, (reader, writer): Link) -> JoinHandle<SpinelError> {
        let client = Arc::clone(client);
        tokio::spawn(async move { client.run(reader, writer).await })
    }

    /// Run the client on a first link and lose it, then run it on a second one.
    async fn relinked(client: &Arc<Client>) -> (JoinHandle<SpinelError>, Rcp) {
        let (first, first_rcp) = link();
        let first_run = run(client, first);
        drop(first_rcp);
        assert!(matches!(
            first_run.await.unwrap(),
            SpinelError::TransportClosed
        ));

        let (second, second_rcp) = link();
        (run(client, second), second_rcp)
    }

    fn resets(events: &StdMutex<Vec<SpinelEvent>>) -> Vec<SpinelStatus> {
        events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|event| match event {
                SpinelEvent::Reset(status) => Some(*status),
                _ => None,
            })
            .collect()
    }

    fn is_stack_reset(frame: &SpinelFrame) -> bool {
        frame.command_id == SpinelCommandId::Reset
            && frame.payload == [SpinelResetReason::Stack as u8]
    }

    /// Get a property the RCP never answers: two timeouts, as a get is retried once.
    async fn get_unanswered(client: &Client) {
        assert!(matches!(
            client.prop_value_get(SpinelPropertyId::NcpVersion).await,
            Err(SpinelError::Timeout)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_later_run_resets_the_rcp_over_the_new_link() {
        let (client, _events) = client();
        let (_run, mut rcp) = relinked(&client).await;

        let frames = rcp.frames(TIMEOUT).await;
        assert!(frames.first().is_some_and(is_stack_reset), "{frames:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn test_the_first_run_sends_no_reset() {
        let (client, events) = client();
        let (first, mut rcp) = link();
        let _run = run(&client, first);

        assert_eq!(rcp.frames(TIMEOUT * 2).await, vec![]);
        assert_eq!(resets(&events), vec![]);
    }

    #[tokio::test(start_paused = true)]
    async fn test_commands_get_responses_over_the_new_link() {
        let (client, events) = client();
        let (_run, mut rcp) = relinked(&client).await;
        rcp.frames(TIMEOUT).await;
        rcp.announce_reset().await;
        // A command made before the reset arrives is cancelled by it
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(resets(&events), vec![SpinelStatus::ResetSoftware]);

        let get = client.prop_value_get(SpinelPropertyId::NcpVersion);
        let (value, ()) = tokio::join!(get, rcp.answer_get(b"OPENTHREAD"));
        assert_eq!(value.unwrap(), b"OPENTHREAD");
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_reset_announced_after_a_later_run_is_forwarded_once() {
        let (client, events) = client();
        let (_run, mut rcp) = relinked(&client).await;
        rcp.frames(TIMEOUT).await;
        rcp.announce_reset().await;

        tokio::time::sleep(TIMEOUT * 2).await;
        assert_eq!(resets(&events), vec![SpinelStatus::ResetSoftware]);
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_silent_rcp_after_a_later_run_gets_a_synthesized_reset() {
        let (client, events) = client();
        let (_run, mut rcp) = relinked(&client).await;
        rcp.frames(TIMEOUT).await;

        tokio::time::sleep(TIMEOUT - Duration::from_millis(100)).await;
        assert_eq!(resets(&events), vec![]);
        tokio::time::sleep(TIMEOUT).await;
        assert_eq!(resets(&events), vec![SpinelStatus::ResetUnknown]);
    }

    #[tokio::test(start_paused = true)]
    async fn test_commands_fail_while_no_run_is_active() {
        let (client, _events) = client();
        let (first, rcp) = link();
        let first_run = run(&client, first);
        drop(rcp);
        first_run.await.unwrap();

        assert!(matches!(
            client.prop_value_get(SpinelPropertyId::NcpVersion).await,
            Err(SpinelError::TransportClosed)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn test_an_unresponsive_link_is_closed_when_enabled() {
        let (client, events) = client();
        client.set_close_when_unresponsive(true);
        let (first, _rcp) = link();
        let first_run = run(&client, first);

        get_unanswered(&client).await;
        get_unanswered(&client).await;

        assert!(matches!(
            first_run.await.unwrap(),
            SpinelError::Unresponsive
        ));
        assert_eq!(resets(&events), vec![]);
    }

    #[tokio::test(start_paused = true)]
    async fn test_an_earlier_unresponsive_link_does_not_end_the_next_run() {
        let (client, _events) = client();
        client.set_close_when_unresponsive(true);
        let (first, _first_rcp) = link();
        let first_run = run(&client, first);
        get_unanswered(&client).await;
        get_unanswered(&client).await;
        first_run.await.unwrap();

        let (second, mut rcp) = link();
        let second_run = run(&client, second);
        rcp.frames(TIMEOUT).await;
        rcp.announce_reset().await;

        tokio::time::sleep(TIMEOUT * 4).await;
        assert!(!second_run.is_finished());
    }

    #[tokio::test(start_paused = true)]
    async fn test_an_unresponsive_link_gets_a_reset_by_default() {
        let (client, events) = client();
        let (first, _rcp) = link();
        let first_run = run(&client, first);

        get_unanswered(&client).await;
        get_unanswered(&client).await;

        assert_eq!(resets(&events), vec![SpinelStatus::ResponseTimeout]);
        assert!(!first_run.is_finished());
    }
}
