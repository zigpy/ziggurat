use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep;
use ziggurat_phy::{
    Eui64, Nwk, RadioConfig, RadioError, RadioPhy, ResetEvent, RxFrame, TxFrame, TxPriority,
    TxResult,
};

use crate::proto::{HubMsg, NodeMsg, Position, read_frame, write_frame};

type Sink<T> = Arc<Mutex<Option<mpsc::Sender<T>>>>;
type Pending = Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>>;

pub struct SimPhy {
    to_hub: mpsc::Sender<NodeMsg>,
    home_channel: Mutex<u8>,
    rx_sink: Sink<RxFrame>,
    reset_sink: Sink<ResetEvent>,
    pending: Pending,
    next_id: AtomicU32,
}

impl SimPhy {
    /// Connect to a medium server at `position`, taking ownership of the transport.
    pub async fn connect<A: ToSocketAddrs>(addr: A, position: Position) -> std::io::Result<Self> {
        let (mut read_half, mut write_half) = TcpStream::connect(addr).await?.into_split();

        let (to_hub, mut to_hub_rx) = mpsc::channel::<NodeMsg>(64);
        tokio::spawn(async move {
            while let Some(msg) = to_hub_rx.recv().await {
                if write_frame(&mut write_half, &msg.encode()).await.is_err() {
                    break;
                }
            }
        });

        let rx_sink: Sink<RxFrame> = Arc::new(Mutex::new(None));
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let reader_sink = Arc::clone(&rx_sink);
        let reader_pending = Arc::clone(&pending);
        tokio::spawn(async move {
            while let Ok(bytes) = read_frame(&mut read_half).await {
                match HubMsg::decode(&bytes) {
                    Some(HubMsg::Frame {
                        channel,
                        rssi,
                        lqi,
                        psdu,
                    }) => {
                        // A real radio validates and strips the 2-byte FCS before handing
                        // the frame up; the trait delivers FCS-stripped frames.
                        if psdu.len() < 2 {
                            continue;
                        }
                        let frame = RxFrame {
                            psdu: psdu[..psdu.len() - 2].to_vec(),
                            channel,
                            rssi,
                            lqi,
                            timestamp_us: 0,
                        };
                        let sink = reader_sink.lock().clone();
                        if let Some(sink) = sink {
                            let _ = sink.send(frame).await;
                        }
                    }
                    Some(HubMsg::TxResult { id, acked }) => {
                        let waiter = reader_pending.lock().remove(&id);
                        if let Some(waiter) = waiter {
                            let _ = waiter.send(acked);
                        }
                    }
                    None => {}
                }
            }
        });

        let _ = to_hub.send(NodeMsg::SetPosition(position)).await;

        Ok(Self {
            to_hub,
            home_channel: Mutex::new(11),
            rx_sink,
            reset_sink: Arc::new(Mutex::new(None)),
            pending,
            next_id: AtomicU32::new(0),
        })
    }

    async fn send(&self, msg: NodeMsg) -> Result<(), RadioError> {
        self.to_hub
            .send(msg)
            .await
            .map_err(|_| RadioError::TransportClosed)
    }

    /// Transmit `psdu` on `channel` and await the hub's MAC-level ack outcome.
    async fn transmit_awaiting_ack(&self, channel: u8, psdu: Vec<u8>) -> Result<bool, RadioError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (ack_tx, ack_rx) = oneshot::channel();
        self.pending.lock().insert(id, ack_tx);
        self.send(NodeMsg::Transmit { id, channel, psdu }).await?;
        ack_rx.await.map_err(|_| RadioError::TransportClosed)
    }
}

impl RadioPhy for SimPhy {
    async fn reset(&self) -> Result<(), RadioError> {
        // No hardware to reset; surface the notification the driver's reset path awaits.
        let sink = self.reset_sink.lock().clone();
        if let Some(sink) = sink {
            let _ = sink
                .send(ResetEvent {
                    reason: "sim reset".to_string(),
                })
                .await;
        }
        Ok(())
    }

    async fn reconfigure(&self, config: &RadioConfig) -> Result<(), RadioError> {
        *self.home_channel.lock() = config.channel;
        self.send(NodeMsg::SetAddresses {
            short: config.short_address.0,
            extended: config.extended_address.0,
        })
        .await?;
        self.send(NodeMsg::Listen {
            channel: config.channel,
        })
        .await
    }

    async fn set_channel(&self, channel: u8) -> Result<(), RadioError> {
        *self.home_channel.lock() = channel;
        self.send(NodeMsg::Listen { channel }).await
    }

    async fn set_frame_pending_table(
        &self,
        _short: &[Nwk],
        _extended: &[Eui64],
    ) -> Result<(), RadioError> {
        // The medium has no MAC-layer frame-pending; sleepy-child polling is not modeled.
        Ok(())
    }

    async fn transmit(
        &self,
        frame: TxFrame,
        _priority: TxPriority,
    ) -> Result<TxResult, RadioError> {
        let channel = frame.channel.unwrap_or_else(|| *self.home_channel.lock());
        let acked = self.transmit_awaiting_ack(channel, frame.psdu).await?;
        Ok(if acked {
            TxResult::Acked
        } else {
            TxResult::NoAck
        })
    }

    async fn energy_detect(&self, _channel: u8, _duration: Duration) -> Result<i8, RadioError> {
        Ok(-90)
    }

    async fn active_scan(
        &self,
        channels: &[u8],
        beacon_request: &[u8],
        dwell: Duration,
    ) -> Result<(), RadioError> {
        for &channel in channels {
            self.send(NodeMsg::Listen { channel }).await?;
            self.transmit_awaiting_ack(channel, beacon_request.to_vec())
                .await?;
            sleep(dwell).await;
        }
        let home = *self.home_channel.lock();
        self.send(NodeMsg::Listen { channel: home }).await
    }

    fn set_rx_sink(&self, sink: mpsc::Sender<RxFrame>) {
        *self.rx_sink.lock() = Some(sink);
    }

    fn set_reset_sink(&self, sink: mpsc::Sender<ResetEvent>) {
        *self.reset_sink.lock() = Some(sink);
    }
}
