//! SPIKE smoke test: two backbone nodes over loopback, each wrapping a fake radio.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::mpsc;
use ziggurat_ieee_802154::types::{Eui64, Nwk, PanId};
use ziggurat_phy::*;
use ziggurat_phy_trel::{DenyList, TrelConfig, TrelPhy};

#[derive(Default)]
struct FakeState {
    sent: Mutex<Vec<Vec<u8>>>,
    rx: Mutex<Option<mpsc::Sender<RxFrame>>>,
}

struct FakeRadio(Arc<FakeState>);

struct Rx<T>(mpsc::Receiver<T>);
impl<T: Send> Receiver<T> for Rx<T> {
    async fn recv(&mut self) -> Option<T> {
        self.0.recv().await
    }
}
struct NoExclusive;
impl ExclusiveRadio for NoExclusive {
    async fn set_channel(&self, _: u8) -> Result<(), RadioError> {
        Ok(())
    }
    async fn transmit(&self, _: TxFrame) -> Result<TxResult, RadioError> {
        Ok(TxResult::Acked)
    }
}

impl RadioPhy for FakeRadio {
    type Exclusive<'a> = NoExclusive;
    type RxStream = Rx<RxFrame>;
    type ResetStream = Rx<ResetEvent>;
    async fn reset(&self) -> Result<(), RadioError> {
        Ok(())
    }
    async fn reconfigure(&self, _: &RadioConfig) -> Result<(), RadioError> {
        Ok(())
    }
    async fn set_frame_pending_table(&self, _: &[Nwk], _: &[Eui64]) -> Result<(), RadioError> {
        Ok(())
    }
    async fn transmit(&self, frame: TxFrame) -> Result<TxResult, RadioError> {
        self.0.sent.lock().push(frame.psdu);
        Ok(TxResult::NoAck)
    }
    async fn energy_detect(&self, _: u8, _: Duration) -> Result<i8, RadioError> {
        Ok(0)
    }
    async fn lock(&self) -> NoExclusive {
        NoExclusive
    }
    fn subscribe_rx(&self) -> Rx<RxFrame> {
        let (tx, rx) = mpsc::channel(8);
        *self.0.rx.lock() = Some(tx);
        Rx(rx)
    }
    fn subscribe_reset(&self) -> Rx<ResetEvent> {
        Rx(mpsc::channel(1).1)
    }
}

fn config(eui: u8, nwk: u16) -> RadioConfig {
    RadioConfig {
        channel: 15,
        tx_power: 0,
        short_address: Nwk(nwk),
        extended_address: Eui64([eui; 8]),
        pan_id: PanId(0x1234),
        promiscuous: false,
        rx_on_when_idle: true,
        frame_pending_short: vec![],
        frame_pending_extended: vec![],
    }
}

/// Data frame, short dst/src, PAN compression, ack request as given.
fn data_frame(dst: u16, src: u16, ack: bool) -> TxFrame {
    let fcf: u16 = 0x0001 | (u16::from(ack) << 5) | (1 << 6) | (2 << 10) | (2 << 14);
    let mut psdu = fcf.to_le_bytes().to_vec();
    psdu.push(7);
    psdu.extend_from_slice(&0x1234u16.to_le_bytes());
    psdu.extend_from_slice(&dst.to_le_bytes());
    psdu.extend_from_slice(&src.to_le_bytes());
    psdu.extend_from_slice(b"hello");
    TxFrame {
        psdu,
        channel: None,
        csma_ca: true,
        max_frame_retries: 3,
        max_csma_backoffs: 4,
        security_processed: true,
    }
}

async fn node(
    port: u16,
    peer: u16,
    eui: u8,
    nwk: u16,
    mdns: bool,
) -> (TrelPhy<FakeRadio>, Arc<FakeState>) {
    let radio = Arc::new(FakeState::default());
    let phy = TrelPhy::new(
        FakeRadio(Arc::clone(&radio)),
        TrelConfig {
            port,
            static_peers: if mdns {
                vec![]
            } else {
                vec![([127, 0, 0, 1], peer).into()]
            },
            mdns,
            deny: DenyList::default(),
        },
    )
    .await
    .unwrap();
    phy.reconfigure(&config(eui, nwk)).await.unwrap();
    (phy, radio)
}

#[tokio::test(flavor = "multi_thread")]
async fn static_peers_broadcast_then_unicast() {
    let (a, radio_a) = node(47101, 47102, 0xAA, 0x0000, false).await;
    let (b, radio_b) = node(47102, 47101, 0xBB, 0x1111, false).await;
    let mut rx_a = a.subscribe_rx();
    let mut rx_b = b.subscribe_rx();

    // Broadcast from B: over the air and to A; A learns B
    b.transmit(data_frame(0xFFFF, 0x1111, false)).await.unwrap();
    assert_eq!(
        radio_b.sent.lock().len(),
        1,
        "broadcast also goes over the air"
    );
    let got = tokio::time::timeout(Duration::from_secs(1), rx_a.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.lqi, 255);

    // A unicasts to B: backbone only, acked
    let result = a.transmit(data_frame(0x1111, 0x0000, true)).await.unwrap();
    assert_eq!(result, TxResult::Acked);
    assert!(
        radio_a.sent.lock().is_empty(),
        "unicast to a peer stays off the air"
    );
    let got = tokio::time::timeout(Duration::from_secs(1), rx_b.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got.psdu[got.psdu.len() - 5..], b"hello");

    // Unknown destination: falls through to the radio
    let result = a.transmit(data_frame(0x2222, 0x0000, true)).await.unwrap();
    assert_eq!(result, TxResult::NoAck);
    assert_eq!(radio_a.sent.lock().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn mdns_discovery() {
    let (a, _) = node(47201, 0, 0xA1, 0x0000, true).await;
    let (b, _) = node(47202, 0, 0xB1, 0x2222, true).await;
    let mut rx_b = b.subscribe_rx();

    // Wait for A to resolve B over mDNS, then unicast by NWK address
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if a.peers()
            .iter()
            .any(|p| p.contains("0x2222") || p.contains("2222"))
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no mDNS peer: {:?}",
            a.peers()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let result = a.transmit(data_frame(0x2222, 0x0000, true)).await.unwrap();
    assert_eq!(result, TxResult::Acked);
    tokio::time::timeout(Duration::from_secs(1), rx_b.recv())
        .await
        .unwrap()
        .unwrap();
}
