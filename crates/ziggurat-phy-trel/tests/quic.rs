//! SPIKE: secure ZLOE (QUIC) between two nodes over loopback, each with a fake radio.

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

use ziggurat_phy_trel::QuicConfig;

const NWK_KEY: [u8; 16] = [0x11; 16];

async fn secure_node(
    epan: Eui64,
    port: u16,
    eui: u8,
    nwk: u16,
    key: Option<[u8; 16]>,
) -> (TrelPhy<FakeRadio>, Arc<FakeState>) {
    let radio = Arc::new(FakeState::default());
    let phy = TrelPhy::new(
        FakeRadio(Arc::clone(&radio)),
        TrelConfig {
            port,
            static_peers: vec![],
            mdns: true,
            interface: None,
            prefer_ipv4: false,
            mcast_port: 0,
            mcast_block_file: None,
            ipv4_only: false,
            quic: Some(QuicConfig {
                port: port + 1,
                code_file: None,
            }),
            deny: DenyList::default(),
        },
    )
    .await
    .unwrap();
    phy.reconfigure(&config(eui, nwk)).await.unwrap();
    phy.set_extended_pan_id(epan);
    if let Some(key) = key {
        phy.set_network_key(&key, epan, Eui64([eui; 8]), nwk == 0)
            .unwrap();
    }
    (phy, radio)
}

/// Send until acked over QUIC (the link needs mDNS discovery plus a handshake first).
async fn send_until_acked(phy: &TrelPhy<FakeRadio>, radio: &FakeState, dst: u16) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline {
        let before = radio.sent.lock().len();
        let result = phy.transmit(data_frame(dst, 0x0000, true)).await.unwrap();
        // Acked without touching the radio: it went over QUIC
        if result == TxResult::Acked && radio.sent.lock().len() == before {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread")]
async fn secure_peers_exchange_over_quic() {
    let epan = Eui64([0x51; 8]);
    let (a, radio_a) = secure_node(epan, 47301, 0xA1, 0x0000, Some(NWK_KEY)).await;
    let (b, _radio_b) = secure_node(epan, 47303, 0xB1, 0x2222, Some(NWK_KEY)).await;
    let mut rx_b = b.subscribe_rx();
    assert!(
        send_until_acked(&a, &radio_a, 0x2222).await,
        "peers: {:?}",
        a.peers()
    );
    let got = tokio::time::timeout(Duration::from_secs(1), rx_b.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got.psdu[got.psdu.len() - 5..], b"hello");
}

#[tokio::test(flavor = "multi_thread")]
async fn other_network_key_is_refused() {
    let epan = Eui64([0x52; 8]);
    let (a, radio_a) = secure_node(epan, 47311, 0xA2, 0x0000, Some(NWK_KEY)).await;
    let (_b, _) = secure_node(epan, 47313, 0xB2, 0x3333, Some([0x22; 16])).await;
    // B is discovered as a secure peer (same epan), so only TLS can keep it out
    let found = tokio::time::Instant::now() + Duration::from_secs(10);
    while !a.peers().iter().any(|p| p.contains("b2:b2")) {
        assert!(tokio::time::Instant::now() < found, "B never discovered");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Never acked over QUIC: TLS fails, every send falls back to the radio
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while tokio::time::Instant::now() < deadline {
        let before = radio_a.sent.lock().len();
        a.transmit(data_frame(0x3333, 0x0000, true)).await.unwrap();
        assert_eq!(
            radio_a.sent.lock().len(),
            before + 1,
            "sent over the backbone"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn coordinator_with_settings(epan: Eui64, port: u16, eui: u8) -> TrelPhy<FakeRadio> {
    let (coord, _) = secure_node(epan, port, eui, 0x0000, Some(NWK_KEY)).await;
    coord.set_netinfo_provider(Arc::new(|| Some(b"network settings".to_vec())));
    coord
}

#[tokio::test(flavor = "multi_thread")]
async fn enrollment_with_code() {
    let epan = Eui64([0x53; 8]);
    let dir = std::env::temp_dir().join(format!("zloe-enroll-{}", std::process::id()));
    let code_file = dir.with_extension("code");
    let coord = {
        let radio = Arc::new(FakeState::default());
        let phy = TrelPhy::new(
            FakeRadio(radio),
            TrelConfig {
                port: 47321,
                static_peers: vec![],
                mdns: true,
                interface: None,
                prefer_ipv4: false,
                mcast_port: 0,
                mcast_block_file: None,
                ipv4_only: false,
                quic: Some(QuicConfig {
                    port: 47322,
                    code_file: Some(code_file.clone()),
                }),
                deny: DenyList::default(),
            },
        )
        .await
        .unwrap();
        phy.reconfigure(&config(0xA3, 0x0000)).await.unwrap();
        phy.set_extended_pan_id(epan);
        phy.set_network_key(&NWK_KEY, epan, Eui64([0xA3; 8]), true)
            .unwrap();
        phy.set_netinfo_provider(Arc::new(|| Some(b"network settings".to_vec())));
        phy
    };
    let code = std::fs::read_to_string(&code_file).unwrap();
    // Satellite: no network key yet
    let (sat, _) = secure_node(epan, 47323, 0xB3, 0x4444, None).await;

    let wrong = sat
        .enroll(
            Some(epan),
            "AAAAAAAAAAAAAAAAAAAAAAAAAA",
            Duration::from_secs(10),
        )
        .await;
    assert!(wrong.is_err(), "wrong code accepted");
    let settings = sat
        .enroll(Some(epan), code.trim(), Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(settings, b"network settings");
    // One use
    assert!(
        sat.enroll(Some(epan), code.trim(), Duration::from_secs(5))
            .await
            .is_err()
    );
    drop(coord);
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_enrollment_only_while_pairing() {
    let epan = Eui64([0x54; 8]);
    let coord = coordinator_with_settings(epan, 47331, 0xA4).await;
    let pairing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&pairing);
    coord.set_pairing_open(Arc::new(move || {
        flag.load(std::sync::atomic::Ordering::Relaxed)
    }));
    let (sat, _) = secure_node(epan, 47333, 0xB4, 0x5555, None).await;

    assert!(
        sat.enroll(Some(epan), "", Duration::from_secs(10))
            .await
            .is_err(),
        "closed"
    );
    pairing.store(true, std::sync::atomic::Ordering::Relaxed);
    let settings = sat
        .enroll(Some(epan), "", Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(settings, b"network settings");
}
