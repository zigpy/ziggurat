//! Hardware crypto backend for the ESP32-C6.

use core::cell::RefCell;

use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use esp_hal::aes::cipher_modes::{Cbc, Ctr};
use esp_hal::aes::dma::{AesDma, AesDmaChannel, DmaCipherState};
use esp_hal::aes::{Aes, Operation};
use esp_hal::dma::aligned::DmaAlignedMut;
use esp_hal::dma::{DmaRxBuf, DmaTxBuf};
use esp_hal::dma_buffers;
use esp_hal::peripherals::AES;
use subtle::ConstantTimeEq;

use ziggurat_ieee_802154::FrameBytes;
use ziggurat_ieee_802154::types::Key;
use ziggurat_zigbee::crypto::{self, CryptoBackend, DecryptionError, MIC_LENGTH};

/// Scratch/DMA buffer size.
const DMA_BUF_SIZE: usize = 256;

/// The AES peripheral in DMA mode plus its two DMA buffers. `AesDma::process` consumes
/// the driver + buffers and hands them back from the transfer, so they live in
/// `Option`s and are taken/replaced around each pass. Behind a critical-section mutex:
/// the peripheral is shared by every task that does crypto.
struct DmaState {
    aes: Option<AesDma<'static>>,
    rx: Option<DmaRxBuf>,
    tx: Option<DmaTxBuf>,
}

static HW: Mutex<CriticalSectionRawMutex, RefCell<Option<DmaState>>> =
    Mutex::new(RefCell::new(None));

struct EspCrypto;

impl CryptoBackend for EspCrypto {
    fn aes128_encrypt_block(&self, key: &[u8; 16], block: &mut [u8; 16]) {
        HW.lock(|cell| {
            let mut guard = cell.borrow_mut();
            let dma = guard.as_mut().expect("hw_crypto::init was never called");
            // Single ECB block on the Typical path (the inner non-DMA driver).
            dma.aes.as_mut().unwrap().aes.encrypt(block, *key);
        });
    }

    fn encrypt_ccm(
        &self,
        key: &Key,
        nonce: &[u8; 13],
        auth_data: &[u8],
        buffer: FrameBytes,
    ) -> FrameBytes {
        let plen = buffer.len();

        let mut cbc_in = [0u8; DMA_BUF_SIZE];
        let cbc_len = format_cbc_mac_input(&mut cbc_in, nonce, auth_data, buffer.as_slice());

        let mut ctr_in = [0u8; DMA_BUF_SIZE];
        ctr_in[16..16 + plen].copy_from_slice(buffer.as_slice());
        let ctr_len = round_up_16(16 + plen);

        let mut cbc_out = [0u8; DMA_BUF_SIZE];
        let mut ctr_out = [0u8; DMA_BUF_SIZE];
        let cbc_state: DmaCipherState = Cbc::new([0u8; 16]).into();
        let ctr_state: DmaCipherState = Ctr::new(ctr_block(nonce, 0)).into();
        HW.lock(|cell| {
            let mut guard = cell.borrow_mut();
            let dma = guard.as_mut().expect("hw_crypto::init was never called");
            run(dma, &cbc_state, &key.0, &cbc_in[..cbc_len], &mut cbc_out[..cbc_len]);
            run(dma, &ctr_state, &key.0, &ctr_in[..ctr_len], &mut ctr_out[..ctr_len]);
        });

        let tag = &cbc_out[cbc_len - 16..cbc_len];
        let s0 = &ctr_out[0..16];

        let mut out = FrameBytes::new();
        out.extend_from_slice(&ctr_out[16..16 + plen])
            .expect("ciphertext fits a frame");
        for i in 0..MIC_LENGTH {
            out.push(tag[i] ^ s0[i]).expect("frame has room for the MIC");
        }
        out
    }

    fn decrypt_ccm(
        &self,
        key: &Key,
        nonce: &[u8; 13],
        auth_data: &[u8],
        tagged_ciphertext: FrameBytes,
    ) -> Result<FrameBytes, DecryptionError> {
        let clen = tagged_ciphertext
            .len()
            .checked_sub(MIC_LENGTH)
            .ok_or(DecryptionError::CiphertextTooShort)?;
        let (ciphertext, recv_mic) = tagged_ciphertext.as_slice().split_at(clen);

        let mut ctr_in = [0u8; DMA_BUF_SIZE];
        ctr_in[16..16 + clen].copy_from_slice(ciphertext);
        let ctr_len = round_up_16(16 + clen);

        let mut ctr_out = [0u8; DMA_BUF_SIZE];
        let ctr_state: DmaCipherState = Ctr::new(ctr_block(nonce, 0)).into();
        // Recover the plaintext (and S0) first, then MAC the recovered plaintext.
        let mut cbc_out = [0u8; DMA_BUF_SIZE];
        let cbc_state: DmaCipherState = Cbc::new([0u8; 16]).into();
        let mut cbc_in = [0u8; DMA_BUF_SIZE];
        let cbc_len = HW.lock(|cell| {
            let mut guard = cell.borrow_mut();
            let dma = guard.as_mut().expect("hw_crypto::init was never called");
            run(dma, &ctr_state, &key.0, &ctr_in[..ctr_len], &mut ctr_out[..ctr_len]);

            let cbc_len = format_cbc_mac_input(&mut cbc_in, nonce, auth_data, &ctr_out[16..16 + clen]);
            run(dma, &cbc_state, &key.0, &cbc_in[..cbc_len], &mut cbc_out[..cbc_len]);
            cbc_len
        });

        let tag = &cbc_out[cbc_len - 16..cbc_len];
        let s0 = &ctr_out[0..16];

        let expected_mic: [u8; MIC_LENGTH] = core::array::from_fn(|i| tag[i] ^ s0[i]);
        if !bool::from(expected_mic[..].ct_eq(recv_mic)) {
            return Err(DecryptionError::InvalidMacTag);
        }

        Ok(FrameBytes::from_slice(&ctr_out[16..16 + clen]).expect("plaintext fits a frame"))
    }
}

static BACKEND: EspCrypto = EspCrypto;

/// One DMA-AES pass over `input` (length a multiple of 16), copying the result into
/// `out`.
fn run(dma: &mut DmaState, state: &DmaCipherState, key: &[u8; 16], input: &[u8], out: &mut [u8]) {
    let blocks = input.len() / 16;
    let mut tx = dma.tx.take().unwrap();
    let mut rx = dma.rx.take().unwrap();
    let aes = dma.aes.take().unwrap();

    tx.fill(input);
    rx.set_length(input.len());

    let Ok(transfer) = aes.process(blocks, rx, tx, Operation::Encrypt, state, *key) else {
        panic!("AES DMA transfer setup failed");
    };
    let (aes, rx, tx) = transfer.wait();
    out.copy_from_slice(&rx.as_slice()[..input.len()]);

    dma.aes = Some(aes);
    dma.rx = Some(rx);
    dma.tx = Some(tx);
}

fn round_up_16(n: usize) -> usize {
    n.div_ceil(16) * 16
}

/// CCM* counter block `A_i`: flags = L-1 = 1, then the nonce, then the 2-byte counter.
fn ctr_block(nonce: &[u8; 13], counter: u16) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[0] = 1;
    block[1..14].copy_from_slice(nonce);
    block[14..16].copy_from_slice(&counter.to_be_bytes());
    block
}

/// Builds the CBC-MAC input `B0 || AAD-blocks || payload-blocks` into `out` (which must
/// be zeroed, so the padding is implicit) and returns its length (a multiple of 16).
/// AAD is assumed to be shorter than `0xFF00`, which always holds for Zigbee frames.
fn format_cbc_mac_input(out: &mut [u8], nonce: &[u8; 13], aad: &[u8], payload: &[u8]) -> usize {
    // B0: flags, nonce, message length.
    let adata = u8::from(!aad.is_empty());
    out[0] = (adata << 6) | (1 << 3) | 1; // Adata | (M-2)/2=1 | L-1=1
    out[1..14].copy_from_slice(nonce);
    out[14..16].copy_from_slice(&(payload.len() as u16).to_be_bytes());

    let mut pos = 16;
    if !aad.is_empty() {
        out[pos..pos + 2].copy_from_slice(&(aad.len() as u16).to_be_bytes());
        out[pos + 2..pos + 2 + aad.len()].copy_from_slice(aad);
        pos = round_up_16(pos + 2 + aad.len());
    }
    out[pos..pos + payload.len()].copy_from_slice(payload);
    round_up_16(pos + payload.len())
}

/// Claim the AES peripheral + a DMA channel and install the hardware crypto backend. Call
/// once during startup, before the stack processes frames.
pub fn init(aes: AES<'static>, dma: impl AesDmaChannel<'static>) {
    let (rx_buffer, rx_descriptors, tx_buffer, tx_descriptors) = dma_buffers!(DMA_BUF_SIZE);
    let rx = DmaRxBuf::new(
        DmaAlignedMut::new(rx_descriptors).unwrap(),
        DmaAlignedMut::new(rx_buffer).unwrap(),
    )
    .unwrap();
    let tx = DmaTxBuf::new(
        DmaAlignedMut::new(tx_descriptors).unwrap(),
        DmaAlignedMut::new(tx_buffer).unwrap(),
    )
    .unwrap();
    let aes_dma = Aes::new(aes).with_dma(dma);

    HW.lock(|cell| {
        *cell.borrow_mut() = Some(DmaState {
            aes: Some(aes_dma),
            rx: Some(rx),
            tx: Some(tx),
        });
    });

    crypto::install(&BACKEND);
}
