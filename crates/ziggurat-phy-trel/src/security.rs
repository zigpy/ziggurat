//! SPIKE: ZLOE security material (see BROADCAST.md, "Secure ZLOE over QUIC").
//!
//! Every secret is derived from the Zigbee network key, salted with the extended PAN
//! ID, so nodes stay stateless: the network CA is the same on every member, and
//! rotating the network key revokes everything.

use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ED25519, SanType, SerialNumber,
};
use ring::{hkdf, hmac, rand::SecureRandom};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use ziggurat_ieee_802154::types::Eui64;

pub const ALPN_ZLOE: &[u8] = b"zloe/1";
pub const ALPN_ENROLL: &[u8] = b"zloe-enroll/1";
const EXPORTER_LABEL: &[u8] = b"EXPORTER-zloe-enroll";

/// The node's role, written into its certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Coordinator,
    Satellite,
}

/// Everything a network member derives from the network key.
pub struct NetworkSecrets {
    pub epan: Eui64,
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
    /// Group key for sealed multicast (not used by the PoC yet)
    pub mcast_key: [u8; 32],
}

/// This node's identity on the backbone: an ephemeral key with a certificate issued
/// by the network CA.
pub struct NodeIdentity {
    pub cert: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
}

struct Len(usize);
impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf32(nwk_key: &[u8; 16], epan: Eui64, info: &[u8]) -> [u8; 32] {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &epan.0).extract(nwk_key);
    let mut out = [0u8; 32];
    prk.expand(&[info], Len(32))
        .and_then(|okm| okm.fill(&mut out))
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// PKCS#8 v1 wrapper for a raw Ed25519 seed (RFC 8410).
fn ed25519_pkcs8(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(seed);
    der
}

/// The DNS name a node's certificate is valid for: `x<eui64 hex>.zloe`.
pub fn node_name(eui64: Eui64) -> String {
    let hex: String = eui64
        .to_be_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("x{hex}.zloe")
}

fn fixed_validity(params: &mut CertificateParams) {
    // MCU satellites have no trusted clock; validity is not what revocation relies on
    params.not_before = rcgen::date_time_ymd(2000, 1, 1);
    params.not_after = rcgen::date_time_ymd(2100, 1, 1);
}

impl NetworkSecrets {
    pub fn derive(nwk_key: &[u8; 16], epan: Eui64) -> Result<Self, rcgen::Error> {
        let seed = hkdf32(nwk_key, epan, b"zloe ca v1");
        let der = ed25519_pkcs8(&seed);
        let ca_key = KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(der.as_slice()),
            &PKCS_ED25519,
        )?;

        // Every field fixed, Ed25519 signatures deterministic: the same CA certificate on
        // every member
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        let mut dn = DistinguishedName::new();
        let epan_hex: String = epan
            .to_be_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        dn.push(DnType::CommonName, format!("ZLOE network {epan_hex}"));
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.serial_number = Some(SerialNumber::from(1u64));
        fixed_validity(&mut params);
        let ca_cert = params.self_signed(&ca_key)?;

        Ok(Self {
            epan,
            ca_cert,
            ca_key,
            mcast_key: hkdf32(nwk_key, epan, b"zloe multicast v1"),
        })
    }

    pub fn ca_der(&self) -> CertificateDer<'static> {
        self.ca_cert.der().clone()
    }

    /// Issue a certificate for this node with a fresh key.
    pub fn issue(&self, eui64: Eui64, role: Role) -> Result<NodeIdentity, rcgen::Error> {
        let key = KeyPair::generate_for(&PKCS_ED25519)?;
        let mut params = CertificateParams::new(vec![node_name(eui64)])?;
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            format!(
                "{} {}",
                match role {
                    Role::Coordinator => "coordinator",
                    Role::Satellite => "satellite",
                },
                node_name(eui64)
            ),
        );
        params.distinguished_name = dn;
        params.subject_alt_names = vec![SanType::DnsName(node_name(eui64).try_into()?)];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        fixed_validity(&mut params);
        let cert = params.signed_by(&key, &self.ca_cert, &self.ca_key)?;
        Ok(NodeIdentity {
            cert: cert.der().clone(),
            key: PrivatePkcs8KeyDer::from(key.serialize_der()),
        })
    }

    fn roots(&self) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(self.ca_der())
            .expect("the network CA is a valid trust anchor");
        roots
    }

    /// TLS for connections we dial to a peer: verify it against the network CA under
    /// `x<eui64>.zloe`, present our certificate.
    pub fn client_config(&self, me: &NodeIdentity) -> Result<rustls::ClientConfig, rustls::Error> {
        let mut config = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(self.roots())
            .with_client_auth_cert(vec![me.cert.clone()], me.key())?;
        config.alpn_protocols = vec![ALPN_ZLOE.to_vec()];
        Ok(config)
    }

    /// TLS for connections we accept: peers must present a certificate from the network
    /// CA (ALPN `zloe/1`); enrollment (`zloe-enroll/1`) has none, and is checked by its
    /// code proofs instead.
    pub fn server_config(&self, me: &NodeIdentity) -> Result<rustls::ServerConfig, rustls::Error> {
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(self.roots()),
            provider(),
        )
        .allow_unauthenticated()
        .build()
        .map_err(|e| rustls::Error::General(e.to_string()))?;
        let mut config = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![me.cert.clone()], me.key())?;
        config.alpn_protocols = vec![ALPN_ZLOE.to_vec(), ALPN_ENROLL.to_vec()];
        Ok(config)
    }
}

impl NodeIdentity {
    fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(self.key.clone_key())
    }
}

/// Whether `cert` (already verified to chain to the network CA by TLS) names `eui64`.
pub fn cert_names(cert: &CertificateDer<'_>, eui64: Eui64) -> bool {
    let Ok(end_entity) = webpki::EndEntityCert::try_from(cert) else {
        return false;
    };
    let Ok(name) = ServerName::try_from(node_name(eui64)) else {
        return false;
    };
    end_entity.verify_is_valid_for_subject_name(&name).is_ok()
}

pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

// -- enrollment ---------------------------------------------------------------------

/// A fresh one-time enrollment code: 128 random bits, base32 (26 characters).
pub fn new_enrollment_code() -> String {
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("system randomness");
    base32(&bytes)
}

fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// TLS session binding for enrollment proofs (RFC 5705 exporter).
pub fn exporter(conn: &quinn::Connection) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, EXPORTER_LABEL, b"")
        .ok()?;
    Some(out)
}

/// `HMAC-SHA256(code, exporter ‖ side)`: proves knowledge of the code, bound to this
/// TLS session, so a man in the middle (two sessions, no code) can produce neither.
pub fn enrollment_proof(code: &str, exporter: &[u8; 32], side: u8) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, code.trim().to_uppercase().as_bytes());
    let mut msg = exporter.to_vec();
    msg.push(side);
    let tag = hmac::sign(&key, &msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

pub fn proof_matches(code: &str, exporter: &[u8; 32], side: u8, proof: &[u8]) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, code.trim().to_uppercase().as_bytes());
    let mut msg = exporter.to_vec();
    msg.push(side);
    hmac::verify(&key, &msg, proof).is_ok()
}

/// TLS for the enrolling satellite: it has no network CA yet, so it accepts any server
/// certificate (signatures still checked); the code proofs authenticate the server.
pub fn enroll_client_config() -> Result<rustls::ClientConfig, rustls::Error> {
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyServer(provider())))
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_ENROLL.to_vec()];
    Ok(config)
}

#[derive(Debug)]
struct AnyServer(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_network_key_same_ca() {
        let epan = Eui64([1, 2, 3, 4, 5, 6, 7, 8]);
        let a = NetworkSecrets::derive(&[7; 16], epan).unwrap();
        let b = NetworkSecrets::derive(&[7; 16], epan).unwrap();
        let c = NetworkSecrets::derive(&[8; 16], epan).unwrap();
        assert_eq!(a.ca_der(), b.ca_der());
        assert_eq!(a.mcast_key, b.mcast_key);
        assert_ne!(a.ca_der(), c.ca_der());
    }

    #[test]
    fn node_cert_names_its_eui64() {
        let secrets = NetworkSecrets::derive(&[7; 16], Eui64([9; 8])).unwrap();
        let me = Eui64([0x20, 1, 2, 3, 4, 5, 6, 7]);
        let id = secrets.issue(me, Role::Satellite).unwrap();
        assert!(cert_names(&id.cert, me));
        assert!(!cert_names(&id.cert, Eui64([0x21; 8])));
    }

    #[test]
    fn enrollment_proofs() {
        let code = new_enrollment_code();
        assert_eq!(code.len(), 26);
        let exp = [3u8; 32];
        let proof = enrollment_proof(&code, &exp, b'C');
        assert!(proof_matches(&code, &exp, b'C', &proof));
        assert!(!proof_matches(&code, &exp, b'S', &proof));
        assert!(!proof_matches("WRONGCODE", &exp, b'C', &proof));
        assert!(!proof_matches(&code, &[4u8; 32], b'C', &proof));
    }
}
