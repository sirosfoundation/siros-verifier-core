//! ISO/IEC 18013-5 §9.1.1 session encryption, reader side, sans-IO.
//!
//! Both directions use AES-256-GCM with keys from HKDF-SHA256 over the ECDH
//! shared secret, salted with SHA-256 of the SessionTranscriptBytes. The IV is
//! an 8-byte direction identifier followed by a 4-byte big-endian message
//! counter that starts at 1. Any failure poisons the session: later calls fail
//! closed rather than resynchronising counters.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ciborium::Value;
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::Generate;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Error, Result};

const MAX_MESSAGE: usize = 1 << 20;
const ID_READER: [u8; 8] = [0; 8];
const ID_DEVICE: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 1];

/// What a SessionData message from the device carried.
#[derive(Debug, PartialEq, Eq)]
pub enum Incoming {
    /// Decrypted payload (typically a DeviceResponse), possibly with a status.
    Data {
        plaintext: Vec<u8>,
        status: Option<u64>,
    },
    /// Status only; the session is over (20 = termination).
    Status(u64),
}

pub struct ReaderSession {
    sk_reader: Zeroizing<[u8; 32]>,
    sk_device: Zeroizing<[u8; 32]>,
    sent: u32,
    received: u32,
    poisoned: bool,
    /// Kept for `deviceMac` verification. Never leaves the session.
    ereader: SecretKey,
    transcript: Vec<u8>,
    ereader_cose_key: Vec<u8>,
}

fn derive(zab: &[u8], transcript_bytes: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let salt = Sha256::digest(transcript_bytes);
    let hk = Hkdf::<Sha256>::new(Some(&salt), zab);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut *out)
        .map_err(|_| Error::Crypto("hkdf expand".into()))?;
    Ok(out)
}

fn iv(id: [u8; 8], counter: u32) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[..8].copy_from_slice(&id);
    iv[8..].copy_from_slice(&counter.to_be_bytes());
    iv
}

impl ReaderSession {
    /// `transcript_bytes` is the tag-24 wrapped SessionTranscript (Annex D "SessionTranscriptBytes").
    pub fn new(ereader: &SecretKey, edevice: &PublicKey, transcript_bytes: &[u8]) -> Result<Self> {
        let zab = diffie_hellman(ereader.to_nonzero_scalar(), edevice.as_affine());
        let z = zab.raw_secret_bytes();
        Ok(Self {
            sk_reader: derive(z, transcript_bytes, b"SKReader")?,
            sk_device: derive(z, transcript_bytes, b"SKDevice")?,
            sent: 0,
            received: 0,
            poisoned: false,
            ereader: ereader.clone(),
            transcript: transcript_bytes.to_vec(),
            ereader_cose_key: cose_key_bytes(&ereader.public_key()),
        })
    }

    /// The tag-24 wrapped SessionTranscript this session was derived from.
    pub fn transcript_bytes(&self) -> &[u8] {
        &self.transcript
    }

    /// Build a DeviceRequest and any ReaderAuth against this session's own transcript.
    pub fn build_device_request(
        &self,
        documents: &[crate::mdoc_request::RequestedDocument<'_>],
    ) -> Result<Vec<u8>> {
        crate::mdoc_request::build_device_request(&self.transcript, documents)
    }

    /// Verify a decrypted DeviceResponse against this session (transcript and reader key are the session's own).
    pub fn verify_response(
        &self,
        response: &[u8],
        now: i64,
        expected_doc_types: Option<&[&str]>,
    ) -> Result<Vec<crate::mdoc::MdocVerified>> {
        crate::mdoc::verify_device_response(
            response,
            &crate::mdoc::Params {
                session_transcript_bytes: &self.transcript,
                now,
                device_auth: crate::mdoc::DeviceKeyAuth::Mac {
                    ereader: &self.ereader,
                },
                expected_doc_types,
            },
        )
    }

    /// The first reader message: `{ "eReaderKey", "data" }`. Only valid before anything has been sent.
    pub fn establishment_message(&mut self, device_request: &[u8]) -> Result<Vec<u8>> {
        if self.sent != 0 {
            return Err(Error::Policy("already_established".into()));
        }
        let ct = self.encrypt(device_request)?;
        session_establishment(&self.ereader_cose_key.clone(), ct)
    }

    /// Later reader messages: `{ "data" }`.
    pub fn data_message(&mut self, device_request: &[u8]) -> Result<Vec<u8>> {
        if self.sent == 0 {
            return Err(Error::Policy("not_established".into()));
        }
        let ct = self.encrypt(device_request)?;
        session_data(ct)
    }

    fn live(&self) -> Result<()> {
        if self.poisoned {
            return Err(Error::Policy("session_poisoned".into()));
        }
        Ok(())
    }

    /// Encrypt one reader-to-device message and return the AEAD output (ciphertext || tag).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.live()?;
        if plaintext.len() > MAX_MESSAGE {
            return Err(Error::Policy("message_too_large".into()));
        }
        let counter = self
            .sent
            .checked_add(1)
            .ok_or_else(|| Error::Policy("counter_exhausted".into()))?;
        let cipher =
            Aes256Gcm::new_from_slice(&*self.sk_reader).map_err(|_| Error::Crypto("key".into()))?;
        let ct = cipher
            .encrypt(
                &Nonce::from(iv(ID_READER, counter)),
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .map_err(|_| Error::Crypto("encrypt".into()))?;
        self.sent = counter;
        Ok(ct)
    }

    /// Parse and decrypt a SessionData message from the device.
    pub fn decrypt(&mut self, session_data: &[u8]) -> Result<Incoming> {
        self.live()?;
        let r = self.decrypt_inner(session_data);
        if r.is_err() {
            self.poisoned = true;
        }
        r
    }

    fn decrypt_inner(&mut self, session_data: &[u8]) -> Result<Incoming> {
        if session_data.len() > MAX_MESSAGE * 2 {
            return Err(Error::Policy("message_too_large".into()));
        }
        let v: Value = ciborium::from_reader(session_data)
            .map_err(|_| Error::Malformed("session_data_cbor".into()))?;
        let Value::Map(entries) = v else {
            return Err(Error::Malformed("session_data_not_map".into()));
        };
        let (mut data, mut status) = (None, None);
        for (k, val) in entries {
            match (k, val) {
                (Value::Text(k), Value::Bytes(b)) if k == "data" && data.is_none() => {
                    data = Some(b)
                }
                (Value::Text(k), Value::Integer(i)) if k == "status" && status.is_none() => {
                    status = Some(
                        u64::try_from(i).map_err(|_| Error::Malformed("session_status".into()))?,
                    )
                }
                _ => return Err(Error::Malformed("session_data_member".into())),
            }
        }
        match data {
            None => status
                .map(Incoming::Status)
                .ok_or_else(|| Error::Malformed("session_data_empty".into())),
            Some(ct) => {
                let counter = self
                    .received
                    .checked_add(1)
                    .ok_or_else(|| Error::Policy("counter_exhausted".into()))?;
                let cipher = Aes256Gcm::new_from_slice(&*self.sk_device)
                    .map_err(|_| Error::Crypto("key".into()))?;
                let pt = cipher
                    .decrypt(
                        &Nonce::from(iv(ID_DEVICE, counter)),
                        Payload { msg: &ct, aad: &[] },
                    )
                    .map_err(|_| Error::Integrity("session_decrypt".into()))?;
                self.received = counter;
                Ok(Incoming::Data {
                    plaintext: pt,
                    status,
                })
            }
        }
    }

    /// Diagnostics and vector tests only.
    #[cfg(feature = "testutil")]
    pub fn keys(&self) -> ([u8; 32], [u8; 32]) {
        (*self.sk_reader, *self.sk_device)
    }
}

fn cose_key_bytes(pk: &PublicKey) -> Vec<u8> {
    let pt = pk.to_sec1_bytes();
    let key = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(2.into())),
        (Value::Integer((-1).into()), Value::Integer(1.into())),
        (
            Value::Integer((-2).into()),
            Value::Bytes(pt[1..33].to_vec()),
        ),
        (
            Value::Integer((-3).into()),
            Value::Bytes(pt[33..65].to_vec()),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&key, &mut out).expect("in-memory cbor write");
    out
}

/// QR or NFC engagement handover. NDEF messages remain opaque application data;
/// their exact bytes are bound into the session transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Handover<'a> {
    Qr,
    Nfc {
        select: &'a [u8],
        request: Option<&'a [u8]>,
    },
}

impl Handover<'_> {
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        match self {
            Self::Qr => Ok(vec![0xf6]),
            Self::Nfc { select, request } => {
                if select.is_empty() || request.is_some_and(|message| message.is_empty()) {
                    return Err(Error::Malformed("handover_empty_ndef".into()));
                }
                to_cbor(&Value::Array(vec![
                    Value::Bytes(select.to_vec()),
                    request.map_or(Value::Null, |message| Value::Bytes(message.to_vec())),
                ]))
            }
        }
    }
}

fn validate_handover_cbor(handover: &[u8]) -> Result<()> {
    match parse_exact(handover, "handover_cbor")? {
        Value::Null => Ok(()),
        Value::Array(items) if items.len() == 2 => {
            let select = matches!(&items[0], Value::Bytes(message) if !message.is_empty());
            let request = match &items[1] {
                Value::Null => true,
                Value::Bytes(message) if !message.is_empty() => true,
                _ => false,
            };
            if select && request {
                Ok(())
            } else {
                Err(Error::Malformed("handover_shape".into()))
            }
        }
        _ => Err(Error::Malformed("handover_shape".into())),
    }
}

/// The reader's side of the handshake: owns a fresh ephemeral key that never leaves Rust.
pub struct ReaderHandshake {
    sk: SecretKey,
}

impl ReaderHandshake {
    pub fn generate() -> Self {
        Self {
            sk: SecretKey::generate(),
        }
    }

    /// Fixed key, for vector tests.
    #[cfg(feature = "testutil")]
    pub fn from_secret(sk: SecretKey) -> Self {
        Self { sk }
    }

    /// `EReaderKey` as a CBOR COSE_Key (public part only).
    pub fn ereader_cose_key(&self) -> Vec<u8> {
        cose_key_bytes(&self.sk.public_key())
    }

    /// Complete the handshake using a typed QR/NFC handover.
    pub fn establish_with_handover(
        self,
        device_engagement: &[u8],
        handover: Handover<'_>,
    ) -> Result<ReaderSession> {
        let handover = handover.to_cbor()?;
        self.establish(device_engagement, &handover)
    }

    /// Complete the handshake from the scanned or received DeviceEngagement (raw CBOR, not tag-24 wrapped) and
    /// the handover structure (raw CBOR: `null` for QR engagement, `[Hs, Hr]` for NFC). Builds the
    /// SessionTranscript `[DeviceEngagementBytes, EReaderKeyBytes, Handover]`, derives the session keys.
    pub fn establish(self, device_engagement: &[u8], handover: &[u8]) -> Result<ReaderSession> {
        let de = parse_exact(device_engagement, "device_engagement_cbor")?;
        let Value::Map(m) = &de else {
            return Err(Error::Malformed("device_engagement_not_map".into()));
        };
        let member = |k: i64| {
            m.iter()
                .find(|(x, _)| *x == Value::Integer(k.into()))
                .map(|(_, v)| v)
        };
        match member(0) {
            Some(Value::Text(v)) if v == "1.0" || v == "1.1" => {}
            _ => return Err(Error::Policy("device_engagement_version".into())),
        }
        let Some(Value::Array(sec)) = member(1) else {
            return Err(Error::Malformed("device_engagement_security".into()));
        };
        if sec.len() != 2 || sec[0] != Value::Integer(1.into()) {
            return Err(Error::Policy("cipher_suite".into()));
        }
        let Value::Tag(24, inner) = &sec[1] else {
            return Err(Error::Malformed("device_key_not_tag24".into()));
        };
        let Value::Bytes(key_bytes) = &**inner else {
            return Err(Error::Malformed("device_key_not_bytes".into()));
        };
        let edevice = crate::mdoc::cose_key_p256(&parse_exact(key_bytes, "device_key_cbor")?)?;
        validate_handover_cbor(handover)?;

        let mut st = vec![0x83];
        st.extend(to_cbor(&Value::Tag(
            24,
            Box::new(Value::Bytes(device_engagement.to_vec())),
        ))?);
        st.extend(to_cbor(&Value::Tag(
            24,
            Box::new(Value::Bytes(self.ereader_cose_key())),
        ))?);
        st.extend_from_slice(handover);
        let transcript = to_cbor(&Value::Tag(24, Box::new(Value::Bytes(st))))?;
        ReaderSession::new(&self.sk, &edevice, &transcript)
    }
}

fn parse_exact(b: &[u8], what: &str) -> Result<Value> {
    let mut cur = b;
    let v: Value = ciborium::from_reader(&mut cur).map_err(|_| Error::Malformed(what.into()))?;
    if !cur.is_empty() {
        return Err(Error::Malformed(format!("{what}_trailing_bytes")));
    }
    Ok(v)
}

fn to_cbor(v: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).map_err(|_| Error::Malformed("cbor_write".into()))?;
    Ok(out)
}

/// First reader message: `{ "eReaderKey": 24(<<COSE_Key>>), "data": bstr }`.
pub fn session_establishment(ereader_cose_key: &[u8], ciphertext: Vec<u8>) -> Result<Vec<u8>> {
    to_cbor(&Value::Map(vec![
        (
            Value::Text("eReaderKey".into()),
            Value::Tag(24, Box::new(Value::Bytes(ereader_cose_key.to_vec()))),
        ),
        (Value::Text("data".into()), Value::Bytes(ciphertext)),
    ]))
}

/// Later reader messages: `{ "data": bstr }`.
pub fn session_data(ciphertext: Vec<u8>) -> Result<Vec<u8>> {
    to_cbor(&Value::Map(vec![(
        Value::Text("data".into()),
        Value::Bytes(ciphertext),
    )]))
}

/// Termination: `{ "status": 20 }`.
pub fn session_termination() -> Result<Vec<u8>> {
    to_cbor(&Value::Map(vec![(
        Value::Text("status".into()),
        Value::Integer(20.into()),
    )]))
}
