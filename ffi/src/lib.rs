//! UniFFI facade for proximity apps. Thin on purpose: bytes in, plain records out.
//! The core stays sans-IO; the app owns BLE/NFC and passes whole messages through.

use std::sync::{Arc, Mutex};

use siros_verifier_core::mdoc_session::{
    session_termination, Incoming, ReaderHandshake, ReaderSession,
};
use siros_verifier_core::trust::TrustQuery;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// `code` is the stable machine-readable class: malformed, integrity, policy, crypto.
    #[error("{code}: {detail}")]
    Rejected { code: String, detail: String },
    /// The device ended the session with this status (20 = normal termination).
    #[error("session over, status {status}")]
    SessionOver { status: u64 },
}

impl From<siros_verifier_core::Error> for FfiError {
    fn from(e: siros_verifier_core::Error) -> Self {
        FfiError::Rejected {
            code: e.code().to_owned(),
            detail: e.to_string(),
        }
    }
}

#[derive(uniffi::Record)]
pub struct Element {
    pub namespace: String,
    pub identifier: String,
    /// CBOR-encoded element value; the app decodes what it needs.
    pub value_cbor: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct VerifiedDocument {
    pub doc_type: String,
    pub elements: Vec<Element>,
    /// DER certificates from the issuer's x5chain, leaf first. Authentic, **not trusted**.
    pub issuer_x5c: Vec<Vec<u8>>,
    pub valid_until: i64,
    /// AuthZEN evaluation request for go-trust (JSON). Send it to the tenant PDP; the document is
    /// only acceptable if the answer is permit.
    pub authzen_request_json: String,
}

#[derive(uniffi::Object)]
pub struct Reader {
    session: Mutex<ReaderSession>,
}

impl Reader {
    /// Not exported over FFI: lets Rust tests build a reader from a session with a fixed key.
    pub fn from_session(session: ReaderSession) -> Arc<Self> {
        Arc::new(Self {
            session: Mutex::new(session),
        })
    }
}

#[uniffi::export]
impl Reader {
    /// Begin a session from the scanned or received DeviceEngagement (raw CBOR) and the handover (raw CBOR: `null`
    /// for QR engagement, `[Hs, Hr]` for NFC). The reader's ephemeral key is generated here and never leaves Rust.
    #[uniffi::constructor]
    pub fn start(device_engagement: Vec<u8>, handover: Vec<u8>) -> Result<Arc<Self>, FfiError> {
        let session = ReaderHandshake::generate().establish(&device_engagement, &handover)?;
        Ok(Self::from_session(session))
    }

    /// The first message to send to the device: carries the reader key and the encrypted DeviceRequest.
    pub fn establishment_message(&self, device_request: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        Ok(self
            .session
            .lock()
            .expect("session lock")
            .establishment_message(&device_request)?)
    }

    /// A later message to the device (after the first).
    pub fn data_message(&self, device_request: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        Ok(self
            .session
            .lock()
            .expect("session lock")
            .data_message(&device_request)?)
    }

    /// The message that ends the session.
    pub fn termination_message(&self) -> Result<Vec<u8>, FfiError> {
        Ok(session_termination()?)
    }

    /// Decrypt a SessionData message from the device and verify the DeviceResponse inside it.
    /// An empty `accepted_doc_types` accepts any document type.
    pub fn open_response(
        &self,
        session_data: Vec<u8>,
        now: i64,
        accepted_doc_types: Vec<String>,
    ) -> Result<Vec<VerifiedDocument>, FfiError> {
        let mut session = self.session.lock().expect("session lock");
        let plaintext = match session.decrypt(&session_data)? {
            Incoming::Status(status) => return Err(FfiError::SessionOver { status }),
            Incoming::Data { plaintext, .. } => plaintext,
        };
        let allowed: Vec<&str> = accepted_doc_types.iter().map(String::as_str).collect();
        let docs = session.verify_response(
            &plaintext,
            now,
            if allowed.is_empty() {
                None
            } else {
                Some(&allowed)
            },
        )?;
        docs.into_iter()
            .map(|d| {
                let q = TrustQuery::for_mdoc_issuer(&d.issuer, "pid-provider", &d.doc_type)
                    .to_authzen();
                let mut elements = vec![];
                for (ns, m) in &d.elements {
                    for (id, v) in m {
                        let mut buf = vec![];
                        ciborium::into_writer(v, &mut buf).expect("cbor");
                        elements.push(Element {
                            namespace: ns.clone(),
                            identifier: id.clone(),
                            value_cbor: buf,
                        });
                    }
                }
                Ok(VerifiedDocument {
                    doc_type: d.doc_type,
                    elements,
                    issuer_x5c: d.issuer.x5c_der,
                    valid_until: d.validity.valid_until,
                    authzen_request_json: q.to_string(),
                })
            })
            .collect()
    }
}

#[cfg(feature = "vector-tests")]
#[uniffi::export]
impl Reader {
    /// TEST ONLY (feature `vector-tests`): start a session with a fixed reader key so published test vectors can be replayed.
    #[uniffi::constructor]
    pub fn start_with_key_for_vectors(
        ereader_d: Vec<u8>,
        device_engagement: Vec<u8>,
        handover: Vec<u8>,
    ) -> Result<Arc<Self>, FfiError> {
        let sk = p256::SecretKey::from_slice(&ereader_d).map_err(|_| FfiError::Rejected {
            code: "malformed".into(),
            detail: "reader key".into(),
        })?;
        let session = ReaderHandshake::from_secret(sk).establish(&device_engagement, &handover)?;
        Ok(Self::from_session(session))
    }
}
