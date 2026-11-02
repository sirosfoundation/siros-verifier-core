//! UniFFI facade for proximity apps. Thin on purpose: bytes in, plain records out.
//! The core stays sans-IO; the app owns BLE/NFC and passes whole messages through.

use std::sync::{Arc, Mutex};

use kryptering::{EcCurve, HashAlgorithm, SignatureAlgorithm, Signer};
use siros_verifier_core::mdoc_request::{ReaderAuthParams, RequestedDocument as CoreDocument};
use siros_verifier_core::mdoc_session::{
    session_termination, Handover, Incoming, ReaderHandshake, ReaderSession,
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

#[derive(uniffi::Record)]
pub struct RequestedElement {
    pub identifier: String,
    pub intent_to_retain: bool,
}

#[derive(uniffi::Record)]
pub struct RequestedNamespace {
    pub namespace: String,
    pub elements: Vec<RequestedElement>,
}

/// Host-backed ReaderAuth key. The callback receives the exact COSE signing
/// input and must return a raw P-256 `r || s` signature.
#[uniffi::export(with_foreign)]
pub trait ReaderAuthSigner: Send + Sync {
    fn sign_es256(&self, data: Vec<u8>) -> Result<Vec<u8>, FfiError>;
}

#[derive(uniffi::Object)]
pub struct ReaderAuth {
    /// DER certificates, leaf first. The wallet decides whether to trust them.
    pub x5c_der: Vec<Vec<u8>>,
    pub signer: Arc<dyn ReaderAuthSigner>,
}

#[uniffi::export]
impl ReaderAuth {
    #[uniffi::constructor]
    pub fn new(x5c_der: Vec<Vec<u8>>, signer: Arc<dyn ReaderAuthSigner>) -> Self {
        Self { x5c_der, signer }
    }
}

#[derive(uniffi::Record)]
pub struct RequestedDocument {
    pub doc_type: String,
    pub namespaces: Vec<RequestedNamespace>,
    pub reader_auth: Option<Arc<ReaderAuth>>,
}

struct CallbackSigner(Arc<dyn ReaderAuthSigner>);

impl Signer for CallbackSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ecdsa(EcCurve::P256, HashAlgorithm::Sha256)
    }

    fn sign(&self, data: &[u8]) -> kryptering::Result<Vec<u8>> {
        self.0
            .sign_es256(data.to_vec())
            .map_err(|error| kryptering::Error::Crypto(error.to_string()))
    }
}

/// Encode a static or negotiated NFC handover without interpreting NDEF or
/// performing transport I/O.
#[uniffi::export]
pub fn nfc_handover_cbor(select: Vec<u8>, request: Option<Vec<u8>>) -> Result<Vec<u8>, FfiError> {
    Ok(Handover::Nfc {
        select: &select,
        request: request.as_deref(),
    }
    .to_cbor()?)
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

    /// Build a DeviceRequest against this session's transcript. Foreign signing
    /// callbacks run after the session lock has been released.
    pub fn build_device_request(
        &self,
        documents: Vec<RequestedDocument>,
    ) -> Result<Vec<u8>, FfiError> {
        let transcript = self
            .session
            .lock()
            .expect("session lock")
            .transcript_bytes()
            .to_vec();
        let signers: Vec<Option<CallbackSigner>> = documents
            .iter()
            .map(|document| {
                document
                    .reader_auth
                    .as_ref()
                    .map(|auth| CallbackSigner(auth.signer.clone()))
            })
            .collect();
        let documents: Vec<CoreDocument<'_>> = documents
            .iter()
            .zip(&signers)
            .map(|(document, signer)| CoreDocument {
                doc_type: document.doc_type.clone(),
                namespaces: document
                    .namespaces
                    .iter()
                    .map(
                        |namespace| siros_verifier_core::mdoc_request::RequestedNamespace {
                            namespace: namespace.namespace.clone(),
                            elements: namespace
                                .elements
                                .iter()
                                .map(|element| {
                                    siros_verifier_core::mdoc_request::RequestedElement {
                                        identifier: element.identifier.clone(),
                                        intent_to_retain: element.intent_to_retain,
                                    }
                                })
                                .collect(),
                        },
                    )
                    .collect(),
                request_info: vec![],
                reader_auth: match (&document.reader_auth, signer) {
                    (Some(auth), Some(signer)) => Some(ReaderAuthParams {
                        signer,
                        x5c_der: &auth.x5c_der,
                    }),
                    (None, None) => None,
                    _ => unreachable!("each document has one optional signer"),
                },
            })
            .collect();
        Ok(siros_verifier_core::mdoc_request::build_device_request(
            &transcript,
            &documents,
        )?)
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
