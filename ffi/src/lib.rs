//! UniFFI facade for proximity apps. Thin on purpose: bytes in, plain records out.
//! The core stays sans-IO; the app owns BLE/NFC and passes whole messages through.

use std::sync::{Arc, Mutex};

use kryptering::{EcCurve, HashAlgorithm, SignatureAlgorithm, Signer};
use siros_verifier_core::mdoc::MdocVerified;
use siros_verifier_core::mdoc_request::{ReaderAuthParams, RequestedDocument as CoreDocument};
use siros_verifier_core::mdoc_session::{
    session_termination, Handover, Incoming, ReaderHandshake, ReaderSession,
};
use siros_verifier_core::trust::TrustQuery;

const DEFAULT_MDOC_ISSUER_ROLE: &str = "pid-provider";

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

#[derive(Clone)]
struct RequestPolicy {
    documents: Vec<RequestedDocumentPolicy>,
}

#[derive(Clone)]
struct RequestedDocumentPolicy {
    doc_type: String,
    namespaces: Vec<RequestedNamespacePolicy>,
}

#[derive(Clone)]
struct RequestedNamespacePolicy {
    namespace: String,
    elements: Vec<String>,
}

fn policy_error(detail: &str) -> FfiError {
    siros_verifier_core::Error::Policy(detail.into()).into()
}

fn validate_mdoc_issuer_role(role: &str) -> Result<(), FfiError> {
    if role.trim().is_empty() || role.trim() != role || role.chars().any(char::is_control) {
        return Err(policy_error("invalid_mdoc_issuer_role"));
    }
    Ok(())
}

impl RequestPolicy {
    fn from_documents(documents: &[RequestedDocument]) -> Self {
        Self {
            documents: documents
                .iter()
                .map(|document| RequestedDocumentPolicy {
                    doc_type: document.doc_type.clone(),
                    namespaces: document
                        .namespaces
                        .iter()
                        .map(|namespace| RequestedNamespacePolicy {
                            namespace: namespace.namespace.clone(),
                            elements: namespace
                                .elements
                                .iter()
                                .map(|element| element.identifier.clone())
                                .collect(),
                        })
                        .collect(),
                })
                .collect(),
        }
    }

    fn enforce(&self, documents: &[MdocVerified]) -> Result<(), FfiError> {
        for requested in &self.documents {
            if !documents
                .iter()
                .any(|document| document.doc_type == requested.doc_type)
            {
                return Err(policy_error("requested_doc_type_missing"));
            }
        }
        for document in documents {
            let matching: Vec<_> = self
                .documents
                .iter()
                .filter(|requested| requested.doc_type == document.doc_type)
                .collect();
            if matching.is_empty() {
                return Err(policy_error("doc_type_not_requested"));
            }
            for requested in matching {
                for namespace in &requested.namespaces {
                    let Some(elements) = document.elements.get(&namespace.namespace) else {
                        return Err(policy_error("requested_namespace_missing"));
                    };
                    if namespace
                        .elements
                        .iter()
                        .any(|identifier| !elements.contains_key(identifier))
                    {
                        return Err(policy_error("requested_element_missing"));
                    }
                }
            }
        }
        Ok(())
    }
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
    mdoc_issuer_role: String,
    request_policy: Mutex<Option<RequestPolicy>>,
    /// Serializes request/response exchanges without holding the session lock
    /// across a foreign ReaderAuth signing callback.
    exchange: Mutex<()>,
}

impl Reader {
    /// Not exported over FFI: lets Rust tests build a reader from a session with a fixed key.
    pub fn from_session(session: ReaderSession) -> Arc<Self> {
        Self::from_session_with_role(session, DEFAULT_MDOC_ISSUER_ROLE.into())
            .expect("the default mdoc issuer role is valid")
    }

    /// Not exported over FFI: fixed-session constructor with an explicit trust-query role.
    pub fn from_session_with_role(
        session: ReaderSession,
        mdoc_issuer_role: String,
    ) -> Result<Arc<Self>, FfiError> {
        validate_mdoc_issuer_role(&mdoc_issuer_role)?;
        Ok(Arc::new(Self {
            session: Mutex::new(session),
            mdoc_issuer_role,
            request_policy: Mutex::new(None),
            exchange: Mutex::new(()),
        }))
    }

    fn build_request(&self, documents: &[RequestedDocument]) -> Result<Vec<u8>, FfiError> {
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

    fn raw_message(&self, device_request: &[u8], establishment: bool) -> Result<Vec<u8>, FfiError> {
        let _exchange = self.exchange.lock().expect("exchange lock");
        let message = {
            let mut session = self.session.lock().expect("session lock");
            if establishment {
                session.establishment_message(device_request)?
            } else {
                session.data_message(device_request)?
            }
        };
        // Raw requests retain the legacy accepted-doc-types-only behavior.
        *self.request_policy.lock().expect("request policy lock") = None;
        Ok(message)
    }

    fn message_from_documents(
        &self,
        documents: &[RequestedDocument],
        establishment: bool,
    ) -> Result<Vec<u8>, FfiError> {
        let _exchange = self.exchange.lock().expect("exchange lock");
        let device_request = self.build_request(documents)?;
        let policy = RequestPolicy::from_documents(documents);
        let message = {
            let mut session = self.session.lock().expect("session lock");
            if establishment {
                session.establishment_message(&device_request)?
            } else {
                session.data_message(&device_request)?
            }
        };
        *self.request_policy.lock().expect("request policy lock") = Some(policy);
        Ok(message)
    }
}

#[uniffi::export]
impl Reader {
    /// Begin a session using the compatibility-default `pid-provider` mdoc issuer role.
    /// The reader's ephemeral key is generated here and never leaves Rust.
    #[uniffi::constructor]
    pub fn start(device_engagement: Vec<u8>, handover: Vec<u8>) -> Result<Arc<Self>, FfiError> {
        Self::start_with_role(device_engagement, handover, DEFAULT_MDOC_ISSUER_ROLE.into())
    }

    /// Begin a session with a verifier-owned mdoc issuer role for AuthZEN evidence.
    /// `device_engagement` is raw CBOR; `handover` is `null` for QR or `[Hs, Hr]` for NFC.
    #[uniffi::constructor]
    pub fn start_with_role(
        device_engagement: Vec<u8>,
        handover: Vec<u8>,
        mdoc_issuer_role: String,
    ) -> Result<Arc<Self>, FfiError> {
        validate_mdoc_issuer_role(&mdoc_issuer_role)?;
        let session = ReaderHandshake::generate().establish(&device_engagement, &handover)?;
        Self::from_session_with_role(session, mdoc_issuer_role)
    }

    /// Build a DeviceRequest against this session's transcript. Foreign signing
    /// callbacks run after the session lock has been released.
    pub fn build_device_request(
        &self,
        documents: Vec<RequestedDocument>,
    ) -> Result<Vec<u8>, FfiError> {
        self.build_request(&documents)
    }

    /// The first message to send to the device: carries the reader key and the encrypted DeviceRequest.
    pub fn establishment_message(&self, device_request: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        self.raw_message(&device_request, true)
    }

    /// Build, encrypt, and retain the policy for the first DeviceRequest in one operation.
    pub fn establishment_message_from_documents(
        &self,
        documents: Vec<RequestedDocument>,
    ) -> Result<Vec<u8>, FfiError> {
        self.message_from_documents(&documents, true)
    }

    /// A later message to the device (after the first).
    pub fn data_message(&self, device_request: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        self.raw_message(&device_request, false)
    }

    /// Build, encrypt, and retain the policy for a later DeviceRequest in one operation.
    pub fn data_message_from_documents(
        &self,
        documents: Vec<RequestedDocument>,
    ) -> Result<Vec<u8>, FfiError> {
        self.message_from_documents(&documents, false)
    }

    /// The message that ends the session.
    pub fn termination_message(&self) -> Result<Vec<u8>, FfiError> {
        Ok(session_termination()?)
    }

    /// Decrypt a SessionData message and cryptographically verify its DeviceResponse.
    /// An empty `accepted_doc_types` accepts any document type unless a retained
    /// request policy narrows it. Requests made with `*_message_from_documents`
    /// also require every requested doc type, namespace, and element; extra
    /// disclosed claims remain allowed. No claims are returned on policy failure.
    pub fn open_response(
        &self,
        session_data: Vec<u8>,
        now: i64,
        accepted_doc_types: Vec<String>,
    ) -> Result<Vec<VerifiedDocument>, FfiError> {
        let _exchange = self.exchange.lock().expect("exchange lock");
        let request_policy = self
            .request_policy
            .lock()
            .expect("request policy lock")
            .clone();
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
        if let Some(policy) = request_policy {
            policy.enforce(&docs)?;
        }
        docs.into_iter()
            .map(|d| {
                let q = TrustQuery::for_mdoc_issuer(&d.issuer, &self.mdoc_issuer_role, &d.doc_type)
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
