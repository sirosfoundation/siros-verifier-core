//! DeviceRequest/ReaderAuth vectors from ISO/IEC 18013-5 Annex D.

use std::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use ciborium::Value as C;
use kryptering::{EcCurve, HashAlgorithm, SignatureAlgorithm, Signer};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::SecretKey;
use serde_json::Value;
use sha2::{Digest, Sha256};
use siros_verifier_core::mdoc_request::*;
use siros_verifier_core::mdoc_session::{Handover, ReaderHandshake, ReaderSession};
use x509_cert::der::Decode;

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/iso18013_annex_d5.json")).unwrap()
}

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn h(vector: &Value, key: &str) -> Vec<u8> {
    hex(vector[key].as_str().unwrap())
}

fn encode(value: &C) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

fn decode(bytes: &[u8]) -> C {
    ciborium::from_reader(bytes).unwrap()
}

fn member<'a>(value: &'a C, key: &str) -> &'a C {
    let C::Map(entries) = value else {
        panic!("expected map")
    };
    &entries
        .iter()
        .find(|(candidate, _)| candidate == &C::Text(key.into()))
        .unwrap_or_else(|| panic!("missing {key}"))
        .1
}

fn array(value: &C) -> &[C] {
    let C::Array(items) = value else {
        panic!("expected array")
    };
    items
}

fn bytes(value: &C) -> &[u8] {
    let C::Bytes(bytes) = value else {
        panic!("expected bytes")
    };
    bytes
}

fn session() -> ReaderSession {
    let vector = vector();
    let secret = SecretKey::from_slice(&hex(vector["ereader"]["d"].as_str().unwrap())).unwrap();
    ReaderHandshake::from_secret(secret)
        .establish(&h(&vector, "device_engagement"), &h(&vector, "handover"))
        .unwrap()
}

fn spec_request() -> Vec<u8> {
    let vector = vector();
    let establishment = decode(&h(&vector, "session_establishment"));
    let ciphertext = bytes(member(&establishment, "data"));
    let mut iv = [0u8; 12];
    iv[11] = 1;
    Aes256Gcm::new_from_slice(&h(&vector, "sk_reader"))
        .unwrap()
        .decrypt(&Nonce::from(iv), ciphertext)
        .unwrap()
}

fn mdl_document() -> RequestedDocument<'static> {
    RequestedDocument {
        doc_type: "org.iso.18013.5.1.mDL".into(),
        namespaces: vec![RequestedNamespace {
            namespace: "org.iso.18013.5.1".into(),
            elements: [
                ("family_name", true),
                ("document_number", true),
                ("driving_privileges", true),
                ("issue_date", true),
                ("expiry_date", true),
                ("portrait", false),
            ]
            .into_iter()
            .map(|(identifier, intent_to_retain)| RequestedElement {
                identifier: identifier.into(),
                intent_to_retain,
            })
            .collect(),
        }],
        request_info: vec![],
        reader_auth: None,
    }
}

struct ReplaySigner {
    signature: Vec<u8>,
    algorithm: SignatureAlgorithm,
    seen: Mutex<Vec<u8>>,
}

impl ReplaySigner {
    fn es256(signature: Vec<u8>) -> Self {
        Self {
            signature,
            algorithm: SignatureAlgorithm::Ecdsa(EcCurve::P256, HashAlgorithm::Sha256),
            seen: Mutex::new(Vec::new()),
        }
    }
}

impl Signer for ReplaySigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn sign(&self, data: &[u8]) -> kryptering::Result<Vec<u8>> {
        *self.seen.lock().unwrap() = data.to_vec();
        Ok(self.signature.clone())
    }
}

fn spec_auth(request: &C) -> (Vec<u8>, Vec<u8>, C) {
    let doc = &array(member(request, "docRequests"))[0];
    let auth = array(member(doc, "readerAuth"));
    let signature = bytes(&auth[3]).to_vec();
    let C::Map(unprotected) = &auth[1] else {
        panic!("expected unprotected map")
    };
    let chain = &unprotected
        .iter()
        .find(|(key, _)| key == &C::Integer(33.into()))
        .unwrap()
        .1;
    let certificate = bytes(chain).to_vec();
    (signature, certificate, member(doc, "itemsRequest").clone())
}

fn signing_input(items_request: &C) -> (Vec<u8>, Vec<u8>) {
    let vector = vector();
    let C::Tag(24, transcript) = decode(&h(&vector, "session_transcript_bytes")) else {
        panic!("expected transcript tag")
    };
    let C::Bytes(transcript) = *transcript else {
        panic!("expected transcript bytes")
    };
    let authentication = C::Array(vec![
        C::Text("ReaderAuthentication".into()),
        decode(&transcript),
        items_request.clone(),
    ]);
    let authentication_bytes = encode(&C::Tag(24, Box::new(C::Bytes(encode(&authentication)))));
    let signing_input = encode(&C::Array(vec![
        C::Text("Signature1".into()),
        C::Bytes(vec![0xa1, 0x01, 0x26]),
        C::Bytes(vec![]),
        C::Bytes(authentication_bytes.clone()),
    ]));
    (authentication_bytes, signing_input)
}

#[test]
fn reproduces_the_spec_device_request_and_verifies_reader_auth() {
    let spec = spec_request();
    assert_eq!(spec.len(), 719);
    let root = decode(&spec);
    let (signature, certificate, items_request) = spec_auth(&root);
    let (authentication_bytes, expected_input) = signing_input(&items_request);
    assert_eq!(authentication_bytes.len(), 755);
    assert_eq!(
        hex(&Sha256::digest(&authentication_bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()),
        hex("d6e35addfc49a676827927344952930758be15354bc022a3da8524bff0ba35c9")
    );
    assert_eq!(expected_input.len(), 775);

    let signer = ReplaySigner::es256(signature.clone());
    let chain = vec![certificate.clone()];
    let mut document = mdl_document();
    document.reader_auth = Some(ReaderAuthParams {
        signer: &signer,
        x5c_der: &chain,
    });
    let built = session().build_device_request(&[document]).unwrap();
    assert_eq!(built, spec, "the complete DeviceRequest must match Annex D");
    assert_eq!(*signer.seen.lock().unwrap(), expected_input);

    let cert = x509_cert::Certificate::from_der(&certificate).unwrap();
    let key = VerifyingKey::from_sec1_bytes(
        cert.tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    )
    .unwrap();
    key.verify(&expected_input, &Signature::from_slice(&signature).unwrap())
        .unwrap();
}

#[test]
fn unsigned_requests_preserve_order_request_info_and_false_retain() {
    let mut first = mdl_document();
    first.request_info = vec![
        ("z-last".into(), C::Integer(1.into())),
        ("a-first".into(), C::Text("two".into())),
    ];
    let mut second = mdl_document();
    second.request_info = vec![("purpose".into(), C::Text("other-elements".into()))];
    second.namespaces[0].elements.truncate(1);
    let built = session().build_device_request(&[first, second]).unwrap();
    let root = decode(&built);
    let docs = array(member(&root, "docRequests"));
    assert_eq!(docs.len(), 2);
    let tagged = member(&docs[0], "itemsRequest");
    let C::Tag(24, inner) = tagged else { panic!() };
    let C::Bytes(inner) = &**inner else { panic!() };
    let inner = decode(inner);
    let C::Map(request_info) = member(&inner, "requestInfo") else {
        panic!()
    };
    assert_eq!(request_info[0].0, C::Text("z-last".into()));
    assert_eq!(request_info[1].0, C::Text("a-first".into()));
    let C::Map(namespaces) = member(&inner, "nameSpaces") else {
        panic!()
    };
    let C::Map(elements) = &namespaces[0].1 else {
        panic!()
    };
    assert!(elements.contains(&(C::Text("portrait".into()), C::Bool(false))));
}

#[test]
fn invalid_request_shapes_are_refused() {
    let transcript = session().transcript_bytes().to_vec();
    assert!(build_device_request(&transcript, &[]).is_err());
    let mut document = mdl_document();
    document.doc_type.clear();
    assert!(build_device_request(&transcript, &[document]).is_err());
    let mut document = mdl_document();
    document.namespaces.clear();
    assert!(build_device_request(&transcript, &[document]).is_err());
    let mut document = mdl_document();
    let duplicate = document.namespaces[0].clone();
    document.namespaces.push(duplicate);
    assert!(build_device_request(&transcript, &[document]).is_err());
    let mut document = mdl_document();
    let duplicate = document.namespaces[0].elements[0].clone();
    document.namespaces[0].elements.push(duplicate);
    assert!(build_device_request(&transcript, &[document]).is_err());
    let mut document = mdl_document();
    document.request_info = vec![("same".into(), C::Null), ("same".into(), C::Null)];
    assert!(build_device_request(&transcript, &[document]).is_err());
}

#[test]
fn reader_auth_configuration_and_signature_failures_are_refused() {
    let spec = spec_request();
    let (signature, certificate, _) = spec_auth(&decode(&spec));
    let transcript = session().transcript_bytes().to_vec();

    let mut signer = ReplaySigner::es256(signature.clone());
    signer.algorithm = SignatureAlgorithm::Ecdsa(EcCurve::P384, HashAlgorithm::Sha384);
    let chain = vec![certificate.clone()];
    let mut document = mdl_document();
    document.reader_auth = Some(ReaderAuthParams {
        signer: &signer,
        x5c_der: &chain,
    });
    assert!(build_device_request(&transcript, &[document]).is_err());

    let signer = ReplaySigner::es256(signature.clone());
    let mut document = mdl_document();
    document.reader_auth = Some(ReaderAuthParams {
        signer: &signer,
        x5c_der: &[],
    });
    assert!(build_device_request(&transcript, &[document]).is_err());

    let signer = ReplaySigner::es256(vec![1]);
    let mut document = mdl_document();
    document.reader_auth = Some(ReaderAuthParams {
        signer: &signer,
        x5c_der: &chain,
    });
    assert!(build_device_request(&transcript, &[document]).is_err());

    let mut wrong = signature;
    wrong[0] ^= 1;
    let signer = ReplaySigner::es256(wrong);
    let mut document = mdl_document();
    document.reader_auth = Some(ReaderAuthParams {
        signer: &signer,
        x5c_der: &chain,
    });
    assert!(build_device_request(&transcript, &[document]).is_err());
    let mut document = mdl_document();
    document.reader_auth = Some(ReaderAuthParams {
        signer: &signer,
        x5c_der: &chain,
    });
    assert!(build_device_request(&[0xf6], &[document]).is_err());
}

#[test]
fn a_certificate_chain_uses_an_array_and_reader_auth_is_untagged() {
    let spec = spec_request();
    let (signature, certificate, _) = spec_auth(&decode(&spec));
    let signer = ReplaySigner::es256(signature);
    let chain = vec![certificate.clone(), certificate];
    let mut document = mdl_document();
    document.reader_auth = Some(ReaderAuthParams {
        signer: &signer,
        x5c_der: &chain,
    });
    let built = session().build_device_request(&[document]).unwrap();
    let root = decode(&built);
    let auth = array(member(
        &array(member(&root, "docRequests"))[0],
        "readerAuth",
    ));
    assert_eq!(auth.len(), 4);
    assert_eq!(bytes(&auth[0]), &[0xa1, 0x01, 0x26]);
    assert_eq!(auth[2], C::Null);
    let C::Map(unprotected) = &auth[1] else {
        panic!()
    };
    let chain_header = &unprotected
        .iter()
        .find(|(key, _)| key == &C::Integer(33.into()))
        .unwrap()
        .1;
    assert_eq!(array(chain_header).len(), 2);
}

#[test]
fn nfc_handover_round_trips_the_spec_and_qr_is_null() {
    let vector = vector();
    let encoded = h(&vector, "handover");
    let decoded = decode(&encoded);
    let items = array(&decoded);
    let select = bytes(&items[0]);
    let request = bytes(&items[1]);
    assert_eq!(select.len(), 195);
    assert_eq!(request.len(), 205);
    assert_eq!(encoded.len(), 405);
    let handover = Handover::Nfc {
        select,
        request: Some(request),
    };
    assert_eq!(handover.to_cbor().unwrap(), encoded);
    assert_eq!(
        ReaderHandshake::from_secret(
            SecretKey::from_slice(&hex(vector["ereader"]["d"].as_str().unwrap())).unwrap()
        )
        .establish_with_handover(&h(&vector, "device_engagement"), handover)
        .unwrap()
        .transcript_bytes(),
        h(&vector, "session_transcript_bytes")
    );
    assert_eq!(
        Handover::Nfc {
            select,
            request: None,
        }
        .to_cbor()
        .unwrap(),
        encode(&C::Array(vec![C::Bytes(select.to_vec()), C::Null]))
    );
    assert_eq!(Handover::Qr.to_cbor().unwrap(), vec![0xf6]);
}

#[test]
fn malformed_handover_shapes_are_refused() {
    let vector = vector();
    let engagement = h(&vector, "device_engagement");
    for handover in [
        vec![0x80],
        encode(&C::Array(vec![C::Null, C::Null])),
        encode(&C::Array(vec![C::Bytes(vec![]), C::Null])),
        encode(&C::Text("not a handover".into())),
    ] {
        assert!(ReaderHandshake::from_secret(
            SecretKey::from_slice(&hex(vector["ereader"]["d"].as_str().unwrap())).unwrap()
        )
        .establish(&engagement, &handover)
        .is_err());
    }
    assert!(Handover::Nfc {
        select: &[],
        request: None,
    }
    .to_cbor()
    .is_err());
}
