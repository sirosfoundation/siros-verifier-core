use siros_verifier_core_ffi::*;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn reader() -> (std::sync::Arc<Reader>, serde_json::Value) {
    use ciborium::Value as C;
    use siros_verifier_core::mdoc_session::ReaderHandshake;
    let v: serde_json::Value =
        serde_json::from_str(include_str!("iso18013_annex_d5.json")).unwrap();
    // DeviceEngagement and Handover are recovered from the spec transcript; the reader key is the spec's.
    let C::Tag(24, inner) =
        ciborium::from_reader::<C, _>(&hex(v["session_transcript_bytes"].as_str().unwrap())[..])
            .unwrap()
    else {
        panic!()
    };
    let C::Bytes(st) = *inner else { panic!() };
    let C::Array(a) = ciborium::from_reader::<C, _>(&st[..]).unwrap() else {
        panic!()
    };
    let C::Tag(24, de) = &a[0] else { panic!() };
    let C::Bytes(de) = &**de else { panic!() };
    let mut ho = vec![];
    ciborium::into_writer(&a[2], &mut ho).unwrap();
    let sk = p256::SecretKey::from_slice(&hex(v["ereader"]["d"].as_str().unwrap())).unwrap();
    let session = ReaderHandshake::from_secret(sk).establish(de, &ho).unwrap();
    (Reader::from_session(session), v)
}

fn spec_request(v: &serde_json::Value) -> Vec<u8> {
    use aes_gcm::aead::{Aead, KeyInit};
    let est: ciborium::Value =
        ciborium::from_reader(&hex(v["session_establishment"].as_str().unwrap())[..]).unwrap();
    let ciborium::Value::Map(m) = est else {
        panic!()
    };
    let ciborium::Value::Bytes(ct) = m
        .iter()
        .find(|(k, _)| *k == ciborium::Value::Text("data".into()))
        .unwrap()
        .1
        .clone()
    else {
        panic!()
    };
    let key = hex(v["sk_reader"].as_str().unwrap());
    let mut iv = [0u8; 12];
    iv[11] = 1;
    aes_gcm::Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .decrypt(&aes_gcm::Nonce::from(iv), &ct[..])
        .unwrap()
}

fn spec_auth(request: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use ciborium::Value as C;
    let root: C = ciborium::from_reader(request).unwrap();
    let C::Map(root) = root else { panic!() };
    let C::Array(docs) = &root
        .iter()
        .find(|(k, _)| *k == C::Text("docRequests".into()))
        .unwrap()
        .1
    else {
        panic!()
    };
    let C::Map(doc) = &docs[0] else { panic!() };
    let C::Array(auth) = &doc
        .iter()
        .find(|(k, _)| *k == C::Text("readerAuth".into()))
        .unwrap()
        .1
    else {
        panic!()
    };
    let C::Bytes(signature) = &auth[3] else {
        panic!()
    };
    let C::Map(unprotected) = &auth[1] else {
        panic!()
    };
    let C::Bytes(certificate) = &unprotected
        .iter()
        .find(|(k, _)| *k == C::Integer(33.into()))
        .unwrap()
        .1
    else {
        panic!()
    };
    (signature.clone(), certificate.clone())
}

struct ReplaySigner(Vec<u8>);

impl ReaderAuthSigner for ReplaySigner {
    fn sign_es256(&self, _data: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        Ok(self.0.clone())
    }
}

#[test]
fn spec_response_through_the_facade() {
    let (r, v) = reader();
    let docs = r
        .open_response(
            hex(v["session_data"].as_str().unwrap()),
            1_610_000_000,
            vec!["org.iso.18013.5.1.mDL".into()],
        )
        .unwrap();
    assert_eq!(docs.len(), 1);
    assert!(docs[0]
        .elements
        .iter()
        .any(|e| e.identifier == "family_name"));
    let q: serde_json::Value = serde_json::from_str(&docs[0].authzen_request_json).unwrap();
    assert_eq!(q["resource"]["type"], "x5c");
}

#[test]
fn errors_cross_the_boundary_with_a_stable_code() {
    let (r, v) = reader();
    // doc type not requested
    match r.open_response(
        hex(v["session_data"].as_str().unwrap()),
        1_610_000_000,
        vec!["x".into()],
    ) {
        Err(FfiError::Rejected { code, .. }) => assert_eq!(code, "policy"),
        other => panic!("{:?}", other.err()),
    }
}

#[test]
fn termination_is_distinct_from_failure() {
    let (r, _) = reader();
    assert!(matches!(
        r.open_response(hex("a16673746174757314"), 0, vec![]),
        Err(FfiError::SessionOver { status: 20 })
    ));
}

#[test]
fn start_generates_its_own_key_and_rejects_garbage() {
    assert!(matches!(
        Reader::start(vec![0xa0], vec![0xf6]),
        Err(FfiError::Rejected { .. })
    ));
    assert!(
        matches!(Reader::start(vec![], vec![]), Err(FfiError::Rejected { code, .. }) if code == "malformed")
    );
}

#[test]
fn first_message_matches_the_spec_and_cannot_be_sent_twice() {
    let (r, v) = reader();
    // the plaintext DeviceRequest the spec used: recover it with the reader key (independent AES-GCM use)
    let pt = spec_request(&v);
    assert_eq!(
        r.establishment_message(pt.clone()).unwrap(),
        hex(v["session_establishment"].as_str().unwrap())
    );
    assert!(
        matches!(r.establishment_message(pt.clone()), Err(FfiError::Rejected { code, .. }) if code == "policy")
    );
    assert!(r.data_message(pt).is_ok());
    assert_eq!(r.termination_message().unwrap(), hex("a16673746174757314"));
}

#[test]
fn request_builder_and_host_signer_reproduce_the_spec() {
    let (r, v) = reader();
    let spec = spec_request(&v);
    let (signature, certificate) = spec_auth(&spec);
    let auth = ReaderAuth::new(
        vec![certificate],
        std::sync::Arc::new(ReplaySigner(signature)),
    );
    let document = RequestedDocument {
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
        reader_auth: Some(std::sync::Arc::new(auth)),
    };
    let request = r.build_device_request(vec![document]).unwrap();
    assert_eq!(request, spec);
    assert_eq!(
        r.establishment_message(request).unwrap(),
        hex(v["session_establishment"].as_str().unwrap())
    );
}

#[test]
fn nfc_handover_helper_reproduces_the_spec() {
    let (_, v) = reader();
    let encoded = hex(v["handover"].as_str().unwrap());
    let handover: ciborium::Value = ciborium::from_reader(&encoded[..]).unwrap();
    let ciborium::Value::Array(items) = handover else {
        panic!()
    };
    let ciborium::Value::Bytes(select) = &items[0] else {
        panic!()
    };
    let ciborium::Value::Bytes(request) = &items[1] else {
        panic!()
    };
    assert_eq!(
        nfc_handover_cbor(select.clone(), Some(request.clone())).unwrap(),
        encoded
    );
    assert!(nfc_handover_cbor(vec![], None).is_err());
}
