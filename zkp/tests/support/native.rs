//! Shared genuine-vector checks for the native nym_auth proof backends.

use serde_json::Value;
use siros_verifier_zkp::backend::ProofBackend;
use siros_verifier_zkp::functions::{AgeCheck, FunctionRegistry, FUNCTION_AGE_CHECK};
use siros_verifier_zkp::request::Request;

pub fn document() -> Value {
    serde_json::from_str(include_str!("../../testdata/nymauth/fixture.json")).unwrap()
}

pub fn decompress(bytes: &[u8]) -> Vec<u8> {
    zstd::decode_all(std::io::Cursor::new(bytes)).unwrap()
}

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

pub fn request(document: &Value) -> (Request, Vec<u8>) {
    let mut sec1 = vec![4u8];
    sec1.extend_from_slice(&hex(document["issuer_key_x"].as_str().unwrap()));
    sec1.extend_from_slice(&hex(document["issuer_key_y"].as_str().unwrap()));
    let age = AgeCheck {
        le: Some(document["cutoff"].as_str().unwrap().into()),
        ..Default::default()
    };
    let request = Request {
        issuer_key: p256::PublicKey::from_sec1_bytes(&sec1).unwrap(),
        now: siros_verifier_core::mdoc::parse_utc(document["time"].as_str().unwrap()).unwrap(),
        inputs: vec![age.bounds().unwrap().circuit_input()],
        supported_functions: vec![FUNCTION_AGE_CHECK.into()],
        session_transcript: hex(document["session_transcript"].as_str().unwrap()),
        doc_type: document["doc_type"].as_str().unwrap().into(),
        verifier_input: hex(document["verifier_input"].as_str().unwrap())
            .try_into()
            .unwrap(),
    };
    let claimed = hex(document["pseudonym"].as_str().unwrap());
    (request, claimed)
}

pub fn exercise_native_backend<B: ProofBackend>(
    backend: &B,
    request: &Request,
    claimed: &[u8],
    proof: &[u8],
) {
    request.check(&FunctionRegistry::with_builtins()).unwrap();
    assert_eq!(backend.verify(request, claimed, proof).unwrap(), claimed);
    assert!(backend.verify(request, &[0u8; 32], proof).is_err());

    let mut other_verifier = request.clone();
    other_verifier.verifier_input = [1u8; 32];
    assert!(backend.verify(&other_verifier, claimed, proof).is_err());

    let mut tampered = proof.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(backend.verify(request, claimed, &tampered).is_err());

    let mut wrong_time = request.clone();
    wrong_time.now += 86_400;
    assert!(backend.verify(&wrong_time, claimed, proof).is_err());

    let mut wrong_transcript = request.clone();
    wrong_transcript.session_transcript[0] ^= 1;
    assert!(backend.verify(&wrong_transcript, claimed, proof).is_err());

    let mut wrong_age = request.clone();
    wrong_age.inputs = vec![AgeCheck {
        le: Some("2000-01-01".into()),
        ..Default::default()
    }
    .bounds()
    .unwrap()
    .circuit_input()];
    assert!(backend.verify(&wrong_age, claimed, proof).is_err());
}
