//! Genuine Vega nym_auth vectors from zk-cred-vega 8e7be172.
use std::io::Cursor;

use serde_json::Value;
use siros_verifier_zkp::backend::{BackendError, ProofBackend};
use siros_verifier_zkp::circuits::Entry;
use siros_verifier_zkp::functions::{AgeCheck, FunctionRegistry, FUNCTION_AGE_CHECK};
use siros_verifier_zkp::nym_auth::{
    CONFIG_KNOWN_OFFENDER_MATCHING_PSC, CONFIG_KNOWN_OFFENDER_MATCHING_SSC, SYSTEM_VEGA,
};
use siros_verifier_zkp::request::Request;
use siros_verifier_zkp::vega::VegaBackend;

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

fn circuit_entry(config: &str) -> Entry {
    Entry {
        system_id: SYSTEM_VEGA.into(),
        config: config.into(),
        hash_circuit_id: String::new(),
        sig_circuit_id: String::new(),
        block_enc_hash: 0,
        block_enc_sig: 0,
        path: String::new(),
        id: "nymauth-vega-mdoc-v1".into(),
        sha256: "4da5e73afb9be2682e70be793c9956a73304e21f31246aa10da0d3e95c926425".into(),
        bytes: 12_205_144,
    }
}

fn fixture() -> (VegaBackend, Request, Vec<u8>, Vec<u8>) {
    let document: Value =
        serde_json::from_str(include_str!("../testdata/nymauth/fixture.json")).unwrap();
    let compressed = include_bytes!("../testdata/nymauth/shapes.zst");
    let shapes = zstd::decode_all(Cursor::new(compressed)).unwrap();
    assert_eq!(shapes.len(), 12_205_144);
    let backend =
        VegaBackend::from_entry(&circuit_entry(CONFIG_KNOWN_OFFENDER_MATCHING_SSC), &shapes)
            .unwrap();
    let x = hex(document["issuer_key_x"].as_str().unwrap());
    let y = hex(document["issuer_key_y"].as_str().unwrap());
    let mut sec1 = vec![4u8];
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let issuer_key = p256::PublicKey::from_sec1_bytes(&sec1).unwrap();
    let age = AgeCheck {
        le: Some(document["cutoff"].as_str().unwrap().into()),
        ..Default::default()
    };
    let request = Request {
        issuer_key,
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
    let proof = include_bytes!("../testdata/nymauth/reference-proof.bin").to_vec();
    (backend, request, claimed, proof)
}

#[test]
fn genuine_vega_proof_verifies_and_mutations_fail() {
    let (backend, request, claimed, proof) = fixture();
    request.check(&FunctionRegistry::with_builtins()).unwrap();
    assert_eq!(backend.verify(&request, &claimed, &proof).unwrap(), claimed);

    assert!(matches!(
        backend.verify(&request, &[0u8; 32], &proof),
        Err(BackendError::PseudonymMismatch)
    ));

    let mut other_verifier = request.clone();
    other_verifier.verifier_input = [1u8; 32];
    assert!(backend.verify(&other_verifier, &claimed, &proof).is_err());

    let mut tampered = proof.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(backend.verify(&request, &claimed, &tampered).is_err());

    let mut wrong_time = request.clone();
    wrong_time.now += 86_400;
    assert!(backend.verify(&wrong_time, &claimed, &proof).is_err());

    let mut wrong_transcript = request.clone();
    wrong_transcript.session_transcript[0] ^= 1;
    assert!(backend.verify(&wrong_transcript, &claimed, &proof).is_err());

    let mut wrong_age = request.clone();
    wrong_age.inputs = vec![AgeCheck {
        le: Some("2000-01-01".into()),
        ..Default::default()
    }
    .bounds()
    .unwrap()
    .circuit_input()];
    assert!(backend.verify(&wrong_age, &claimed, &proof).is_err());
}

#[test]
fn shapes_and_configuration_are_checked_before_verification() {
    let mut shapes = zstd::decode_all(Cursor::new(include_bytes!(
        "../testdata/nymauth/shapes.zst"
    )))
    .unwrap();
    shapes[0] ^= 1;
    assert!(
        VegaBackend::from_entry(&circuit_entry(CONFIG_KNOWN_OFFENDER_MATCHING_SSC), &shapes)
            .is_err()
    );
    let valid = zstd::decode_all(Cursor::new(include_bytes!(
        "../testdata/nymauth/shapes.zst"
    )))
    .unwrap();
    assert!(
        VegaBackend::from_entry(&circuit_entry(CONFIG_KNOWN_OFFENDER_MATCHING_PSC), &valid)
            .is_err()
    );
}
