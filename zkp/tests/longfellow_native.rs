//! Genuine Longfellow nym_auth vectors from zk-cred-longfellow e09fdcd.
use std::io::Cursor;

use serde_json::Value;
use sha2::{Digest, Sha256};
use siros_verifier_zkp::backend::ProofBackend;
use siros_verifier_zkp::functions::{AgeCheck, FunctionRegistry, FUNCTION_AGE_CHECK};
use siros_verifier_zkp::longfellow::LongfellowBackend;
use siros_verifier_zkp::request::Request;
use zk_cred_longfellow::nymauth::NymAuthCircuitParams;

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

fn fixture() -> (LongfellowBackend, Request, Vec<u8>, Vec<u8>) {
    let document: Value =
        serde_json::from_str(include_str!("../testdata/nymauth/fixture.json")).unwrap();
    let params = NymAuthCircuitParams {
        block_enc_hash: document["block_enc_hash"].as_u64().unwrap() as usize,
        block_enc_sig: document["block_enc_sig"].as_u64().unwrap() as usize,
        hash_circuit_id: document["hash_circuit_id"].as_str().unwrap().into(),
        sig_circuit_id: document["sig_circuit_id"].as_str().unwrap().into(),
    };
    let compressed = include_bytes!("../testdata/nymauth/mdoc-circuits.zst");
    let circuit = zstd::decode_all(Cursor::new(compressed)).unwrap();
    assert_eq!(circuit.len(), 1_062_842);
    let digest: String = Sha256::digest(&circuit)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        digest,
        "92dd42fdf99673249eec33c7d07850bd9da66fbdab01ef26391e04c8341c1b7f"
    );
    let backend = LongfellowBackend::with_params(&circuit, &params).unwrap();
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
    let proof = include_bytes!("../testdata/nymauth/mdoc-proof.bin").to_vec();
    (backend, request, claimed, proof)
}

#[test]
fn genuine_longfellow_proof_verifies_and_mutations_fail() {
    let (backend, request, claimed, proof) = fixture();
    request.check(&FunctionRegistry::with_builtins()).unwrap();
    assert_eq!(backend.verify(&request, &claimed, &proof).unwrap(), claimed);

    let mut other_verifier = request.clone();
    other_verifier.verifier_input = [1u8; 32];
    assert!(backend.verify(&other_verifier, &claimed, &proof).is_err());

    assert!(backend.verify(&request, &[0u8; 32], &proof).is_err());

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
