//! Genuine Longfellow nym_auth vectors from zk-cred-longfellow e09fdcd.

#[path = "support/native.rs"]
mod native;

use sha2::{Digest, Sha256};
use siros_verifier_zkp::longfellow::LongfellowBackend;
use zk_cred_longfellow::nymauth::NymAuthCircuitParams;

fn fixture() -> (
    LongfellowBackend,
    siros_verifier_zkp::request::Request,
    Vec<u8>,
    Vec<u8>,
) {
    let document = native::document();
    let params = NymAuthCircuitParams {
        block_enc_hash: document["block_enc_hash"].as_u64().unwrap() as usize,
        block_enc_sig: document["block_enc_sig"].as_u64().unwrap() as usize,
        hash_circuit_id: document["hash_circuit_id"].as_str().unwrap().into(),
        sig_circuit_id: document["sig_circuit_id"].as_str().unwrap().into(),
    };
    let circuit = native::decompress(include_bytes!("../testdata/nymauth/mdoc-circuits.zst"));
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
    let (request, claimed) = native::request(&document);
    let proof = include_bytes!("../testdata/nymauth/mdoc-proof.bin").to_vec();
    (backend, request, claimed, proof)
}

#[test]
fn genuine_longfellow_proof_verifies_and_mutations_fail() {
    let (backend, request, claimed, proof) = fixture();
    native::exercise_native_backend(&backend, &request, &claimed, &proof);
}
