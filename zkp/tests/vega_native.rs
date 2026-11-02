//! Genuine Vega nym_auth vectors from zk-cred-vega 8e7be172.

#[path = "support/native.rs"]
mod native;

use siros_verifier_zkp::backend::{BackendError, ProofBackend};
use siros_verifier_zkp::circuits::Entry;
use siros_verifier_zkp::nym_auth::{
    CONFIG_KNOWN_OFFENDER_MATCHING_PSC, CONFIG_KNOWN_OFFENDER_MATCHING_SSC, SYSTEM_VEGA,
};
use siros_verifier_zkp::request::Request;
use siros_verifier_zkp::vega::VegaBackend;

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
    let document = native::document();
    let shapes = native::decompress(include_bytes!("../testdata/nymauth/shapes.zst"));
    assert_eq!(shapes.len(), 12_205_144);
    let backend =
        VegaBackend::from_entry(&circuit_entry(CONFIG_KNOWN_OFFENDER_MATCHING_SSC), &shapes)
            .unwrap();
    let (request, claimed) = native::request(&document);
    let proof = include_bytes!("../testdata/nymauth/reference-proof.bin").to_vec();
    (backend, request, claimed, proof)
}

#[test]
fn genuine_vega_proof_verifies_and_mutations_fail() {
    let (backend, request, claimed, proof) = fixture();
    native::exercise_native_backend(&backend, &request, &claimed, &proof);
    assert!(matches!(
        backend.verify(&request, &[0u8; 32], &proof),
        Err(BackendError::PseudonymMismatch)
    ));
}

#[test]
fn shapes_and_configuration_are_checked_before_verification() {
    let mut shapes = native::decompress(include_bytes!("../testdata/nymauth/shapes.zst"));
    shapes[0] ^= 1;
    assert!(
        VegaBackend::from_entry(&circuit_entry(CONFIG_KNOWN_OFFENDER_MATCHING_SSC), &shapes)
            .is_err()
    );
    let valid = native::decompress(include_bytes!("../testdata/nymauth/shapes.zst"));
    assert!(
        VegaBackend::from_entry(&circuit_entry(CONFIG_KNOWN_OFFENDER_MATCHING_PSC), &valid)
            .is_err()
    );
}
