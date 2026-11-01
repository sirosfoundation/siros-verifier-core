//! Each refusal names its own reason, so a mistake is legible rather than reported as a bad proof.
mod support;
use support::*;

use siros_verifier_zkp::backend::*;
use siros_verifier_zkp::circuits::*;
use siros_verifier_zkp::nym_auth::*;
use siros_verifier_zkp::refusal::*;
use siros_verifier_zkp::request::Request;
use siros_verifier_zkp::transcript::*;
use std::sync::Arc;

fn msg<T: std::fmt::Debug>(r: siros_verifier_core::Result<T>) -> String {
    r.err()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "OK".into())
}

const N: &str = "pOA0oqEAhLnqug2r7Ve4tQ";

#[test]
fn transcript_inputs_each_have_their_own_message() {
    assert!(msg(session_transcript_dcapi("", N, None)).contains("calling origin"));
    assert!(msg(session_transcript_dcapi("https://o.example", "", None))
        .contains("needs the request nonce"));
    assert!(msg(session_transcript_dcapi(
        "https://o.example",
        "abcdefghijklmno",
        None
    ))
    .contains("at least 16"));
    assert!(msg(session_transcript_dcapi(
        "https://o.example",
        N,
        Some(&[0u8; 31])
    ))
    .contains("31 bytes"));
    assert!(msg(session_transcript_redirect(
        "",
        N,
        "https://u.example",
        &[0u8; 32]
    ))
    .contains("client_id"));
    assert!(msg(session_transcript_redirect(
        "c",
        "",
        "https://u.example",
        &[0u8; 32]
    ))
    .contains("needs the request nonce"));
    assert!(msg(session_transcript_redirect("c", N, "", &[0u8; 32])).contains("response_uri"));
    assert!(msg(session_transcript_redirect(
        "c",
        N,
        "https://u.example",
        &[]
    ))
    .contains("0 bytes"));
    assert!(msg(challenge(&[], "d")).contains("needs a session transcript"));
    assert!(msg(challenge(&[0x80], "d")).contains("0 items"));
    assert!(msg(challenge(&[0xa0], "d")).contains("not a CBOR array"));
    let t = session_transcript_dcapi("https://o.example", N, None).unwrap();
    assert!(msg(challenge(&t, "")).contains("docType"));
}

#[test]
fn the_nonce_length_is_counted_in_characters_not_bytes() {
    // 16 two-byte characters are 16 characters
    let ok: String = "é".repeat(16);
    session_transcript_dcapi("https://o.example", &ok, None).unwrap();
    let short: String = "é".repeat(15);
    assert!(session_transcript_dcapi("https://o.example", &short, None).is_err());
}

#[test]
fn system_ids_and_backend_profiles_are_checked_with_their_own_messages() {
    assert!(msg(check_system_id("")).contains("no system_id"));
    assert!(msg(check_system_id("urn:x")).contains("not a nym_auth system_id"));
    let mut reg = BackendRegistry::new();
    let f = |_: &Entry, _: &[u8]| -> ZkpResult<Box<dyn ProofBackend>> {
        Err(ZkpError::fault("unused"))
    };
    let mut p = SystemProfile::single_issuer_age_check();
    p.issuer_key_set_min = 0;
    assert!(
        reg.register(SYSTEM_VEGA, p, f).is_err(),
        "an empty set is not a range"
    );
    let mut p = SystemProfile::single_issuer_age_check();
    p.issuer_key_set_min = 3;
    p.issuer_key_set_max = 2;
    assert!(reg.register(SYSTEM_VEGA, p, f).is_err(), "a reversed range");
    assert!(reg
        .register("urn:unknown", SystemProfile::single_issuer_age_check(), f)
        .is_err());
    assert!(reg.systems().is_empty());
    reg.register(SYSTEM_VEGA, SystemProfile::single_issuer_age_check(), f)
        .unwrap();
    assert_eq!(reg.systems(), vec![SYSTEM_VEGA]);
    assert!(reg.profile(SYSTEM_LONGFELLOW).is_err());
    assert!(reg.factory(SYSTEM_LONGFELLOW).is_err());
}

#[test]
fn check_claimed_compares_whole_values() {
    check_claimed(&[1; 32], &[1; 32]).unwrap();
    assert_eq!(
        check_claimed(&[1; 32], &[2; 32]),
        Err(BackendError::PseudonymMismatch)
    );
    assert_eq!(
        check_claimed(&[1; 32], &[1; 31]),
        Err(BackendError::PseudonymMismatch),
        "a prefix is not equal"
    );
    assert_eq!(
        check_claimed(&[1; 31], &[1; 32]),
        Err(BackendError::PseudonymMismatch)
    );
    assert_eq!(
        check_claimed(&[], &[1]),
        Err(BackendError::PseudonymMismatch)
    );
}

/// A backend that violates its contract: it returns a pseudonym different from the claimed one without an error.
struct Careless;
impl ProofBackend for Careless {
    fn verify(&self, _: &Request, _claimed: &[u8], _: &[u8]) -> Result<Vec<u8>, BackendError> {
        Ok(vec![0xee; 32])
    }
}

#[test]
fn what_leaves_the_dispatch_equals_what_was_claimed_even_if_a_backend_forgets_to_check() {
    let (file, cfg) = artifact(b"x");
    let allow = Allowlist::new(&CircuitsConfig {
        sources: vec![],
        allow: vec![cfg],
    })
    .unwrap();
    let mut reg = BackendRegistry::new();
    reg.register(
        SYSTEM_LONGFELLOW,
        SystemProfile::single_issuer_age_check(),
        |_, _| Ok(Box::new(Careless) as Box<dyn ProofBackend>),
    )
    .unwrap();
    let v = siros_verifier_zkp::verify::ZkpVerifier::new(
        allow,
        Box::new(FsArtifactSource),
        siros_verifier_zkp::functions::FunctionRegistry::with_builtins(),
        reg,
        siros_verifier_zkp::verify::VerifierPolicy {
            role: "r".into(),
            issuer_set: siros_verifier_core::issuer_set::IssuerSetPolicy::AllTrusted,
            tolerance: Default::default(),
        },
    )
    .unwrap();
    let f = fx(Opts::default());
    let ch = dc_channel();
    let ex = siros_verifier_zkp::verify::Exchange {
        plan: &f.plan,
        channel: &ch,
        nonce: NONCE,
        reader_thumbprint: None,
        verifier_id: VERIFIER_ID,
        now: NOW,
    };
    let e = v
        .begin(&ex, &vp_token(&[f.honest()]))
        .unwrap()
        .finish(&trusted(1))
        .unwrap_err();
    assert_eq!(e.code(), Some(PSEUDONYM_MISMATCH), "{e}");
    drop(file);
    let _ = Arc::new(());
}
