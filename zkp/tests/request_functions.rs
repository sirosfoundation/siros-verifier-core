//! The circuit request check and the open function vocabulary (ported from SUNET/vc's functions and request tests).
use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use siros_verifier_zkp::functions::*;
use siros_verifier_zkp::nym_auth::*;
use siros_verifier_zkp::request::Request;
use siros_verifier_zkp::transcript;

const NONCE: &str = "pOA0oqEAhLnqug2r7Ve4tQ";
const DOC: &str = "eu.europa.ec.eudi.nym_auth.1";

fn issuer_key() -> p256::PublicKey {
    p256::SecretKey::from_slice(&[3u8; 32])
        .unwrap()
        .public_key()
}

fn request() -> Request {
    let t = transcript::session_transcript_dcapi("https://verifier.example", NONCE, None).unwrap();
    Request {
        issuer_key: issuer_key(),
        now: 1_790_000_000,
        inputs: vec![],
        supported_functions: vec![FUNCTION_AGE_CHECK.into()],
        session_transcript: t,
        doc_type: DOC.into(),
        verifier_input: verifier_input("x509_san_dns:verifier.example").unwrap(),
    }
}

fn err<T: std::fmt::Debug>(r: siros_verifier_core::Result<T>) -> String {
    r.err()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "OK".into())
}

fn custom(id: &str, input: &str) -> Function {
    Function {
        id: id.into(),
        inputs: vec![input.into()],
        check: None,
        minimum_selectivity: None,
    }
}

fn input(id: &str, name: &str, value: &str) -> CircuitInput {
    CircuitInput {
        function_id: id.into(),
        values: BTreeMap::from([(name.to_owned(), value.as_bytes().to_vec())]),
    }
}

fn age_input(e: &str, c: &str) -> CircuitInput {
    AgeBounds {
        earliest: e.into(),
        cutoff: c.into(),
    }
    .circuit_input()
}

// ---- the request ----

#[test]
fn a_well_formed_request_checks_and_derives_its_challenge() {
    let r = request();
    r.check(&FunctionRegistry::with_builtins()).unwrap();
    assert_eq!(
        r.time_string().unwrap().len(),
        20,
        "the circuits take exactly 20 ASCII bytes"
    );
    assert_eq!(r.time_string().unwrap(), "2026-09-21T14:13:20Z");
    assert_eq!(
        r.e2().unwrap(),
        transcript::challenge_digest(&r.session_transcript, DOC).unwrap()
    );
}

#[test]
fn the_request_refuses_what_it_cannot_check_against() {
    let f = FunctionRegistry::with_builtins();
    let mut r = request();
    r.now = 0;
    assert!(err(r.check(&f)).contains("no verification time"));
    let mut r = request();
    r.now = -5;
    assert!(r.check(&f).is_err());
    let mut r = request();
    r.now = 253_402_300_800; // year 10000
    assert!(err(r.check(&f)).contains("20-byte time format"));
    let mut r = request();
    r.session_transcript = vec![];
    assert!(err(r.check(&f)).contains("needs a session transcript"));
    let mut r = request();
    r.session_transcript = vec![0x82, 0xf6, 0xf6];
    assert!(err(r.check(&f)).contains("items"));
    let mut r = request();
    r.session_transcript.push(0);
    assert!(err(r.check(&f)).contains("after its single CBOR item"));
    let mut r = request();
    r.doc_type.clear();
    assert!(err(r.check(&f)).contains("binds the proof to this credential type"));
    let mut r = request();
    r.verifier_input = [0; 32];
    assert!(err(r.check(&f)).contains("scoped to this verifier"));
}

// ---- verifier id and pseudonym ----

#[test]
fn verifier_input_is_the_published_ids_digest() {
    let v = verifier_input("x509_san_dns:verifier.example").unwrap();
    assert!(
        v.iter()
            .take(4)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            == "6eae85a0",
        "rulebook v0.4's reference digest"
    );
    // semantic ids hash the whole string
    let s = verifier_input("semantic_id:verifier.example").unwrap();
    assert_eq!(
        s.to_vec(),
        Sha256::digest(b"semantic_id:verifier.example").to_vec()
    );
    assert!(verifier_input("").is_err());
}

#[test]
fn a_verifier_id_of_another_form_is_refused_with_a_hint() {
    let e = err(verifier_input("verifier.example"));
    assert!(e.contains("neither"), "{e}");
    assert!(
        e.contains("\"x509_san_dns:verifier.example\""),
        "a bare DNS name gets the likely fix: {e}"
    );
    assert!(
        err(verifier_input("x509_hash:abc")).contains("no other form"),
        "x509_hash is not a verifier id under v0.4"
    );
    assert!(err(verifier_input("x509_san_dns:")).contains("no identifier after it"));
    assert!(err(verifier_input("semantic_id:")).contains("no identifier after it"));
    assert!(
        !err(verifier_input("a/b")).contains("probably"),
        "no hint for something that is not a DNS name"
    );
}

#[test]
fn the_pseudonym_derivation_is_domain_separated_and_strict() {
    let seed = [7u8; 16];
    let a = known_offender_matching(
        CONFIG_KNOWN_OFFENDER_MATCHING_SSC,
        &seed,
        "x509_san_dns:a.example",
    )
    .unwrap();
    let b = known_offender_matching(
        CONFIG_KNOWN_OFFENDER_MATCHING_SSC,
        &seed,
        "x509_san_dns:b.example",
    )
    .unwrap();
    let c = known_offender_matching(
        CONFIG_KNOWN_OFFENDER_MATCHING_PSC,
        &seed,
        "x509_san_dns:a.example",
    )
    .unwrap();
    assert_ne!(a, b, "scoped to the verifier");
    assert_ne!(a, c, "scoped to the configuration");
    assert_eq!(
        a,
        known_offender_matching(
            CONFIG_KNOWN_OFFENDER_MATCHING_SSC,
            &seed,
            "x509_san_dns:a.example"
        )
        .unwrap()
    );
    assert!(
        known_offender_matching("account-recovery-ssc", &seed, "x509_san_dns:a.example").is_err()
    );
    assert!(known_offender_matching(
        CONFIG_KNOWN_OFFENDER_MATCHING_SSC,
        &[0u8; 15],
        "x509_san_dns:a.example"
    )
    .is_err());
    assert!(pseudonym("", &seed, &[0; 32], &[0; 32]).is_err());
    assert!(pseudonym("x", &seed, &[0; 31], &[0; 32]).is_err());
    // the reference construction, written out
    let mut h = Sha256::new();
    h.update(b"nym_auth/v1/known-offender-matching-ssc");
    h.update(seed);
    h.update([0u8; 32]);
    h.update(Sha256::digest(b"x509_san_dns:a.example"));
    assert_eq!(a.to_vec(), h.finalize().to_vec());
}

#[test]
fn system_ids_are_closed() {
    check_system_id(SYSTEM_LONGFELLOW).unwrap();
    check_system_id(SYSTEM_VEGA).unwrap();
    assert!(check_system_id("").is_err());
    assert!(
        err(check_system_id("urn:circuits:other:nym_auth:v1")).contains("not a nym_auth system_id")
    );
}

// ---- the open function vocabulary ----

#[test]
fn the_check_is_function_agnostic() {
    let mut f = FunctionRegistry::with_builtins();
    f.register(custom("test.document_number_prefix", "prefix"))
        .unwrap();
    let mut r = request();
    r.inputs = vec![input("test.document_number_prefix", "prefix", "SE")];
    r.supported_functions = vec!["test.document_number_prefix".into()];
    r.check(&f)
        .expect("a registered function the circuit supports needs no change to Request");
    // alongside the age check
    r.inputs.push(
        AgeCheck {
            ge: Some("2000-01-01".into()),
            ..Default::default()
        }
        .bounds()
        .unwrap()
        .circuit_input(),
    );
    r.supported_functions.push(FUNCTION_AGE_CHECK.into());
    r.check(&f).unwrap();
}

#[test]
fn unregistered_and_unsupported_functions_are_refused_both_ways() {
    let mut f = FunctionRegistry::with_builtins();
    f.register(custom("test.unsupported", "value")).unwrap();
    let mut r = request();
    r.inputs = vec![input("test.never_registered", "value", "x")];
    r.supported_functions = vec!["test.never_registered".into()];
    assert!(
        err(r.check(&f)).contains("not a registered predicate function"),
        "a circuit claiming support does not make it expressible"
    );
    let mut r = request();
    r.inputs = vec![input("test.unsupported", "value", "x")];
    r.supported_functions = vec![];
    assert!(err(r.check(&f)).contains("does not support"));
    // a value no circuit reads
    let mut bad = input("test.unsupported", "value", "x");
    bad.values.insert("extra".into(), b"y".to_vec());
    let mut r = request();
    r.inputs = vec![bad];
    r.supported_functions = vec!["test.unsupported".into()];
    assert!(err(r.check(&f)).contains("does not fill"));
    // an input left unset or empty
    for empty in [
        CircuitInput {
            function_id: "test.unsupported".into(),
            values: BTreeMap::new(),
        },
        input("test.unsupported", "value", ""),
    ] {
        let mut r = request();
        r.inputs = vec![empty];
        r.supported_functions = vec!["test.unsupported".into()];
        assert!(err(r.check(&f)).contains("unset"));
    }
    // two contributions from one function
    let mut r = request();
    r.inputs = vec![
        input("test.unsupported", "value", "a"),
        input("test.unsupported", "value", "b"),
    ];
    r.supported_functions = vec!["test.unsupported".into()];
    assert!(err(r.check(&f)).contains("contributes twice"));
}

#[test]
fn registering_an_unusable_function_is_refused() {
    let mut f = FunctionRegistry::empty();
    assert!(f
        .register(Function {
            id: String::new(),
            inputs: vec!["x".into()],
            check: None,
            minimum_selectivity: None
        })
        .is_err());
    assert!(f
        .register(Function {
            id: "test.no_inputs".into(),
            inputs: vec![],
            check: None,
            minimum_selectivity: None
        })
        .is_err());
    assert!(f.ids().is_empty());
}

#[test]
fn the_age_check_declares_its_selectivity_floor_and_checks_its_own_values() {
    let f = FunctionRegistry::with_builtins();
    let age = f.lookup(FUNCTION_AGE_CHECK).unwrap();
    assert!(age.minimum_selectivity.as_deref().unwrap().contains("365"));
    assert_eq!(
        age.inputs,
        vec![INPUT_EARLIEST.to_string(), INPUT_CUTOFF.to_string()]
    );
    // built by hand, so Bounds() never ran
    assert!(f
        .check_input(&age_input("not-a-date", NO_UPPER_BOUND))
        .is_err());
    assert!(f
        .check_input(&age_input(NO_LOWER_BOUND, "2008-13-01"))
        .is_err());
    assert!(err(f.check_input(&age_input("2001-01-01", "2001-06-01"))).contains("at least 365"));
    f.check_input(&age_input(NO_LOWER_BOUND, NO_UPPER_BOUND))
        .unwrap();
    f.check_input(&age_input(NO_LOWER_BOUND, "2008-10-07"))
        .unwrap();
    f.check_input(&age_input("2001-01-01", "2001-12-31"))
        .unwrap();
    // a function without its own check accepts any non-empty value
    let mut g = FunctionRegistry::empty();
    g.register(custom("test.plain", "value")).unwrap();
    g.check_input(&input("test.plain", "value", "anything"))
        .unwrap();
}
