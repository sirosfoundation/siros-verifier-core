use siros_verifier_core::oid4vp::{create_request, software_signer, RequestConfig};
use siros_verifier_core::session_seal::SessionSealer;
use siros_verifier_core::testutil::*;
use siros_verifier_core::Error;

const NOW: i64 = 1_800_000_000;
const MASTER: [u8; 32] = [7u8; 32];

fn session() -> siros_verifier_core::oid4vp::Session {
    let (cert, key) = self_signed_ec("verifier.example", "ES256");
    let signer = software_signer(&key).unwrap();
    let cfg = RequestConfig {
        response_uri: "https://v.example/r/x".into(),
        dcql_query: serde_json::json!({"credentials": []}),
        ttl_secs: 300,
    };
    create_request(&cfg, &signer, "ES256", &[cert], NOW)
        .unwrap()
        .1
}

fn sealer(tenant: &str) -> SessionSealer {
    SessionSealer::from_master(&MASTER, tenant).unwrap()
}

#[test]
fn round_trips_and_never_shows_the_private_key() {
    let s = session();
    let d = s.enc_key.d.clone().expect("session holds the private key");
    let sealed = sealer("acme").seal(&s, b"flow-1").unwrap();
    assert!(sealed.starts_with("v1."));
    assert!(
        !sealed.contains(&d),
        "private key must not appear in the clear"
    );
    let back = sealer("acme").unseal(&sealed, b"flow-1").unwrap();
    assert_eq!(back.nonce, s.nonce);
    assert_eq!(back.state, s.state);
    assert_eq!(back.enc_key.d, s.enc_key.d);
}

#[test]
fn a_sealed_session_is_bound_to_its_flow_and_tenant() {
    let sealed = sealer("acme").seal(&session(), b"flow-1").unwrap();
    assert!(matches!(
        sealer("acme").unseal(&sealed, b"flow-2"),
        Err(Error::Integrity(_))
    ));
    assert!(matches!(
        sealer("globex").unseal(&sealed, b"flow-1"),
        Err(Error::Integrity(_))
    ));
    let other_master = SessionSealer::from_master(&[8u8; 32], "acme").unwrap();
    assert!(matches!(
        other_master.unseal(&sealed, b"flow-1"),
        Err(Error::Integrity(_))
    ));
}

#[test]
fn previous_masters_open_inflight_sessions_and_results_during_rotation() {
    let old_master = [8u8; 32];
    let new_master = [9u8; 32];
    let old = SessionSealer::from_master(&old_master, "acme").unwrap();
    let original = session();
    let session_token = old.seal(&original, b"flow-1").unwrap();
    let result_token = old
        .seal_json(&serde_json::json!({"sub": "Lovelace"}), b"result:flow-1")
        .unwrap();
    let rotated = SessionSealer::from_master(&new_master, "acme")
        .unwrap()
        .with_previous_masters(&[&old_master], "acme")
        .unwrap();
    assert_eq!(
        rotated.unseal(&session_token, b"flow-1").unwrap().state,
        original.state
    );
    let result: serde_json::Value = rotated
        .unseal_json(&result_token, b"result:flow-1")
        .unwrap();
    assert_eq!(result["sub"], "Lovelace");
    let fresh = rotated
        .seal_json(&serde_json::json!({"sub": "new"}), b"result:flow-2")
        .unwrap();
    assert!(old
        .unseal_json::<serde_json::Value>(&fresh, b"result:flow-2")
        .is_err());
    assert!(SessionSealer::from_master(&new_master, "acme")
        .unwrap()
        .with_previous_masters(&[&[1u8; 31]], "acme")
        .is_err());
}

#[test]
fn tampering_truncation_and_wrong_versions_are_refused() {
    let sealed = sealer("acme").seal(&session(), b"f").unwrap();
    let mut bytes = sealed.clone().into_bytes();
    let n = bytes.len() - 2;
    bytes[n] = if bytes[n] == b'A' { b'B' } else { b'A' };
    assert!(sealer("acme")
        .unseal(&String::from_utf8(bytes).unwrap(), b"f")
        .is_err());
    assert!(matches!(
        sealer("acme").unseal("v1.AAAA", b"f"),
        Err(Error::Malformed(_))
    ));
    assert!(matches!(
        sealer("acme").unseal(&sealed.replacen("v1.", "v2.", 1), b"f"),
        Err(Error::Malformed(_))
    ));
    assert!(matches!(
        sealer("acme").unseal("garbage", b"f"),
        Err(Error::Malformed(_))
    ));
    assert!(matches!(
        sealer("acme").unseal(&"x".repeat(1024 * 1024 + 1), b"f"),
        Err(Error::Policy(_))
    ));
}

#[test]
fn generic_stored_values_are_encrypted_and_bound_to_their_purpose() {
    let value = serde_json::json!({"subject": "Lovelace", "given_name": "Ada"});
    let sealed = sealer("acme").seal_json(&value, b"result:flow-1").unwrap();
    assert!(!sealed.contains("Lovelace"));
    assert!(!sealed.contains("Ada"));
    let back: serde_json::Value = sealer("acme")
        .unseal_json(&sealed, b"result:flow-1")
        .unwrap();
    assert_eq!(back, value);
    assert!(sealer("acme")
        .unseal_json::<serde_json::Value>(&sealed, b"session:flow-1")
        .is_err());
    assert!(sealer("acme")
        .unseal_json::<serde_json::Value>(&sealed, b"result:flow-2")
        .is_err());
}

#[test]
fn every_seal_is_different_and_a_weak_master_is_refused() {
    let s = session();
    let a = sealer("acme").seal(&s, b"f").unwrap();
    let b = sealer("acme").seal(&s, b"f").unwrap();
    assert_ne!(a, b, "fresh nonce per seal");
    assert!(SessionSealer::from_master(&[1u8; 31], "acme").is_err());
    assert!(SessionSealer::from_master(b"", "acme").is_err());
}
