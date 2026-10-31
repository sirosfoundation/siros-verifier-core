//! Repeated JSON member names are refused everywhere attacker-controlled JSON is read.
use jose_rs::jwk::Jwk;
use p256::ecdsa::signature::Signer;
use serde_json::{json, Value};
use siros_verifier_core::json_strict::{from_slice, from_str};
use siros_verifier_core::receipt::*;
use siros_verifier_core::sdjwt::*;
use siros_verifier_core::testutil::*;
use siros_verifier_core::Error;

const NOW: i64 = 1_800_000_000;

fn msg(r: Result<Value, Error>) -> String {
    match r {
        Ok(v) => format!("OK {v}"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn repeated_names_are_refused_at_any_depth() {
    for (name, text) in [
        ("top level", r#"{"a":1,"a":2}"#),
        ("same value", r#"{"a":1,"a":1}"#),
        ("nested", r#"{"x":{"a":1,"b":2,"a":3}}"#),
        ("inside an array", r#"{"x":[{"a":1},{"b":1,"b":2}]}"#),
        ("escaped spelling", r#"{"a":1,"\u0061":2}"#),
        ("empty name", r#"{"":1,"":2}"#),
    ] {
        let m = msg(from_str(text));
        assert!(m.contains("json_duplicate_member"), "{name}: {m}");
    }
}

#[test]
fn well_formed_documents_parse_exactly_as_serde_json_does() {
    let corpus: Vec<String> =
        serde_json::from_str(include_str!("vectors/jcs_inputs.json")).unwrap();
    assert!(corpus.len() >= 15);
    for text in &corpus {
        assert_eq!(
            from_str(text).unwrap(),
            serde_json::from_str::<Value>(text).unwrap(),
            "{text}"
        );
    }
}

#[test]
fn other_malformed_input_is_still_refused() {
    for text in [
        "",
        "{",
        r#"{"a":1} x"#,
        r#"{"a":1}{"b":2}"#,
        r#"{"a":}"#,
        "nul",
        r#"{"a":1,}"#,
    ] {
        let m = msg(from_str(text));
        assert!(m.starts_with("malformed input: json:"), "{text:?}: {m}");
    }
    let deep = format!("{}1{}", "[".repeat(300), "]".repeat(300));
    assert!(
        from_str(&deep).is_err(),
        "nesting beyond the parser's limit"
    );
    assert!(from_slice(&[0xff, 0xfe]).is_err(), "not UTF-8");
}

fn issuer() -> Jwk {
    ec_jwk("ES256", "iss-1")
}

#[test]
fn an_sd_jwt_with_a_repeated_claim_is_refused() {
    let key = issuer();
    let good = format!(
        r#"{{"iss":"https://i.example","vct":"urn:eudi:pid:1","iat":{},"exp":{}}}"#,
        NOW - 10,
        NOW + 1000
    );
    let ok = format!(
        "{}~",
        sign_raw_bytes(&key, "dc+sd-jwt", good.as_bytes(), &[])
    );
    let resolver = StaticKey(key.to_public_jwk());
    let p = VerifyParams::new(NOW, HolderBinding::NotRequired);
    verify(&ok, &resolver, &p).expect("control: the same credential without the repeat verifies");

    let dup = format!(
        r#"{{"iss":"https://i.example","vct":"urn:eudi:other","vct":"urn:eudi:pid:1","iat":{},"exp":{}}}"#,
        NOW - 10,
        NOW + 1000
    );
    let bad = format!(
        "{}~",
        sign_raw_bytes(&key, "dc+sd-jwt", dup.as_bytes(), &[])
    );
    match verify(&bad, &resolver, &p) {
        Err(Error::Malformed(m)) => assert!(m.contains("json_duplicate_member"), "{m}"),
        other => panic!("{:?}", other.err()),
    }
}

#[test]
fn an_sd_jwt_header_with_a_repeated_name_is_refused() {
    let key = issuer();
    let payload = format!(
        r#"{{"iss":"https://i.example","vct":"urn:eudi:pid:1","iat":{},"exp":{}}}"#,
        NOW - 10,
        NOW + 1000
    );
    let good = sign_raw_bytes(&key, "dc+sd-jwt", payload.as_bytes(), &[]);
    let mut parts = good.split('.');
    let _old_header = parts.next().unwrap();
    let payload = parts.next().unwrap();
    let signature = parts.next().unwrap();
    let header =
        jose_rs::base64url::encode(br#"{"alg":"ES256","typ":"dc+sd-jwt","typ":"dc+sd-jwt"}"#);
    let bad = format!("{header}.{payload}.{signature}~");
    match verify(
        &bad,
        &StaticKey(key.to_public_jwk()),
        &VerifyParams::new(NOW, HolderBinding::NotRequired),
    ) {
        Err(Error::Malformed(m)) => assert!(m.contains("json_duplicate_member"), "{m}"),
        other => panic!("{:?}", other.err()),
    }
}

#[test]
fn a_disclosure_whose_value_repeats_a_name_is_refused() {
    let key = issuer();
    let hash = HashAlg::Sha256;
    let raw_value = r#"{"street":"A","street":"B"}"#;
    let disclosure = jose_rs::base64url::encode(
        format!(r#"["salt1234567890ab","address",{raw_value}]"#).as_bytes(),
    );
    let digest = hash.digest_b64u(disclosure.as_bytes());
    let payload = format!(
        r#"{{"iss":"https://i.example","vct":"urn:eudi:pid:1","iat":{},"exp":{},"_sd":["{digest}"],"_sd_alg":"sha-256"}}"#,
        NOW - 10,
        NOW + 1000
    );
    let sdjwt = format!(
        "{}~{disclosure}~",
        sign_raw_bytes(&key, "dc+sd-jwt", payload.as_bytes(), &[])
    );
    let p = VerifyParams::new(NOW, HolderBinding::NotRequired);
    match verify(&sdjwt, &StaticKey(key.to_public_jwk()), &p) {
        Err(Error::Malformed(m)) => assert!(m.contains("json_duplicate_member"), "{m}"),
        other => panic!("{:?}", other.err()),
    }
}

fn signed_receipt(header: &[u8], claims: &[u8]) -> (String, Verifier) {
    use std::collections::HashMap;
    let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
    let b64 = |b: &[u8]| jose_rs::base64url::encode(b);
    let si = format!("{}.{}", b64(header), b64(claims));
    let sig: p256::ecdsa::Signature = sk.sign(si.as_bytes());
    let mut keys = HashMap::new();
    keys.insert("k1".to_string(), p256::ecdsa::VerifyingKey::from(&sk));
    (
        format!("{si}.{}", b64(&sig.to_bytes())),
        Verifier {
            keys,
            iss: "core".into(),
            aud: "t".into(),
            skew: 60,
        },
    )
}

#[test]
fn a_receipt_whose_claims_repeat_a_name_is_refused() {
    let claims = format!(
        r#"{{"iss":"core","aud":"t","pdp":"p","decision":false,"decision":true,"req_sha256":"x","iat":{NOW},"nbf":{NOW},"refresh_after":{NOW},"exp":{},"jti":"j"}}"#,
        NOW + 100
    );
    let (jws, verifier) = signed_receipt(
        br#"{"alg":"ES256","typ":"authzen-decision+jwt","kid":"k1"}"#,
        claims.as_bytes(),
    );
    match verifier.verify(&jws, &json!({}), NOW) {
        Err(Error::Malformed(m)) => assert!(m.contains("json_duplicate_member"), "{m}"),
        other => panic!("{:?}", other.err()),
    }
}

#[test]
fn a_receipt_whose_header_repeats_a_name_is_refused() {
    let claims = format!(
        r#"{{"iss":"core","aud":"t","pdp":"p","decision":true,"req_sha256":"{}","iat":{NOW},"nbf":{NOW},"refresh_after":{NOW},"exp":{},"jti":"j"}}"#,
        req_sha256(&json!({})).unwrap(),
        NOW + 100
    );
    let (jws, verifier) = signed_receipt(
        br#"{"alg":"ES256","typ":"authzen-decision+jwt","kid":"k1","kid":"k1"}"#,
        claims.as_bytes(),
    );
    match verifier.verify(&jws, &json!({}), NOW) {
        Err(Error::Malformed(m)) => assert!(m.contains("json_duplicate_member"), "{m}"),
        other => panic!("{:?}", other.err()),
    }
}
