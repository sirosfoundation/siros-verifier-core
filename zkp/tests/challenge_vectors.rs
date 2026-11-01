//! The shared nym_auth challenge vectors (vendored verbatim, see tests/vectors/SOURCE), run through our derivation.
use serde_json::Value;
use sha2::{Digest, Sha256};
use siros_verifier_zkp::transcript::*;

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/challenge-vectors.json")).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn opt_hex(v: &Value) -> Option<Vec<u8>> {
    v.as_str().map(hex)
}
fn s(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap_or_else(|| panic!("{k}")).to_owned()
}

#[test]
fn the_vendored_file_is_the_pinned_one() {
    // Re-vendor rather than edit: a local change turns a cross-implementation check into a self-consistency one.
    let digest = to_hex(&Sha256::digest(include_bytes!(
        "vectors/challenge-vectors.json"
    )));
    assert_eq!(
        digest,
        "611f6ba601034c37cefddb91422bcafd648c93b181e5eab730305ff46101cb6a"
    );
    assert!(include_str!("vectors/SOURCE").contains(&digest));
}

#[test]
fn dc_api_transcripts_and_digests_match() {
    let v = vectors();
    let cases = v["derive"].as_array().unwrap();
    assert!(cases.len() >= 4);
    for c in cases {
        let thumb = opt_hex(&c["jwk_thumbprint_hex"]);
        let t =
            session_transcript_dcapi(&s(c, "origin"), &s(c, "nonce"), thumb.as_deref()).unwrap();
        assert_eq!(
            to_hex(&t),
            s(c, "session_transcript_hex"),
            "{}",
            s(c, "name")
        );
        let d = challenge_digest(&t, &s(c, "doc_type")).unwrap();
        assert_eq!(to_hex(&d), s(c, "challenge_digest_hex"), "{}", s(c, "name"));
    }
}

#[test]
fn the_digest_of_a_given_transcript_matches() {
    for c in vectors()["digest"].as_array().unwrap() {
        let d = challenge_digest(&hex(&s(c, "session_transcript_hex")), &s(c, "doc_type")).unwrap();
        assert_eq!(to_hex(&d), s(c, "challenge_digest_hex"), "{}", s(c, "name"));
    }
}

#[test]
fn redirect_handover_info_transcripts_and_digests_match() {
    let v = vectors();
    let cases = v["derive_redirect"].as_array().unwrap();
    assert!(cases.len() >= 6);
    for c in cases {
        let thumb = hex(c["jwk_thumbprint_hex"].as_str().unwrap());
        let (cid, nonce, uri) = (s(c, "client_id"), s(c, "nonce"), s(c, "response_uri"));
        assert_eq!(
            to_hex(&handover_info_redirect(&cid, &nonce, &uri, &thumb)),
            s(c, "handover_info_hex"),
            "{}",
            s(c, "name")
        );
        let t = session_transcript_redirect(&cid, &nonce, &uri, &thumb).unwrap();
        assert_eq!(
            to_hex(&t),
            s(c, "session_transcript_hex"),
            "{}",
            s(c, "name")
        );
        assert_eq!(
            to_hex(&challenge_digest(&t, &s(c, "doc_type")).unwrap()),
            s(c, "challenge_digest_hex"),
            "{}",
            s(c, "name")
        );
    }
}

#[test]
fn every_reject_vector_is_refused() {
    let v = vectors();
    let mut n = 0;
    for c in v["rejects"].as_array().unwrap() {
        let r = match s(c, "op").as_str() {
            "derive" => {
                let thumb = opt_hex(&c["jwk_thumbprint_hex"]);
                session_transcript_dcapi(&s(c, "origin"), &s(c, "nonce"), thumb.as_deref())
                    .and_then(|t| challenge_digest(&t, &s(c, "doc_type")).map(|_| ()))
            }
            "digest" => challenge_digest(&hex(&s(c, "session_transcript_hex")), &s(c, "doc_type"))
                .map(|_| ()),
            other => panic!("unknown op {other}"),
        };
        assert!(r.is_err(), "accepted: {}", s(c, "name"));
        n += 1;
    }
    for c in v["rejects_redirect"].as_array().unwrap() {
        assert_eq!(s(c, "op"), "derive_redirect");
        let thumb = opt_hex(&c["jwk_thumbprint_hex"]).unwrap_or_default();
        let r = session_transcript_redirect(
            &s(c, "client_id"),
            &s(c, "nonce"),
            &s(c, "response_uri"),
            &thumb,
        )
        .and_then(|t| challenge_digest(&t, &s(c, "doc_type")).map(|_| ()));
        assert!(r.is_err(), "accepted: {}", s(c, "name"));
        n += 1;
    }
    assert_eq!(n, 13 + 8, "every reject vector ran");
}
