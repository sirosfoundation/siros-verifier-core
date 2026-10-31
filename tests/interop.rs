//! Go -> Rust interop. Vectors in tests/vectors/ are produced by
//! tools/interop-go (go-jose for JWE, SUNET/vc sdjwtvc for SD-JWT VC) and
//! committed; regenerate with `scripts/interop.sh gen`.

use jose_rs::jwe::compact as jwe_compact;
use jose_rs::jwk::Jwk;
use serde::Deserialize;
use serde_json::Value;
use siros_verifier_core::sdjwt::{verify, HolderBinding, StaticKey, VerifyParams};

fn load(name: &str) -> Value {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))).unwrap()
}

#[derive(Deserialize)]
struct JweVec {
    enc: String,
    with_party_info: bool,
    jwe: String,
}

#[test]
fn go_jose_ecdh_es_jwe_decrypts() {
    let v = load("go_jwe.json");
    let mut recipient: Jwk = serde_json::from_value(v["private_jwk"].clone()).unwrap();
    recipient.alg = Some("ECDH-ES".into());
    recipient.use_ = Some("enc".into());
    let plaintext = v["plaintext"].as_str().unwrap();
    let vectors: Vec<JweVec> = serde_json::from_value(v["vectors"].clone()).unwrap();
    assert_eq!(vectors.len(), 2);
    for jv in vectors {
        let d = jwe_compact::decrypt_with_jwk_authenticated(&recipient, &jv.jwe)
            .unwrap_or_else(|e| panic!("{} party={}: {e}", jv.enc, jv.with_party_info));
        assert_eq!(d.value, plaintext.as_bytes());
        assert_eq!(d.protected.enc.as_deref(), Some(jv.enc.as_str()));
        assert_eq!(d.protected.kid.as_deref(), Some("go-recipient"));
        assert!(
            !jv.with_party_info
                && !d.protected.extra.contains_key("apu")
                && !d.protected.extra.contains_key("apv")
        );
    }
}

#[test]
fn vc_issued_sd_jwt_vc_verifies() {
    let v = load("vc_sdjwt.json");
    let issuer: Jwk = serde_json::from_value(v["issuer_public_jwk"].clone()).unwrap();
    let now = v["generated_at"].as_i64().unwrap() + 2;
    let (nonce, aud) = (v["nonce"].as_str().unwrap(), v["aud"].as_str().unwrap());
    let p = VerifyParams::new(
        now,
        HolderBinding::Required {
            aud,
            nonce,
            max_age_secs: 300,
        },
    );
    let r = verify(v["presentation"].as_str().unwrap(), &StaticKey(issuer), &p)
        .expect("vc-issued credential must verify");

    let e = &v["expect"];
    assert_eq!(r.issuer.iss, e["iss"].as_str().unwrap());
    assert_eq!(r.vct, e["vct"].as_str().unwrap());
    assert_eq!(r.claims["given_name"], e["given_name"]);
    assert_eq!(r.claims["family_name"], e["family_name"]);
    assert_eq!(
        r.claims["address"]["street"], e["street"],
        "nested disclosure from vc"
    );
    assert_eq!(r.claims["address"]["locality"], e["locality"]);
    assert!(r.holder_key.is_some());

    // the same presentation under a different nonce or audience must fail
    for (a, n) in [(aud, "other"), ("https://evil.example", nonce)] {
        let p = VerifyParams::new(
            now,
            HolderBinding::Required {
                aud: a,
                nonce: n,
                max_age_secs: 300,
            },
        );
        assert!(verify(
            v["presentation"].as_str().unwrap(),
            &StaticKey(serde_json::from_value(v["issuer_public_jwk"].clone()).unwrap()),
            &p
        )
        .is_err());
    }
}
