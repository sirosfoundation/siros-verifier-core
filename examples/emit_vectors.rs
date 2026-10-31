//! Writes Rust-produced vectors to target/interop/ for tools/interop-go to verify.

use jose_rs::algorithm::{JweAlgorithm, JweEncryption};
use jose_rs::jwe::compact as jwe_compact;
use jose_rs::jwk::generate_ec;
use jose_rs::JoseHeader;
use serde_json::json;
use siros_verifier_core::sdjwt::HashAlg;
use siros_verifier_core::testutil::*;

fn main() {
    let dir = format!("{}/target/interop", env!("CARGO_MANIFEST_DIR"));
    std::fs::create_dir_all(&dir).unwrap();

    // ECDH-ES JWE, with and without apu/apv, both content encryptions.
    let mut recipient = generate_ec("P-256").unwrap();
    recipient.alg = Some("ECDH-ES".into());
    recipient.use_ = Some("enc".into());
    let plaintext = r#"{"vp_token":{"pid":["x"]},"state":"s-from-rust"}"#;
    let mut vectors = vec![];
    for enc in [JweEncryption::A128GCM, JweEncryption::A256GCM] {
        for party in [false, true] {
            let mut header = JoseHeader::for_jwe(JweAlgorithm::EcdhEs, enc);
            header.kid = Some("rust-recipient".into());
            if party {
                header.extra.insert(
                    "apu".into(),
                    json!(jose_rs::base64url::encode(b"mdoc-nonce")),
                );
                header.extra.insert(
                    "apv".into(),
                    json!(jose_rs::base64url::encode(b"req-nonce")),
                );
            }
            let jwe = jwe_compact::encrypt_with_jwk_header(
                &recipient.to_public_jwk(),
                header,
                plaintext.as_bytes(),
                enc,
            )
            .unwrap();
            vectors.push(json!({ "enc": enc.as_str(), "with_party_info": party, "jwe": jwe }));
        }
    }
    std::fs::write(
        format!("{dir}/rust_jwe.json"),
        serde_json::to_vec_pretty(
            &json!({ "private_jwk": recipient, "plaintext": plaintext, "vectors": vectors }),
        )
        .unwrap(),
    )
    .unwrap();

    // SD-JWT VC with nested and array disclosures, key-bound.
    let issuer = ec_jwk("ES256", "rust-issuer");
    let holder = ec_jwk("ES256", "rust-holder");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut spec = IssueSpec::new(json!({
        "iss": "https://rust-issuer.example", "vct": "urn:vp-spike:test:1",
        "iat": now - 5, "nbf": now - 5, "exp": now + 86_400,
        "given_name": "Ada", "family_name": "Lovelace",
        "address": { "street": "St James's Square 1", "locality": "London" },
    }));
    spec.holder_pub = Some(public_of(&holder));
    spec.conceal = vec![
        vec![Seg::Key("given_name")],
        vec![Seg::Key("family_name")],
        vec![Seg::Key("address"), Seg::Key("street")],
    ];
    spec.decoys = 3;
    let issued = issue(&issuer, &spec).unwrap();
    let (nonce, aud) = ("rust-nonce-123", "https://verifier.example");
    let pres = present(
        &issued,
        &[0, 1, 2],
        Some(KbSpec {
            holder: &holder,
            aud,
            nonce,
            iat: now,
        }),
        HashAlg::Sha256,
    )
    .unwrap();
    std::fs::write(
        format!("{dir}/rust_sdjwt.json"),
        serde_json::to_vec_pretty(&json!({
            "issuer_public_jwk": public_of(&issuer), "presentation": pres, "nonce": nonce, "aud": aud,
        }))
        .unwrap(),
    )
    .unwrap();
    println!("wrote {dir}/rust_jwe.json and rust_sdjwt.json");
}
