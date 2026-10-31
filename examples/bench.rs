//! Rough per-operation timings. Run: cargo run --release --example bench
//! (also built for wasm32-wasip1 and run under a WASI runtime for a comparison).

use jose_rs::algorithm::JweEncryption;
use jose_rs::jwe::compact as jwe_compact;
use jose_rs::jwk::generate_ec;
use serde_json::json;
use siros_verifier_core::sdjwt::{verify, HashAlg, HolderBinding, StaticKey, VerifyParams};
use siros_verifier_core::testutil::*;
use std::time::Instant;

fn time<F: FnMut()>(name: &str, n: u32, mut f: F) {
    for _ in 0..(n / 10).max(1) {
        f();
    }
    let t = Instant::now();
    for _ in 0..n {
        f();
    }
    let per = t.elapsed().as_secs_f64() * 1e6 / n as f64;
    println!("{name:<36} {per:>9.1} us/op");
}

fn main() {
    let issuer = ec_jwk("ES256", "i");
    let holder = ec_jwk("ES256", "h");
    let now = 1_800_000_000i64;
    let mut spec = IssueSpec::new(json!({
        "iss": "https://i.example", "vct": "urn:t", "iat": now - 1, "exp": now + 1000,
        "a": "1", "b": "2", "c": "3", "d": { "e": "4" },
    }));
    spec.holder_pub = Some(public_of(&holder));
    spec.conceal = vec![
        vec![Seg::Key("a")],
        vec![Seg::Key("b")],
        vec![Seg::Key("c")],
        vec![Seg::Key("d"), Seg::Key("e")],
    ];
    spec.decoys = 3;
    let issued = issue(&issuer, &spec).unwrap();
    let pres = present(
        &issued,
        &[0, 1, 2, 3],
        Some(KbSpec {
            holder: &holder,
            aud: "v",
            nonce: "n",
            iat: now,
        }),
        HashAlg::Sha256,
    )
    .unwrap();
    let key = StaticKey(public_of(&issuer));
    let p = VerifyParams::new(
        now,
        HolderBinding::Required {
            aud: "v",
            nonce: "n",
            max_age_secs: 300,
        },
    );
    time("sd-jwt vc verify (2 ES256 verifies)", 500, || {
        verify(&pres, &key, &p).unwrap();
    });

    let mut r = generate_ec("P-256").unwrap();
    r.alg = Some("ECDH-ES".into());
    r.use_ = Some("enc".into());
    let rp = r.to_public_jwk();
    let body = vec![b'x'; 4096];
    let jwe = jwe_compact::encrypt_with_jwk(&rp, &body, JweEncryption::A128GCM).unwrap();
    time("ECDH-ES decrypt (4 KiB, A128GCM)", 500, || {
        jwe_compact::decrypt_with_jwk(&r, &jwe).unwrap();
    });
    time("ECDH-ES encrypt (4 KiB, A128GCM)", 500, || {
        jwe_compact::encrypt_with_jwk(&rp, &body, JweEncryption::A128GCM).unwrap();
    });
}
