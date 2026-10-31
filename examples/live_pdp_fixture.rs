//! Writes an issuer certificate (PEM) and the AuthZEN request the verifier would send for it, so a real
//! go-trust can be pointed at the certificate. Run: cargo run --example live_pdp_fixture -- <outdir>
use serde_json::json;
use siros_verifier_core::testutil::*;
use siros_verifier_core::trust::TrustQuery;

fn main() {
    let out = std::env::args().nth(1).expect("outdir");
    std::fs::create_dir_all(&out).unwrap();
    let (cert, key) = self_signed_ec("issuer.example", "ES256");
    let holder = ec_jwk("ES256", "h");
    let mut spec = IssueSpec::new(
        json!({"iss": "https://issuer.example", "vct": "urn:eudi:pid:1", "iat": 1, "exp": 4_000_000_000i64}),
    );
    spec.holder_pub = Some(public_of(&holder));
    spec.x5c_der = vec![cert.clone()];
    let issued = issue(&key, &spec).unwrap();
    let hdr = jose_rs::jws::decode_header(&issued.jwt).unwrap();
    let chain = siros_verifier_core::sdjwt::x5c_chain(&hdr).unwrap();
    let jwk = siros_verifier_core::sdjwt::jwk_from_cert_der(&chain[0]).unwrap();
    let _ = jwk;
    let q = TrustQuery::for_mdoc_issuer(
        &siros_verifier_core::mdoc::MdocIssuer { x5c_der: chain },
        "pid-provider",
        "urn:eudi:pid:1",
    )
    .to_authzen();
    println!("{}", q["subject"]["id"].as_str().unwrap());
    std::fs::write(
        format!("{out}/request.json"),
        serde_json::to_string_pretty(&q).unwrap(),
    )
    .unwrap();
    let b64 = base64_std(&cert);
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        b64.as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    );
    std::fs::write(format!("{out}/issuer.pem"), pem).unwrap();
}
fn base64_std(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}
