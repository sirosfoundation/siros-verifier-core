//! The WMP surface skeleton: the config block builds the member
//! provider, the config-declared invites parse fail-fast, and the
//! non-join purposes refuse.

use siros_verifier_service::wmp::{ParsedInvite, WmpConfig, WmpSurface};
use std::path::Path;

fn fixture_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/wmp"))
}

/// A real key pair + self-signed chain: the member provider's
/// construction needs a real chain (leaf first), same as every other
/// certificate surface in this service.
fn write_identity(dir: &Path) -> String {
    // Unique per test: tests run in parallel, the chain writes are not
    // coordinated.
    let name = format!("identity-{}.pem", std::process::id());
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["verifier.example".to_string()])
        .unwrap()
        .self_signed(&kp)
        .unwrap();
    let chain = dir.join(name);
    std::fs::write(&chain, cert.pem()).unwrap();
    chain.display().to_string()
}

fn config_with(invites: Vec<serde_json::Value>) -> WmpConfig {
    serde_json::from_value(serde_json::json!({
        "join_pdp_url": "http://sirosid-gdc-spocp.internal:8000/access/v1/evaluation",
        "identity": "x509:san:dns:verifier.example",
        "identity_chain_path": write_identity(&fixture_dir()),
        "invites": invites,
    }))
    .unwrap()
}

#[test]
fn the_surface_builds_with_a_valid_identity_chain() {
    let config = config_with(vec![]);
    let surface = WmpSurface::new(config, &fixture_dir()).expect("the surface builds");
    assert_eq!(
        surface.identity(),
        "x509:san:dns:verifier.example",
        "the member identity is the config's"
    );
    assert!(
        surface.config_invites().is_empty(),
        "no config invites, none parsed"
    );
}

#[test]
fn a_config_invite_without_the_join_purpose_refuses_the_build() {
    // The wmp://invite URI with a bogus purpose: the surface joins
    // GROUPS, it does not bootstrap sessions — the gate refuses the
    // purpose at construction, fail-fast at boot.
    let uri = "wmp://invite?data=eyJwcm92aWRlciI6InBhcnRuZXIuZXhhbXBsZSIsInNlbmRlciI6InNlbmRlci5leGFtcGxlIiwibm9uY2UiOiJuLWEiLCJwdXJwb3NlIjoic2Vzc2lvbiJ9";
    let config = config_with(vec![serde_json::json!({ "uri": uri })]);
    let err = match WmpSurface::new(config, &fixture_dir()) {
        Ok(_) => panic!("a session-purpose invite must refuse the build"),
        Err(e) => e,
    };
    let chained = format!("{err:#}");
    assert!(
        chained.contains("not a group invitation"),
        "the refusal names the purpose problem: {chained}"
    );
}

#[test]
fn an_empty_identity_chain_refuses_the_build() {
    let mut config = config_with(vec![]);
    config.identity_chain_path = fixture_dir().join("no-such.pem").display().to_string();
    let err = match WmpSurface::new(config, &fixture_dir()) {
        Ok(_) => panic!("a missing identity chain must refuse the build"),
        Err(e) => e,
    };
    let chained = format!("{err:#}");
    assert!(
        chained.contains("reading the WMP identity chain"),
        "the refusal names the chain: {chained}"
    );
}

#[test]
fn a_malformed_invite_uri_refuses_the_parse() {
    let err = match ParsedInvite::parse("https://verifier.example/#not-an-invite") {
        Ok(_) => panic!("a malformed invite must refuse"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("invite"),
        "the refusal names the invite: {err:#}"
    );
}
