//! The WMP surface skeleton: the config block builds the member
//! provider, the config-declared invites parse fail-fast, and the
//! non-join purposes refuse.

use siros_verifier_service::wmp::{WmpConfig, WmpSurface};
use std::path::Path;

/// One owned temp dir per test: parallel tests share a pid (one test
/// binary), so a shared name would race — each test's chain lives and
/// dies with the test.
fn fixture_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "wmp-surface-test-{}-{}",
        std::process::id(),
        std::thread::current()
            .name()
            .unwrap_or("test")
            .replace("::", "-")
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A real key pair + self-signed chain (the identity's DNS name is
/// `verifier.example`): the boot's leaf validation needs a real,
/// matching chain.
fn write_identity(dir: &Path, dns: &str) -> String {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec![dns.to_string()])
        .unwrap()
        .self_signed(&kp)
        .unwrap();
    let chain = dir.join("identity_chain.pem");
    std::fs::write(&chain, cert.pem()).unwrap();
    chain.display().to_string()
}

fn config_in(dir: &Path, invites: Vec<serde_json::Value>) -> WmpConfig {
    serde_json::from_value(serde_json::json!({
        "join_pdp_url": "https://sirosid-gdc-spocp.internal:8000/access/v1/evaluation",
        "identity": "x509:san:dns:verifier.example",
        "identity_chain_path": write_identity(dir, "verifier.example"),
        "invites": invites,
    }))
    .unwrap()
}

/// The test's owned dir + the config built in it: ONE dir, held for the
/// test's lifetime (the second fixture_dir() call would wipe the first
/// — the config's chain lives in it).
fn config_with(invites: Vec<serde_json::Value>) -> (WmpConfig, std::path::PathBuf) {
    let dir = fixture_dir();
    (config_in(&dir, invites), dir)
}

#[test]
fn the_surface_builds_with_a_valid_identity_chain() {
    let (config, dir) = config_with(vec![]);
    let surface = WmpSurface::new(config, &dir).expect("the surface builds");
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
    let (config, dir) = config_with(vec![serde_json::json!({ "uri": uri })]);
    let err = match WmpSurface::new(config, &dir) {
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
    let (mut config, dir) = config_with(vec![]);
    config.identity_chain_path = dir.join("no-such.pem").display().to_string();
    let err = match WmpSurface::new(config, &dir) {
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

use siros_verifier_service::wmp::{
    parse_authzen_decision, AuthZenEntity, AuthZenRequest, Decision, ParsedInvite,
};

fn invite() -> ParsedInvite {
    ParsedInvite::parse(
        "wmp://invite?data=eyJwcm92aWRlciI6InBhcnRuZXIuZXhhbXBsZSIsInNlbmRlciI6InNlbmRlci5leGFtcGxlIiwibm9uY2UiOiJuLWEiLCJwdXJwb3NlIjoiam9pbiIsInJlbGF5IjoicmVsYXkuZXhhbXBsZSJ9",
    )
    .expect("the join-purpose invite parses")
}

#[test]
fn the_join_request_follows_the_go_spocp_wire_shape() {
    // The subject is the resource owner (the verifier); the group is
    // the resource; the counterpart rides the context — and the wire
    // JSON is exactly go-spocp's EvaluationRequest shape.
    let invite = invite();
    let request = AuthZenRequest::join("x509:san:dns:verifier.example", &invite);
    let json = request.to_json();
    assert_eq!(json["subject"]["type"], "verifier");
    assert_eq!(json["subject"]["id"], "x509:san:dns:verifier.example");
    assert_eq!(json["resource"]["type"], "wmp_group");
    assert_eq!(json["resource"]["id"], "partner.example");
    assert_eq!(json["action"]["name"], "join");
    assert_eq!(json["context"]["sender"], "sender.example");
    assert_eq!(json["context"]["relay"], "relay.example");
    assert_eq!(json["context"]["purpose"], "join");
}

#[test]
fn the_entity_properties_ride_the_wire_when_present() {
    let entity = AuthZenEntity {
        kind: "verifier",
        id: "v".into(),
        properties: Some(serde_json::json!({"x": 1})),
    };
    let json = entity.to_json();
    assert_eq!(json["properties"]["x"], 1);
    let bare = AuthZenEntity {
        kind: "verifier",
        id: "v".into(),
        properties: None,
    };
    assert!(bare.to_json().get("properties").is_none());
}

#[test]
fn the_decision_parser_takes_booleans_and_refuses_everything_else() {
    assert_eq!(
        parse_authzen_decision(&serde_json::json!({"decision": true})).unwrap(),
        Decision::Allow
    );
    assert_eq!(
        parse_authzen_decision(&serde_json::json!({"decision": false})).unwrap(),
        Decision::Deny
    );
    // A present-but-non-boolean decision is malformed, never guessed:
    for malformed in [
        serde_json::json!({"decision": "Allow"}),
        serde_json::json!({"decision": 1}),
        serde_json::json!({"decision": null}),
        serde_json::json!({}),
        serde_json::json!({"context": {}}),
    ] {
        assert!(
            parse_authzen_decision(&malformed).is_err(),
            "the malformed answer {malformed} must refuse"
        );
    }
}

#[tokio::test]
async fn the_pdp_denies_fail_closed_when_unreachable() {
    // An unreachable PDP (nothing listens here) denies — the
    // fail-closed contract the gate's decisions ride on.
    let pdp =
        siros_verifier_service::wmp::SpocpPdp::new("http://127.0.0.1:1/access/v1/evaluation", true)
            .expect("the client builds (loopback http)");
    let request = AuthZenRequest::join("x509:san:dns:verifier.example", &invite());
    assert_eq!(pdp.evaluate(&request).await, Decision::Deny);
}

#[test]
fn the_pdp_url_scheme_refuses_plain_http_without_the_opt_in() {
    let err = match siros_verifier_service::wmp::SpocpPdp::new(
        "http://sirosid-gdc-spocp.internal:8000/access/v1/evaluation",
        false,
    ) {
        Ok(_) => panic!("a plain-HTTP non-loopback PDP must refuse without the opt-in"),
        Err(e) => e,
    };
    assert!(
        format!("{err:#}").contains("https"),
        "the refusal names the scheme: {err:#}"
    );
}

#[test]
fn an_identity_chain_for_another_host_refuses_the_build() {
    // The leaf's SAN DNS must match the configured identity: a chain
    // for another host is not this member's identity.
    let (mut config, dir) = config_with(vec![]);
    config.identity_chain_path = write_identity(&dir, "other.example");
    let err = match WmpSurface::new(config, &dir) {
        Ok(_) => panic!("a foreign leaf must refuse the build"),
        Err(e) => e,
    };
    let chained = format!("{err:#}");
    assert!(
        chained.contains("no SAN DNS"),
        "the refusal names the identity mismatch: {chained}"
    );
}
