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
    // The chain AND the leaf's PKCS#8 key: the surface's signer is the
    // certificate's key (RFC 9420 §5.3.1's binding).
    std::fs::write(dir.join("identity_chain.pem"), cert.pem()).unwrap();
    std::fs::write(dir.join("identity_key.pem"), kp.serialize_pem()).unwrap();
    dir.join("identity_chain.pem").display().to_string()
}

fn config_in(dir: &Path, invites: Vec<serde_json::Value>) -> WmpConfig {
    serde_json::from_value(serde_json::json!({
        "join_pdp_url": "http://127.0.0.1:1/access/v1/evaluation",
        "identity": "x509:san:dns:verifier.example",
        "identity_chain_path": write_identity(dir, "verifier.example"),
        "identity_key_path": dir.join("identity_key.pem").display().to_string(),
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
    assert_eq!(json["context"]["provider"], "partner.example");
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

#[test]
fn a_bare_identity_refuses_the_build() {
    // The identity must be the x509:san:dns:<host> form — a bare
    // hostname is not a WMP identifier scheme, and the AuthZEN subject
    // must be the documented form.
    let (mut config, dir) = config_with(vec![]);
    config.identity = "verifier.example".to_string();
    let err = match WmpSurface::new(config, &dir) {
        Ok(_) => panic!("a bare identity must refuse the build"),
        Err(e) => e,
    };
    let chained = format!("{err:#}");
    assert!(
        chained.contains("x509:san:dns:"),
        "the refusal names the required form: {chained}"
    );
}

#[test]
fn a_key_that_is_not_the_leafs_refuses_the_build() {
    // RFC 9420 §5.3.1: the MLS credential's key must bind to the
    // signer. A key from another leaf than the chain's is a misbinding
    // — the constructor (or a peer) would catch it later; the boot
    // catches it now.
    let (config, dir) = config_with(vec![]);
    // A DIFFERENT key pair's key, written over the fixture's.
    let other = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    std::fs::write(dir.join("identity_key.pem"), other.serialize_pem()).unwrap();
    let err = match WmpSurface::new(config, &dir) {
        Ok(_) => panic!("a foreign key must refuse the build"),
        Err(e) => e,
    };
    let chained = format!("{err:#}");
    assert!(
        chained.contains("signer") || chained.contains("key"),
        "the refusal names the key binding: {chained}"
    );
}

#[test]
fn a_compressed_leaf_point_binds_the_matching_key() {
    // RFC 5480 §2.2: a certificate's SPKI may carry a COMPRESSED SEC1
    // point (0x02/0x03 prefix) while the key's own SPKI emits the
    // uncompressed form — the same key, two encodings. The regression
    // protection goes THROUGH WmpSurface::new: the leaf re-encoded
    // with the compressed point must still build (a byte comparison
    // would reject it).
    let dir = fixture_dir();
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["verifier.example".to_string()])
        .unwrap()
        .self_signed(&kp)
        .unwrap();
    // The leaf's DER with the SPKI's point replaced by the compressed
    // form. The signature no longer covers the modified TBS — the
    // surface does not verify the identity file's self-signature (the
    // deployment's own file), only the parse, the SAN and the key
    // binding, so the re-encode is faithful to what the constructor
    // reads.
    let compressed = {
        let key_der = pem::parse_many(kp.serialize_pem())
            .unwrap()
            .into_iter()
            .find(|b| b.tag() == "PRIVATE KEY")
            .map(pem::Pem::into_contents)
            .unwrap();
        let secret =
            <p256::SecretKey as p256::pkcs8::DecodePrivateKey>::from_pkcs8_der(&key_der).unwrap();
        use p256::elliptic_curve::sec1::ToSec1Point;
        secret.public_key().to_sec1_point(true).as_bytes().to_vec()
    };
    let modified = {
        use x509_cert::der::{asn1::BitString, Decode, Encode};
        let parsed = x509_cert::Certificate::from_der(cert.der()).unwrap();
        let mut spki = parsed.tbs_certificate.subject_public_key_info.clone();
        spki.subject_public_key = BitString::from_bytes(&compressed).unwrap();
        let mut tbs = parsed.tbs_certificate.clone();
        tbs.subject_public_key_info = spki;
        let rebuilt = x509_cert::Certificate {
            tbs_certificate: tbs,
            ..parsed.clone()
        };
        rebuilt.to_der().unwrap()
    };
    // The config BEFORE the fixture overwrite: config_in would generate
    // a fresh uncompressed identity over both files — the constructor
    // must consume THIS compressed leaf and ITS matching key.
    let config = config_in(&dir, vec![]);
    let block = pem::Pem::new("CERTIFICATE", modified);
    std::fs::write(dir.join("identity_chain.pem"), pem::encode(&block)).unwrap();
    std::fs::write(dir.join("identity_key.pem"), kp.serialize_pem()).unwrap();
    WmpSurface::new(config, &dir)
        .expect("a compressed leaf point binds the matching key through the constructor");
}

#[test]
fn an_ed25519_identity_key_binds_its_leaf() {
    // The other MLS suite algorithm (Ed25519, RFC 8410): the binding
    // check must decode it as happily as the P-256 half.
    let dir = fixture_dir();
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["verifier.example".to_string()])
        .unwrap()
        .self_signed(&kp)
        .unwrap();
    // The config BEFORE the fixture overwrite: config_in would generate
    // a P-256 pair over both files — the constructor must consume THIS
    // Ed25519 leaf and ITS matching key.
    let config = config_in(&dir, vec![]);
    std::fs::write(dir.join("identity_chain.pem"), cert.pem()).unwrap();
    std::fs::write(dir.join("identity_key.pem"), kp.serialize_pem()).unwrap();
    WmpSurface::new(config, &dir)
        .expect("an Ed25519 identity key binds its leaf through the constructor");
}

/// A real MLS join round trip through the gate: the orchestrator
/// mints the group FIRST (the stable id the config declares), the
/// candidate is configured, the member's package is fetched, the add
/// produces the Welcome — and the unreachable PDP's denial refuses
/// BEFORE any MLS state (the fail-closed contract).
#[tokio::test]
async fn a_welcome_from_an_orchestrator_joins_through_the_gate() {
    use wmp_core::mls::MlsProvider as _;

    // The orchestrator mints the group id (the stable identifier the
    // config declares).
    let orchestrator =
        wmp_mls::OpenMlsProvider::for_identity("x509:san:dns:sirosid-gdc-wmp-mcp.fly.dev").unwrap();
    let (group_id, _) = orchestrator
        .create_group(1, &[])
        .expect("the group creates");

    let dir = fixture_dir();
    let (config, dir2) = config_with(vec![]);
    let mut config = config;
    let _ = dir2;
    config.groups = vec![siros_verifier_service::wmp::WmpGroupDeclaration {
        id: group_id.clone(),
        via: "x509:san:dns:sirosid-gdc-wmp-mcp.fly.dev".to_string(),
    }];
    let surface = WmpSurface::new(config, &dir).expect("the surface builds");

    // The member's fresh KeyPackage — the add flow consumes it.
    let key_package = surface
        .fresh_key_package(1)
        .expect("the member's key package generates");
    let (_commit, welcome) = orchestrator
        .add_member(&group_id, &key_package)
        .expect("the member is added");

    // The join: the PDP is unreachable (nothing listens on loopback:1)
    // — the fail-closed deny refuses BEFORE any MLS state processes.
    let declaration = surface
        .resolve_candidate(&group_id)
        .expect("the candidate is configured");
    let err = match surface.join_by_welcome(&declaration, &welcome).await {
        Ok(_) => panic!("the unreachable PDP must deny the join"),
        Err(e) => e,
    };
    assert!(
        format!("{err:#}").contains("denied"),
        "the fail-closed refusal: {err:#}"
    );
    assert!(surface.joined_groups().await.is_empty());
}

#[test]
fn the_mls_group_id_from_a_created_group_round_trips() {
    // The MLS machinery itself: create + add + process_welcome on bare
    // providers — the surface's join_by_welcome wraps exactly this
    // exchange, so the wire artifacts it consumes are pinned here.
    use wmp_core::mls::MlsProvider as _;
    let orchestrator =
        wmp_mls::OpenMlsProvider::for_identity("x509:san:dns:orchestrator.example").unwrap();
    let member = wmp_mls::OpenMlsProvider::for_identity("x509:san:dns:verifier.example").unwrap();
    let (group_id, _) = orchestrator.create_group(1, &[]).expect("creates");
    let package = member.generate_key_package(1).expect("the package");
    let (_commit, welcome) = orchestrator
        .add_member(&group_id, &package.key_package)
        .expect("adds");
    let (joined_id, epoch) = member.process_welcome(&welcome).expect("joins");
    assert_eq!(joined_id, group_id, "the MLS GroupId round trips");
    assert!(epoch >= 1, "the epoch advances past the add");
}

/// The delivery endpoint end to end, the real deployment's order:
/// the orchestrator mints the group, the config declares the
/// candidate, the service boots, the orchestrator fetches the
/// member's KeyPackage over HTTP, adds the member, and the Welcome
/// posts through the endpoint — the unreachable PDP's fail-closed
/// denial answering 400, the whole path over the real HTTP surface.
#[tokio::test]
async fn the_delivery_endpoint_refuses_fail_closed_over_http() {
    use std::process::Stdio;
    use tokio::process::Command;
    use wmp_core::mls::MlsProvider as _;

    // 1. The orchestrator mints the group (the stable id).
    let orchestrator =
        wmp_mls::OpenMlsProvider::for_identity("x509:san:dns:orchestrator.example").unwrap();
    let (group_id, _) = orchestrator.create_group(1, &[]).unwrap();

    // 2. The verifier's member identity + the config with the candidate.
    let dir = std::env::temp_dir().join(format!("wmp-endpoint-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["verifier.example".to_string()])
        .unwrap()
        .self_signed(&kp)
        .unwrap();
    std::fs::write(dir.join("identity_chain.pem"), cert.pem()).unwrap();
    std::fs::write(dir.join("identity_key.pem"), kp.serialize_pem()).unwrap();

    let config_path = dir.join("proxy.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
base_url = "https://verifier.example"
state_encryption_key = "a-32-byte-or-longer-test-secret!!"

[[frontend]]
type = "ui"
name = "ui"

[[backend]]
type = "openid4vp"
name = "vp"
  [backend.config]
  request_signing_key_path = "{key}"
  request_certificate_chain_path = "{chain}"
  pdp_endpoint = "http://127.0.0.1:1/evaluation"
  role = "pid-provider"
  dcql = {{ credentials = [{{ id = "pid", format = "dc+sd-jwt",
    claims = [{{ path = ["given_name"] }}] }}] }}
  attribute_map = {{}}
  subject_pointer = "/given_name"

  [backend.config.storage]
  backend = "memory"

  [backend.config.wmp]
  join_pdp_url = "http://127.0.0.1:1/access/v1/evaluation"
  identity = "x509:san:dns:verifier.example"
  identity_chain_path = "{chain}"
  identity_key_path = "{key2}"

  [[backend.config.wmp.groups]]
  id = "{group}"
  via = "x509:san:dns:orchestrator.example"
"#,
            key = dir.join("identity_key.pem").display(),
            key2 = dir.join("identity_key.pem").display(),
            chain = dir.join("identity_chain.pem").display(),
            group = group_id,
        ),
    )
    .unwrap();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut child = Command::new(env!("CARGO_BIN_EXE_siros-verifier-service"))
        .arg(&config_path)
        .env("TUNNELBANA_BIND", address.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let healthy = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            if let Ok(Some(status)) = child.try_wait() {
                panic!("the service exited before becoming healthy: {status}");
            }
            if let Ok(response) = client.get(format!("http://{address}/health")).send().await {
                if response.status().is_success() {
                    return;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        }
    })
    .await;
    assert!(
        healthy.is_ok(),
        "the service booted healthy with the [wmp] block"
    );

    // 3. The orchestrator fetches the member's KeyPackage over HTTP
    //    (the private key stays in the service's keystore).
    let package_response = client
        .get(format!("http://{address}/wmp/key-package"))
        .send()
        .await
        .expect("the package endpoint answers");
    assert!(package_response.status().is_success());
    let package_body: serde_json::Value = package_response.json().await.unwrap();
    let key_package = package_body["key_package"].as_str().unwrap().to_string();

    // 4. The add produces the Welcome.
    let (_commit, welcome) = orchestrator.add_member(&group_id, &key_package).unwrap();

    // 5. The delivery: the unreachable PDP denies — 400, the public
    //    reason, never the rule text.
    let response = client
        .post(format!("http://{address}/wmp/joins"))
        .json(&serde_json::json!({
            "group_id": group_id,
            "welcome": welcome,
        }))
        .send()
        .await
        .expect("the delivery posts");
    assert_eq!(
        response.status().as_u16(),
        400,
        "the fail-closed denial answers 400"
    );
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "join_refused");
    assert!(
        body["reason"].as_str().unwrap_or("").contains("denied"),
        "the refusal's reason is public: {body}"
    );

    let _ = child.kill().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A tiny controllable AuthZEN PDP: a hand-rolled HTTP responder over
/// a listener, flipping its decision per test demand. The full local
/// loop the fail-closed tests can't prove: the ALLOW side.
/// The fields are moved into the spawned thread's closure — the struct
/// itself is only a scope for the two.
struct ControllablePdp {
    #[allow(dead_code)]
    listener: std::net::TcpListener,
    #[allow(dead_code)]
    allow: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl ControllablePdp {
    fn spawn() -> (
        std::net::SocketAddr,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let allow = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = allow.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let allow = flag.load(std::sync::atomic::Ordering::SeqCst);
                let Ok(_) = stream.set_read_timeout(Some(std::time::Duration::from_secs(2))) else {
                    continue;
                };
                // Drain the request (headers + body — small, one read is
                // enough for the tests' payloads).
                let mut buf = [0u8; 16384];
                use std::io::Read;
                let _ = (&stream).read(&mut buf);
                let body = if allow {
                    r#"{"decision": true}"#
                } else {
                    r#"{"decision": false}"#
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                use std::io::Write;
                let _ = (&stream).write_all(response.as_bytes());
            }
        });
        (addr, allow)
    }
}

/// The ALLOWING round trip — the denial first (nothing joined, the
/// Welcome preserved), then the allow (the same Welcome joins and
/// registers): the gate's decision is the only variable.
#[tokio::test]
async fn the_pdp_denial_preserves_and_the_allow_joins_the_same_welcome() {
    use wmp_core::mls::MlsProvider as _;
    let (pdp_addr, allow) = ControllablePdp::spawn();

    // The orchestrator mints the group; the config declares the
    // candidate; the PDP is the controllable one.
    let orchestrator =
        wmp_mls::OpenMlsProvider::for_identity("x509:san:dns:orchestrator.example").unwrap();
    let (group_id, _) = orchestrator.create_group(1, &[]).unwrap();

    let dir = fixture_dir();
    let (mut config, _) = config_with(vec![]);
    config.join_pdp_url = format!("http://{pdp_addr}/access/v1/evaluation");
    config.groups = vec![siros_verifier_service::wmp::WmpGroupDeclaration {
        id: group_id.clone(),
        via: "x509:san:dns:orchestrator.example".to_string(),
    }];
    let surface = WmpSurface::new(config, &dir).expect("the surface builds");

    // The member's package + the Welcome (the real MLS exchange).
    let key_package = surface.fresh_key_package(1).unwrap();
    let (_commit, welcome) = orchestrator.add_member(&group_id, &key_package).unwrap();
    let declaration = surface.resolve_candidate(&group_id).unwrap();

    // DENY first: the gate refuses; the registry holds nothing — and
    // the Welcome is NOT consumed (the same bytes join below).
    allow.store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(
        surface
            .join_by_welcome(&declaration, &welcome)
            .await
            .is_err(),
        "the denied join refuses"
    );
    assert!(
        surface.joined_groups().await.is_empty(),
        "the denial joins nothing"
    );

    // ALLOW: the SAME Welcome joins and registers.
    allow.store(true, std::sync::atomic::Ordering::SeqCst);
    let joined = surface
        .join_by_welcome(&declaration, &welcome)
        .await
        .expect("the allowed join processes");
    assert_eq!(joined.id, group_id);
    let registry = surface.joined_groups().await;
    assert_eq!(registry.len(), 1, "the registry holds the join");
    assert_eq!(registry[0].id, group_id);
}
