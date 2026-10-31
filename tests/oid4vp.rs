use jose_rs::algorithm::{JweAlgorithm, JweEncryption};
use jose_rs::jwe::compact as jwe_compact;
use jose_rs::jwk::Jwk;
use jose_rs::jws;
use jose_rs::JoseHeader;
use serde_json::{json, Value};
use siros_verifier_core::oid4vp::*;
use siros_verifier_core::sdjwt::{self, X5cLeaf};
use siros_verifier_core::testutil::*;
use siros_verifier_core::trust::TrustQuery;
use siros_verifier_core::Error;

const NOW: i64 = 1_800_000_000;

struct World {
    verifier_cert: Vec<u8>,
    verifier_key: Jwk,
    holder: Jwk,
    issued: Issued,
    issuer_cert: Vec<u8>,
}

fn world() -> World {
    let (verifier_cert, verifier_key) = self_signed_ec("verifier.example", "ES256");
    let (issuer_cert, issuer_key) = self_signed_ec("issuer.example", "ES256");
    let holder = ec_jwk("ES256", "holder");
    let mut spec = IssueSpec::new(json!({
        "iss": "https://issuer.example", "vct": "urn:eudi:pid:1",
        "iat": NOW - 10, "exp": NOW + 100_000,
        "given_name": "Ada", "family_name": "Lovelace", "birthdate": "1815-12-10",
        "nationalities": ["SE", "DK"],
    }));
    spec.holder_pub = Some(public_of(&holder));
    spec.x5c_der = vec![issuer_cert.clone()];
    spec.conceal = vec![
        vec![Seg::Key("given_name")],
        vec![Seg::Key("family_name")],
        vec![Seg::Key("birthdate")],
        vec![Seg::Key("nationalities")],
    ];
    spec.decoys = 2;
    let issued = issue(&issuer_key, &spec).unwrap();
    World {
        verifier_cert,
        verifier_key,
        holder,
        issued,
        issuer_cert,
    }
}

fn dcql(claims: &[&str]) -> Value {
    json!({ "credentials": [{
        "id": "pid", "format": "dc+sd-jwt",
        "meta": { "vct_values": ["urn:eudi:pid:1"] },
        "claims": claims.iter().map(|c| json!({ "path": [c] })).collect::<Vec<_>>(),
    }]})
}

fn start(w: &World, q: Value) -> (String, Session) {
    let signer = software_signer(&w.verifier_key).unwrap();
    let cfg = RequestConfig {
        response_uri: "https://verify.example/resp".into(),
        dcql_query: q,
        ttl_secs: 300,
    };
    create_request(
        &cfg,
        &signer,
        "ES256",
        std::slice::from_ref(&w.verifier_cert),
        NOW,
    )
    .unwrap()
}

fn disclosure_idx(w: &World, name: &str) -> usize {
    w.issued
        .disclosures
        .iter()
        .position(|d| {
            String::from_utf8(jose_rs::base64url::decode(d).unwrap())
                .unwrap()
                .contains(name)
        })
        .unwrap()
}

#[test]
fn happy_path_end_to_end() {
    let w = world();
    let (jar, session) = start(&w, dcql(&["given_name", "family_name"]));

    // the request object is verifiable from its own x5c and carries no private key material
    let header = jws::decode_header(&jar).unwrap();
    let chain = sdjwt::x5c_chain(&header).unwrap();
    let leaf = sdjwt::jwk_from_cert_der(&chain[0]).unwrap();
    let payload: Value =
        serde_json::from_slice(&jws::compact::verify_with_jwk(&leaf, &jar).unwrap()).unwrap();
    assert!(payload["client_metadata"]["jwks"]["keys"][0]
        .get("d")
        .is_none());
    assert_eq!(payload["aud"], "https://self-issued.me/v2");
    assert!(session.client_id.starts_with("x509_hash:"));

    let sel = [
        disclosure_idx(&w, "given_name"),
        disclosure_idx(&w, "family_name"),
    ];
    let jwe = wallet_respond(
        &jar,
        &w.holder,
        &[WalletCredential {
            id: "pid",
            issued: &w.issued,
            disclose: &sel,
        }],
        NOW,
    )
    .unwrap();
    let res = process_response(&session, &jwe, NOW + 5, &X5cLeaf).unwrap();

    assert_eq!(res.len(), 1);
    let v = &res[0].verified;
    assert_eq!(v.claims["given_name"], "Ada");
    assert!(
        v.claims.get("birthdate").is_none(),
        "undisclosed claim stays hidden"
    );

    // what the trust layer would send to go-trust
    let q = TrustQuery::for_issuer(&v.issuer, "https://example.org/roles/pid-issuer", &v.vct)
        .to_authzen();
    assert_eq!(
        q["subject"],
        json!({ "type": "key", "id": "https://issuer.example" })
    );
    assert_eq!(q["resource"]["type"], "x5c");
    assert_eq!(q["resource"]["id"], "https://issuer.example");
    assert_eq!(q["resource"]["key"].as_array().unwrap().len(), 1);
    assert_eq!(
        q["action"]["parameters"]["credential_types"],
        json!(["urn:eudi:pid:1"])
    );
    let _ = &w.issuer_cert;
}

#[test]
fn dc_api_uses_the_browser_origin_for_holder_binding() {
    let w = world();
    let signer = software_signer(&w.verifier_key).unwrap();
    let cfg = RequestConfig {
        response_uri: "https://verify.example/resp".into(),
        dcql_query: dcql(&["given_name"]),
        ttl_secs: 300,
    };
    let origin = "https://verify.example";
    let (jar, session) = create_dc_api_request(
        &cfg,
        &signer,
        "ES256",
        std::slice::from_ref(&w.verifier_cert),
        NOW,
        origin,
    )
    .unwrap();
    let payload: Value = serde_json::from_slice(
        &jws::compact::verify_with_jwk(&public_of(&w.verifier_key), &jar).unwrap(),
    )
    .unwrap();
    assert_eq!(payload["response_mode"], "dc_api.jwt");
    assert_eq!(session.dc_api_origin.as_deref(), Some(origin));

    let selected = [disclosure_idx(&w, "given_name")];
    let credentials = [WalletCredential {
        id: "pid",
        issued: &w.issued,
        disclose: &selected,
    }];
    let jwe = wallet_respond_dc_api(&jar, &w.holder, &credentials, NOW, origin).unwrap();
    let verified = process_response(&session, &jwe, NOW + 1, &X5cLeaf).unwrap();
    assert_eq!(verified[0].verified.claims["given_name"], "Ada");

    let wrong_origin = wallet_respond_dc_api(
        &jar,
        &w.holder,
        &credentials,
        NOW,
        "https://attacker.example",
    )
    .unwrap();
    assert!(process_response(&session, &wrong_origin, NOW + 1, &X5cLeaf).is_err());
}

#[test]
fn dc_api_origin_must_be_a_bare_http_origin() {
    let w = world();
    let signer = software_signer(&w.verifier_key).unwrap();
    let cfg = RequestConfig {
        response_uri: "https://verify.example/resp".into(),
        dcql_query: dcql(&[]),
        ttl_secs: 300,
    };
    for origin in [
        "https://verify.example/path",
        "ftp://verify.example",
        "https://user@host",
    ] {
        assert!(create_dc_api_request(
            &cfg,
            &signer,
            "ES256",
            std::slice::from_ref(&w.verifier_cert),
            NOW,
            origin,
        )
        .is_err());
    }
}

fn answer(w: &World, jar: &str, claims: &[usize]) -> String {
    wallet_respond(
        jar,
        &w.holder,
        &[WalletCredential {
            id: "pid",
            issued: &w.issued,
            disclose: claims,
        }],
        NOW,
    )
    .unwrap()
}

#[test]
fn expired_session_is_refused() {
    let w = world();
    let (jar, s) = start(&w, dcql(&["given_name"]));
    let jwe = answer(&w, &jar, &[disclosure_idx(&w, "given_name")]);
    assert!(matches!(
        process_response(&s, &jwe, NOW + 301, &X5cLeaf),
        Err(Error::Policy(_))
    ));
}

#[test]
fn response_for_another_session_cannot_be_decrypted() {
    let w = world();
    let (jar_a, _a) = start(&w, dcql(&["given_name"]));
    let (_jar_b, b) = start(&w, dcql(&["given_name"]));
    let jwe = answer(&w, &jar_a, &[disclosure_idx(&w, "given_name")]);
    assert!(process_response(&b, &jwe, NOW, &X5cLeaf).is_err());
}

#[test]
fn requested_claim_must_be_disclosed() {
    let w = world();
    let (jar, s) = start(&w, dcql(&["given_name", "birthdate"]));
    let jwe = answer(&w, &jar, &[disclosure_idx(&w, "given_name")]);
    assert!(matches!(
        process_response(&s, &jwe, NOW, &X5cLeaf),
        Err(Error::Policy(_))
    ));
}

#[test]
fn vct_must_match_dcql() {
    let w = world();
    let mut q = dcql(&["given_name"]);
    q["credentials"][0]["meta"]["vct_values"] = json!(["urn:something:else"]);
    let (jar, s) = start(&w, q);
    let jwe = answer(&w, &jar, &[disclosure_idx(&w, "given_name")]);
    assert!(matches!(
        process_response(&s, &jwe, NOW, &X5cLeaf),
        Err(Error::Policy(_))
    ));
}

#[test]
fn trailing_array_selector_matches_disclosed_elements() {
    let w = world();
    let mut q = dcql(&["nationalities"]);
    q["credentials"][0]["claims"][0]["path"] = json!(["nationalities", null]);
    let (jar, s) = start(&w, q.clone());
    let jwe = answer(&w, &jar, &[disclosure_idx(&w, "nationalities")]);
    let verified = process_response(&s, &jwe, NOW, &X5cLeaf).unwrap();
    assert_eq!(
        verified[0].verified.claims["nationalities"],
        json!(["SE", "DK"])
    );

    q["credentials"][0]["claims"][0]["values"] = json!(["SE"]);
    let (jar, s) = start(&w, q.clone());
    let jwe = answer(&w, &jar, &[disclosure_idx(&w, "nationalities")]);
    assert!(process_response(&s, &jwe, NOW, &X5cLeaf).is_ok());
    q["credentials"][0]["claims"][0]["values"] = json!(["FR"]);
    let (jar, s) = start(&w, q);
    let jwe = answer(&w, &jar, &[disclosure_idx(&w, "nationalities")]);
    assert!(process_response(&s, &jwe, NOW, &X5cLeaf).is_err());
}

#[test]
fn claim_values_are_enforced() {
    let w = world();
    let mut q = dcql(&["given_name"]);
    q["credentials"][0]["claims"][0]["values"] = json!(["Grace"]);
    let (jar, s) = start(&w, q);
    let jwe = answer(&w, &jar, &[disclosure_idx(&w, "given_name")]);
    assert!(matches!(
        process_response(&s, &jwe, NOW, &X5cLeaf),
        Err(Error::Policy(_))
    ));
}

/// Encrypt an arbitrary body to the session's response key, as a (malicious) wallet could.
fn raw_response_enc(
    s: &Session,
    body: Value,
    kid_override: Option<&str>,
    enc: JweEncryption,
) -> String {
    let pubkey = s.enc_key.to_public_jwk();
    let mut header = JoseHeader::for_jwe(JweAlgorithm::EcdhEs, enc);
    header.kid = Some(
        kid_override
            .unwrap_or(s.enc_key.kid.as_deref().unwrap())
            .to_owned(),
    );
    jwe_compact::encrypt_with_jwk_header(&pubkey, header, body.to_string().as_bytes(), enc).unwrap()
}

fn raw_response(s: &Session, body: Value, kid_override: Option<&str>) -> String {
    raw_response_enc(s, body, kid_override, JweEncryption::A128GCM)
}

fn real_presentation(w: &World, s: &Session, claims: &[usize]) -> String {
    present(
        &w.issued,
        claims,
        Some(KbSpec {
            holder: &w.holder,
            aud: &s.client_id,
            nonce: &s.nonce,
            iat: NOW,
        }),
        sdjwt::HashAlg::Sha256,
    )
    .unwrap()
}

#[test]
fn response_shape_attacks() {
    let w = world();
    let (_jar, s) = start(&w, dcql(&["given_name"]));
    let sel = [disclosure_idx(&w, "given_name")];
    let pres = real_presentation(&w, &s, &sel);

    // baseline for this hand-built path
    let ok = raw_response(
        &s,
        json!({ "vp_token": { "pid": [pres.clone()] }, "state": s.state }),
        None,
    );
    process_response(&s, &ok, NOW, &X5cLeaf).unwrap();

    let cases: Vec<(&str, Value, Option<&str>, &str)> = vec![
        (
            "wrong state",
            json!({ "vp_token": { "pid": [pres.clone()] }, "state": "nope" }),
            None,
            "integrity",
        ),
        (
            "missing state",
            json!({ "vp_token": { "pid": [pres.clone()] } }),
            None,
            "integrity",
        ),
        (
            "unrequested id",
            json!({ "vp_token": { "pid": [pres.clone()], "extra": [pres.clone()] }, "state": s.state }),
            None,
            "policy",
        ),
        (
            "missing required id",
            json!({ "vp_token": {}, "state": s.state }),
            None,
            "policy",
        ),
        (
            "two presentations without multiple",
            json!({ "vp_token": { "pid": [pres.clone(), pres.clone()] }, "state": s.state }),
            None,
            "policy",
        ),
        (
            "empty list",
            json!({ "vp_token": { "pid": [] }, "state": s.state }),
            None,
            "policy",
        ),
        (
            "string instead of list",
            json!({ "vp_token": { "pid": pres.clone() }, "state": s.state }),
            None,
            "policy",
        ),
        (
            "vp_token not an object",
            json!({ "vp_token": pres.clone(), "state": s.state }),
            None,
            "malformed",
        ),
        (
            "wallet error",
            json!({ "error": "access_denied", "state": s.state }),
            None,
            "policy",
        ),
        (
            "wrong kid",
            json!({ "vp_token": { "pid": [pres.clone()] }, "state": s.state }),
            Some("other-kid"),
            "integrity",
        ),
    ];
    for (name, body, kid, code) in cases {
        let jwe = raw_response(&s, body, kid);
        let err = process_response(&s, &jwe, NOW, &X5cLeaf).expect_err(name);
        assert_eq!(err.code(), code, "case: {name}: {err}");
    }
}

#[test]
fn presentation_for_other_verifier_or_nonce_is_refused() {
    let w = world();
    let (_jar, s) = start(&w, dcql(&["given_name"]));
    let sel = [disclosure_idx(&w, "given_name")];
    for (aud, nonce) in [
        ("x509_hash:other", s.nonce.as_str()),
        (s.client_id.as_str(), "other-nonce"),
    ] {
        let pres = present(
            &w.issued,
            &sel,
            Some(KbSpec {
                holder: &w.holder,
                aud,
                nonce,
                iat: NOW,
            }),
            sdjwt::HashAlg::Sha256,
        )
        .unwrap();
        let jwe = raw_response(
            &s,
            json!({ "vp_token": { "pid": [pres] }, "state": s.state }),
            None,
        );
        assert!(
            matches!(
                process_response(&s, &jwe, NOW, &X5cLeaf),
                Err(Error::Policy(_))
            ),
            "aud {aud} nonce {nonce}"
        );
    }
}

#[test]
fn session_roundtrips_through_json_for_sealing() {
    let w = world();
    let (jar, s) = start(&w, dcql(&["given_name"]));
    let stored = serde_json::to_vec(&s).unwrap();
    let restored: Session = serde_json::from_slice(&stored).unwrap();
    let jwe = answer(&w, &jar, &[disclosure_idx(&w, "given_name")]);
    process_response(&restored, &jwe, NOW, &X5cLeaf).unwrap();
}

#[test]
fn unsupported_query_features_fail_closed() {
    let w = world();
    let sel = [disclosure_idx(&w, "given_name")];

    // a format other than dc+sd-jwt
    let mut q = dcql(&["given_name"]);
    q["credentials"][0]["format"] = json!("mso_mdoc");
    let (jar, s) = start(&w, q);
    let jwe = answer(&w, &jar, &sel);
    let err = process_response(&s, &jwe, NOW, &X5cLeaf).unwrap_err();
    assert_eq!(err.code(), "policy");
    assert!(err.to_string().contains("dc+sd-jwt"), "{err}");

    // credential_sets are not implemented, so a query using them is refused rather than half-evaluated
    let mut q = dcql(&["given_name"]);
    q["credential_sets"] = json!([{ "options": [["pid"]] }]);
    let (jar, s) = start(&w, q);
    let jwe = answer(&w, &jar, &sel);
    let err = process_response(&s, &jwe, NOW, &X5cLeaf).unwrap_err();
    assert_eq!(err.code(), "policy");
    assert!(err.to_string().contains("credential_sets"), "{err}");
}

#[test]
fn request_time_dcql_validation_is_closed_and_deterministic() {
    let valid = dcql(&["given_name"]);
    assert!(validate_dcql_query(&valid).is_ok());
    let mut array_path = valid.clone();
    array_path["credentials"][0]["claims"][0]["path"] = json!(["nationalities", null]);
    assert!(validate_dcql_query(&array_path).is_ok());

    let mut credential_sets = valid.clone();
    credential_sets["credential_sets"] = json!([{ "options": [["pid"]] }]);
    let mut wrong_format = valid.clone();
    wrong_format["credentials"][0]["format"] = json!("mso_mdoc");
    let mut duplicate_id = valid.clone();
    duplicate_id["credentials"] = json!([
        valid["credentials"][0].clone(),
        valid["credentials"][0].clone()
    ]);
    let mut unknown_member = valid.clone();
    unknown_member["credentials"][0]["claims"][0]["claim_sets"] = json!([]);
    let mut non_array_claims = valid.clone();
    non_array_claims["credentials"][0]["claims"] = json!({});
    let mut non_string_path = valid.clone();
    non_string_path["credentials"][0]["claims"][0]["path"] =
        json!(["nationalities", null, "child"]);
    let mut empty_vct = valid.clone();
    empty_vct["credentials"][0]["meta"]["vct_values"] = json!([]);
    for invalid in [
        credential_sets,
        wrong_format,
        duplicate_id,
        unknown_member,
        non_array_claims,
        non_string_path,
        empty_vct,
    ] {
        assert!(validate_dcql_query(&invalid).is_err(), "{invalid}");
    }
}

fn mutate_jwe_part(token: &str, index: usize, f: impl Fn(String) -> String) -> String {
    let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    parts[index] = f(parts[index].clone());
    parts.join(".")
}

fn mutate_jwe_header(token: &str, f: impl Fn(&mut Value)) -> String {
    mutate_jwe_part(token, 0, |h| {
        let mut value: Value =
            serde_json::from_slice(&jose_rs::base64url::decode(&h).unwrap()).unwrap();
        f(&mut value);
        jose_rs::base64url::encode(&serde_json::to_vec(&value).unwrap())
    })
}

#[test]
fn response_jwe_supports_both_advertised_content_algorithms() {
    let w = world();
    let (_jar, s) = start(&w, dcql(&["given_name"]));
    let pres = real_presentation(&w, &s, &[disclosure_idx(&w, "given_name")]);
    for enc in [JweEncryption::A128GCM, JweEncryption::A256GCM] {
        let jwe = raw_response_enc(
            &s,
            json!({ "vp_token": { "pid": [pres.clone()] }, "state": s.state }),
            None,
            enc,
        );
        process_response(&s, &jwe, NOW, &X5cLeaf).unwrap();
    }
}

#[test]
fn response_jwe_policy_and_structure_checks_survive_the_library_migration() {
    let w = world();
    let (_jar, s) = start(&w, dcql(&["given_name"]));
    let pres = real_presentation(&w, &s, &[disclosure_idx(&w, "given_name")]);
    let token = raw_response(
        &s,
        json!({ "vp_token": { "pid": [pres] }, "state": s.state }),
        None,
    );

    for (name, value) in [
        ("alg", json!("dir")),
        ("enc", json!("A128CBC-HS256")),
        ("zip", json!("DEF")),
        ("crit", json!(["private"])),
    ] {
        let changed = mutate_jwe_header(&token, |header| header[name] = value.clone());
        assert!(
            matches!(
                process_response(&s, &changed, NOW, &X5cLeaf),
                Err(Error::Policy(_))
            ),
            "header {name}"
        );
    }
    let private_epk = mutate_jwe_header(&token, |header| {
        header["epk"]["d"] = json!(jose_rs::base64url::encode(&[3u8; 32]));
    });
    assert!(matches!(
        process_response(&s, &private_epk, NOW, &X5cLeaf),
        Err(Error::Policy(_))
    ));

    let non_empty_key = mutate_jwe_part(&token, 1, |_| "AAAA".into());
    assert!(matches!(
        process_response(&s, &non_empty_key, NOW, &X5cLeaf),
        Err(Error::Malformed(_))
    ));
    assert!(matches!(
        process_response(&s, "a..c", NOW, &X5cLeaf),
        Err(Error::Malformed(_))
    ));

    let oversized = mutate_jwe_part(&token, 3, |_| {
        jose_rs::base64url::encode(&vec![0u8; 512 * 1024 + 1])
    });
    assert!(matches!(
        process_response(&s, &oversized, NOW, &X5cLeaf),
        Err(Error::Policy(_))
    ));
    assert!(matches!(
        process_response(&s, &"x".repeat(1024 * 1024 + 1), NOW, &X5cLeaf),
        Err(Error::Policy(_))
    ));
}

#[test]
fn response_jwe_tampering_is_an_integrity_failure() {
    let w = world();
    let (_jar, s) = start(&w, dcql(&["given_name"]));
    let pres = real_presentation(&w, &s, &[disclosure_idx(&w, "given_name")]);
    let token = raw_response(
        &s,
        json!({ "vp_token": { "pid": [pres] }, "state": s.state }),
        None,
    );
    for index in [0, 3, 4] {
        let changed = mutate_jwe_part(&token, index, |part| {
            if index == 0 {
                let mut value: Value =
                    serde_json::from_slice(&jose_rs::base64url::decode(&part).unwrap()).unwrap();
                value["kid"] = json!("changed");
                jose_rs::base64url::encode(&serde_json::to_vec(&value).unwrap())
            } else {
                let mut bytes = jose_rs::base64url::decode(&part).unwrap();
                bytes[0] ^= 1;
                jose_rs::base64url::encode(&bytes)
            }
        });
        assert!(
            matches!(
                process_response(&s, &changed, NOW, &X5cLeaf),
                Err(Error::Integrity(_))
            ),
            "changed part {index}"
        );
    }
}

#[test]
fn a_repeated_jwe_header_member_is_malformed() {
    let w = world();
    let (_jar, s) = start(&w, dcql(&["given_name"]));
    let header =
        jose_rs::base64url::encode(br#"{"alg":"ECDH-ES","enc":"A128GCM","enc":"A256GCM"}"#);
    let token = format!("{header}..AAAAAAAAAAAAAAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA");
    match process_response(&s, &token, NOW, &X5cLeaf) {
        Err(Error::Malformed(m)) => assert!(m.contains("json_duplicate_member"), "{m}"),
        other => panic!("unexpected result: {:?}", other.err()),
    }
}
