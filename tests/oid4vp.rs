use jose_rs::algorithm::{JweAlgorithm, JweEncryption};
use jose_rs::jwk::Jwk;
use jose_rs::jws;
use jose_rs::JoseHeader;
use p256::elliptic_curve::Generate;
use serde_json::{json, Value};
use siros_verifier_core::oid4vp::*;
use siros_verifier_core::sdjwt::{self, X5cLeaf};
use siros_verifier_core::testutil::*;
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
        vp_formats_supported: None,
        client_id: None,

        verifier_info: None,
        wrprc: None,
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
    assert_eq!(payload["response_uri"], "https://verify.example/resp");
    assert!(payload.get("expected_origins").is_none());
    for key in ["nonce", "state"] {
        assert_eq!(
            jose_rs::base64url::decode(payload[key].as_str().unwrap())
                .unwrap()
                .len(),
            32,
            "{key} must carry 256 bits of fresh entropy"
        );
    }
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
    let claims = v.claims().unwrap();
    assert_eq!(claims["given_name"], "Ada");
    assert!(
        claims.get("birthdate").is_none(),
        "undisclosed claim stays hidden"
    );

    // what the trust layer would send to go-trust
    let q = v
        .trust_query("https://example.org/roles/pid-issuer", "mdoc-issuer")
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
fn post_request_object_echoes_wallet_nonce_and_preserves_flow() {
    let w = world();
    let (jar, _session) = start(&w, dcql(&["given_name"]));
    let original: Value = serde_json::from_slice(
        &jws::compact::verify_with_jwk(&public_of(&w.verifier_key), &jar).unwrap(),
    )
    .unwrap();
    let signer = software_signer(&w.verifier_key).unwrap();
    let reissued = reissue_request_with_wallet_nonce(
        &jar,
        "wallet-generated-nonce",
        &signer,
        std::slice::from_ref(&w.verifier_cert),
    )
    .unwrap();
    let payload: Value = serde_json::from_slice(
        &jws::compact::verify_with_jwk(&public_of(&w.verifier_key), &reissued).unwrap(),
    )
    .unwrap();
    assert_eq!(payload["wallet_nonce"], "wallet-generated-nonce");
    let mut unchanged = payload.clone();
    unchanged
        .as_object_mut()
        .unwrap()
        .remove("wallet_nonce")
        .unwrap();
    assert_eq!(unchanged, original);
    let too_long = "x".repeat(257);
    for malformed in ["", "bad nonce", too_long.as_str()] {
        assert!(reissue_request_with_wallet_nonce(
            &jar,
            malformed,
            &signer,
            std::slice::from_ref(&w.verifier_cert),
        )
        .is_err());
    }
}

#[test]
fn dc_api_uses_the_browser_origin_for_holder_binding() {
    let w = world();
    let signer = software_signer(&w.verifier_key).unwrap();
    let cfg = RequestConfig {
        response_uri: "https://verify.example/resp".into(),
        dcql_query: dcql(&["given_name"]),
        ttl_secs: 300,
        vp_formats_supported: None,
        client_id: None,

        verifier_info: None,
        wrprc: None,
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
    assert_eq!(payload["expected_origins"], json!([origin]));
    assert!(payload.get("response_uri").is_none());
    assert_eq!(session.dc_api_origin.as_deref(), Some(origin));

    let selected = [disclosure_idx(&w, "given_name")];
    let credentials = [WalletCredential {
        id: "pid",
        issued: &w.issued,
        disclose: &selected,
    }];
    let jwe = wallet_respond_dc_api(&jar, &w.holder, &credentials, NOW, origin).unwrap();
    let verified = process_response(&session, &jwe, NOW + 1, &X5cLeaf).unwrap();
    assert_eq!(verified[0].verified.claims().unwrap()["given_name"], "Ada");

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
        vp_formats_supported: None,
        client_id: None,

        verifier_info: None,
        wrprc: None,
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
        verified[0].verified.claims().unwrap()["nationalities"],
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
    encrypt_response(&pubkey, header, body.to_string().as_bytes(), enc).unwrap()
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
    q["credentials"][0]["format"] = json!("jwt_vc_json");
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
    let mdoc = json!({"credentials": [{
        "id": "mdl", "format": "mso_mdoc",
        "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
        "claims": [{"path": ["org.iso.18013.5.1", "family_name"]}],
    }]});
    assert!(validate_dcql_query(&mdoc).is_ok());
    let mut short_mdoc_path = mdoc.clone();
    short_mdoc_path["credentials"][0]["claims"][0]["path"] = json!(["family_name"]);
    assert!(validate_dcql_query(&short_mdoc_path).is_err());
    let mut null_mdoc_path = mdoc;
    null_mdoc_path["credentials"][0]["claims"][0]["path"] = json!(["org.iso.18013.5.1", null]);
    assert!(validate_dcql_query(&null_mdoc_path).is_err());

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

#[test]
fn a_credential_query_without_claims_requests_nothing_selectively_disclosable() {
    // OpenID4VP 1.0 section 6.4.1: an absent `claims` member means the
    // Verifier is requesting no claims that are selectively disclosable —
    // a compliant wallet returns only the mandatory claims and there is
    // nothing to map (vc-verifier issue 920's failure, one deployer-visible
    // symptom of the silent shape). The validator rejects it at request
    // time instead of arming a request whose response can only be empty.
    let mut no_claims = dcql(&["given_name"]);
    no_claims["credentials"][0]
        .as_object_mut()
        .unwrap()
        .remove("claims");
    let error = validate_dcql_query(&no_claims).unwrap_err();
    assert_eq!(error.code(), "policy");
    assert!(
        error
            .to_string()
            .contains("no selectively disclosable claims"),
        "{error}"
    );

    // The same rule for mso_mdoc: absent claims request nothing.
    let mdoc_no_claims = json!({"credentials": [{
        "id": "mdl", "format": "mso_mdoc",
        "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
    }]});
    assert!(validate_dcql_query(&mdoc_no_claims).is_err());

    // An EXPLICIT empty claims list is the deliberate ask — only the
    // mandatory claims, consciously — and stays valid for both formats.
    let mut deliberate_empty = no_claims;
    deliberate_empty["credentials"][0]["claims"] = json!([]);
    assert!(validate_dcql_query(&deliberate_empty).is_ok());
    let mdoc_deliberate_empty = json!({"credentials": [{
        "id": "mdl", "format": "mso_mdoc",
        "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
        "claims": [],
    }]});
    assert!(validate_dcql_query(&mdoc_deliberate_empty).is_ok());
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
    let unsupported_enc =
        mutate_jwe_header(&token, |header| header["enc"] = json!("A128CBC-HS256"));
    match process_response(&s, &unsupported_enc, NOW, &X5cLeaf) {
        Err(Error::Policy(message)) => {
            assert_eq!(message, "unsupported response enc in protected header")
        }
        other => panic!("unexpected unsupported-enc result: {:?}", other.err()),
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
        jose_rs::base64url::encode(&vec![0u8; 1024 * 1024 + 1])
    });
    let oversized_result = process_response(&s, &oversized, NOW, &X5cLeaf);
    assert!(
        matches!(oversized_result, Err(Error::Policy(_))),
        "{oversized_result:?}"
    );
    assert!(matches!(
        process_response(&s, &"x".repeat(2 * 1024 * 1024 + 1), NOW, &X5cLeaf),
        Err(Error::Policy(_))
    ));
}

#[test]
fn a_genuine_sized_response_is_not_rejected_by_the_jose_compact_default() {
    let w = world();
    let (_jar, s) = start(&w, dcql(&["given_name"]));
    let pres = real_presentation(&w, &s, &[disclosure_idx(&w, "given_name")]);
    let token = raw_response(
        &s,
        json!({
            "vp_token": { "pid": [pres] },
            "state": s.state,
            "padding": "x".repeat(800 * 1024),
        }),
        None,
    );
    assert!(token.len() > 1024 * 1024);
    assert!(token.len() <= 2 * 1024 * 1024);
    process_response(&s, &token, NOW, &X5cLeaf).unwrap();
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

fn mdoc_query() -> Value {
    json!({"credentials": [{
        "id": "mdl", "format": "mso_mdoc",
        "meta": {"doctype_value": "eu.europa.ec.eudi.pid.1"},
        "claims": [{"path": ["eu.europa.ec.eudi.pid.1", "family_name"]}],
    }]})
}

fn start_mdoc(w: &World, dc_api: bool) -> (String, Session) {
    let signer = software_signer(&w.verifier_key).unwrap();
    let cfg = RequestConfig {
        response_uri: "https://verify.example/resp".into(),
        dcql_query: mdoc_query(),
        ttl_secs: 300,
        vp_formats_supported: None,
        client_id: None,

        verifier_info: None,
        wrprc: None,
    };
    if dc_api {
        create_dc_api_request(
            &cfg,
            &signer,
            "ES256",
            std::slice::from_ref(&w.verifier_cert),
            NOW,
            "https://verify.example",
        )
        .unwrap()
    } else {
        create_request(
            &cfg,
            &signer,
            "ES256",
            std::slice::from_ref(&w.verifier_cert),
            NOW,
        )
        .unwrap()
    }
}

fn mdoc_token(
    session: &Session,
    issuer: &siros_verifier_core::testutil::mdoc_sim::Party,
    device: &p256::SecretKey,
    mut spec: siros_verifier_core::testutil::mdoc_sim::Spec,
) -> String {
    spec.valid_from = "2026-01-01T00:00:00Z".into();
    spec.valid_until = "2028-01-01T00:00:00Z".into();
    let transcript = session.mdoc_session_transcript_bytes().unwrap();
    let reader = p256::SecretKey::generate();
    let response = siros_verifier_core::testutil::mdoc_sim::response(
        &spec,
        issuer,
        device,
        &transcript,
        Some(&reader.public_key()),
    );
    jose_rs::base64url::encode(&response)
}

fn encrypted_body(session: &Session, body: Value) -> String {
    raw_response_enc(session, body, None, JweEncryption::A128GCM)
}

#[test]
fn mdoc_redirect_and_dc_api_verify_with_their_own_handovers() {
    let w = world();
    let issuer = siros_verifier_core::testutil::mdoc_sim::issuer();
    let device = siros_verifier_core::testutil::mdoc_sim::device();
    for dc_api in [false, true] {
        let (_jar, session) = start_mdoc(&w, dc_api);
        let token = mdoc_token(&session, &issuer, &device, Default::default());
        let body = json!({"vp_token": {"mdl": [token]}, "state": session.state});
        let jwe = encrypted_body(&session, body);
        let verified = process_response(&session, &jwe, NOW + 1, &X5cLeaf).unwrap();
        assert_eq!(verified.len(), 1);
        let credential = &verified[0].verified;
        assert_eq!(credential.vct(), "eu.europa.ec.eudi.pid.1");
        assert_eq!(
            credential.claims().unwrap()["eu.europa.ec.eudi.pid.1"]["family_name"],
            "Svensson"
        );
        let trust = credential
            .trust_query("pid-provider", "mdoc-issuer")
            .to_authzen();
        assert_eq!(trust["action"]["name"], "mdoc-issuer");
        assert_eq!(trust["resource"]["type"], "x5c");
        assert_eq!(trust["subject"]["id"], "https://issuer.example");
    }
}

#[test]
fn mixed_sd_jwt_and_mdoc_presentations_stay_distinct() {
    let w = world();
    let signer = software_signer(&w.verifier_key).unwrap();
    let mut query = mdoc_query();
    query["credentials"]
        .as_array_mut()
        .unwrap()
        .insert(0, dcql(&["given_name"])["credentials"][0].clone());
    let cfg = RequestConfig {
        response_uri: "https://verify.example/resp".into(),
        dcql_query: query,
        ttl_secs: 300,
        vp_formats_supported: None,
        client_id: None,

        verifier_info: None,
        wrprc: None,
    };
    let (jar, session) = create_request(
        &cfg,
        &signer,
        "ES256",
        std::slice::from_ref(&w.verifier_cert),
        NOW,
    )
    .unwrap();
    let payload: Value = serde_json::from_slice(
        &jws::compact::verify_with_jwk(&public_of(&w.verifier_key), &jar).unwrap(),
    )
    .unwrap();
    assert_eq!(
        payload["client_metadata"]["vp_formats_supported"]["mso_mdoc"]["issuerauth_alg_values"],
        json!([-7])
    );
    assert_eq!(
        payload["client_metadata"]["vp_formats_supported"]["mso_mdoc"]["deviceauth_alg_values"],
        json!([-7])
    );
    let sd = present(
        &w.issued,
        &[disclosure_idx(&w, "given_name")],
        Some(KbSpec {
            holder: &w.holder,
            aud: &session.client_id,
            nonce: &session.nonce,
            iat: NOW,
        }),
        sdjwt::HashAlg::Sha256,
    )
    .unwrap();
    let issuer = siros_verifier_core::testutil::mdoc_sim::issuer();
    let device = siros_verifier_core::testutil::mdoc_sim::device();
    let mdoc = mdoc_token(&session, &issuer, &device, Default::default());
    let body = json!({"vp_token": {"pid": [sd], "mdl": [mdoc]}, "state": session.state});
    let jwe = encrypted_body(&session, body);
    let verified = process_response(&session, &jwe, NOW + 1, &X5cLeaf).unwrap();
    assert_eq!(verified.len(), 2);
    assert!(matches!(verified[0].verified, VerifiedCredential::SdJwt(_)));
    assert!(matches!(verified[1].verified, VerifiedCredential::Mdoc(_)));
}

#[test]
fn mdoc_rejects_wrong_doctype_missing_claims_and_wrong_handover() {
    let w = world();
    let issuer = siros_verifier_core::testutil::mdoc_sim::issuer();
    let device = siros_verifier_core::testutil::mdoc_sim::device();

    let (_jar, session) = start_mdoc(&w, false);
    let mut wrong_doctype = mdoc_query();
    wrong_doctype["credentials"][0]["meta"]["doctype_value"] = json!("org.example.other");
    let signer = software_signer(&w.verifier_key).unwrap();
    let cfg = RequestConfig {
        response_uri: session.response_uri.clone(),
        dcql_query: wrong_doctype,
        ttl_secs: 300,
        vp_formats_supported: None,
        client_id: None,

        verifier_info: None,
        wrprc: None,
    };
    let (_jar, wrong_session) = create_request(
        &cfg,
        &signer,
        "ES256",
        std::slice::from_ref(&w.verifier_cert),
        NOW,
    )
    .unwrap();
    let token = mdoc_token(&wrong_session, &issuer, &device, Default::default());
    let body = json!({"vp_token": {"mdl": [token]}, "state": wrong_session.state});
    let jwe = encrypted_body(&wrong_session, body);
    assert!(process_response(&wrong_session, &jwe, NOW + 1, &X5cLeaf).is_err());

    let (_jar, dc_session) = start_mdoc(&w, true);
    let (_jar, qr_session) = start_mdoc(&w, false);
    let token = mdoc_token(&dc_session, &issuer, &device, Default::default());
    let body = json!({"vp_token": {"mdl": [token]}, "state": qr_session.state});
    let jwe = encrypted_body(&qr_session, body);
    assert!(process_response(&qr_session, &jwe, NOW + 1, &X5cLeaf).is_err());
}

#[test]
fn mdoc_rejects_missing_claim_and_remote_device_mac() {
    let w = world();
    let issuer = siros_verifier_core::testutil::mdoc_sim::issuer();
    let device = siros_verifier_core::testutil::mdoc_sim::device();
    let signer = software_signer(&w.verifier_key).unwrap();
    let mut query = mdoc_query();
    query["credentials"][0]["claims"]
        .as_array_mut()
        .unwrap()
        .push(json!({"path": ["eu.europa.ec.eudi.pid.1", "not_released"]}));
    let cfg = RequestConfig {
        response_uri: "https://verify.example/resp".into(),
        dcql_query: query,
        ttl_secs: 300,
        vp_formats_supported: None,
        client_id: None,

        verifier_info: None,
        wrprc: None,
    };
    let (_jar, session) = create_request(
        &cfg,
        &signer,
        "ES256",
        std::slice::from_ref(&w.verifier_cert),
        NOW,
    )
    .unwrap();
    let token = mdoc_token(&session, &issuer, &device, Default::default());
    let body = json!({"vp_token": {"mdl": [token]}, "state": session.state});
    let jwe = encrypted_body(&session, body);
    assert!(process_response(&session, &jwe, NOW + 1, &X5cLeaf).is_err());

    let (_jar, session) = start_mdoc(&w, false);
    let spec = siros_verifier_core::testutil::mdoc_sim::Spec {
        use_mac: true,
        ..Default::default()
    };
    let token = mdoc_token(&session, &issuer, &device, spec);
    let body = json!({"vp_token": {"mdl": [token]}, "state": session.state});
    let jwe = encrypted_body(&session, body);
    assert!(process_response(&session, &jwe, NOW + 1, &X5cLeaf).is_err());
}

/// OpenID4VP 1.0 response encryption: the final spec's
/// client_metadata defines exactly `jwks`,
/// `encrypted_response_enc_values_supported`, and
/// `vp_formats_supported`, and this verifier's output policy is to
/// send exactly those three. The response JWE's alg MUST equal the
/// chosen jwks key's `alg` member (ECDH-ES) and its enc comes from
/// `encrypted_response_enc_values_supported`. The JARM
/// client-registration names `authorization_encrypted_response_alg`
/// and `authorization_encrypted_response_enc` appear nowhere in the
/// final spec text — the 2024 draft (openid/OpenID4VP#233) still
/// permitted them as client_metadata members, and the final spec
/// removed them; the OIDF suite's
/// VP1FinalCheckForUnexpectedParametersInVpClientMetadata flags
/// them there (9 of 14 modules failed while this branch carried
/// them). The exact member-set assertion pins the verifier to the
/// final-spec output.
#[test]
fn encrypted_response_metadata_matches_openid4vp_1_0() {
    let w = world();
    let signer = software_signer(&w.verifier_key).unwrap();
    let cfg = RequestConfig {
        response_uri: "https://verify.example/resp".to_owned(),
        dcql_query: json!({
            "credentials": [{
                "id": "pid", "format": "dc+sd-jwt",
                "meta": {"vct_values": ["urn:eudi:pid:arf-1.8:1"]},
                "claims": [{"path": ["given_name"]}],
            }]
        }),
        ttl_secs: 300,
        vp_formats_supported: None,
        client_id: None,

        verifier_info: None,
        wrprc: None,
    };
    let (jar, _session) =
        create_request(&cfg, &signer, "ES256", &[w.verifier_cert], NOW).expect("the request arms");
    let header = jws::decode_header(&jar).unwrap();
    let chain = sdjwt::x5c_chain(&header).unwrap();
    let leaf = sdjwt::jwk_from_cert_der(&chain[0]).unwrap();
    let payload: Value =
        serde_json::from_slice(&jws::compact::verify_with_jwk(&leaf, &jar).unwrap()).unwrap();
    assert!(
        payload
            .get("authorization_encrypted_response_alg")
            .is_none()
            && payload
                .get("authorization_encrypted_response_enc")
                .is_none(),
        "OpenID4VP 1.0 defines no top-level members of the JARM names"
    );
    let metadata = payload["client_metadata"]
        .as_object()
        .expect("client_metadata is an object");
    assert!(
        !metadata.contains_key("authorization_encrypted_response_alg")
            && !metadata.contains_key("authorization_encrypted_response_enc"),
        "the OIDF suite rejects the JARM names as client_metadata members"
    );
    let mut members: Vec<&str> = metadata.keys().map(String::as_str).collect();
    members.sort_unstable();
    assert_eq!(
        members,
        vec![
            "encrypted_response_enc_values_supported",
            "jwks",
            "vp_formats_supported"
        ],
        "the final OpenID4VP 1.0 spec defines exactly these client_metadata members"
    );
    assert!(
        metadata["encrypted_response_enc_values_supported"]
            .as_array()
            .is_some_and(|values| values.contains(&json!("A128GCM"))),
        "the wallet's enc pick comes from the advertised values"
    );
    assert_eq!(
        metadata["jwks"]["keys"][0]["alg"], "ECDH-ES",
        "the JWE alg rides the ephemeral key's own alg member"
    );
    assert_eq!(
        metadata["jwks"]["keys"][0]["use"], "enc",
        "the ephemeral key is an encryption key"
    );
}
