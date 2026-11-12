//! The WRPRC carrier (increment 1 of the intermediary feature, #39): the
//! `rc-wrp+jwt` parse (ETSI TS 119 475 §5.2) and the `verifier_info`
//! request-object members (ETSI TS 119 472-2 §6.3.2.2).

use serde_json::{json, Value};
use siros_verifier_core::oid4vp::{self, RequestConfig};
use siros_verifier_core::testutil::{self_signed_ec, sign_raw};
use siros_verifier_core::wrprc::{build_verifier_info, parse_wrprc};

fn b64u_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .expect("valid base64url")
}

const NOW: i64 = 1_793_656_800;
const SIGNING_ALG: &str = "ES256";

/// A registrar's signing chain and key — the WRPRC provider per
/// GEN-5.2.1-03.
fn registrar() -> (Vec<u8>, jose_rs::jwk::Jwk) {
    self_signed_ec("registrar.example", "ES256")
}

/// The verifier's request-signing chain and signer, as the armed request's
/// own signature (the WRPAC half comes with increment 2).
fn verifier() -> (Vec<u8>, jose_rs::jwk::Jwk) {
    self_signed_ec("verifier.example", "ES256")
}

/// The Table 7 register payload: every member a complete register carries.
fn register_claims() -> Value {
    json!({
        // GEN-5.2.4-02 / NOTE 2: the subject is the registered — always the
        // FINAL — relying party, never the presenting intermediary.
        "sub": "urn:glas:se:registrar:5561234567",
        "iat": NOW - 1_000,
        "country": "SE",
        "sub_ln": "Arbetsformedlingen",
        "registry_uri": "https://registrar.example/api/5561234567",
        "srv_description": [
            {"lang": "sv", "value": "Arbetsformedlingens tjänst"},
            {"lang": "en", "value": "The Swedish Public Employment Service"},
        ],
        // GEN-5.2.4-03: at least one clause A.2 entitlement.
        "entitlements": ["pid_provision", "qeaaprovider"],
        "privacy_policy": "https://arbetsformedlingen.example/privacy",
        "info_uri": "https://arbetsformedlingen.example/info",
        "support_uri": "https://arbetsformedlingen.example/support",
        "supervisory_authority": {
            "email": "imy@imy.se",
            "uri": "https://imy.example",
        },
        "policy_id": "https://registrar.example/policies/wrp",
        "certificate_policy": "https://registrar.example/cps",
        // NOTE 5: the IETF Token Status List URI.
        "status": "https://registrar.example/statuslists/9",
    })
}

fn mint_wrprc(claims: &Value) -> String {
    let (cert, key) = registrar();
    sign_raw(&key, "rc-wrp+jwt", claims, std::slice::from_ref(&cert))
}

/// The 472-2 B.2 registrar dataset — the JSON members the
/// `registrar_dataset` element carries (RO-06..12).
fn registrar_dataset() -> Value {
    json!({
        "identifier": [
            {"type": "eori", "identifier": "SE556123456701"},
            {"type": "lei", "identifier": "529900T8BM49AURSDO55"},
        ],
        "srvDescription": [{"lang": "sv", "content": "Arbetsformedlingens tjänst"}],
        "registryURI": "https://registrar.example/api/5561234567",
        "intendedUseIdentifier": "urn:registrar:use:employment-verification",
        "purpose": [{"lang": "en", "content": "Verify employment eligibility"}],
        "policyURI": "https://arbetsformedlingen.example/privacy",
        "credential": [{"format": "dc+sd-jwt", "meta": "urn:eudi:pid:arf-1.8:1"}],
    })
}

#[test]
fn a_genuine_wrprc_parses_and_carries_its_chain() {
    let token = mint_wrprc(&register_claims());
    let parsed = parse_wrprc(&token, NOW).unwrap();
    // The registrar's chain, leaf first — for the trust layer to evaluate;
    // this parse asserts consistency, never trust.
    assert_eq!(parsed.x5c_der.len(), 1);
    // The payload is carried verbatim.
    assert_eq!(parsed.claims["sub"], "urn:glas:se:registrar:5561234567");
    assert_eq!(parsed.claims["entitlements"][1], "qeaaprovider");
}

#[test]
fn the_wrprc_header_is_held_to_the_475_profile() {
    // GEN-5.2.2 Table 5: typ rc-wrp+jwt. A differently-typed JWT is not a
    // WRPRC, whatever its claims say.
    let (cert, key) = registrar();
    let wrong_typ = sign_raw(&key, "jwt", &register_claims(), std::slice::from_ref(&cert));
    let error = parse_wrprc(&wrong_typ, NOW).unwrap_err();
    assert_eq!(error.code(), "policy");
    assert!(error.to_string().contains("wrprc_typ"), "{error}");

    // GEN-5.2.2 Table 5: the whole certificate chain. Without x5c there is
    // no consistency to check and nothing for the trust layer to evaluate.
    let chainless = {
        use jose_rs::jws::compact::{sign_with_jwk_options, SignOptions};
        use jose_rs::JoseHeader;
        let mut header = JoseHeader::new("ES256");
        header.typ = Some("rc-wrp+jwt".into());
        let opts = SignOptions::new().with_key_reference_headers(true);
        sign_with_jwk_options(
            &key,
            &serde_json::to_vec(&register_claims()).unwrap(),
            &header,
            &opts,
        )
        .unwrap()
    };
    let error = parse_wrprc(&chainless, NOW).unwrap_err();
    assert_eq!(error.code(), "malformed");

    // GEN-5.2.1-03: the signature must verify under the presented leaf. A
    // token signed by a DIFFERENT registrar's key, presenting this one's
    // chain, fails integrity.
    let (cert, _key) = registrar();
    let (_other_cert, other_key) = self_signed_ec("registrar.example", "ES256");
    let forged = sign_raw(
        &other_key,
        "rc-wrp+jwt",
        &register_claims(),
        std::slice::from_ref(&cert),
    );
    let error = parse_wrprc(&forged, NOW).unwrap_err();
    assert_eq!(error.code(), "integrity");
}

#[test]
fn the_wrprc_payload_is_held_to_table_7() {
    // GEN-5.2.4-02: the registered subject is required.
    for missing in ["sub", "registry_uri", "privacy_policy", "iat"] {
        let mut claims = register_claims();
        claims.as_object_mut().unwrap().remove(missing);
        let error = parse_wrprc(&mint_wrprc(&claims), NOW).unwrap_err();
        assert_eq!(error.code(), "malformed", "{missing}: {error}");
        assert!(
            error
                .to_string()
                .contains(&format!("wrprc_missing_{missing}")),
            "{missing}: {error}"
        );
    }
    // GEN-5.2.4-03: at least one entitlement; each an identifier string.
    let mut claims = register_claims();
    claims["entitlements"] = json!([]);
    assert!(parse_wrprc(&mint_wrprc(&claims), NOW).is_err());
    let mut claims = register_claims();
    claims["entitlements"] = json!([{"id": "pid_provision"}]);
    assert!(parse_wrprc(&mint_wrprc(&claims), NOW).is_err());
    // Table 7: srv_description — non-empty, MultiLangString entries.
    let mut claims = register_claims();
    claims["srv_description"] = json!([]);
    assert!(parse_wrprc(&mint_wrprc(&claims), NOW).is_err());
    let mut claims = register_claims();
    claims["srv_description"] = json!([{"lang": "sv"}]);
    assert!(parse_wrprc(&mint_wrprc(&claims), NOW).is_err());
    // The iat skew and the exp window match the status-list tokens'.
    let mut claims = register_claims();
    claims["iat"] = json!(NOW + 120);
    let error = parse_wrprc(&mint_wrprc(&claims), NOW).unwrap_err();
    assert_eq!(error.code(), "policy");
    assert!(error.to_string().contains("wrprc_iat_future"));
    let mut claims = register_claims();
    claims["exp"] = json!(NOW);
    let error = parse_wrprc(&mint_wrprc(&claims), NOW).unwrap_err();
    assert!(error.to_string().contains("wrprc_expired"));
    // Optional members are type-checked when present, never required.
    let mut claims = register_claims();
    claims["country"] = json!(42);
    let error = parse_wrprc(&mint_wrprc(&claims), NOW).unwrap_err();
    assert!(error.to_string().contains("wrprc_country_not_string"));
}

#[test]
fn the_request_carries_verifier_info_per_the_472_2_profile() {
    let (verifier_cert, verifier_key) = verifier();
    let signer = oid4vp::software_signer(&verifier_key).unwrap();
    let wrprc = mint_wrprc(&register_claims());
    let cfg = RequestConfig {
        response_uri: "https://verifier.example/vp/response".into(),
        dcql_query: json!({"credentials": [{
            "id": "pid", "format": "dc+sd-jwt",
            "meta": {"vct_values": ["urn:eudi:pid:1"]},
            "claims": [{"path": ["given_name"]}],
        }]}),
        ttl_secs: 300,
        vp_formats_supported: None,
        client_id: None,
        verifier_info: Some(registrar_dataset()),
        wrprc: Some(wrprc.clone()),
    };
    let (jar, _session) =
        oid4vp::create_request(&cfg, &signer, SIGNING_ALG, &[verifier_cert], NOW).unwrap();
    let payload = jar.split('.').nth(1).unwrap();
    let payload: Value = serde_json::from_slice(&b64u_decode(payload)).unwrap();
    // RO-01: the RO body carries verifier_info; RO-02..12 the registrar
    // dataset element; RO-13..16 the registration certificate element.
    let verifier_info = payload["verifier_info"].as_array().unwrap();
    assert_eq!(verifier_info.len(), 2);
    let dataset = &verifier_info[0];
    assert_eq!(dataset["format"], "registrar_dataset");
    assert_eq!(
        dataset["data"]["registryURI"],
        "https://registrar.example/api/5561234567"
    );
    assert_eq!(
        dataset["data"]["intendedUseIdentifier"],
        "urn:registrar:use:employment-verification"
    );
    let registration = &verifier_info[1];
    assert_eq!(registration["format"], "registration_cert");
    // RO-16: the base64url of the serialized WRPRC, byte-exact.
    let decoded = b64u_decode(registration["data"].as_str().unwrap());
    assert_eq!(decoded, wrprc.as_bytes());
    // The WRPRC itself parses — the arm checked it.
    parse_wrprc(&wrprc, NOW).unwrap();
}

#[test]
fn an_unconfigured_request_carries_no_verifier_info() {
    // The pre-EAAP shape is byte-compatible: no verifier_info member at
    // all, so the OIDF conformance surfaces are unaffected.
    let (verifier_cert, verifier_key) = verifier();
    let signer = oid4vp::software_signer(&verifier_key).unwrap();
    let cfg = RequestConfig {
        response_uri: "https://verifier.example/vp/response".into(),
        dcql_query: json!({"credentials": [{
            "id": "pid", "format": "dc+sd-jwt",
            "meta": {"vct_values": ["urn:eudi:pid:1"]},
            "claims": [{"path": ["given_name"]}],
        }]}),
        ttl_secs: 300,
        vp_formats_supported: None,
        client_id: None,
        verifier_info: None,
        wrprc: None,
    };
    let (jar, _) =
        oid4vp::create_request(&cfg, &signer, SIGNING_ALG, &[verifier_cert], NOW).unwrap();
    assert!(build_verifier_info(None, None).unwrap().is_none());
    let payload = jar.split('.').nth(1).unwrap();
    let payload: Value = serde_json::from_slice(&b64u_decode(payload)).unwrap();
    assert!(payload.get("verifier_info").is_none());
}

#[test]
fn a_malformed_wrprc_fails_the_arm_and_a_forged_dataset_fails_the_build() {
    // The arm refuses to carry a WRPRC that does not parse: a wallet would
    // only reject it later.
    let (verifier_cert, verifier_key) = verifier();
    let signer = oid4vp::software_signer(&verifier_key).unwrap();
    let (cert, key) = registrar();
    let _ = cert;
    let mut claims = register_claims();
    claims.as_object_mut().unwrap().remove("sub");
    let bad = sign_raw(&key, "rc-wrp+jwt", &claims, std::slice::from_ref(&cert));
    let cfg = RequestConfig {
        response_uri: "https://verifier.example/vp/response".into(),
        dcql_query: json!({"credentials": [{
            "id": "pid", "format": "dc+sd-jwt",
            "meta": {"vct_values": ["urn:eudi:pid:1"]},
            "claims": [{"path": ["given_name"]}],
        }]}),
        ttl_secs: 300,
        vp_formats_supported: None,
        client_id: None,
        verifier_info: None,
        wrprc: Some(bad),
    };
    assert!(oid4vp::create_request(&cfg, &signer, SIGNING_ALG, &[verifier_cert], NOW).is_err());

    // RO-03: the registrar-data element carries no credential_ids member.
    let mut dataset = registrar_dataset();
    dataset["credential_ids"] = json!(["pid"]);
    let error = build_verifier_info(Some(&dataset), None).unwrap_err();
    assert_eq!(error.code(), "policy");
    // RO-06..11: the required B.2 members are validated.
    let mut dataset = registrar_dataset();
    dataset.as_object_mut().unwrap().remove("purpose");
    assert!(build_verifier_info(Some(&dataset), None).is_err());
}

#[test]
fn duplicate_header_members_and_malformed_dataset_entries_fail_the_arm() {
    // Copilot round 1: the protected header is attacker-controlled JSON —
    // it must go through the same strict parse as sdjwt's decode_header.
    // A duplicated member is ambiguous to different parsers: a wallet's
    // JOSE decoder may read a DIFFERENT typ or x5c than the one this
    // parse validated, and forward it.
    let (cert, key) = registrar();
    // The duplicate-member header, as RAW JSON text — the json! macro
    // deduplicates into its map, so the bytes must be crafted by hand.
    let header_json = format!(
        "{{\"typ\":\"rc-wrp+jwt\",\"typ\":\"application/jwt\",\"alg\":\"ES256\",\"x5c\":[\"{}\"]}}",
        jose_rs::base64url::encode(&cert)
    );
    let forged_header = {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64U, Engine};
        use jose_rs::jws::compact::{sign_with_jwk_options, SignOptions};
        use jose_rs::JoseHeader;
        let mut header = JoseHeader::new("ES256");
        header.typ = Some("rc-wrp+jwt".into());
        header.x5c = Some(vec![jose_rs::base64url::encode(&cert)]);
        let opts = SignOptions::new().with_key_reference_headers(true);
        let signed = sign_with_jwk_options(
            &key,
            &serde_json::to_vec(&register_claims()).unwrap(),
            &header,
            &opts,
        )
        .unwrap();
        let parts: Vec<&str> = signed.split('.').collect();
        // Swap the genuinely-signed header for the duplicate-member bytes
        // (base64url of the raw JSON text above) — the parse rejects on the
        // STRICT pass, before any signature is even read.
        let header_b64 = B64U.encode(header_json.as_bytes());
        format!("{header_b64}.{}.{}}}", parts[1], parts[2])
    };
    let error = parse_wrprc(&forged_header, NOW).unwrap_err();
    assert_eq!(error.code(), "malformed");

    // Copilot round 1: the B.2 arrays are validated per ENTRY, not just as
    // containers — [null] entries, missing identifier members, and
    // wrong-shaped multilanguage strings all fail the build.
    let null_entries = json!({
        "identifier": [null],
        "srvDescription": [{"lang": "sv"}],
        "purpose": [null],
        "registryURI": "https://registrar.example/api",
        "intendedUseIdentifier": "urn:registrar:use:1",
        "policyURI": "https://example.com/privacy",
    });
    let error = build_verifier_info(Some(&null_entries), None).unwrap_err();
    assert!(
        error.to_string().contains("verifier_info_identifier"),
        "{error}"
    );
    let mut dataset = registrar_dataset();
    dataset["identifier"] = json!([{"type": "eori"}]);
    let error = build_verifier_info(Some(&dataset), None).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("verifier_info_entry_missing_identifier"),
        "{error}"
    );
    let mut dataset = registrar_dataset();
    dataset["srvDescription"] = json!([{"lang": "sv", "value": "Tjänst"}]);
    let error = build_verifier_info(Some(&dataset), None).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("verifier_info_entry_missing_content"),
        "{error}"
    );
    let mut dataset = registrar_dataset();
    dataset["credential"] = json!([{"format": 42}]);
    let error = build_verifier_info(Some(&dataset), None).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("verifier_info_entry_missing_format"),
        "{error}"
    );
}
