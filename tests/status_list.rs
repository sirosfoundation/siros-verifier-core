use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};
use siros_verifier_core::sdjwt::{StatusRef, X5cLeaf};
use siros_verifier_core::status_list::{
    index_parts, status_at, verify_token, StatusListKeyResolver, StatusListKeySource,
};
use siros_verifier_core::testutil::{self_signed_ec, sign_raw, sign_raw_embedded_jwk};
use siros_verifier_core::trust::TrustQuery;

const NOW: i64 = 1_793_656_800;
const TOKEN: &str = "eyJ4NWMiOlsiTUlJQnZqQ0NBV09nQXdJQkFnSVVmdzRpbjJ4YmJhTzRCUlZ6Q01KOWpjeCtNWVV3Q2dZSUtvWkl6ajBFQXdJd0lqRWdNQjRHQTFVRUF3d1hZMjl1Wm05eWJXRnVZMlV1WlhoaGJYQnNaUzVqYjIwd0hoY05Nall3TlRFMU1EYzFNelExV2hjTk1qY3dOVEUxTURjMU16UTFXakFpTVNBd0hnWURWUVFEREJkamIyNW1iM0p0WVc1alpTNWxlR0Z0Y0d4bExtTnZiVEJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCQno3UkdCQkVEUm5EaGhyVUY1NXZGVzI2OGxtRGhlM1paa3luQThDTVpPdEtudjAyOTY4WFNpRW1OU29HUGFIWDNMWGwrYm9RenRzSzBEQjQ2VmhFNitqZHpCMU1CMEdBMVVkRGdRV0JCUi96QTdoMytpa0tCb2EzanlNaVNYN3NGZGt5ekFmQmdOVkhTTUVHREFXZ0JSL3pBN2gzK2lrS0JvYTNqeU1pU1g3c0Zka3l6QVBCZ05WSFJNQkFmOEVCVEFEQVFIL01DSUdBMVVkRVFRYk1CbUNGMk52Ym1admNtMWhibU5sTG1WNFlXMXdiR1V1WTI5dE1Bb0dDQ3FHU000OUJBTUNBMGtBTUVZQ0lRQzRsaHh3aVF5MytHUHR6ZFFXOUlsRFNyUW9Fbm5jb202WXNLWjNpekh1SWdJaEFLWklqTllXVEcweElwRnJTNERWa3ZvMXFpVjlrTmYxUXZwOFN0T1c2cEVyIl0sInR5cCI6InN0YXR1c2xpc3Qrand0IiwiYWxnIjoiRVMyNTYiLCJqd2siOnsia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJjcnYiOiJQLTI1NiIsImtpZCI6InZwLXZlcmlmaWVyLWtleS0xIiwieDVjIjpbIk1JSUJ2akNDQVdPZ0F3SUJBZ0lVZnc0aW4yeGJiYU80QlJWekNNSjlqY3grTVlVd0NnWUlLb1pJemowRUF3SXdJakVnTUI0R0ExVUVBd3dYWTI5dVptOXliV0Z1WTJVdVpYaGhiWEJzWlM1amIyMHdIaGNOTWpZd05URTFNRGMxTXpRMVdoY05NamN3TlRFMU1EYzFNelExV2pBaU1TQXdIZ1lEVlFRRERCZGpiMjVtYjNKdFlXNWpaUzVsZUdGdGNHeGxMbU52YlRCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQkJ6N1JHQkJFRFJuRGhoclVGNTV2RlcyNjhsbURoZTNaWmt5bkE4Q01aT3RLbnYwMjk2OFhTaUVtTlNvR1BhSFgzTFhsK2JvUXp0c0swREI0NlZoRTYramR6QjFNQjBHQTFVZERnUVdCQlIvekE3aDMraWtLQm9hM2p5TWlTWDdzRmRreXpBZkJnTlZIU01FR0RBV2dCUi96QTdoMytpa0tCb2EzanlNaVNYN3NGZGt5ekFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQ0lHQTFVZEVRUWJNQm1DRjJOdmJtWnZjbTFoYm1ObExtVjRZVzF3YkdVdVkyOXRNQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUUM0bGh4d2lReTMrR1B0emRRVzlJbERTclFvRW5uY29tNllzS1ozaXpIdUlnSWhBS1pJak5ZV1RHMHhJcEZyUzREVmt2bzFxaVY5a05mMVF2cDhTdE9XNnBFciJdLCJ4IjoiSFB0RVlFRVFOR2NPR0d0UVhubThWYmJyeVdZT0Y3ZGxtVEtjRHdJeGs2MCIsInkiOiJLbnYwMjk2OFhTaUVtTlNvR1BhSFgzTFhsLWJvUXp0c0swREI0NlZoRTY4IiwiYWxnIjoiRVMyNTYifX0.eyJzdWIiOiJodHRwczovL2xvY2FsaG9zdC5lbW9iaXguY28udWs6ODQ0My90ZXN0L2Evc2lyb3MtdmVyaWZpZXItdnAtdGVzdC9zdGF0dXNsaXN0cy9FY1VJdjlyaGtpaWJBcWduSmpKSyIsImV4cCI6MTc5Mzc0MzE5NiwiaWF0IjoxNzkzNjU2Nzk2LCJ0dGwiOjMwMCwic3RhdHVzX2xpc3QiOnsiYml0cyI6MSwibHN0IjoiZU5wYnRRb19BQUJlenhWQiJ9fQ.YbQ89wmpUFsZQXyK-dimVsrPmM6pC4yy6jiPV3idF-EnGzhuFinBV0GelpBMk2sww45vBk9ntApmFCCVSPI02A";

const LIST_URI: &str =
    "https://localhost.emobix.co.uk:8443/test/a/siros-verifier-vp-test/statuslists/EcUIv9rhkiibAqgnJjJK";

fn reference(idx: u64) -> StatusRef {
    StatusRef {
        idx,
        uri: LIST_URI.into(),
    }
}

#[test]
fn genuine_suite_token_verifies_and_reads_revocation_bits() {
    let token = verify_token(TOKEN, LIST_URI, &X5cLeaf, NOW).unwrap();
    assert_eq!(status_at(&token, &reference(5)).unwrap(), 1);
    assert_eq!(status_at(&token, &reference(4)).unwrap(), 0);
    let query = TrustQuery::for_issuer(&token.issuer, "status-list-signer", "status-list");
    assert_eq!(query.role, "status-list-signer");
    assert_eq!(query.subject_id, reference(0).uri);
}

#[test]
fn signature_time_subject_and_index_are_checked() {
    assert!(verify_token(TOKEN, LIST_URI, &X5cLeaf, 1_793_743_196).is_err());
    let token = verify_token(TOKEN, LIST_URI, &X5cLeaf, NOW).unwrap();
    assert!(status_at(&token, &reference(1000)).is_err());
    let mut tampered = TOKEN.to_owned();
    tampered.push('x');
    assert!(verify_token(&tampered, LIST_URI, &X5cLeaf, NOW).is_err());
}

#[test]
fn an_index_beyond_the_native_usize_range_is_rejected_not_truncated() {
    let token = verify_token(TOKEN, LIST_URI, &X5cLeaf, NOW).unwrap();
    // 2^32 truncates to zero on 32-bit targets. The production arithmetic must
    // retain the exact bit offset on every target, and status lookup must stay
    // out of range rather than selecting the first status entry.
    assert_eq!(index_parts(1_u64 << 32, 1).unwrap(), (1_u64 << 32, 0));
    let error = status_at(&token, &reference(1_u64 << 32)).unwrap_err();
    assert_eq!(error.code(), "policy");
    assert!(error.to_string().contains("status_list_index_out_of_range"));
}

fn valid_claims() -> Value {
    serde_json::from_slice(&jose_rs::base64url::decode(TOKEN.split('.').nth(1).unwrap()).unwrap())
        .unwrap()
}

#[test]
fn embedded_jwk_status_lists_verify_under_the_configured_key_source() {
    // Status-list tokens in the wild — the GDC registry's among them, and IETF
    // Token Status List issuers generally — embed the signer as a `jwk` with
    // no certificate chain. The default `x5c` policy refuses them; the
    // `x5c-or-jwk` interop policy accepts: the x5c leaf when the header
    // carries a chain, otherwise the embedded key.
    let (_cert, key) = self_signed_ec("status.example", "ES256");
    let token = sign_raw_embedded_jwk(&key, "statuslist+jwt", &valid_claims());

    // Default (`x5c`): refused — the token carries no chain.
    let error = verify_token(&token, LIST_URI, &StatusListKeyResolver::default(), NOW).unwrap_err();
    assert_eq!(error.code(), "malformed");
    assert!(error.to_string().contains("no x5c chain"));

    // `x5c-or-jwk`: the embedded key verifies and the list reads.
    let interop = StatusListKeyResolver {
        source: StatusListKeySource::X5cOrJwk,
    };
    let verified = verify_token(&token, LIST_URI, &interop, NOW).unwrap();
    assert_eq!(status_at(&verified, &reference(4)).unwrap(), 0);

    // `jwk`-only: the token's carrier is a jwk, so it verifies too...
    let jwk_only = StatusListKeyResolver {
        source: StatusListKeySource::Jwk,
    };
    let verified = verify_token(&token, LIST_URI, &jwk_only, NOW).unwrap();
    // ...and the strict bindings still hold under every policy: a list whose
    // subject is not the referenced URI never speaks for the credential.
    let mut claims = valid_claims();
    claims["sub"] = json!("https://status.example/other-list");
    let foreign = sign_raw_embedded_jwk(&key, "statuslist+jwt", &claims);
    assert!(verify_token(&foreign, LIST_URI, &jwk_only, NOW).is_err());
    assert!(verify_token(&foreign, LIST_URI, &interop, NOW).is_err());
    let _ = verified;

    // The certificate-bound token still resolves under the interop policy
    // (its carrier is x5c) and is refused under `jwk`-only — an x5c-carrying
    // token with NO embedded key has no jwk carrier to resolve.
    let (cert, key) = self_signed_ec("status.example", "ES256");
    let x5c_only = sign_raw(
        &key,
        "statuslist+jwt",
        &valid_claims(),
        std::slice::from_ref(&cert),
    );
    verify_token(&x5c_only, LIST_URI, &interop, NOW).unwrap();
    let error = verify_token(&x5c_only, LIST_URI, &jwk_only, NOW).unwrap_err();
    assert!(error.to_string().contains("no embedded jwk"));
    // The conformance suite's token carries BOTH members: every policy
    // resolves it (x5c when accepted, else the embedded jwk).
    verify_token(TOKEN, LIST_URI, &StatusListKeyResolver::default(), NOW).unwrap();
    verify_token(TOKEN, LIST_URI, &interop, NOW).unwrap();
    verify_token(TOKEN, LIST_URI, &jwk_only, NOW).unwrap();
}

#[test]
fn an_embedded_key_never_parades_a_header_chain_as_trust_evidence() {
    // The security heart of the carrier policy: a dual-carrier token whose
    // signature verifies under its embedded `jwk` while its header ALSO
    // carries a foreign certificate chain. The trust query's evidence is
    // the resolver's own provenance — NO chain for an embedded key — so
    // go-trust judges the embedded key, never the decoy chain; and the
    // interop policy, seeing a present chain, resolves through it, fails the
    // signature, and does not fall back.
    let (decoy_cert, _decoy_key) = self_signed_ec("trusted-status.example", "ES256");
    let (_signer_cert, signer_key) = self_signed_ec("status.example", "ES256");
    let claims = valid_claims();
    let token = dual_carrier_token(&signer_key, &claims, &decoy_cert);

    // `jwk` policy: the embedded key verifies...
    let jwk_only = StatusListKeyResolver {
        source: StatusListKeySource::Jwk,
    };
    let verified = verify_token(&token, LIST_URI, &jwk_only, NOW).unwrap();
    // ...but the evidence carries no chain: the embedded key vouched for
    // itself, and the decoy chain must not reach go-trust.
    assert!(
        verified.issuer.x5c_der.is_empty(),
        "an embedded-key resolution must not emit chain evidence"
    );

    // `x5c-or-jwk` on the same token: the header carries a chain, so
    // resolution goes through it — it does not vouch for the signer — and
    // the signature fails rather than falling back to the embedded key.
    let interop = StatusListKeyResolver {
        source: StatusListKeySource::X5cOrJwk,
    };
    let error = verify_token(&token, LIST_URI, &interop, NOW).unwrap_err();
    assert_eq!(error.code(), "integrity");

    // And the resolution-failure leg of the no-fallback guarantee: a token
    // with NO x5c and a malformed embedded jwk fails resolution outright —
    // there is no second carrier to fall through to.
    let broken = broken_embedded_jwk_token();
    let error = verify_token(&broken, LIST_URI, &interop, NOW).unwrap_err();
    assert_eq!(error.code(), "malformed");
}

/// Mint a `statuslist+jwt` carrying BOTH an embedded signer `jwk` and an
/// `x5c` chain (leaf first) — the dual-carrier confusion probe: the signature
/// is the signer's, the chain is the decoy's.
fn dual_carrier_token(signer: &jose_rs::jwk::Jwk, claims: &Value, decoy_cert_der: &[u8]) -> String {
    use jose_rs::jws::compact::{sign_with_jwk_options, SignOptions};
    use jose_rs::JoseHeader;
    let mut header = JoseHeader::new("ES256");
    header.typ = Some("statuslist+jwt".into());
    // `x5c` rides standard base64 — the engine `x5c_chain` decodes with —
    // unlike the compact segments' base64url.
    header.x5c = Some(vec![STANDARD.encode(decoy_cert_der)]);
    header.jwk = Some(serde_json::to_value(signer.to_public_jwk()).unwrap());
    let opts = SignOptions::new().with_key_reference_headers(true);
    sign_with_jwk_options(signer, &serde_json::to_vec(claims).unwrap(), &header, &opts)
        .expect("sign")
}

/// A token whose embedded `jwk` is not a parseable JWK at all and which
/// carries no chain: resolution itself must fail, with no other carrier to
/// fall through to.
fn broken_embedded_jwk_token() -> String {
    use jose_rs::jws::compact::{sign_with_jwk_options, SignOptions};
    use jose_rs::JoseHeader;
    let (_cert, key) = self_signed_ec("status.example", "ES256");
    let mut header = JoseHeader::new("ES256");
    header.typ = Some("statuslist+jwt".into());
    // `kty` must be a string; this is not a JWK any parser will accept.
    header.jwk = Some(serde_json::json!({"kty": 42}));
    let opts = SignOptions::new().with_key_reference_headers(true);
    sign_with_jwk_options(
        &key,
        &serde_json::to_vec(&valid_claims()).unwrap(),
        &header,
        &opts,
    )
    .expect("sign")
}

#[test]
fn non_integer_time_claims_are_rejected_even_with_valid_signatures() {
    let (cert, key) = self_signed_ec("status.example", "ES256");
    for (name, value) in [
        ("exp", json!("0")),
        ("iat", json!([])),
        ("iat", json!("future")),
    ] {
        let mut claims = valid_claims();
        claims[name] = value.clone();
        let token = sign_raw(&key, "statuslist+jwt", &claims, std::slice::from_ref(&cert));
        let error = verify_token(&token, LIST_URI, &X5cLeaf, NOW).unwrap_err();
        assert_eq!(error.code(), "malformed", "{name}={value}");
    }
}

#[test]
fn a_list_whose_subject_is_not_the_referenced_uri_never_speaks_for_the_credential() {
    // Token Status List §5.1/§8.3: the token's `sub` MUST equal the `uri` the
    // credential's status reference named. A second list — even signed by the
    // same trusted signer — must not be substitutable for the one referenced.
    let (cert, key) = self_signed_ec("status.example", "ES256");
    let mut claims = valid_claims();
    claims["sub"] = json!("https://status.example/other-list");
    let token = sign_raw(&key, "statuslist+jwt", &claims, std::slice::from_ref(&cert));
    // Rejected at validation: the token does not speak for the reference.
    let error = verify_token(&token, LIST_URI, &X5cLeaf, NOW).unwrap_err();
    assert_eq!(error.code(), "policy");
    assert!(error.to_string().contains("status_list_uri_mismatch"));
    // The same token against its own URI verifies — the binding, not the
    // signature, is what rejected it.
    let token = verify_token(&token, "https://status.example/other-list", &X5cLeaf, NOW)
        .unwrap_or_else(|e| panic!("the same list must verify against its own URI: {e}"));
    // And the public lookup enforces its own contract even then: reading a
    // bit for a reference through a list that reference does not name is
    // refused, whichever boundary the caller came from.
    let mut foreign = reference(4);
    foreign.uri = LIST_URI.into();
    let error = status_at(&token, &foreign).unwrap_err();
    assert_eq!(error.code(), "policy");
    assert!(error.to_string().contains("status_list_subject_mismatch"));
    let own = StatusRef {
        idx: 4,
        uri: "https://status.example/other-list".into(),
    };
    assert_eq!(status_at(&token, &own).unwrap(), 0);
}

#[test]
fn a_status_list_token_without_issued_at_is_rejected() {
    // Token Status List §5.1: `iat` is REQUIRED. Without it a list has no
    // issuance instant at all — nothing to judge freshness against.
    let (cert, key) = self_signed_ec("status.example", "ES256");
    let mut claims = valid_claims();
    claims.as_object_mut().expect("claims object").remove("iat");
    let token = sign_raw(&key, "statuslist+jwt", &claims, std::slice::from_ref(&cert));
    let error = verify_token(&token, LIST_URI, &X5cLeaf, NOW).unwrap_err();
    assert_eq!(error.code(), "malformed");
    assert!(error.to_string().contains("status_list_missing_iat"));
}

#[test]
fn a_status_list_token_issued_in_the_future_is_rejected() {
    let (cert, key) = self_signed_ec("status.example", "ES256");
    let mut claims = valid_claims();
    claims["iat"] = json!(NOW + 61);
    let token = sign_raw(&key, "statuslist+jwt", &claims, std::slice::from_ref(&cert));
    let error = verify_token(&token, LIST_URI, &X5cLeaf, NOW).unwrap_err();
    assert_eq!(error.code(), "policy");
    assert!(error.to_string().contains("status_list_iat_future"));
}
