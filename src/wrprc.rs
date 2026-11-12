//! The Wallet-Relying-Party Registration Certificate (WRPRC) carrier —
//! ETSI TS 119 475 §5.2's `rc-wrp+jwt` and ETSI TS 119 472-2 §6.3.2.2's
//! `verifier_info` request-object members.
//!
//! This module is the INCREMENT 1 surface of the intermediary feature (#39):
//! the core ACCEPTS and STRICTLY PARSES a WRPRC, and the request builder
//! carries it on the armed request per the 472-2 EAAP profile. It does not
//! decide trust — the WRPRC's signer (the registrar, GEN-5.2.1-03) is
//! evaluated by the trust layer, and the WRPAC chain (119 411-8) is the
//! intermediary's half, later increments both.
//!
//! What the specs require, and this module enforces:
//!
//! - GEN-5.2.1-01: a WRPRC is a signed JWT (the CWT form is out of scope
//!   here; the verifier's registrar toolchain emits JWTs).
//! - GEN-5.2.2 / Table 5: the header carries `typ` = `rc-wrp+jwt`, `alg`
//!   (the JAdES B-B profile per 119 182-1 §5.1.2), and `x5c` — the whole
//!   certificate chain (119 182-1 §5.1.8).
//! - GEN-5.2.4 / Table 7: the payload carries the registrar's register
//!   fields. Required here: `sub` (GEN-5.2.4-02 — the WRP's registered
//!   identifier; NOTE 2: always the FINAL relying party, never the
//!   intermediary, even when an intermediary presents it), `iat`,
//!   `entitlements` (GEN-5.2.4-03: at least one), `srv_description`
//!   (multilanguage), `registry_uri`, and `privacy_policy`. Optional members
//!   are type-checked when present: `country`, the person names (`sub_ln`,
//!   `sub_gn`, `sub_fn`), `info_uri`, `support_uri`,
//!   `supervisory_authority`, `policy_id`, `certificate_policy`, `status`
//!   (NOTE 5: an IETF Token Status List URI), and `exp`.
//! - The signature must verify under the `x5c` leaf — cryptographic
//!   consistency of the token with its own presented chain, the same
//!   sans-trust contract as the status-list tokens. Chain TRUST is never
//!   decided here.
//!
//! The 472-2 §6.3.2.2 request-object requirements the builder enforces
//! (OIDFVP-HAIP-COMMON-REQ-RO-*, the OID4VP surface — the mdoc
//! `requestInfo` CBOR members of §5.3.2 are the wallet's native surface,
//! not this HTTP one):
//!
//! - RO-01: when configured, the RO body carries `verifier_info`.
//! - RO-02..05, RO-06..12: the registrar dataset element — `format`
//!   `registrar_dataset`, a `data` object (no `credential_ids` member,
//!   RO-03) with the B.2 members: `identifier` (non-empty array),
//!   `srvDescription` (non-empty array), `registryURI`,
//!   `intendedUseIdentifier`, `purpose` (non-empty array), `policyURI`,
//!   and the optional `credential` array.
//! - RO-13..16: the registration certificate element, present when the
//!   WRPRC is configured — `format` `registration_cert`, `data` the
//!   base64url encoding of the serialized WRPRC.
//!
//! NOTE 2 of 472-2 §6.3.2.2 records the intermediary consequence the later
//! increments implement: when an intermediary fronts the RP, the dataset's
//! `identifier` (the registered RP) differs from the intermediary's access
//! certificate identity — the request is signed by the INTERMEDIARY's key
//! (WRPAC, 119 411-8) while the `verifier_info` and the WRPRC speak for the
//! fronted RP.

use crate::error::{integrity, malformed, policy, Result};
use crate::sdjwt::{jwk_from_cert_der, x5c_chain};
use jose_rs::jws;
use jose_rs::JoseHeader;
use serde_json::Value;

/// The maximum serialized WRPRC this verifier will parse or carry: the
/// registrar's register data is a few kilobytes; a bound keeps hostile
/// inputs from bloating every armed request.
const MAX_WRPRC_BYTES: usize = 64 * 1024;

/// A parsed, signature-consistent WRPRC. The payload is the registrar's
/// data, carried verbatim — the wallet consumes it through the request
/// object; nothing here interprets the register fields beyond shape.
#[derive(Clone, Debug)]
pub struct Wrprc {
    /// The registrar's certificate chain, leaf first (GEN-5.2.2 Table 5's
    /// `x5c`). Trust in that chain is the trust layer's decision, never
    /// this parse's.
    pub x5c_der: Vec<Vec<u8>>,
    /// The verified payload, exactly as the registrar sealed it.
    pub claims: Value,
}

/// Parse and signature-check a serialized `rc-wrp+jwt` (GEN-5.2.1-01,
/// GEN-5.2.2, GEN-5.2.4). Shape-strict, trust-free: the signature must verify
/// under the token's own `x5c` leaf, and every REQUIRED register member must
/// be present and well-formed — a malformed WRPRC fails the arm rather than
/// riding a request the wallet can only reject later.
pub fn parse_wrprc(token: &str, now: i64) -> Result<Wrprc> {
    if token.len() > MAX_WRPRC_BYTES || token.split('.').count() != 3 {
        return Err(malformed("wrprc_token_shape"));
    }
    // The protected header is attacker-controlled JSON: run it through the
    // same strict parse as sdjwt's decode_header (duplicate members are
    // ambiguous to different parsers — a wallet's JOSE decoder may read a
    // DIFFERENT typ or x5c than the one validated here, and forward it).
    {
        let encoded = token
            .split('.')
            .next()
            .ok_or_else(|| malformed("wrprc has no header"))?;
        crate::json_strict::from_slice(&crate::b64u_decode(encoded)?)?;
    }
    let header: JoseHeader =
        jws::decode_header(token).map_err(|e| malformed(format!("wrprc_header: {e}")))?;
    // GEN-5.2.2 Table 5: the type marks the register artefact.
    if header.typ.as_deref() != Some("rc-wrp+jwt") {
        return Err(policy("wrprc_typ"));
    }
    if header.alg.is_empty() {
        return Err(malformed("wrprc_missing_alg"));
    }
    // GEN-5.2.2 Table 5: the whole certificate chain. Without it the token
    // cannot be checked for consistency at all, and the trust layer would
    // have nothing to evaluate.
    let chain = x5c_chain(&header)?;
    let leaf = chain
        .first()
        .ok_or_else(|| malformed("wrprc_missing_x5c"))?;
    let jwk = jwk_from_cert_der(leaf)?;
    // GEN-5.2.1-03: signed by the WRPRC provider. Verified here only as
    // consistency of the token with its own presented chain — the signer's
    // TRUST is the trust layer's call.
    let payload = jws::compact::verify_with_jwk(&jwk, token)
        .map_err(|e| integrity(format!("wrprc signature: {e}")))?;
    let claims: Value = crate::json_strict::from_slice(&payload)?;
    let claims = claims
        .as_object()
        .ok_or_else(|| malformed("wrprc_claims_not_object"))?;
    let require_string = |name: &str| -> Result<&str> {
        claims
            .get(name)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| malformed(format!("wrprc_missing_{name}")))
    };
    // GEN-5.2.4-02 / Table 7 NOTE 2: the subject is the registered — and
    // always the FINAL — relying party, never the presenting intermediary.
    let _ = require_string("sub")?;
    // Table 7: `registry_uri` (the national registry API) and
    // `privacy_policy` (B.2.8) are the wallet's user-facing anchors.
    let _ = require_string("registry_uri")?;
    let _ = require_string("privacy_policy")?;
    // GEN-5.2.4-01/-03: at least one entitlement, each a clause A.2
    // identifier string.
    let entitlements = claims
        .get("entitlements")
        .and_then(Value::as_array)
        .filter(|list| !list.is_empty())
        .ok_or_else(|| malformed("wrprc_missing_entitlements"))?;
    if entitlements.iter().any(|e| e.as_str().is_none()) {
        return Err(malformed("wrprc_entitlements_not_strings"));
    }
    // Table 7: `srv_description` — one or more localized service
    // descriptions, each a MultiLangString (lang + value).
    let description = claims
        .get("srv_description")
        .and_then(Value::as_array)
        .filter(|list| !list.is_empty())
        .ok_or_else(|| malformed("wrprc_missing_srv_description"))?;
    for entry in description {
        let object = entry
            .as_object()
            .ok_or_else(|| malformed("wrprc_srv_description_entry"))?;
        let lang = object
            .get("lang")
            .and_then(Value::as_str)
            .filter(|lang| !lang.is_empty())
            .ok_or_else(|| malformed("wrprc_srv_description_lang"))?;
        let value = object
            .get("value")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| malformed("wrprc_srv_description_value"))?;
        let _ = (lang, value);
    }
    // Table 7's technical members. `iat` is required; `exp` is not in the
    // table but is validated when a registrar includes it. The future skew
    // matches the status-list tokens'.
    let iat = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(|| malformed("wrprc_missing_iat"))?;
    if iat > now + 60 {
        return Err(policy("wrprc_iat_future"));
    }
    if let Some(exp) = claims.get("exp") {
        if !exp.is_i64() {
            return Err(malformed("wrprc_exp_not_integer"));
        }
        if now >= exp.as_i64().expect("checked") {
            return Err(policy("wrprc_expired"));
        }
    }
    // Table 7's optional members: type-checked when present, never required
    // — the registrar decides which the register carries.
    for name in [
        "country",
        "sub_ln",
        "sub_gn",
        "sub_fn",
        "info_uri",
        "support_uri",
        "policy_id",
        "certificate_policy",
        "status",
    ] {
        if let Some(value) = claims.get(name) {
            if !value.is_string() {
                return Err(malformed(format!("wrprc_{name}_not_string")));
            }
        }
    }
    if let Some(authority) = claims.get("supervisory_authority") {
        if !authority.is_object() {
            return Err(malformed("wrprc_supervisory_authority_not_object"));
        }
    }
    Ok(Wrprc {
        x5c_der: chain,
        claims: Value::Object(claims.clone()),
    })
}

/// Build the 472-2 §6.3.2.2 `verifier_info` array from the configured
/// registrar dataset and/or the parsed WRPRC — the request-object half of
/// the EAAP profile. Returns `None` when nothing is configured (the
/// request stays exactly the pre-EAAP shape; the OIDF conformance plan's
/// surfaces are unaffected).
///
/// The `registrar_dataset` element (RO-02..12) is the RP Registrar-provided
/// data: the B.2 JSON members, config-supplied because their shape is the
/// registrar's own (the WRPRC payload maps them differently — Table 7 —
/// and a derived dataset would guess at the registrar's data). The
/// `registration_cert` element (RO-13..16) is the serialized WRPRC,
/// base64url-encoded, present when the RP has a registration certificate.
pub fn build_verifier_info(
    registrar_dataset: Option<&Value>,
    wrprc: Option<&str>,
) -> Result<Option<Value>> {
    if registrar_dataset.is_none() && wrprc.is_none() {
        return Ok(None);
    }
    let mut elements = Vec::new();
    if let Some(dataset) = registrar_dataset {
        let data = dataset
            .as_object()
            .ok_or_else(|| malformed("verifier_info_dataset_not_object"))?;
        // RO-06..11: the B.2 members the wallet renders and the registrar
        // API query needs. Arrays are non-empty; strings are non-empty;
        // and every ENTRY is validated, not just the container — a
        // malformed entry would ride the armed request until the wallet
        // rejected it, the same failure class the arm exists to prevent.
        let require_string_member =
            |object: &serde_json::Map<String, Value>, name: &str| -> Result<()> {
                let value = object
                    .get(name)
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| malformed(format!("verifier_info_entry_missing_{name}")))?;
                let _ = value;
                Ok(())
            };
        // RO-06 / B.2.2: the identifiers — objects of {type, identifier}.
        let identifiers = data
            .get("identifier")
            .and_then(Value::as_array)
            .filter(|list| !list.is_empty())
            .ok_or_else(|| malformed("verifier_info_missing_identifier"))?;
        for entry in identifiers {
            let object = entry
                .as_object()
                .ok_or_else(|| malformed("verifier_info_identifier_not_object"))?;
            require_string_member(object, "type")?;
            require_string_member(object, "identifier")?;
        }
        // RO-07 / RO-10 / B.2.6: the multilanguage strings — each entry a
        // {lang, content} pair (the 472-2 MultiLangString shape).
        for name in ["srvDescription", "purpose"] {
            let list = data
                .get(name)
                .and_then(Value::as_array)
                .filter(|list| !list.is_empty())
                .ok_or_else(|| malformed(format!("verifier_info_missing_{name}")))?;
            for entry in list {
                let object = entry
                    .as_object()
                    .ok_or_else(|| malformed(format!("verifier_info_{name}_entry_not_object")))?;
                require_string_member(object, "lang")?;
                require_string_member(object, "content")?;
            }
        }
        for name in ["registryURI", "intendedUseIdentifier", "policyURI"] {
            let value = data
                .get(name)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| malformed(format!("verifier_info_missing_{name}")))?;
            let _ = value;
        }
        // RO-12 / B.2.9: the optional credential array — each entry an
        // object with format and meta strings.
        if let Some(credential) = data.get("credential") {
            let list = credential
                .as_array()
                .ok_or_else(|| malformed("verifier_info_credential_not_array"))?;
            for entry in list {
                let object = entry
                    .as_object()
                    .ok_or_else(|| malformed("verifier_info_credential_entry_not_object"))?;
                require_string_member(object, "format")?;
                require_string_member(object, "meta")?;
            }
        }
        // RO-03: the registrar-data element carries no credential_ids
        // member — the DCQL credential selection is a different member
        // with different semantics.
        if data.contains_key("credential_ids") {
            return Err(policy("verifier_info_credential_ids_forbidden"));
        }
        elements.push(serde_json::json!({
            // RO-04: the format marks the registrar dataset.
            "format": "registrar_dataset",
            "data": dataset,
        }));
    }
    if let Some(wrprc) = wrprc {
        // RO-15/16: the registration certificate element — the serialized
        // WRPRC, base64url-encoded.
        elements.push(serde_json::json!({
            "format": "registration_cert",
            "data": crate::b64u(wrprc.as_bytes()),
        }));
    }
    Ok(Some(Value::Array(elements)))
}
