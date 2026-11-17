//! IETF Token Status List (JWT) parsing and bit lookup, sans-I/O.
//!
//! Fetching and signer trust belong to the caller. This module verifies the
//! token's signature and returns status evidence; it never decides trust.

use std::io::Read;

use ciborium::Value as Cbor;
use flate2::read::ZlibDecoder;
use jose_rs::jwk::Jwk;
use jose_rs::{jws, JoseHeader};
use serde_json::Value;

use crate::error::{integrity, malformed, policy};
use crate::sdjwt::{x5c_chain, IssuerEvidence, IssuerKeyResolver, ResolvedKey, StatusRef};
use crate::{b64u_decode, json_strict, Result};

const MAX_TOKEN_BYTES: usize = 64 * 1024;
const MAX_DECOMPRESSED_BYTES: usize = 1024 * 1024;

/// Which JOSE header members a deployment accepts as the carrier of a
/// status-list token's signing key.
///
/// TSL-style deployments bind every list to a certificate chain and accept
/// `x5c` only. Tokens in the wild — the IETF Token Status List profile among
/// them — commonly embed the signer as a `jwk` with no chain at all; a
/// deployment that must interoperate with those issuers accepts the embedded
/// key as well. Either way the token itself is held to the same rules: the
/// signature must verify, `sub` must bind the list to the referenced URI,
/// `iat`/`exp` must be present and well-formed, and signer trust is the
/// caller's separate decision.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StatusListKeySource {
    /// The leaf of the JOSE `x5c` chain only. The pre-configuration behavior.
    #[default]
    X5c,
    /// An embedded JOSE `jwk` only.
    Jwk,
    /// The `x5c` leaf when the header carries a chain; otherwise the embedded
    /// `jwk`. The interop posture: certificate-bound where available, embedded
    /// where the issuer emits no chain.
    X5cOrJwk,
}

/// Resolves a status-list token's signing key per a deployment's
/// [`StatusListKeySource`] policy.
///
/// A present-but-unusable carrier is an error, never a silent fallback: under
/// [`StatusListKeySource::X5cOrJwk`] a broken `x5c` chain does not get rescued
/// by an embedded key the deployer may not have meant to honor, and vice
/// versa. Resolution is not trust; [`crate::sdjwt::IssuerKeyResolver`]'s
/// contract holds.
#[derive(Debug, Default)]
pub struct StatusListKeyResolver {
    /// The accepted carriers. Resolution consults only these.
    pub source: StatusListKeySource,
}

impl StatusListKeyResolver {
    fn x5c_leaf(header: &JoseHeader) -> Result<ResolvedKey> {
        let chain = x5c_chain(header)?;
        let leaf = chain
            .first()
            .ok_or_else(|| malformed("status list token carries no x5c chain"))?;
        Ok(ResolvedKey {
            jwk: crate::sdjwt::jwk_from_cert_der(leaf)?,
            x5c_der: chain,
        })
    }

    fn embedded_jwk(header: &JoseHeader) -> Result<ResolvedKey> {
        let value = header
            .jwk
            .as_ref()
            .ok_or_else(|| malformed("status list token carries no embedded jwk"))?;
        let jwk: Jwk = serde_json::from_value(value.clone())
            .map_err(|e| malformed(format!("status list jwk header is not a valid JWK: {e}")))?;
        // The embedded key vouched for itself and nothing else: the evidence
        // must not carry any header-supplied chain.
        Ok(ResolvedKey {
            jwk,
            x5c_der: Vec::new(),
        })
    }
}

impl IssuerKeyResolver for StatusListKeyResolver {
    fn resolve(&self, header: &JoseHeader, _iss: &str) -> Result<ResolvedKey> {
        match self.source {
            StatusListKeySource::X5c => Self::x5c_leaf(header),
            StatusListKeySource::Jwk => Self::embedded_jwk(header),
            StatusListKeySource::X5cOrJwk => match header.x5c.as_deref() {
                Some(_) => Self::x5c_leaf(header),
                None => Self::embedded_jwk(header),
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct StatusListToken {
    pub claims: Value,
    pub issuer: IssuerEvidence,
}

fn header(token: &str) -> Result<JoseHeader> {
    if token.len() > MAX_TOKEN_BYTES || token.split('.').count() != 3 {
        return Err(malformed("status_list_token_shape"));
    }
    let header =
        jws::decode_header(token).map_err(|e| malformed(format!("status_list_header: {e}")))?;
    if header.alg != "ES256" {
        return Err(policy("status_list_alg"));
    }
    if header.typ.as_deref() != Some("statuslist+jwt") {
        return Err(policy("status_list_typ"));
    }
    Ok(header)
}

/// Verify a compact `statuslist+jwt` against the URI the credential referenced
/// and return its claims and signer evidence.
///
/// `expected_uri` is the `uri` from the credential's `status_list` object: per
/// Token Status List (draft-ietf-oauth-status-list) §5.1 and §8.3, the token's
/// `sub` MUST be the Status List Token's own URI and MUST equal that reference,
/// and `iat` is REQUIRED. A different list — even one signed by the same
/// trusted signer — must never speak for this credential.
pub fn verify_token(
    token: &str,
    expected_uri: &str,
    resolver: &dyn IssuerKeyResolver,
    now: i64,
) -> Result<StatusListToken> {
    let header = header(token)?;
    let resolved = resolver.resolve(&header, "status-list")?;
    let payload = jws::compact::verify_with_jwk(&resolved.jwk, token)
        .map_err(|e| integrity(format!("status list signature: {e}")))?;
    let claims: Value = json_strict::from_slice(&payload)?;
    let claims_object = claims
        .as_object()
        .ok_or_else(|| malformed("status_list_claims_not_object"))?;
    let sub = claims_object
        .get("sub")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("status_list_missing_sub"))?;
    if sub.is_empty() {
        return Err(malformed("status_list_missing_sub"));
    }
    // §5.1/§8.3: the subject MUST equal the URI the credential's status
    // reference named. A list is bound to the credentials that point at it;
    // a signer operating many lists must not have one of them speak for a
    // credential that referenced another.
    if sub != expected_uri {
        return Err(policy("status_list_uri_mismatch"));
    }
    for name in ["iat", "exp"] {
        if claims_object.get(name).is_some_and(|value| !value.is_i64()) {
            return Err(malformed(format!("status_list_{name}_not_integer")));
        }
    }
    // `iat` is REQUIRED (§5.1). The loop above rejects present-but-malformed
    // values; this rejects the claim's absence.
    let iat = claims_object
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(|| malformed("status_list_missing_iat"))?;
    if iat > now + 60 {
        return Err(policy("status_list_iat_future"));
    }
    if let Some(exp) = claims_object.get("exp").and_then(Value::as_i64) {
        if now >= exp {
            return Err(policy("status_list_expired"));
        }
    }
    let evidence = IssuerEvidence {
        iss: sub.to_owned(),
        alg: header.alg.clone(),
        kid: header.kid.clone(),
        // The chain that vouched for the verified key — never the raw header,
        // so a dual-carrier token cannot parade a decoy chain as trust
        // evidence for a key resolved from its embedded `jwk`.
        x5c_der: resolved.x5c_der,
        jwk: resolved.jwk,
    };
    Ok(StatusListToken {
        claims,
        issuer: evidence,
    })
}

/// The CWT form's protected-header typ (draft-ietf-oauth-status-list -21
/// §5.2): the FULL media type — `application/statuslist+cwt`, label 16.
const CWT_TYP: &str = "application/statuslist+cwt";
/// COSE algorithm ES256 (RFC 9053 §2) — the one alg the JWT side accepts,
/// the one alg this side accepts.
const COSE_ES256: i64 = -7;

/// Verify a `statuslist+cwt` (draft-ietf-oauth-status-list **-21** §5.2)
/// against the URI the credential referenced and return its claims and
/// signer evidence — the CWT twin of [`verify_token`].
///
/// The wire shape (§5.2): `#6.18(COSE_Sign1)` — the tag-18 wrap is
/// REQUIRED; protected `{1: -7, 16: "application/statuslist+cwt"}`; claims
/// `2 (sub)` REQUIRED = the list URI (the same §8.3 binding the JWT side
/// enforces — a different list must never speak for this credential),
/// `6 (iat)` REQUIRED, `4? (exp)`, `65534? (ttl)`, `65533` = the
/// status_list with TEXT keys: `"bits"` (1|2|4|8), `"lst"` (the RAW
/// compressed bytes — b64u-encoded into the returned claims so
/// [`status_at`] consumes both forms unchanged), `"aggregation_uri"?`.
///
/// Sans-IO as ever: the key is the CALLER'S — COSE headers carry no JOSE
/// `x5c`/`jwk` carriers to resolve, so trust binding (a kid→key registry,
/// a pinned list-signer, whatever the deployment's [`StatusListKeySource`]
/// equivalent is) happens before this call.
#[allow(clippy::result_large_err)]
pub fn verify_token_cwt(
    cwt: &[u8],
    expected_uri: &str,
    key: &Jwk,
    now: i64,
) -> Result<StatusListToken> {
    if cwt.len() > MAX_TOKEN_BYTES {
        return Err(malformed("status_list_token_shape"));
    }
    // §5.2: the CWT MUST be the tagged COSE_Sign1_Tagged (18).
    let (protected_bytes, unprotected, payload, signature) = parse_cwt_parts(cwt)?;
    let protected_cbor = crate::mdoc::parse(&protected_bytes)?;
    let signature_bytes = signature;

    // Protected: {1: alg, 16: typ}.
    let protected = match &protected_cbor {
        Cbor::Map(entries) => entries.clone(),
        _ => return Err(malformed("status_list_cwt_protected_not_map")),
    };
    let int_label = |entries: &[(Cbor, Cbor)], key: i64| -> Option<i64> {
        entries
            .iter()
            .find(|(k, _)| {
                matches!(k, Cbor::Integer(i) if i64::try_from(*i).map(|v| v == key).unwrap_or(false))
            })
            .and_then(|(_, v)| match v {
                Cbor::Integer(i) => i64::try_from(*i).ok(),
                _ => None,
            })
    };
    if int_label(&protected, 1) != Some(COSE_ES256) {
        return Err(policy("status_list_alg"));
    }
    let typ_ok = protected.iter().any(|(k, v)| {
        matches!(k, Cbor::Integer(i) if i64::try_from(*i).map(|n| n == 16).unwrap_or(false))
            && matches!(v, Cbor::Text(t) if t == CWT_TYP)
    });
    if !typ_ok {
        return Err(policy("status_list_typ"));
    }
    // kid, when present, rides the UNPROTECTED header (§5.2's example);
    // the protected position is accepted too (COSE allows both).
    let kid_text = |entries: Option<&[(Cbor, Cbor)]>| -> Option<String> {
        entries?
            .iter()
            .find(|(k, _)| {
                matches!(k, Cbor::Integer(i) if i64::try_from(*i).map(|v| v == 4).unwrap_or(false))
            })
            .and_then(|(_, v)| match v {
                Cbor::Text(t) => Some(t.clone()),
                _ => None,
            })
    };
    // kid rides the UNPROTECTED header (§5.2's example); the protected
    // position is accepted too (COSE allows both).
    let unprotected_entries = match &unprotected {
        Cbor::Map(entries) => Some(entries.as_slice()),
        _ => None,
    };
    let kid = kid_text(unprotected_entries).or_else(|| kid_text(Some(&protected.clone())));

    // The signature: ES256 over the Sig_structure — the same construction
    // mdoc's COSE rides.
    let verifying = verifying_key(key)?;
    crate::mdoc::verify_es256(
        &verifying,
        &crate::mdoc::sig_structure("Signature1", &protected_bytes, &payload),
        &signature_bytes,
    )
    .map_err(|e| integrity(format!("status list signature: {e}")))?;

    // The claims (§5.2 labels) → the SAME JSON shape verify_token produces,
    // so status_at consumes both forms unchanged.
    let claims_cbor = match crate::mdoc::parse(&payload)? {
        Cbor::Map(entries) => entries,
        _ => return Err(malformed("status_list_claims_not_object")),
    };
    let claim = |label: i64| {
        claims_cbor
            .iter()
            .find(|(k, _)| {
                matches!(k, Cbor::Integer(i) if i64::try_from(*i).map(|v| v == label).unwrap_or(false))
            })
            .map(|(_, v)| v.clone())
    };
    fn text(v: &Cbor) -> Result<&str> {
        match v {
            Cbor::Text(t) => Ok(t),
            _ => Err(malformed("status_list_cwt_claim_not_text")),
        }
    }
    fn integer(v: &Cbor, name: &str) -> Result<i64> {
        match v {
            Cbor::Integer(i) => Ok(i64::try_from(*i).unwrap_or(i64::MAX)),
            _ => Err(malformed(format!("status_list_{name}_not_integer"))),
        }
    }
    // sub (2) REQUIRED (§5.2/§8.3): the list URI the reference named.
    let sub_claim = claim(2);
    let sub = text(
        sub_claim
            .as_ref()
            .ok_or_else(|| malformed("status_list_missing_sub"))?,
    )
    .map_err(|_| malformed("status_list_missing_sub"))?;
    if sub.is_empty() {
        return Err(malformed("status_list_missing_sub"));
    }
    if sub != expected_uri {
        return Err(policy("status_list_uri_mismatch"));
    }
    // iat (6) REQUIRED; exp (4) optional — the same windows the JWT side
    // enforces.
    let iat = claim(6)
        .ok_or_else(|| malformed("status_list_missing_iat"))
        .and_then(|v| integer(&v, "iat"))?;
    if iat > now + 60 {
        return Err(policy("status_list_iat_future"));
    }
    if let Some(exp) = claim(4) {
        let exp = integer(&exp, "exp")?;
        if now >= exp {
            return Err(policy("status_list_expired"));
        }
    }
    // ttl (65534): carried when present (no enforcement, as on the JWT
    // side).
    // status_list (65533): the §4.3 map — TEXT keys.
    let status_list = claim(65533).ok_or_else(|| malformed("status_list_missing_bits"))?;
    let Cbor::Map(sl) = &status_list else {
        return Err(malformed("status_list_claims_not_object"));
    };
    let sl_text = |name: &str| {
        sl.iter()
            .find(|(k, _)| matches!(k, Cbor::Text(t) if t == name))
            .map(|(_, v)| v.clone())
    };
    let sl_bits = sl_text("bits")
        .ok_or_else(|| malformed("status_list_missing_bits"))
        .and_then(|v| integer(&v, "bits"))?;
    if !matches!(sl_bits, 1 | 2 | 4 | 8) {
        return Err(policy("status_list_unsupported_bits"));
    }
    // lst: the RAW compressed bytes (§4.3) → b64u for the shared JSON shape.
    let sl_lst = sl_text("lst")
        .ok_or_else(|| malformed("status_list_missing_lst"))
        .and_then(|v| match v {
            Cbor::Bytes(b) => Ok(b),
            _ => Err(malformed("status_list_missing_lst")),
        })?;

    let mut claims = serde_json::Map::new();
    claims.insert("sub".into(), Value::String(sub.to_owned()));
    claims.insert("iat".into(), serde_json::json!(iat));
    if let Some(exp) = claim(4).and_then(|v| integer(&v, "exp").ok()) {
        claims.insert("exp".into(), serde_json::json!(exp));
    }
    if let Some(ttl) = claim(65534).and_then(|v| integer(&v, "ttl").ok()) {
        claims.insert("ttl".into(), serde_json::json!(ttl));
    }
    claims.insert(
        "status_list".into(),
        serde_json::json!({
            "bits": sl_bits,
            "lst": crate::b64u(&sl_lst),
        }),
    );
    let evidence = IssuerEvidence {
        iss: sub.to_owned(),
        alg: "ES256".to_owned(),
        kid,
        // COSE carries no x5c in this profile; the caller's key IS the
        // evidence's key, unadorned.
        x5c_der: Vec::new(),
        jwk: key.clone(),
    };
    Ok(StatusListToken {
        claims: Value::Object(claims),
        issuer: evidence,
    })
}

/// Parse the tag-18 COSE_Sign1 into its four parts: protected (bstr),
/// unprotected (map), payload (bstr), signature (bstr).
/// The COSE_Sign1's four parts: protected (bstr), unprotected (map),
/// payload (bstr), signature (bstr).
type CoseSign1Parts = (Vec<u8>, Cbor, Vec<u8>, Vec<u8>);

fn parse_cwt_parts(cwt: &[u8]) -> Result<CoseSign1Parts> {
    let value = crate::mdoc::parse(cwt)?;
    let Cbor::Tag(18, inner) = value else {
        return Err(malformed("status_list_cwt_not_tagged"));
    };
    let Cbor::Array(parts) = *inner else {
        return Err(malformed("status_list_token_shape"));
    };
    if parts.len() != 4 {
        return Err(malformed("status_list_token_shape"));
    }
    let part = |v: &Cbor| -> Result<Vec<u8>> {
        match v {
            Cbor::Bytes(b) => Ok(b.clone()),
            _ => Err(malformed("status_list_token_shape")),
        }
    };
    Ok((
        part(&parts[0])?,
        parts[1].clone(),
        part(&parts[2])?,
        part(&parts[3])?,
    ))
}

fn verifying_key(key: &Jwk) -> Result<p256::ecdsa::VerifyingKey> {
    let x = crate::b64u_decode(
        key.x
            .as_deref()
            .ok_or_else(|| malformed("status list cwt key is not a public EC jwk"))?,
    )
    .map_err(|_| malformed("status list cwt key x is not b64u"))?;
    let y = crate::b64u_decode(
        key.y
            .as_deref()
            .ok_or_else(|| malformed("status list cwt key is not a public EC jwk"))?,
    )
    .map_err(|_| malformed("status list cwt key y is not b64u"))?;
    let mut uncompressed = vec![0x04u8];
    uncompressed.extend_from_slice(&x);
    uncompressed.extend_from_slice(&y);
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&uncompressed)
        .map_err(|e| integrity(format!("status list cwt key: {e}")))
}

fn bits(value: &Value) -> Result<usize> {
    let bits = value
        .get("status_list")
        .and_then(|list| list.get("bits"))
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed("status_list_missing_bits"))?;
    if !matches!(bits, 1 | 2 | 4 | 8) {
        return Err(policy("status_list_unsupported_bits"));
    }
    Ok(bits as usize)
}

/// Compute a status index without truncating it to the target's native word size.
pub fn index_parts(idx: u64, bits: u64) -> Result<(u64, u32)> {
    let bit = idx
        .checked_mul(bits)
        .ok_or_else(|| policy("status_list_index_overflow"))?;
    Ok((bit, (bit % 8) as u32))
}

/// Return the integer status at `reference.idx` in the list.
pub fn status_at(token: &StatusListToken, reference: &StatusRef) -> Result<u8> {
    // The lookup's own contract, independent of how the caller verified the
    // token: the bit read for a reference must come from the list that
    // reference names. `verify_token` binds the token to the reference at
    // validation time (§8.3 order, before signer trust is even asked); this
    // guard keeps the PUBLIC lookup safe for callers that did not pass the
    // same URI — a mismatched list must never answer for the reference.
    if token.claims["sub"] != Value::String(reference.uri.clone()) {
        return Err(policy("status_list_subject_mismatch"));
    }
    let bits = bits(&token.claims)?;
    let compressed = token.claims["status_list"]["lst"]
        .as_str()
        .ok_or_else(|| malformed("status_list_missing_lst"))?;
    let compressed = b64u_decode(compressed)?;
    let decoder = ZlibDecoder::new(compressed.as_slice());
    let mut bytes = Vec::new();
    decoder
        .take(MAX_DECOMPRESSED_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| malformed("status_list_deflate"))?;
    if bytes.len() > MAX_DECOMPRESSED_BYTES {
        return Err(policy("status_list_too_large"));
    }
    let (bit, shift) = index_parts(reference.idx, bits as u64)?;
    let byte = usize::try_from(bit / 8).map_err(|_| policy("status_list_index_out_of_range"))?;
    let Some(value) = bytes.get(byte) else {
        return Err(policy("status_list_index_out_of_range"));
    };
    let mask = if bits == 8 { 0xff } else { (1 << bits) - 1 };
    Ok(((value >> shift) & mask) as u8)
}

#[cfg(test)]
mod cwt_tests {
    use super::*;
    use ciborium::Value as Cbor;

    /// The draft's own §5.2 example inputs (verified byte-identical on
    /// the producer side): sub, iat, exp, ttl, and the Appendix C 1-bit
    /// vector's zlib bytes. The signature is OURS (a fresh key) — the
    /// one part of the example that cannot be reproduced.
    fn draft_example_cwt() -> (Jwk, Vec<u8>) {
        use p256::ecdsa::signature::Signer;
        use p256::elliptic_curve::Generate;
        let secret = p256::SecretKey::generate();
        let secret = p256::ecdsa::SigningKey::from(&secret);
        let public = secret.verifying_key();
        let sec1 = public.to_sec1_bytes();
        let jwk = serde_json::from_value(serde_json::json!({
            "kty": "EC", "crv": "P-256", "alg": "ES256",
            "x": crate::b64u(&sec1[1..33]),
            "y": crate::b64u(&sec1[33..]),
        }))
        .expect("jwk");

        // The payload, in §5.2's example claim order.
        let lst = [0x78, 0xda, 0xdb, 0xb9, 0x18, 0x00, 0x02, 0x17, 0x01, 0x5d];
        let payload = {
            let v = Cbor::Map(vec![
                (
                    Cbor::Integer(2.into()),
                    Cbor::Text("https://example.com/statuslists/1".into()),
                ),
                (
                    Cbor::Integer(6.into()),
                    Cbor::Integer(0x648c5bea_i64.into()),
                ),
                (
                    Cbor::Integer(4.into()),
                    Cbor::Integer(0x8898dfea_i64.into()),
                ),
                (Cbor::Integer(65534.into()), Cbor::Integer(43200i64.into())),
                (
                    Cbor::Integer(65533.into()),
                    Cbor::Map(vec![
                        (Cbor::Text("bits".into()), Cbor::Integer(1i64.into())),
                        (Cbor::Text("lst".into()), Cbor::Bytes(lst.to_vec())),
                    ]),
                ),
            ]);
            let mut buf = Vec::new();
            ciborium::into_writer(&v, &mut buf).unwrap();
            buf
        };
        let protected = {
            let v = Cbor::Map(vec![
                (Cbor::Integer(1.into()), Cbor::Integer((-7i64).into())),
                (
                    Cbor::Integer(16.into()),
                    Cbor::Text("application/statuslist+cwt".into()),
                ),
            ]);
            let mut buf = Vec::new();
            ciborium::into_writer(&v, &mut buf).unwrap();
            buf
        };
        let sig_structure = {
            let v = Cbor::Array(vec![
                Cbor::Text("Signature1".into()),
                Cbor::Bytes(protected.clone()),
                Cbor::Bytes(Vec::new()),
                Cbor::Bytes(payload.clone()),
            ]);
            let mut buf = Vec::new();
            ciborium::into_writer(&v, &mut buf).unwrap();
            buf
        };
        let signature: p256::ecdsa::Signature = secret.sign(&sig_structure);
        let signature = signature.to_bytes().to_vec();
        let cwt = {
            let v = Cbor::Tag(
                18,
                Box::new(Cbor::Array(vec![
                    Cbor::Bytes(protected),
                    Cbor::Map(Vec::new()),
                    Cbor::Bytes(payload),
                    Cbor::Bytes(signature),
                ])),
            );
            let mut buf = Vec::new();
            ciborium::into_writer(&v, &mut buf).unwrap();
            buf
        };
        (jwk, cwt)
    }

    /// The read side of the byte-oracle: the draft's own example
    /// verifies, and the Appendix C 1-bit vector's statuses read back
    /// EXACTLY — statuses[0]=1, [1]=0, [3]=1, [12]=0, [15]=1 (§4.1's
    /// worked example).
    #[test]
    fn cwt_verifies_and_reads_the_drafts_own_vector() {
        let (jwk, cwt) = draft_example_cwt();
        let now = 0x648c_5bea_i64 + 1;
        let token = verify_token_cwt(&cwt, "https://example.com/statuslists/1", &jwk, now)
            .expect("the draft's example verifies");
        assert_eq!(token.issuer.iss, "https://example.com/statuslists/1");
        let reference = crate::sdjwt::StatusRef {
            uri: "https://example.com/statuslists/1".to_owned(),
            idx: 0,
        };
        let at = |idx: u64| {
            status_at(
                &token,
                &crate::sdjwt::StatusRef {
                    uri: reference.uri.clone(),
                    idx,
                },
            )
        };
        assert_eq!(at(0).unwrap(), 1, "§4.1 status[0] = 1");
        assert_eq!(at(1).unwrap(), 0, "§4.1 status[1] = 0");
        assert_eq!(at(3).unwrap(), 1, "§4.1 status[3] = 1");
        assert_eq!(at(12).unwrap(), 0, "§4.1 status[12] = 0");
        assert_eq!(at(15).unwrap(), 1, "§4.1 status[15] = 1");
    }

    /// §8.3's binding, both directions: a list signed by the SAME key
    /// must not speak for a credential that referenced ANOTHER list.
    #[test]
    fn cwt_wrong_uri_refuses() {
        let (jwk, cwt) = draft_example_cwt();
        let err = verify_token_cwt(
            &cwt,
            "https://someone-else.example.org/lists/1",
            &jwk,
            0x648c_5bea_i64 + 1,
        )
        .unwrap_err();
        assert!(err.to_string().contains("uri_mismatch"), "{err}");
    }

    /// A key that did not sign it: integrity refusal, never a parse.
    #[test]
    fn cwt_wrong_key_refuses() {
        let (_jwk, cwt) = draft_example_cwt();
        let other = serde_json::from_value(serde_json::json!({
            "kty": "EC", "crv": "P-256", "alg": "ES256",
            "x": crate::b64u(&[1u8; 32]),
            "y": crate::b64u(&[2u8; 32]),
        }))
        .expect("jwk");
        let err = verify_token_cwt(
            &cwt,
            "https://example.com/statuslists/1",
            &other,
            0x648c_5bea_i64 + 1,
        )
        .unwrap_err();
        assert!(err.to_string().contains("signature"), "{err}");
    }

    /// exp in the past: expired, exactly as the JWT side.
    #[test]
    fn cwt_expired_refuses() {
        let (jwk, cwt) = draft_example_cwt();
        let err = verify_token_cwt(
            &cwt,
            "https://example.com/statuslists/1",
            &jwk,
            0x8898_dfea_i64 + 1,
        )
        .unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    /// The untagged form: §5.2 says the tag-18 wrap is REQUIRED — a bare
    /// COSE_Sign1 array is not a Status List Token.
    #[test]
    fn cwt_requires_the_tag18_wrap() {
        let (jwk, mut cwt) = draft_example_cwt();
        // Strip the tag: d2 84 … → 84 …
        assert_eq!(cwt[0], 0xd2);
        cwt.remove(0);
        let err = verify_token_cwt(
            &cwt,
            "https://example.com/statuslists/1",
            &jwk,
            0x648c_5bea_i64 + 1,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not_tagged"), "{err}");
    }
}
