//! IETF Token Status List (JWT) parsing and bit lookup, sans-I/O.
//!
//! Fetching and signer trust belong to the caller. This module verifies the
//! token's signature and returns status evidence; it never decides trust.

use std::io::Read;

use flate2::read::ZlibDecoder;
use jose_rs::jwk::Jwk;
use jose_rs::{jws, JoseHeader};
use serde_json::Value;

use crate::error::{integrity, malformed, policy};
use crate::sdjwt::{x5c_chain, IssuerEvidence, IssuerKeyResolver, StatusRef};
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
    fn x5c_leaf(header: &JoseHeader) -> Result<Jwk> {
        let chain = x5c_chain(header)?;
        let leaf = chain
            .first()
            .ok_or_else(|| malformed("status list token carries no x5c chain"))?;
        crate::sdjwt::jwk_from_cert_der(leaf)
    }

    fn embedded_jwk(header: &JoseHeader) -> Result<Jwk> {
        let value = header
            .jwk
            .as_ref()
            .ok_or_else(|| malformed("status list token carries no embedded jwk"))?;
        serde_json::from_value(value.clone())
            .map_err(|e| malformed(format!("status list jwk header is not a valid JWK: {e}")))
    }
}

impl IssuerKeyResolver for StatusListKeyResolver {
    fn resolve(&self, header: &JoseHeader, _iss: &str) -> Result<Jwk> {
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
    let chain = x5c_chain(&header)?;
    let jwk = resolver.resolve(&header, "status-list")?;
    let payload = jws::compact::verify_with_jwk(&jwk, token)
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
        x5c_der: chain,
        jwk,
    };
    Ok(StatusListToken {
        claims,
        issuer: evidence,
    })
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
