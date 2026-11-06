//! IETF Token Status List (JWT) parsing and bit lookup, sans-I/O.
//!
//! Fetching and signer trust belong to the caller. This module verifies the
//! token's signature and returns status evidence; it never decides trust.

use std::io::Read;

use flate2::read::ZlibDecoder;
use jose_rs::{jws, JoseHeader};
use serde_json::Value;

use crate::error::{integrity, malformed, policy};
use crate::sdjwt::{x5c_chain, IssuerEvidence, IssuerKeyResolver, StatusRef};
use crate::{b64u_decode, json_strict, Result};

const MAX_TOKEN_BYTES: usize = 64 * 1024;
const MAX_DECOMPRESSED_BYTES: usize = 1024 * 1024;

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

/// Verify a compact `statuslist+jwt` and return its claims and signer evidence.
pub fn verify_token(
    token: &str,
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
    for name in ["iat", "exp"] {
        if claims_object.get(name).is_some_and(|value| !value.is_i64()) {
            return Err(malformed(format!("status_list_{name}_not_integer")));
        }
    }
    if let Some(exp) = claims_object.get("exp").and_then(Value::as_i64) {
        if now >= exp {
            return Err(policy("status_list_expired"));
        }
    }
    if let Some(iat) = claims_object.get("iat").and_then(Value::as_i64) {
        if iat > now + 60 {
            return Err(policy("status_list_iat_future"));
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
