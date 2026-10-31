//! OpenID4VP verifier side: signed request object and encrypted response.
//!
//! Covers the `x509_hash` client identifier scheme, `response_mode=direct_post.jwt`
//! with an ephemeral ECDH-ES key, DCQL for `dc+sd-jwt`, and key-bound
//! presentations. mdoc, DC API and `credential_sets` are out of the spike.
//!
//! Sans-IO: `create_request` returns the JWT to serve and a [`Session`] to keep
//! (sealed, in the real design); `process_response` takes the posted JWE.

use crate::error::{integrity, malformed, policy};
use crate::sdjwt::{self, CryptoVerified, HolderBinding, IssuerKeyResolver, VerifyParams};
use crate::{b64u, b64u_decode, Error, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use jose_rs::jwe::compact as jwe_compact;
use jose_rs::jwk::Jwk;
use jose_rs::jws::compact::{sign_with_options, SignOptions};
use jose_rs::JoseHeader;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const REQUEST_AUD: &str = "https://self-issued.me/v2";
const MAX_RESPONSE_JWE: usize = 1024 * 1024;
const MAX_RESPONSE_PLAINTEXT: usize = 512 * 1024;

pub struct RequestConfig {
    pub response_uri: String,
    pub dcql_query: Value,
    pub ttl_secs: i64,
}

/// Everything the verifier must remember between request and response.
/// In the service this is AEAD-sealed; it holds the ephemeral private key.
#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    pub client_id: String,
    pub nonce: String,
    pub state: String,
    pub response_uri: String,
    pub dcql_query: Value,
    pub expires_at: i64,
    pub enc_key: Jwk,
    /// Bare browser origin for the DC API holder-binding audience. Redirect
    /// flows leave this unset and use `client_id` instead.
    #[serde(default)]
    pub dc_api_origin: Option<String>,
}

impl Session {
    fn holder_binding_audience(&self) -> String {
        self.dc_api_origin
            .as_ref()
            .map(|origin| format!("origin:{origin}"))
            .unwrap_or_else(|| self.client_id.clone())
    }
}

#[derive(Debug)]
pub struct PresentationResult {
    pub credential_id: String,
    pub verified: CryptoVerified,
}

pub fn x509_hash_client_id(leaf_der: &[u8]) -> String {
    format!("x509_hash:{}", b64u(&Sha256::digest(leaf_der)))
}

fn random_token() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("OS randomness");
    b64u(&b)
}

/// Build a signed request object. `signer` is any kryptering `Signer`, so the
/// long-term key can live in software, an HSM or a KMS behind the same trait.
pub fn create_request(
    cfg: &RequestConfig,
    signer: &dyn kryptering::Signer,
    alg: &str,
    chain_der: &[Vec<u8>],
    now: i64,
) -> Result<(String, Session)> {
    create_request_with_response_mode(cfg, signer, alg, chain_der, now, "direct_post.jwt", None)
}

/// Create a request for the W3C Digital Credentials API's encrypted-response
/// profile. Verification and response processing are identical to QR/direct
/// post; only the response mode advertised to the wallet changes.
pub fn create_dc_api_request(
    cfg: &RequestConfig,
    signer: &dyn kryptering::Signer,
    alg: &str,
    chain_der: &[Vec<u8>],
    now: i64,
    origin: &str,
) -> Result<(String, Session)> {
    create_request_with_response_mode(cfg, signer, alg, chain_der, now, "dc_api.jwt", Some(origin))
}

fn create_request_with_response_mode(
    cfg: &RequestConfig,
    signer: &dyn kryptering::Signer,
    alg: &str,
    chain_der: &[Vec<u8>],
    now: i64,
    response_mode: &str,
    dc_api_origin: Option<&str>,
) -> Result<(String, Session)> {
    if let Some(origin) = dc_api_origin {
        let authority = origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .filter(|rest| {
                !rest.is_empty()
                    && !rest.contains(['/', '?', '#', '@'])
                    && !rest.chars().any(char::is_whitespace)
            });
        if authority.is_none() {
            return Err(malformed("DC API origin must be a bare HTTP(S) origin"));
        }
    }
    let leaf = chain_der
        .first()
        .ok_or_else(|| malformed("certificate chain is empty"))?;
    let client_id = x509_hash_client_id(leaf);

    let mut enc_key = jose_rs::jwk::generate_ec("P-256")?;
    enc_key.alg = Some("ECDH-ES".into());
    enc_key.use_ = Some("enc".into());
    enc_key.kid = Some(random_token());
    let mut enc_pub = enc_key.to_public_jwk();
    enc_pub.alg = Some("ECDH-ES".into());

    let session = Session {
        client_id: client_id.clone(),
        nonce: random_token(),
        state: random_token(),
        response_uri: cfg.response_uri.clone(),
        dcql_query: cfg.dcql_query.clone(),
        expires_at: now + cfg.ttl_secs,
        enc_key,
        dc_api_origin: dc_api_origin.map(str::to_owned),
    };

    let payload = json!({
        "iat": now,
        "exp": session.expires_at,
        "aud": REQUEST_AUD,
        "client_id": client_id,
        "response_type": "vp_token",
        "response_mode": response_mode,
        "response_uri": cfg.response_uri,
        "nonce": session.nonce,
        "state": session.state,
        "dcql_query": cfg.dcql_query,
        "client_metadata": {
            "jwks": { "keys": [enc_pub] },
            "encrypted_response_enc_values_supported": ["A128GCM", "A256GCM"],
            "vp_formats_supported": {
                "dc+sd-jwt": { "sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["ES256"] }
            },
        },
    });
    let mut header = JoseHeader::new(alg);
    header.typ = Some("oauth-authz-req+jwt".into());
    header.x5c = Some(chain_der.iter().map(|d| B64.encode(d)).collect());
    let opts = SignOptions::new().with_key_reference_headers(true);
    let jar = sign_with_options(
        signer,
        &serde_json::to_vec(&payload).unwrap(),
        &header,
        &opts,
    )?;
    Ok((jar, session))
}

/// Validate the DCQL subset this verifier can actually evaluate. User-authored
/// queries are rejected at request time rather than producing a request whose
/// response can only fail later.
pub fn validate_dcql_query(query: &Value) -> Result<()> {
    let root = query
        .as_object()
        .ok_or_else(|| malformed("dcql_query must be an object"))?;
    if root.contains_key("credential_sets") {
        return Err(policy("credential_sets are not supported"));
    }
    if root.keys().any(|k| k != "credentials") {
        return Err(policy("unsupported dcql_query member"));
    }
    let credentials = root
        .get("credentials")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("dcql_query without credentials"))?;
    if credentials.is_empty() {
        return Err(policy("dcql_query must request a credential"));
    }
    let mut credential_ids = std::collections::BTreeSet::new();
    for query in credentials {
        let query = query
            .as_object()
            .ok_or_else(|| malformed("credential query must be an object"))?;
        if query
            .keys()
            .any(|k| !matches!(k.as_str(), "id" | "format" | "meta" | "claims" | "multiple"))
        {
            return Err(policy("unsupported credential query member"));
        }
        if query.get("format").and_then(Value::as_str) != Some("dc+sd-jwt") {
            return Err(policy("only dc+sd-jwt is supported"));
        }
        match query.get("id").and_then(Value::as_str) {
            Some(id) if !id.is_empty() && credential_ids.insert(id) => {}
            Some(_) => return Err(policy("duplicate or empty credential query id")),
            _ => return Err(malformed("credential query without id")),
        }
        if let Some(meta) = query.get("meta") {
            let meta = meta
                .as_object()
                .ok_or_else(|| malformed("credential meta must be an object"))?;
            if meta.keys().any(|k| k != "vct_values") {
                return Err(policy("unsupported credential meta member"));
            }
        }
        if query.get("claims").is_some_and(|claims| !claims.is_array()) {
            return Err(malformed("claims must be an array"));
        }
        if let Some(values) = query.get("meta").and_then(|meta| meta.get("vct_values")) {
            let values = values
                .as_array()
                .ok_or_else(|| malformed("vct_values must be an array"))?;
            if values.is_empty() || values.iter().any(|v| v.as_str().is_none()) {
                return Err(malformed("vct_values must contain strings"));
            }
        }
        if query
            .get("multiple")
            .is_some_and(|multiple| multiple.as_bool().is_none())
        {
            return Err(malformed("multiple must be boolean"));
        }
        for claim in query
            .get("claims")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let claim = claim
                .as_object()
                .ok_or_else(|| malformed("claim must be an object"))?;
            if claim
                .keys()
                .any(|k| !matches!(k.as_str(), "path" | "id" | "values"))
            {
                return Err(policy("unsupported claim member"));
            }
            let path = claim
                .get("path")
                .and_then(Value::as_array)
                .ok_or_else(|| malformed("claim without path"))?;
            if path.is_empty()
                || path.iter().enumerate().any(|(index, segment)| {
                    segment.is_null() && index + 1 != path.len()
                        || (!segment.is_null() && segment.as_str().is_none())
                })
            {
                return Err(policy(
                    "claim paths need string segments and an optional trailing null array selector",
                ));
            }
            if let Some(values) = claim.get("values") {
                if !values.is_array() {
                    return Err(malformed("claim values must be an array"));
                }
            }
        }
    }
    Ok(())
}

/// Minimal DCQL evaluation for `dc+sd-jwt`: format, `vct_values`, claim paths
/// (string segments only) and optional `values`. Anything else fails closed.
fn dcql_match(query: &Value, v: &CryptoVerified) -> Result<()> {
    if query.get("format").and_then(Value::as_str) != Some("dc+sd-jwt") {
        return Err(policy("only dc+sd-jwt is supported in the spike"));
    }
    if let Some(vals) = query.pointer("/meta/vct_values") {
        let vals = vals
            .as_array()
            .ok_or_else(|| malformed("vct_values must be an array"))?;
        if !vals.iter().any(|x| x.as_str() == Some(v.vct.as_str())) {
            return Err(policy("credential vct is not in vct_values"));
        }
    }
    for claim in query
        .get("claims")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let path = claim
            .get("path")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed("claim without path"))?;
        let root = Value::Object(v.claims.clone());
        let mut current = vec![&root];
        for segment in path {
            let mut next = Vec::new();
            for value in current {
                if segment.is_null() {
                    let items = value
                        .as_array()
                        .ok_or_else(|| policy("claim array selector used on a non-array"))?;
                    next.extend(items.iter());
                } else {
                    let name = segment
                        .as_str()
                        .ok_or_else(|| policy("invalid claim path segment"))?;
                    next.push(value.get(name).ok_or_else(|| {
                        policy(format!("requested claim {name} was not disclosed"))
                    })?);
                }
            }
            if next.is_empty() {
                return Err(policy("requested claim path has no values"));
            }
            current = next;
        }
        if let Some(vals) = claim.get("values").and_then(Value::as_array) {
            if !current.iter().any(|value| vals.contains(value)) {
                return Err(policy("claim value is not among the requested values"));
            }
        }
    }
    Ok(())
}

/// Apply the OpenID4VP response policy before handing the authenticated
/// decryption to jose-rs. In particular, reject excessive ciphertext before
/// key operations; jose-rs's one-shot JWK API does not take a plaintext limit.
fn decrypt_response(session: &Session, jwe: &str) -> Result<jose_rs::Authenticated<Vec<u8>>> {
    if jwe.len() > MAX_RESPONSE_JWE {
        return Err(policy("response token too large"));
    }
    let parts: Vec<&str> = jwe.split('.').collect();
    if parts.len() != 5 {
        return Err(malformed("JWE compact serialization needs 5 parts"));
    }
    if !parts[1].is_empty() {
        return Err(malformed(
            "ECDH-ES direct agreement must have an empty encrypted key",
        ));
    }

    // Check the exact protected bytes before jose-rs performs typed decoding;
    // repeated member names are never accepted, even when values are equal.
    crate::json_strict::from_slice(&b64u_decode(parts[0])?)?;
    let header = jwe_compact::decode_header(jwe)?;
    if header.alg != "ECDH-ES" {
        return Err(policy("response alg must be ECDH-ES"));
    }
    if !matches!(header.enc.as_deref(), Some("A128GCM" | "A256GCM")) {
        return Err(policy("unsupported response enc"));
    }
    if header.crit.is_some() || header.extra.contains_key("zip") {
        return Err(policy("unsupported response header parameter"));
    }
    if header
        .extra
        .get("epk")
        .and_then(Value::as_object)
        .is_some_and(|epk| epk.contains_key("d"))
    {
        return Err(policy("epk must not contain private key material"));
    }
    if b64u_decode(parts[3])?.len() > MAX_RESPONSE_PLAINTEXT {
        return Err(policy("response ciphertext exceeds policy limit"));
    }

    let dec = jwe_compact::decrypt_with_jwk_authenticated(&session.enc_key, jwe).map_err(|e| {
        if e.is_authentication_failure() {
            integrity("response JWE authentication failed")
        } else {
            Error::Jose(e)
        }
    })?;
    if dec.value.len() > MAX_RESPONSE_PLAINTEXT {
        return Err(policy("response plaintext exceeds policy limit"));
    }
    Ok(dec)
}

/// Process the wallet's `direct_post.jwt` response (the `response` form value).
pub fn process_response(
    session: &Session,
    jwe: &str,
    now: i64,
    resolver: &dyn IssuerKeyResolver,
) -> Result<Vec<PresentationResult>> {
    if now >= session.expires_at {
        return Err(policy("request has expired"));
    }
    let dec = decrypt_response(session, jwe)?;
    if dec.protected.kid.as_deref() != session.enc_key.kid.as_deref() {
        return Err(integrity("response was encrypted to a different key"));
    }
    let body = crate::json_strict::from_slice(&dec.value)
        .map_err(|e| malformed(format!("response is not JSON: {e}")))?;
    if let Some(err) = body.get("error") {
        return Err(policy(format!("wallet returned an error: {err}")));
    }
    if body.get("state").and_then(Value::as_str) != Some(session.state.as_str()) {
        return Err(integrity("state mismatch"));
    }
    let vp = body
        .get("vp_token")
        .and_then(Value::as_object)
        .ok_or_else(|| malformed("missing vp_token object"))?;

    if session.dcql_query.get("credential_sets").is_some() {
        return Err(policy("credential_sets are not supported in the spike"));
    }
    let queries = session
        .dcql_query
        .get("credentials")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("dcql_query without credentials"))?;
    let find = |id: &str| {
        queries
            .iter()
            .find(|q| q.get("id").and_then(Value::as_str) == Some(id))
    };

    for id in vp.keys() {
        if find(id).is_none() {
            return Err(policy(format!(
                "vp_token contains unrequested credential id {id}"
            )));
        }
    }
    let audience = session.holder_binding_audience();
    let params = VerifyParams::new(
        now,
        HolderBinding::Required {
            aud: &audience,
            nonce: &session.nonce,
            max_age_secs: 300,
        },
    );
    let mut out = Vec::new();
    for q in queries {
        let id = q
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed("credential query without id"))?;
        let list = vp
            .get(id)
            .and_then(Value::as_array)
            .ok_or_else(|| policy(format!("required credential {id} is missing")))?;
        let multiple = q.get("multiple").and_then(Value::as_bool).unwrap_or(false);
        if list.is_empty() || (!multiple && list.len() != 1) {
            return Err(policy(format!("wrong number of presentations for {id}")));
        }
        for item in list {
            let presentation = item
                .as_str()
                .ok_or_else(|| malformed("presentation must be a string"))?;
            let verified = sdjwt::verify(presentation, resolver, &params)?;
            dcql_match(q, &verified)?;
            out.push(PresentationResult {
                credential_id: id.to_owned(),
                verified,
            });
        }
    }
    Ok(out)
}

/// A software signer from a private JWK, for tests and development.
pub fn software_signer(jwk: &Jwk) -> Result<kryptering::SoftwareSigner> {
    let alg = jose_rs::JwsAlgorithm::from_str(
        jwk.alg
            .as_deref()
            .ok_or_else(|| malformed("JWK without alg"))?,
    )?;
    let key = jose_rs::jwk::jwk_to_signature_key(jwk, alg, jose_rs::JwkOp::Sign)?;
    Ok(kryptering::SoftwareSigner::new(alg.to_crypto()?, key)
        .map_err(jose_rs::JoseError::Crypto)?)
}
