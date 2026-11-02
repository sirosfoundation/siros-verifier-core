//! OpenID4VP verifier side: signed request object and encrypted response.
//!
//! Covers the `x509_hash` client identifier scheme, encrypted
//! `direct_post.jwt` and `dc_api.jwt` responses, DCQL for `dc+sd-jwt` and
//! `mso_mdoc`, and their distinct mdoc handover encodings. `credential_sets`
//! remains unsupported.
//!
//! Sans-IO: `create_request` returns the JWT to serve and a [`Session`] to keep
//! (sealed, in the real design); `process_response` takes the posted JWE.

use crate::error::{integrity, malformed, policy};
use crate::sdjwt::{self, CryptoVerified, HolderBinding, IssuerKeyResolver, VerifyParams};
use crate::trust::TrustQuery;
use crate::{b64u, b64u_decode, Error, Result};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use jose_rs::jwk::agreement::{agreement_key, peer_key};
use jose_rs::jwk::Jwk;
use jose_rs::jws::compact::{sign_with_options, SignOptions};
use jose_rs::JoseHeader;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const REQUEST_AUD: &str = "https://self-issued.me/v2";
// Genuine Pixel Longfellow presentations exceed 1 MiB after CBOR and JWE
// base64 expansion. Keep independent token and plaintext ceilings.
const MAX_RESPONSE_JWE: usize = 2 * 1024 * 1024;
const MAX_RESPONSE_PLAINTEXT: usize = 1024 * 1024;

pub struct RequestConfig {
    pub response_uri: String,
    pub dcql_query: Value,
    pub ttl_secs: i64,
    /// `client_metadata.vp_formats_supported` to advertise. `None` derives the
    /// existing SD-JWT/mdoc metadata from the requested credentials.
    pub vp_formats_supported: Option<Value>,
    /// Explicit client ID for formats that require a different scheme from the
    /// default x509_hash. `zkp_req` uses x509_san_dns or semantic_id.
    pub client_id: Option<String>,
}

/// Everything the verifier must remember between request and response.
/// In the service this is AEAD-sealed; it holds the ephemeral private key.
fn default_response_mode() -> String {
    "direct_post.jwt".into()
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    pub client_id: String,
    pub nonce: String,
    pub state: String,
    pub response_uri: String,
    pub dcql_query: Value,
    pub expires_at: i64,
    pub enc_key: Jwk,
    #[serde(default = "default_response_mode")]
    pub response_mode: String,
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

    /// The exact tag-24 SessionTranscriptBytes used by OpenID4VP mdoc. QR
    /// uses client_id/response_uri; DC API uses the bare platform origin.
    pub fn mdoc_session_transcript_bytes(&self) -> Result<Vec<u8>> {
        let thumbprint =
            jose_rs::jwk::thumbprint::thumbprint_sha256(&self.enc_key.to_public_jwk())?;
        let thumbprint = b64u_decode(&thumbprint)?;
        if thumbprint.len() != 32 {
            return Err(malformed("encryption JWK thumbprint must be 32 bytes"));
        }
        mdoc_transcript_parts(
            &self.response_mode,
            &self.client_id,
            &self.nonce,
            &self.response_uri,
            self.dc_api_origin.as_deref(),
            thumbprint,
        )
    }
}

fn mdoc_transcript_parts(
    mode: &str,
    client_id: &str,
    nonce: &str,
    response_uri: &str,
    origin: Option<&str>,
    thumbprint: Vec<u8>,
) -> Result<Vec<u8>> {
    use ciborium::Value as Cbor;
    let (handover, info) = match mode {
        "direct_post.jwt" => (
            "OpenID4VPHandover",
            vec![
                Cbor::Text(client_id.to_owned()),
                Cbor::Text(nonce.to_owned()),
                Cbor::Bytes(thumbprint),
                Cbor::Text(response_uri.to_owned()),
            ],
        ),
        "dc_api.jwt" => (
            "OpenID4VPDCAPIHandover",
            vec![
                Cbor::Text(
                    origin
                        .filter(|origin| !origin.is_empty())
                        .ok_or_else(|| malformed("DC API origin is missing"))?
                        .to_owned(),
                ),
                Cbor::Text(nonce.to_owned()),
                Cbor::Bytes(thumbprint),
            ],
        ),
        _ => return Err(policy("unsupported mdoc response mode")),
    };
    let info = cbor_encode(&Cbor::Array(info));
    let transcript = Cbor::Array(vec![
        Cbor::Null,
        Cbor::Null,
        Cbor::Array(vec![
            Cbor::Text(handover.to_owned()),
            Cbor::Bytes(Sha256::digest(info).to_vec()),
        ]),
    ]);
    Ok(cbor_encode(&Cbor::Tag(
        24,
        Box::new(Cbor::Bytes(cbor_encode(&transcript))),
    )))
}

fn cbor_encode(value: &ciborium::Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("in-memory CBOR write");
    out
}

#[derive(Debug)]
pub enum VerifiedCredential {
    SdJwt(Box<CryptoVerified>),
    Mdoc(crate::mdoc::MdocVerified),
}

impl VerifiedCredential {
    pub fn vct(&self) -> &str {
        match self {
            Self::SdJwt(verified) => &verified.vct,
            Self::Mdoc(verified) => &verified.doc_type,
        }
    }

    pub fn issuer_id(&self) -> String {
        match self {
            Self::SdJwt(verified) => verified.issuer.iss.clone(),
            Self::Mdoc(verified) => verified
                .issuer
                .x5c_der
                .first()
                .map(|leaf| x509_hash_client_id(leaf))
                .unwrap_or_default(),
        }
    }

    pub fn trust_query(&self, role: &str, mdoc_role: &str) -> TrustQuery {
        match self {
            Self::SdJwt(verified) => TrustQuery::for_issuer(&verified.issuer, role, &verified.vct),
            Self::Mdoc(verified) => {
                TrustQuery::for_mdoc_issuer(&verified.issuer, mdoc_role, &verified.doc_type)
            }
        }
    }

    pub fn claims(&self) -> Result<serde_json::Map<String, Value>> {
        match self {
            Self::SdJwt(verified) => Ok(verified.claims.clone()),
            Self::Mdoc(verified) => verified
                .elements
                .iter()
                .map(|(namespace, elements)| {
                    let mut object = serde_json::Map::new();
                    for (name, value) in elements {
                        object.insert(name.clone(), cbor_to_json(value)?);
                    }
                    Ok((namespace.clone(), Value::Object(object)))
                })
                .collect::<Result<serde_json::Map<_, _>>>()
                .map(|claims| {
                    let mut root = serde_json::Map::new();
                    root.extend(claims);
                    root
                }),
        }
    }
}

fn cbor_to_json(value: &ciborium::Value) -> Result<Value> {
    use ciborium::Value as Cbor;
    Ok(match value {
        Cbor::Null => Value::Null,
        Cbor::Bool(value) => Value::Bool(*value),
        Cbor::Integer(value) => {
            let value = i128::from(*value);
            let value = serde_json::Number::from_i128(value)
                .ok_or_else(|| policy("mdoc integer claim is outside JSON range"))?;
            Value::Number(value)
        }
        Cbor::Float(value) => {
            let value = serde_json::Number::from_f64(*value)
                .ok_or_else(|| policy("mdoc float claim is outside JSON range"))?;
            Value::Number(value)
        }
        Cbor::Bytes(_) => {
            return Err(policy(
                "mdoc byte-string claims cannot be mapped to OIDC attributes",
            ))
        }
        Cbor::Text(value) => Value::String(value.clone()),
        Cbor::Array(values) => {
            Value::Array(values.iter().map(cbor_to_json).collect::<Result<_>>()?)
        }
        Cbor::Map(values) => {
            let mut object = serde_json::Map::new();
            for (name, value) in values {
                let Cbor::Text(name) = name else {
                    return Err(policy("mdoc claim map key is not text"));
                };
                if object.insert(name.clone(), cbor_to_json(value)?).is_some() {
                    return Err(policy("duplicate mdoc claim name"));
                }
            }
            Value::Object(object)
        }
        Cbor::Tag(_, value) => cbor_to_json(value)?,
        _ => return Err(policy("unsupported mdoc claim type")),
    })
}

#[derive(Debug)]
pub struct PresentationResult {
    pub credential_id: String,
    pub verified: VerifiedCredential,
}

pub fn x509_hash_client_id(leaf_der: &[u8]) -> String {
    format!("x509_hash:{}", b64u(&Sha256::digest(leaf_der)))
}

fn random_token() -> String {
    let mut b = [0u8; 32];
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
    let client_id = match &cfg.client_id {
        Some(id) => {
            if !(id.starts_with("x509_san_dns:") || id.starts_with("semantic_id:")) {
                return Err(malformed("unsupported explicit client_id scheme"));
            }
            id.clone()
        }
        None => x509_hash_client_id(leaf),
    };

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
        response_mode: response_mode.to_owned(),
        dc_api_origin: dc_api_origin.map(str::to_owned),
    };

    let mdoc_requested = cfg
        .dcql_query
        .get("credentials")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|query| query.get("format").and_then(Value::as_str) == Some("mso_mdoc"));
    let vp_formats_supported = cfg.vp_formats_supported.clone().unwrap_or_else(|| {
        if mdoc_requested {
            json!({
                "dc+sd-jwt": { "sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["ES256"] },
                "mso_mdoc": { "issuerauth_alg_values": [-7], "deviceauth_alg_values": [-7] }
            })
        } else {
            json!({
                "dc+sd-jwt": { "sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["ES256"] }
            })
        }
    });
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
            "vp_formats_supported": vp_formats_supported,
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
    if credentials
        .iter()
        .any(|query| query.get("format").and_then(Value::as_str) == Some("zkp_req"))
    {
        if credentials.len() != 1 {
            return Err(policy("zkp_req must be the only credential query"));
        }
        let metadata = serde_json::json!({
            "vp_formats_supported": {
                "zkp_req": {"system_id_values": ["urn:circuits:longfellow:nym_auth:v1"]}
            }
        });
        let plan = siros_dc_matcher_core::zkp_req::plan(
            &credentials[0].to_string(),
            Some(&metadata.to_string()),
        )
        .map_err(|e| Error::Policy(format!("zkp_req query: {}", e.code())))?;
        siros_dc_matcher_core::zkp_req::unsatisfiable(&plan).map_err(|e| {
            Error::Policy(format!("zkp_req query cannot be satisfied: {}", e.code()))
        })?;
        return Ok(());
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
        let format = query
            .get("format")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed("credential query without format"))?;
        if !matches!(format, "dc+sd-jwt" | "mso_mdoc") {
            return Err(policy("only dc+sd-jwt and mso_mdoc are supported"));
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
            let expected_meta = match format {
                "dc+sd-jwt" => "vct_values",
                "mso_mdoc" => "doctype_value",
                _ => unreachable!(),
            };
            if meta.keys().any(|k| k != expected_meta) {
                return Err(policy("unsupported credential meta member"));
            }
        }
        if format == "mso_mdoc"
            && query
                .get("meta")
                .and_then(|meta| meta.get("doctype_value"))
                .and_then(Value::as_str)
                .filter(|doctype| !doctype.is_empty())
                .is_none()
        {
            return Err(malformed("mdoc query without doctype_value"));
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
            if format == "mso_mdoc"
                && (path.len() != 2 || path.iter().any(|segment| segment.as_str().is_none()))
            {
                return Err(policy(
                    "mdoc claim paths need namespace and element identifier",
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

fn mdoc_match(query: &Value, verified: &crate::mdoc::MdocVerified) -> Result<()> {
    if query.get("format").and_then(Value::as_str) != Some("mso_mdoc") {
        return Err(policy("credential is not an mdoc"));
    }
    let doctype = query
        .get("meta")
        .and_then(|meta| meta.get("doctype_value"))
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("mdoc query without doctype_value"))?;
    if doctype != verified.doc_type {
        return Err(policy("credential doctype is not requested"));
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
        if path.len() != 2 {
            return Err(policy(
                "mdoc claim paths need namespace and element identifier",
            ));
        }
        let namespace = path[0]
            .as_str()
            .ok_or_else(|| policy("mdoc namespace must be a string"))?;
        let element = path[1]
            .as_str()
            .ok_or_else(|| policy("mdoc element identifier must be a string"))?;
        let value = verified
            .elements
            .get(namespace)
            .and_then(|elements| elements.get(element))
            .ok_or_else(|| {
                policy(format!(
                    "requested mdoc claim {namespace}/{element} was not released"
                ))
            })?;
        if let Some(expected) = claim.get("values").and_then(Value::as_array) {
            let actual = cbor_to_json(value)?;
            if !expected.contains(&actual) {
                return Err(policy("mdoc claim value is not among the requested values"));
            }
        }
    }
    Ok(())
}

/// Apply the OpenID4VP response policy before handing the authenticated
/// decryption to jose-rs. In particular, reject excessive ciphertext before
/// key operations; jose-rs's one-shot JWK API does not take a plaintext limit.
fn decrypt_response(session: &Session, jwe: &str) -> Result<(Vec<u8>, JoseHeader)> {
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

    // Check the exact protected bytes before typed decoding; repeated member
    // names are never accepted, even when values are equal. Parsing the small
    // header directly also keeps jose-rs's global compact-token default out of
    // this explicitly bounded application path.
    let protected_bytes = b64u_decode(parts[0])?;
    crate::json_strict::from_slice(&protected_bytes)?;
    let header: JoseHeader = serde_json::from_slice(&protected_bytes)
        .map_err(|e| malformed(format!("bad JWE header: {e}")))?;
    if header.alg != "ECDH-ES" {
        return Err(policy("response alg must be ECDH-ES"));
    }
    let enc = header.enc.as_deref().unwrap_or_default();
    if !matches!(enc, "A128GCM" | "A256GCM") {
        return Err(policy("unsupported response enc in protected header"));
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
    let iv = b64u_decode(parts[2])?;
    let ciphertext = b64u_decode(parts[3])?;
    let tag = b64u_decode(parts[4])?;
    if iv.len() != 12 || tag.len() != 16 {
        return Err(malformed("invalid AES-GCM IV or tag length"));
    }
    let iv: [u8; 12] = iv
        .try_into()
        .map_err(|_| malformed("invalid AES-GCM IV length"))?;
    if ciphertext.len() > MAX_RESPONSE_PLAINTEXT {
        return Err(policy("response ciphertext exceeds policy limit"));
    }

    let cek = response_cek(&session.enc_key, &header, enc)?;
    let mut authenticated = ciphertext;
    authenticated.extend_from_slice(&tag);
    let aad = parts[0].as_bytes();
    let nonce = Nonce::from(iv);
    let plaintext = match enc {
        "A128GCM" => Aes128Gcm::new_from_slice(&cek)
            .map_err(|_| integrity("invalid AES-128 key"))?
            .decrypt(
                &nonce,
                Payload {
                    msg: &authenticated,
                    aad,
                },
            ),
        "A256GCM" => Aes256Gcm::new_from_slice(&cek)
            .map_err(|_| integrity("invalid AES-256 key"))?
            .decrypt(
                &nonce,
                Payload {
                    msg: &authenticated,
                    aad,
                },
            ),
        _ => unreachable!("enc was checked above"),
    }
    .map_err(|_| integrity("response JWE authentication failed"))?;
    if plaintext.len() > MAX_RESPONSE_PLAINTEXT {
        return Err(policy("response plaintext exceeds policy limit"));
    }
    Ok((plaintext, header))
}

/// Derive the content-encryption key with jose-rs's validated JWK agreement
/// and Concat KDF. Compact-token parsing stays above this primitive boundary.
pub(crate) fn response_cek(
    recipient: &Jwk,
    header: &JoseHeader,
    enc: &str,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let epk = header
        .extra
        .get("epk")
        .cloned()
        .ok_or_else(|| malformed("missing epk"))?;
    let epk: Jwk = serde_json::from_value(epk).map_err(|e| malformed(format!("bad epk: {e}")))?;
    if epk.d.is_some() {
        return Err(policy("epk must not contain private key material"));
    }
    let recipient = agreement_key(recipient)?;
    let ephemeral = peer_key(&epk)?;
    let key_len = match enc {
        "A128GCM" => 16,
        "A256GCM" => 32,
        _ => return Err(policy("unsupported response enc")),
    };
    let apu = header.extra.get("apu").and_then(Value::as_str);
    let apv = header.extra.get("apv").and_then(Value::as_str);
    recipient
        .derive_key(&ephemeral, enc, apu, apv, key_len)
        .map_err(Error::Jose)
}

/// A wallet response that decrypted, is addressed to this session, and carries its state.
pub struct OpenedResponse {
    /// The `vp_token` object, parsed with repeated member names refused.
    pub vp_token: serde_json::Map<String, Value>,
}

impl OpenedResponse {
    /// The `vp_token` as JSON text, for validators that take text. Repeated
    /// names were refused when it was parsed, so nothing is lost by serializing.
    pub fn vp_token_text(&self) -> String {
        Value::Object(self.vp_token.clone()).to_string()
    }
}

/// Decrypt a `direct_post.jwt` response and perform the format-independent
/// request, key, error, state, and `vp_token` checks.
pub fn open_response(session: &Session, jwe: &str, now: i64) -> Result<OpenedResponse> {
    if now >= session.expires_at {
        return Err(policy("request has expired"));
    }
    let (plaintext, protected) = decrypt_response(session, jwe)?;
    if protected.kid.as_deref() != session.enc_key.kid.as_deref() {
        return Err(integrity("response was encrypted to a different key"));
    }
    let body = crate::json_strict::from_slice(&plaintext)
        .map_err(|e| malformed(format!("response is not JSON: {e}")))?;
    if let Some(err) = body.get("error") {
        return Err(policy(format!("wallet returned an error: {err}")));
    }
    if body.get("state").and_then(Value::as_str) != Some(session.state.as_str()) {
        return Err(integrity("state mismatch"));
    }
    let vp_token = body
        .get("vp_token")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| malformed("missing vp_token object"))?;
    Ok(OpenedResponse { vp_token })
}

/// Process the wallet's `direct_post.jwt` response (the `response` form value).
pub fn process_response(
    session: &Session,
    jwe: &str,
    now: i64,
    resolver: &dyn IssuerKeyResolver,
) -> Result<Vec<PresentationResult>> {
    let opened = open_response(session, jwe, now)?;
    let vp = &opened.vp_token;

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
            match q.get("format").and_then(Value::as_str) {
                Some("dc+sd-jwt") => {
                    let verified = sdjwt::verify(presentation, resolver, &params)?;
                    dcql_match(q, &verified)?;
                    out.push(PresentationResult {
                        credential_id: id.to_owned(),
                        verified: VerifiedCredential::SdJwt(Box::new(verified)),
                    });
                }
                Some("mso_mdoc") => {
                    let response = b64u_decode(presentation)?;
                    let doctype = q
                        .get("meta")
                        .and_then(|meta| meta.get("doctype_value"))
                        .and_then(Value::as_str)
                        .ok_or_else(|| malformed("mdoc query without doctype_value"))?;
                    let expected = [doctype];
                    let mut documents = crate::mdoc::verify_device_response(
                        &response,
                        &crate::mdoc::Params {
                            session_transcript_bytes: &session.mdoc_session_transcript_bytes()?,
                            now,
                            device_auth: crate::mdoc::DeviceKeyAuth::SignatureOnly,
                            expected_doc_types: Some(&expected),
                        },
                    )?;
                    if documents.len() != 1 {
                        return Err(policy(
                            "mdoc response must contain exactly one document per token",
                        ));
                    }
                    let verified = documents.remove(0);
                    mdoc_match(q, &verified)?;
                    out.push(PresentationResult {
                        credential_id: id.to_owned(),
                        verified: VerifiedCredential::Mdoc(verified),
                    });
                }
                _ => return Err(policy("only dc+sd-jwt and mso_mdoc are supported")),
            }
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
#[cfg(test)]
mod handover_tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }

    fn unwrap_tag24(bytes: &[u8]) -> Vec<u8> {
        let value: ciborium::Value = ciborium::from_reader(bytes).unwrap();
        let ciborium::Value::Tag(24, inner) = value else {
            panic!("expected tag 24")
        };
        let ciborium::Value::Bytes(inner) = *inner else {
            panic!("expected bytes")
        };
        inner
    }

    #[test]
    fn redirect_handover_matches_the_independent_vector() {
        let bare = mdoc_transcript_parts(
            "direct_post.jwt",
            "x509_san_dns:verifier.example.com",
            "n-0S6_WzA2Mj",
            "https://verifier.example.com/verification/oidc-direct_post",
            None,
            (0u8..32).collect(),
        )
        .unwrap();
        let expected = hex("83f6f682714f70656e494434565048616e646f7665725820dc5f031d92b231a269c07fb280c2041f7366da8ded7d461dfa176a80ca76705e");
        assert_eq!(unwrap_tag24(&bare), expected);
    }

    #[test]
    fn dc_api_handover_matches_the_independent_vector() {
        let bare = mdoc_transcript_parts(
            "dc_api.jwt",
            "x509_hash:not-the-origin",
            "pOA0oqEAhLnqug2r7Ve4tQ",
            "https://verifier.example/not-the-response-uri",
            Some("https://verifier.example"),
            vec![0x11; 32],
        )
        .unwrap();
        let expected = hex("83f6f682764f70656e4944345650444341504948616e646f766572582098a74db4c57a62c35763573aa80ce0583c9556e27bddca7c7172eaf38285fd4c");
        assert_eq!(unwrap_tag24(&bare), expected);
    }

    #[test]
    fn dc_api_requires_an_origin() {
        assert!(mdoc_transcript_parts(
            "dc_api.jwt",
            "client",
            "nonce",
            "https://verifier.example/response",
            None,
            vec![0; 32],
        )
        .is_err());
    }
}
