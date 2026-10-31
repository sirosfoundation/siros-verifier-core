//! SD-JWT (RFC 9901) and SD-JWT VC verification.
//!
//! This is the *format layer*: given a presentation and a way to obtain the
//! issuer's key, it checks signatures, disclosures, holder binding and
//! registered claims, and returns [`CryptoVerified`]. It never decides whether
//! the issuer is trusted. That is the trust layer's job, and the returned
//! [`IssuerEvidence`] carries what that layer needs (key, `x5c` chain, `iss`).
//!
//! Sans-IO: the caller supplies `now`; nothing here reads a clock or the network.

use crate::error::{integrity, malformed, policy};
use crate::{b64u, b64u_decode, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use jose_rs::jwk::Jwk;
use jose_rs::{jws, JoseHeader};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::{HashMap, HashSet};
use x509_cert::der::{Decode, Encode};

const MAX_DISCLOSURES: usize = 1000;
const MAX_DEPTH: usize = 32;
const MAX_INPUT: usize = 512 * 1024;

/// Claims that must stay in the clear in an SD-JWT VC.
const NOT_DISCLOSABLE: &[&str] = &[
    "iss",
    "nbf",
    "exp",
    "cnf",
    "vct",
    "vct#integrity",
    "status",
    "_sd_alg",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    pub fn name(self) -> &'static str {
        match self {
            HashAlg::Sha256 => "sha-256",
            HashAlg::Sha384 => "sha-384",
            HashAlg::Sha512 => "sha-512",
        }
    }
    fn from_name(s: &str) -> Result<Self> {
        match s {
            "sha-256" => Ok(HashAlg::Sha256),
            "sha-384" => Ok(HashAlg::Sha384),
            "sha-512" => Ok(HashAlg::Sha512),
            other => Err(policy(format!("unsupported _sd_alg {other}"))),
        }
    }
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => Sha256::digest(data).to_vec(),
            HashAlg::Sha384 => Sha384::digest(data).to_vec(),
            HashAlg::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
    pub fn digest_b64u(self, data: &[u8]) -> String {
        b64u(&self.digest(data))
    }
}

/// What the trust layer needs to know about the issuer's signing key.
#[derive(Clone, Debug)]
pub struct IssuerEvidence {
    pub iss: String,
    pub alg: String,
    pub kid: Option<String>,
    /// DER certificates from the `x5c` header, leaf first. Empty if absent.
    pub x5c_der: Vec<Vec<u8>>,
    /// The key the signature verified under.
    pub jwk: Jwk,
}

/// Resolves the issuer verification key. Implementations must not treat a
/// resolved key as *trusted*; trust is evaluated separately.
pub trait IssuerKeyResolver {
    fn resolve(&self, header: &JoseHeader, iss: &str) -> Result<Jwk>;
}

/// Uses the leaf certificate of the `x5c` header. Performs NO chain validation.
pub struct X5cLeaf;

impl IssuerKeyResolver for X5cLeaf {
    fn resolve(&self, header: &JoseHeader, _iss: &str) -> Result<Jwk> {
        let chain = x5c_chain(header)?;
        let leaf = chain.first().ok_or_else(|| malformed("no x5c header"))?;
        jwk_from_cert_der(leaf)
    }
}

/// A fixed key, for tests and for pinned issuers.
pub struct StaticKey(pub Jwk);

impl IssuerKeyResolver for StaticKey {
    fn resolve(&self, _h: &JoseHeader, _iss: &str) -> Result<Jwk> {
        Ok(self.0.clone())
    }
}

pub fn x5c_chain(header: &JoseHeader) -> Result<Vec<Vec<u8>>> {
    header
        .x5c
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|c| {
            B64.decode(c)
                .map_err(|_| malformed("x5c entry is not standard base64"))
        })
        .collect()
}

pub fn jwk_from_cert_der(der: &[u8]) -> Result<Jwk> {
    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|e| malformed(format!("bad certificate: {e}")))?;
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| malformed(format!("bad SPKI: {e}")))?;
    Ok(jose_rs::jwk::jwk_from_spki_der(&spki)?)
}

#[derive(Clone, Debug)]
pub enum HolderBinding<'a> {
    /// A key-binding JWT is required; aud and nonce must match.
    Required {
        aud: &'a str,
        nonce: &'a str,
        max_age_secs: i64,
    },
    /// No key binding expected. A KB-JWT in the input is an error.
    NotRequired,
}

pub struct VerifyParams<'a> {
    /// Unix seconds, supplied by the caller.
    pub now: i64,
    pub leeway_secs: i64,
    /// Allowed `alg` values for issuer and KB-JWT signatures.
    pub allowed_algs: &'a [&'a str],
    /// Accept the legacy `vc+sd-jwt` typ in addition to `dc+sd-jwt`.
    pub allow_legacy_typ: bool,
    pub holder_binding: HolderBinding<'a>,
}

impl<'a> VerifyParams<'a> {
    pub fn new(now: i64, holder_binding: HolderBinding<'a>) -> Self {
        Self {
            now,
            leeway_secs: 60,
            allowed_algs: &["ES256"],
            allow_legacy_typ: false,
            holder_binding,
        }
    }
}

#[derive(Clone, Debug)]
pub struct StatusRef {
    pub idx: u64,
    pub uri: String,
}

/// A presentation whose signatures and disclosures verified. Issuer trust has
/// NOT been evaluated: callers must pass `issuer` to the trust layer.
#[derive(Debug)]
pub struct CryptoVerified {
    pub claims: Map<String, Value>,
    pub vct: String,
    pub issuer: IssuerEvidence,
    pub holder_key: Option<Jwk>,
    pub status: Option<StatusRef>,
    pub exp: Option<i64>,
}

struct Disclosure {
    name: Option<String>,
    value: Value,
}

struct Walker {
    by_digest: HashMap<String, Disclosure>,
    seen: HashSet<String>,
    used: HashSet<String>,
    hash: HashAlg,
}

fn number_claim(claims: &Map<String, Value>, name: &str) -> Result<Option<i64>> {
    match claims.get(name) {
        None => Ok(None),
        Some(v) => v
            .as_i64()
            .or_else(|| v.as_f64().map(|f| f as i64))
            .map(Some)
            .ok_or_else(|| malformed(format!("{name} must be a number"))),
    }
}

fn parse_disclosure(raw: &str, hash: HashAlg) -> Result<(String, Disclosure)> {
    let bytes = b64u_decode(raw)?;
    let v = crate::json_strict::from_slice(&bytes)
        .map_err(|e| malformed(format!("disclosure is not JSON: {e}")))?;
    let arr = v
        .as_array()
        .ok_or_else(|| malformed("disclosure is not an array"))?;
    if !matches!(arr.first(), Some(Value::String(_))) {
        return Err(malformed("disclosure salt must be a string"));
    }
    let d = match arr.len() {
        3 => {
            let name = arr[1]
                .as_str()
                .ok_or_else(|| malformed("disclosure claim name must be a string"))?;
            if name == "_sd" || name == "..." {
                return Err(policy(format!("disclosure of reserved name {name}")));
            }
            Disclosure {
                name: Some(name.to_owned()),
                value: arr[2].clone(),
            }
        }
        2 => Disclosure {
            name: None,
            value: arr[1].clone(),
        },
        n => return Err(malformed(format!("disclosure has {n} elements"))),
    };
    // The digest is over the exact received string, not a re-serialization.
    Ok((hash.digest_b64u(raw.as_bytes()), d))
}

impl Walker {
    fn note_digest(&mut self, d: &str) -> Result<()> {
        if !self.seen.insert(d.to_owned()) {
            return Err(policy("digest appears more than once"));
        }
        Ok(())
    }

    fn value(&mut self, v: Value, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(policy("claims nested too deeply"));
        }
        match v {
            Value::Object(m) => Ok(Value::Object(self.object(m, depth, false)?)),
            Value::Array(a) => Ok(Value::Array(self.array(a, depth)?)),
            other => Ok(other),
        }
    }

    fn array(&mut self, a: Vec<Value>, depth: usize) -> Result<Vec<Value>> {
        let mut out = Vec::with_capacity(a.len());
        for el in a {
            if let Value::Object(m) = &el {
                if let Some(d) = m.get("...") {
                    if m.len() != 1 {
                        return Err(malformed("array digest object has extra members"));
                    }
                    let digest = d
                        .as_str()
                        .ok_or_else(|| malformed("array digest must be a string"))?
                        .to_owned();
                    self.note_digest(&digest)?;
                    if let Some(disc) = self.by_digest.remove(&digest) {
                        self.used.insert(digest.clone());
                        if disc.name.is_some() {
                            return Err(malformed("property disclosure used for an array element"));
                        }
                        out.push(self.value(disc.value, depth + 1)?);
                    }
                    // No matching disclosure: the element stays concealed and is dropped.
                    continue;
                }
            }
            out.push(self.value(el, depth + 1)?);
        }
        Ok(out)
    }

    fn object(
        &mut self,
        mut m: Map<String, Value>,
        depth: usize,
        top: bool,
    ) -> Result<Map<String, Value>> {
        let sd = m.remove("_sd");
        let mut out = Map::new();
        for (k, v) in std::mem::take(&mut m) {
            out.insert(k, self.value(v, depth + 1)?);
        }
        if let Some(sd) = sd {
            let list = sd
                .as_array()
                .ok_or_else(|| malformed("_sd must be an array"))?;
            for d in list {
                let digest = d
                    .as_str()
                    .ok_or_else(|| malformed("_sd entries must be strings"))?
                    .to_owned();
                self.note_digest(&digest)?;
                if let Some(disc) = self.by_digest.remove(&digest) {
                    self.used.insert(digest);
                    let name = disc
                        .name
                        .ok_or_else(|| malformed("array disclosure used for a property"))?;
                    if top && NOT_DISCLOSABLE.contains(&name.as_str()) {
                        return Err(policy(format!(
                            "claim {name} must not be selectively disclosable"
                        )));
                    }
                    if out.contains_key(&name) {
                        return Err(policy(format!(
                            "disclosed claim {name} collides with an existing claim"
                        )));
                    }
                    let v = self.value(disc.value, depth + 1)?;
                    out.insert(name, v);
                }
            }
        }
        Ok(out)
    }
}

/// Split `jwt~d1~d2~[kb]` into (jwt, disclosures, kb, signed-prefix-for-sd_hash).
fn split(presentation: &str) -> Result<(&str, Vec<&str>, Option<&str>, &str)> {
    if presentation.len() > MAX_INPUT {
        return Err(policy("presentation too large"));
    }
    let parts: Vec<&str> = presentation.split('~').collect();
    if parts.len() < 2 {
        return Err(malformed("not an SD-JWT presentation (no ~ separator)"));
    }
    let last = parts[parts.len() - 1];
    let disclosures = parts[1..parts.len() - 1].to_vec();
    if disclosures.iter().any(|d| d.is_empty()) {
        return Err(malformed("empty disclosure"));
    }
    let prefix_len = presentation.len() - last.len();
    Ok((
        parts[0],
        disclosures,
        if last.is_empty() { None } else { Some(last) },
        &presentation[..prefix_len],
    ))
}

fn check_alg(alg: &str, allowed: &[&str]) -> Result<()> {
    if alg.eq_ignore_ascii_case("none") || !allowed.contains(&alg) {
        return Err(policy(format!("alg {alg} is not allowed")));
    }
    Ok(())
}

fn payload_object(bytes: &[u8]) -> Result<Map<String, Value>> {
    let value = crate::json_strict::from_slice(bytes)
        .map_err(|e| malformed(format!("JWT payload: {e}")))?;
    match value {
        Value::Object(m) => Ok(m),
        _ => Err(malformed("JWT payload is not a JSON object")),
    }
}

fn decode_header(jwt: &str) -> Result<JoseHeader> {
    let encoded = jwt
        .split('.')
        .next()
        .ok_or_else(|| malformed("JWT has no header"))?;
    crate::json_strict::from_slice(&b64u_decode(encoded)?)?;
    Ok(jws::decode_header(jwt)?)
}

/// Verify an SD-JWT VC presentation.
pub fn verify(
    presentation: &str,
    resolver: &dyn IssuerKeyResolver,
    p: &VerifyParams,
) -> Result<CryptoVerified> {
    let (jwt, raw_disclosures, kb, sd_hash_input) = split(presentation)?;
    if raw_disclosures.len() > MAX_DISCLOSURES {
        return Err(policy("too many disclosures"));
    }

    // 1. Issuer-signed JWT: header checks, key resolution, signature.
    let header = decode_header(jwt)?;
    check_alg(&header.alg, p.allowed_algs)?;
    match header.typ.as_deref() {
        Some("dc+sd-jwt") => {}
        Some("vc+sd-jwt") if p.allow_legacy_typ => {}
        other => return Err(policy(format!("unexpected typ {other:?}"))),
    }
    // The unverified `iss` only selects which key to try; it is re-checked below.
    let unverified = jwt
        .split('.')
        .nth(1)
        .ok_or_else(|| malformed("JWT has no payload"))?;
    let unverified = payload_object(&b64u_decode(unverified)?)?;
    let iss_hint = unverified
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("missing iss"))?;
    let jwk = resolver.resolve(&header, iss_hint)?;
    let payload = jws::compact::verify_with_jwk(&jwk, jwt)
        .map_err(|e| integrity(format!("issuer signature: {e}")))?;
    let mut claims = payload_object(&payload)?;
    // Same bytes as the unverified parse above, so `iss` equals `iss_hint`; read it
    // from the verified payload anyway so only verified data feeds the result.
    let iss = claims
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("missing iss"))?
        .to_owned();

    // 2. Registered claims.
    let vct = claims
        .get("vct")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("missing vct"))?
        .to_owned();
    let exp = number_claim(&claims, "exp")?;
    if let Some(exp) = exp {
        if p.now >= exp + p.leeway_secs {
            return Err(policy("credential expired"));
        }
    }
    if let Some(nbf) = number_claim(&claims, "nbf")? {
        if p.now + p.leeway_secs < nbf {
            return Err(policy("credential not yet valid"));
        }
    }
    if let Some(iat) = number_claim(&claims, "iat")? {
        if iat > p.now + p.leeway_secs {
            return Err(policy("credential issued in the future"));
        }
    }

    // 3. Disclosures.
    let hash = match claims.remove("_sd_alg") {
        None => HashAlg::Sha256,
        Some(Value::String(s)) => HashAlg::from_name(&s)?,
        Some(_) => return Err(malformed("_sd_alg must be a string")),
    };
    let mut by_digest = HashMap::new();
    for raw in &raw_disclosures {
        let (digest, d) = parse_disclosure(raw, hash)?;
        if by_digest.insert(digest, d).is_some() {
            return Err(policy("duplicate disclosure"));
        }
    }
    let count = by_digest.len();
    let mut w = Walker {
        by_digest,
        seen: HashSet::new(),
        used: HashSet::new(),
        hash,
    };
    let claims = w.object(claims, 0, true)?;
    if w.used.len() != count {
        return Err(policy(
            "a disclosure is not referenced by the signed payload",
        ));
    }
    let _ = w.hash;

    // 4. Holder binding.
    let cnf_jwk = match claims.get("cnf") {
        None => None,
        Some(c) => {
            let jwk = c.get("jwk").ok_or_else(|| malformed("cnf without jwk"))?;
            let jwk: Jwk = serde_json::from_value(jwk.clone())
                .map_err(|e| malformed(format!("bad cnf.jwk: {e}")))?;
            if jwk.d.is_some() || jwk.k.is_some() {
                return Err(policy("cnf.jwk contains private key material"));
            }
            Some(jwk)
        }
    };
    match (&p.holder_binding, kb) {
        (HolderBinding::NotRequired, None) => {}
        (HolderBinding::NotRequired, Some(_)) => return Err(policy("unexpected key-binding JWT")),
        (HolderBinding::Required { .. }, None) => return Err(policy("key-binding JWT required")),
        (
            HolderBinding::Required {
                aud,
                nonce,
                max_age_secs,
            },
            Some(kb),
        ) => {
            let holder = cnf_jwk
                .as_ref()
                .ok_or_else(|| policy("key binding presented but credential has no cnf"))?;
            let kb_header = decode_header(kb)?;
            check_alg(&kb_header.alg, p.allowed_algs)?;
            if kb_header.typ.as_deref() != Some("kb+jwt") {
                return Err(policy("key-binding JWT typ must be kb+jwt"));
            }
            let kb_payload = jws::compact::verify_with_jwk(holder, kb)
                .map_err(|e| integrity(format!("KB-JWT signature: {e}")))?;
            let kbc = payload_object(&kb_payload)?;
            if kbc.get("aud").and_then(Value::as_str) != Some(*aud) {
                return Err(policy("KB-JWT aud mismatch"));
            }
            if kbc.get("nonce").and_then(Value::as_str) != Some(*nonce) {
                return Err(policy("KB-JWT nonce mismatch"));
            }
            let iat = number_claim(&kbc, "iat")?.ok_or_else(|| malformed("KB-JWT without iat"))?;
            if iat > p.now + p.leeway_secs || iat < p.now - max_age_secs - p.leeway_secs {
                return Err(policy("KB-JWT iat outside the accepted window"));
            }
            let expected = hash.digest_b64u(sd_hash_input.as_bytes());
            if kbc.get("sd_hash").and_then(Value::as_str) != Some(expected.as_str()) {
                return Err(integrity("KB-JWT sd_hash does not match the presentation"));
            }
        }
    }

    // 5. Evidence and status.
    let status = claims
        .get("status")
        .and_then(|s| s.get("status_list"))
        .and_then(|sl| {
            Some(StatusRef {
                idx: sl.get("idx")?.as_u64()?,
                uri: sl.get("uri")?.as_str()?.to_owned(),
            })
        });
    let exp_out = exp;
    Ok(CryptoVerified {
        vct,
        issuer: IssuerEvidence {
            iss,
            alg: header.alg.clone(),
            kid: header.kid.clone(),
            x5c_der: x5c_chain(&header)?,
            jwk,
        },
        holder_key: cnf_jwk,
        status,
        exp: exp_out,
        claims,
    })
}
