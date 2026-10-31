//! Decision receipts: the core service's signed, TTL-bound wrapper around a go-trust answer.
//!
//! go-trust returns an unsigned AuthZEN decision. [`issue`] binds it to the exact request
//! (RFC 8785 canonical SHA-256), clamps its lifetime and signs it. [`Verifier::verify`] applies the
//! six rules from the design (pinned key, typ/iss/aud, request hash, time window, fail closed) and is
//! re-run on every [`Cache`] hit, so the cache needs no integrity protection.

use std::collections::HashMap;

use p256::ecdsa::signature::{Signer, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::{b64u, b64u_decode, Error, Result};

const TYP: &str = "authzen-decision+jwt";
const MAX_JWS: usize = 16 * 1024;

fn malformed(s: &str) -> Error {
    Error::Malformed(s.into())
}
fn policy(s: &str) -> Error {
    Error::Policy(s.into())
}

// ---- RFC 8785 canonical JSON ---------------------------------------------------------------

/// RFC 8785 serialisation for the subset AuthZEN requests use: no floating point numbers.
/// Object members sort by UTF-16 code units, as the RFC requires (not by UTF-8 bytes).
pub fn canonical_json(v: &Value) -> Result<Vec<u8>> {
    let mut out = String::new();
    write_canonical(v, &mut out)?;
    Ok(out.into_bytes())
}

fn write_canonical(v: &Value, out: &mut String) -> Result<()> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            // RFC 8785 prints numbers as IEEE-754 doubles, so integers beyond 2^53 are rounded by
            // conforming implementations (Go prints 2^64-1 as 18446744073709552000). Refuse them
            // rather than guess; I-JSON says to use strings for such values.
            const SAFE: i64 = 9_007_199_254_740_991;
            match n.as_i64() {
                Some(i) if (-SAFE..=SAFE).contains(&i) => out.push_str(&i.to_string()),
                Some(_) => return Err(policy("canonical_json_integer_range")),
                None if n.as_u64().is_some() => return Err(policy("canonical_json_integer_range")),
                None => return Err(policy("canonical_json_float")),
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(x, out)?;
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_canonical(&m[k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn req_sha256(request: &Value) -> Result<String> {
    Ok(b64u(&Sha256::digest(canonical_json(request)?)))
}

// ---- issuing -------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct TrustData {
    pub registry: String,
    pub as_of: i64,
    pub next_update: Option<i64>,
}

/// What go-trust said, already parsed.
#[derive(Clone, Debug)]
pub struct PdpAnswer {
    pub decision: bool,
    pub id: String,
    pub reasons: Vec<String>,
    pub trust_data: Vec<TrustData>,
}

pub struct IssuePolicy<'a> {
    pub iss: &'a str,
    pub aud: &'a str,
    pub kid: &'a str,
    pub pdp: &'a str,
    /// Tenant ceiling for a permit.
    pub max_ttl: i64,
    /// Denials are kept shorter so a fixed trust list is picked up quickly.
    pub deny_ttl: i64,
    /// `refresh_after` = iat + ttl * num / den.
    pub refresh_num: i64,
    pub refresh_den: i64,
}

/// Wrap a PDP answer. The lifetime is the smallest of the tenant ceiling and every consulted
/// registry's `next_update`; a permit built on data that is already stale is refused.
pub fn issue(
    key: &SigningKey,
    pol: &IssuePolicy,
    request: &Value,
    ans: &PdpAnswer,
    now: i64,
) -> Result<String> {
    let mut exp = now
        + if ans.decision {
            pol.max_ttl
        } else {
            pol.deny_ttl.min(pol.max_ttl)
        };
    for td in &ans.trust_data {
        if let Some(nu) = td.next_update {
            exp = exp.min(nu);
        }
    }
    if exp <= now {
        return Err(policy("trust_data_stale"));
    }
    let ttl = exp - now;
    let refresh_after = now + ttl * pol.refresh_num / pol.refresh_den.max(1);
    let header = json!({"alg": "ES256", "typ": TYP, "kid": pol.kid});
    let trust_data: Vec<Value> = ans
        .trust_data
        .iter()
        .map(|t| json!({"registry": t.registry, "as_of": t.as_of, "next_update": t.next_update}))
        .collect();
    let claims = json!({
        "iss": pol.iss, "aud": pol.aud, "pdp": pol.pdp, "decision": ans.decision,
        "req_sha256": req_sha256(request)?,
        "iat": now, "nbf": now, "refresh_after": refresh_after, "exp": exp,
        "scope": "leaf", "reasons": ans.reasons, "trust_data": trust_data, "jti": ans.id,
    });
    let signing_input = format!(
        "{}.{}",
        b64u(&canonical_json(&header)?),
        b64u(&canonical_json(&claims)?)
    );
    let sig: Signature = key.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", b64u(&sig.to_bytes())))
}

// ---- verifying -----------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub decision: bool,
    pub jti: String,
    pub iat: i64,
    pub refresh_after: i64,
    pub exp: i64,
    pub reasons: Vec<String>,
}

pub struct Verifier {
    pub keys: HashMap<String, VerifyingKey>,
    pub iss: String,
    pub aud: String,
    pub skew: i64,
}

fn str_claim<'a>(c: &'a Map<String, Value>, k: &str) -> Result<&'a str> {
    c.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Malformed(format!("claim_{k}")))
}
fn int_claim(c: &Map<String, Value>, k: &str) -> Result<i64> {
    c.get(k)
        .and_then(Value::as_i64)
        .ok_or_else(|| Error::Malformed(format!("claim_{k}")))
}

impl Verifier {
    pub fn verify(&self, jws: &str, request: &Value, now: i64) -> Result<Receipt> {
        if jws.len() > MAX_JWS {
            return Err(policy("receipt_too_large"));
        }
        let parts: Vec<&str> = jws.split('.').collect();
        if parts.len() != 3 {
            return Err(malformed("receipt_parts"));
        }
        // 1. header, key, signature
        let header = crate::json_strict::from_slice(&b64u_decode(parts[0])?)?;
        let Value::Object(h) = header else {
            return Err(malformed("header_not_object"));
        };
        if let Some(bad) = h
            .keys()
            .find(|k| !["alg", "typ", "kid"].contains(&k.as_str()))
        {
            return Err(Error::Policy(format!("header_member_{bad}")));
        }
        if h.get("alg").and_then(Value::as_str) != Some("ES256") {
            return Err(policy("alg_not_es256"));
        }
        let kid = str_claim(&h, "kid")?;
        let key = self.keys.get(kid).ok_or_else(|| policy("unknown_kid"))?;
        let sig =
            Signature::from_slice(&b64u_decode(parts[2])?).map_err(|_| malformed("signature"))?;
        key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
            .map_err(|_| Error::Integrity("receipt_signature".into()))?;
        // 2. typ, iss, aud
        if h.get("typ").and_then(Value::as_str) != Some(TYP) {
            return Err(policy("typ"));
        }
        let c = crate::json_strict::from_slice(&b64u_decode(parts[1])?)?;
        let Value::Object(c) = c else {
            return Err(malformed("claims_not_object"));
        };
        if str_claim(&c, "iss")? != self.iss {
            return Err(policy("iss"));
        }
        if str_claim(&c, "aud")? != self.aud {
            return Err(policy("aud"));
        }
        // 3. request binding
        if str_claim(&c, "req_sha256")? != req_sha256(request)? {
            return Err(policy("req_sha256"));
        }
        // 4. time window
        let (nbf, exp) = (int_claim(&c, "nbf")?, int_claim(&c, "exp")?);
        if now + self.skew < nbf {
            return Err(policy("not_yet_valid"));
        }
        if now > exp {
            return Err(policy("expired"));
        }
        let decision = c
            .get("decision")
            .and_then(Value::as_bool)
            .ok_or_else(|| malformed("claim_decision"))?;
        Ok(Receipt {
            decision,
            jti: str_claim(&c, "jti")?.to_owned(),
            iat: int_claim(&c, "iat")?,
            refresh_after: int_claim(&c, "refresh_after")?,
            exp,
            reasons: c
                .get("reasons")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }
}

// ---- time and cache ------------------------------------------------------------------------

/// Refuses a clock that moves backwards by more than `skew`, so rolling a device clock back
/// cannot extend a receipt. Returns the time to use (never earlier than the high-water mark).
pub struct Monotonic {
    high: i64,
    skew: i64,
}

impl Monotonic {
    pub fn new(skew: i64) -> Self {
        Self {
            high: i64::MIN,
            skew,
        }
    }
    pub fn observe(&mut self, now: i64) -> Result<i64> {
        if self.high != i64::MIN && now < self.high - self.skew {
            return Err(policy("clock_rolled_back"));
        }
        self.high = self.high.max(now);
        Ok(self.high)
    }
}

/// What the caller should do with a cache lookup.
#[derive(Debug, PartialEq, Eq)]
pub enum Lookup {
    /// Valid and fresh: use it.
    Fresh(Receipt),
    /// Valid but past `refresh_after`: use it, and refresh if the PDP is reachable.
    Stale(Receipt),
    Miss,
}

pub struct Cache {
    entries: HashMap<String, String>,
    clock: Monotonic,
}

impl Cache {
    pub fn new(skew: i64) -> Self {
        Self {
            entries: HashMap::new(),
            clock: Monotonic::new(skew),
        }
    }

    pub fn put(&mut self, request: &Value, jws: String) -> Result<()> {
        self.entries.insert(req_sha256(request)?, jws);
        Ok(())
    }

    /// Every hit is fully re-verified. An entry that no longer verifies is evicted and reported as a miss.
    pub fn get(&mut self, v: &Verifier, request: &Value, now: i64) -> Result<Lookup> {
        let now = self.clock.observe(now)?;
        let k = req_sha256(request)?;
        let Some(jws) = self.entries.get(&k) else {
            return Ok(Lookup::Miss);
        };
        match v.verify(jws, request, now) {
            Ok(r) if now >= r.refresh_after => Ok(Lookup::Stale(r)),
            Ok(r) => Ok(Lookup::Fresh(r)),
            Err(_) => {
                self.entries.remove(&k);
                Ok(Lookup::Miss)
            }
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
