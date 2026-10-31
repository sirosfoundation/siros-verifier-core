//! The AuthZEN evaluation request the trust layer sends to go-trust.
//!
//! Shape follows go-trust's `pkg/authzen` types (AuthZEN Trust Registry
//! Profile, draft-johansson-authzen-trust): `subject.type` is `key`,
//! `resource.type` is `x5c` or `jwk` with `resource.id == subject.id`, and the
//! role goes in `action.name` with credential types in `action.parameters`.

use crate::sdjwt::IssuerEvidence;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

#[derive(Clone, Debug)]
pub struct TrustQuery {
    pub subject_id: String,
    /// Standard-base64 DER certificates, leaf first. Preferred when non-empty.
    pub x5c: Vec<String>,
    pub jwk: Value,
    pub role: String,
    pub credential_types: Vec<String>,
}

impl TrustQuery {
    pub fn for_issuer(ev: &IssuerEvidence, role: &str, vct: &str) -> Self {
        Self {
            subject_id: ev.iss.clone(),
            x5c: ev.x5c_der.iter().map(|d| B64.encode(d)).collect(),
            jwk: serde_json::to_value(ev.jwk.to_public_jwk()).expect("jwk serializes"),
            role: role.to_owned(),
            credential_types: vec![vct.to_owned()],
        }
    }

    /// Query for an mdoc issuer: the subject id is `x509_hash:<base64url SHA-256 of the leaf>` (the OpenID4VP scheme go-trust already recognises),
    /// since an MSO carries no issuer identifier of its own.
    pub fn for_mdoc_issuer(chain: &crate::mdoc::MdocIssuer, role: &str, doc_type: &str) -> Self {
        use sha2::{Digest, Sha256};
        let leaf = chain
            .x5c_der
            .first()
            .map(Sha256::digest)
            .unwrap_or_default();
        Self {
            subject_id: format!("x509_hash:{}", crate::b64u(&leaf)),
            x5c: chain.x5c_der.iter().map(|d| B64.encode(d)).collect(),
            jwk: Value::Null,
            role: role.to_owned(),
            credential_types: vec![doc_type.to_owned()],
        }
    }

    pub fn to_authzen(&self) -> Value {
        debug_assert!(
            !(self.x5c.is_empty() && self.jwk.is_null()),
            "TrustQuery needs x5c or jwk"
        );
        let (rtype, key) = if self.x5c.is_empty() {
            ("jwk", json!([self.jwk]))
        } else {
            ("x5c", json!(self.x5c))
        };
        json!({
            "subject":  { "type": "key", "id": self.subject_id },
            "resource": { "type": rtype, "id": self.subject_id, "key": key },
            "action":   { "name": self.role, "parameters": { "credential_types": self.credential_types } },
        })
    }
}
