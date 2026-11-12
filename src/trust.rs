//! The AuthZEN evaluation request the trust layer sends to go-trust.
//!
//! Shape follows go-trust's `pkg/authzen` types (AuthZEN Trust Registry
//! Profile, draft-johansson-authzen-trust): `subject.type` is `key`,
//! `resource.type` is `x5c` or `jwk` with `resource.id == subject.id`, and the
//! role goes in `action.name` with credential types in `action.parameters`.

use crate::sdjwt::IssuerEvidence;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use jose_rs::jwk::Jwk;
use serde_json::{json, Value};
use x509_cert::der::Decode;

/// The trust query's key material, reduced to the members that identify the
/// key itself: `kty`, the key parameters (`crv`/`x`/`y`, `n`/`e`), `alg` and
/// `kid`.
///
/// A JWK may legally carry `x5c`, `x5u` and `jku` members (RFC 7517 §4.6-4.8)
/// — certificate chains and dereferenceable URLs — and a JWK under attacker
/// control can embed a foreign, trusted-looking chain inside itself. The
/// chain evidence the trust layer sees is the resolver's own `x5c_der`,
/// never anything smuggled inside the key, so those members never leave the
/// verifier.
fn minimal_public_jwk(jwk: &Jwk) -> Value {
    let mut full = serde_json::to_value(jwk.to_public_jwk()).expect("jwk serializes");
    if let Value::Object(members) = &mut full {
        members.retain(|name, _| {
            matches!(
                name.as_str(),
                "kty" | "crv" | "x" | "y" | "n" | "e" | "alg" | "kid"
            )
        });
    }
    full
}

#[derive(Clone, Debug)]
pub struct TrustQuery {
    pub subject_id: String,
    /// Standard-base64 DER certificates, leaf first. Preferred when non-empty.
    pub x5c: Vec<String>,
    pub jwk: Value,
    pub role: String,
    pub credential_types: Vec<String>,
    /// Ask whether the key was trusted at this instant (unix seconds) instead of now.
    pub as_of: Option<i64>,
}

impl TrustQuery {
    pub fn for_issuer(ev: &IssuerEvidence, role: &str, vct: &str) -> Self {
        Self {
            subject_id: ev.iss.clone(),
            x5c: ev.x5c_der.iter().map(|d| B64.encode(d)).collect(),
            jwk: minimal_public_jwk(&ev.jwk),
            role: role.to_owned(),
            credential_types: vec![vct.to_owned()],
            as_of: None,
        }
    }

    /// Query for an mdoc issuer using vc's identity rules: URI SAN, then DNS
    /// SAN as an HTTPS origin, with the leaf hash only when no SAN identifies
    /// the issuer. go-trust still makes the actual trust decision.
    pub fn for_mdoc_issuer(chain: &crate::mdoc::MdocIssuer, role: &str, doc_type: &str) -> Self {
        use sha2::{Digest, Sha256};
        let leaf = chain
            .x5c_der
            .first()
            .map(Sha256::digest)
            .unwrap_or_default();
        let subject_id =
            mdoc_issuer_id(chain).unwrap_or_else(|| format!("x509_hash:{}", crate::b64u(&leaf)));
        Self {
            subject_id,
            x5c: chain.x5c_der.iter().map(|d| B64.encode(d)).collect(),
            jwk: Value::Null,
            role: role.to_owned(),
            credential_types: vec![doc_type.to_owned()],
            as_of: None,
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
        let mut query = json!({
            "subject":  { "type": "key", "id": self.subject_id },
            "resource": { "type": rtype, "id": self.subject_id, "key": key },
            "action":   { "name": self.role, "parameters": { "credential_types": self.credential_types } },
        });
        if let Some(t) = self.as_of {
            if let Ok(as_of) = crate::mdoc::format_utc(t) {
                query["context"] = json!({ "as_of": as_of });
            }
        }
        query
    }
}

fn mdoc_issuer_id(chain: &crate::mdoc::MdocIssuer) -> Option<String> {
    use x509_cert::der::oid::ObjectIdentifier;
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::SubjectAltName;

    let cert = x509_cert::Certificate::from_der(chain.x5c_der.first()?).ok()?;
    let san_oid = ObjectIdentifier::new_unwrap("2.5.29.17");
    for extension in cert.tbs_certificate.extensions.iter().flatten() {
        if extension.extn_id != san_oid {
            continue;
        }
        let san = SubjectAltName::from_der(extension.extn_value.as_bytes()).ok()?;
        let mut dns = None;
        for name in san.0 {
            match name {
                GeneralName::UniformResourceIdentifier(uri) => {
                    let value = uri.to_string();
                    if let Some(host) = value.strip_prefix("http://") {
                        return Some(format!("https://{host}"));
                    }
                    if value.starts_with("https://") {
                        return Some(value);
                    }
                }
                GeneralName::DnsName(host) => {
                    let host = host.to_string();
                    if !host.starts_with("*.") && dns.is_none() {
                        dns = Some(host);
                    }
                }
                _ => {}
            }
        }
        if let Some(host) = dns {
            return Some(format!("https://{host}"));
        }
    }
    None
}

#[cfg(all(test, feature = "testutil"))]
mod tests {
    use super::*;
    use crate::mdoc::MdocIssuer;

    fn certificate(sans: Vec<rcgen::SanType>) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = sans;
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn mdoc_issuer_uses_vc_san_identity_rules() {
        let chain = MdocIssuer {
            x5c_der: vec![certificate(vec![
                rcgen::SanType::URI(
                    rcgen::string::Ia5String::try_from("https://issuer.example").unwrap(),
                ),
                rcgen::SanType::DnsName(
                    rcgen::string::Ia5String::try_from("other.example").unwrap(),
                ),
            ])],
        };
        let query = TrustQuery::for_mdoc_issuer(&chain, "mdoc-issuer", "doc");
        assert_eq!(query.subject_id, "https://issuer.example");
        assert_eq!(query.role, "mdoc-issuer");
        assert_eq!(query.credential_types, vec!["doc"]);

        let chain = MdocIssuer {
            x5c_der: vec![certificate(vec![rcgen::SanType::DnsName(
                rcgen::string::Ia5String::try_from("verifier.example").unwrap(),
            )])],
        };
        assert_eq!(
            TrustQuery::for_mdoc_issuer(&chain, "mdoc-issuer", "doc").subject_id,
            "https://verifier.example"
        );

        let chain = MdocIssuer {
            x5c_der: vec![certificate(vec![])],
        };
        assert!(TrustQuery::for_mdoc_issuer(&chain, "mdoc-issuer", "doc")
            .subject_id
            .starts_with("x509_hash:"));
    }
}
