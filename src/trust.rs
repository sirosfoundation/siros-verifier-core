//! The AuthZEN evaluation request the trust layer sends to go-trust.
//!
//! Shape follows go-trust's `pkg/authzen` types (AuthZEN Trust Registry
//! Profile, draft-johansson-authzen-trust): `subject.type` is `key`,
//! `resource.type` is `x5c` or `jwk` with `resource.id == subject.id`, and the
//! role goes in `action.name` with credential types in `action.parameters`.

use crate::sdjwt::IssuerEvidence;
use crate::Result;
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
    /// Query for an SD-JWT VC issuer (issue #81, the security report's
    /// first finding): the subject identity is BOUND to the presented
    /// evidence, never raw `iss` — whoever holds the key of any certificate
    /// chaining to an accepted anchor can no longer name any `iss` they
    /// like.
    ///
    /// With an `x5c` chain the identity is derived from the validated leaf:
    /// the https origin its SubjectAltName names — a URI SAN exactly as
    /// written (an `http://` URI is not an https origin and never becomes
    /// one), or a non-wildcard DNS SAN as `https://<host>` (the TLS
    /// semantics: a hostname certifies its https origin) — or, when the
    /// leaf carries no usable SAN (the profile's self-contained issuer
    /// shape — the pinned OIDF conformance issuer among them), the leaf's
    /// own `x509_hash:<sha256>`. When the leaf DOES name origins, a present
    /// `iss` MUST be one of them: a certificate that names `issuer-b`
    /// cannot carry a credential for `issuer-a`. The leaf's purpose is
    /// checked along the way (digitalSignature, not a CA, no TLS EKU): a
    /// TLS serverAuth-only certificate is not an attestation issuer.
    ///
    /// Without `x5c` (the kid/JWKS profile) the `iss` stands: the
    /// discovery is https-only and the metadata must name the same issuer,
    /// so the `iss` there is the profile's own binding. The trust decision
    /// still runs through go-trust either way.
    pub fn for_issuer(ev: &IssuerEvidence, role: &str, vct: &str) -> Result<Self> {
        let subject_id = if ev.x5c_der.is_empty() {
            ev.iss.clone()
        } else {
            let leaf = ev.x5c_der.first().expect("checked non-empty");
            check_issuer_leaf_purpose(leaf)?;
            match issuer_leaf_san_origins(leaf)? {
                // No SAN extension at all: nothing for an `iss` to
                // mismatch — the binding is the certificate's own hash,
                // and go-trust's registry decides on the true signer.
                None => {}
                // The leaf names origins: the `iss` MUST be one of them.
                Some(origins) if !origins.is_empty() => {
                    if !origins.iter().any(|origin| origin == &ev.iss) {
                        return Err(crate::error::policy(format!(
                            "the credential's iss {} is none of the origins its x5c leaf names ({}) — the issuer is not bound to the presented certificate",
                            ev.iss,
                            origins.join(", ")
                        )));
                    }
                }
                // A SAN extension that names no https origin (a
                // plain-HTTP URI, wildcards, other name forms) can
                // certify no issuer origin: refuse.
                Some(_) => {
                    return Err(crate::error::policy(
                        "the issuer leaf's SAN names no https origin, so the credential's iss cannot be certified by it",
                    ));
                }
            }
            issuer_leaf_identity(leaf)?
        };
        Ok(Self {
            subject_id,
            x5c: ev.x5c_der.iter().map(|d| B64.encode(d)).collect(),
            jwk: minimal_public_jwk(&ev.jwk),
            role: role.to_owned(),
            credential_types: vec![vct.to_owned()],
            as_of: None,
        })
    }

    /// Query for a Token Status List signer: a status token's `iss` names
    /// the LIST (the TSL shape), not the signer, so the presentation
    /// binding above does not apply and the signer's certificate policy is
    /// go-trust's own role policy (go-trust #270), not this binding. The
    /// `iss` — the list's subject — is the query's subject.
    pub fn for_status_list_signer(ev: &IssuerEvidence) -> Self {
        Self {
            subject_id: ev.iss.clone(),
            x5c: ev.x5c_der.iter().map(|d| B64.encode(d)).collect(),
            jwk: minimal_public_jwk(&ev.jwk),
            role: "status-list-signer".to_owned(),
            credential_types: vec!["status-list".to_owned()],
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

/// The leaf's SAN extension decoded to its https origins: `None` when the
/// certificate carries no SAN extension at all (the self-contained issuer
/// shape — the pinned OIDF conformance issuer among them), `Some` —
/// possibly empty — when it does. The origins follow the profile's
/// precedence: `https` URI SANs exactly as written first, then non-wildcard
/// DNS SANs as `https://<host>` (the TLS semantics: a hostname certifies its
/// https origin). An `http://` URI SAN is not an https origin and never
/// becomes one — a scheme rewrite would let a plain-HTTP name satisfy an
/// https `iss` — and a wildcard certifies no single origin.
pub(crate) fn issuer_leaf_san_origins(leaf_der: &[u8]) -> Result<Option<Vec<String>>> {
    use x509_cert::der::oid::ObjectIdentifier;
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::SubjectAltName;

    let cert = x509_cert::Certificate::from_der(leaf_der)
        .map_err(|e| crate::error::malformed(format!("the issuer leaf does not parse: {e}")))?;
    let san_oid = ObjectIdentifier::new_unwrap("2.5.29.17");
    let mut has_san = false;
    let mut uris = Vec::new();
    let mut dns = Vec::new();
    for extension in cert.tbs_certificate.extensions.iter().flatten() {
        if extension.extn_id != san_oid {
            continue;
        }
        has_san = true;
        let san = SubjectAltName::from_der(extension.extn_value.as_bytes()).map_err(|e| {
            crate::error::malformed(format!("the issuer leaf's SAN does not parse: {e}"))
        })?;
        for name in san.0 {
            match name {
                GeneralName::UniformResourceIdentifier(uri) => {
                    let value = uri.to_string();
                    if value.starts_with("https://") {
                        uris.push(value);
                    }
                }
                GeneralName::DnsName(host) => {
                    let host = host.to_string();
                    if !host.starts_with("*.") {
                        dns.push(format!("https://{host}"));
                    }
                }
                _ => {}
            }
        }
    }
    if !has_san {
        return Ok(None);
    }
    uris.extend(dns);
    Ok(Some(uris))
}

/// The SD-JWT issuer's bound identity from the leaf certificate: the first
/// https origin its SubjectAltName names, or — when the leaf carries no
/// usable SAN — the leaf's own hash (the `x509_hash` scheme, the same
/// fallback the mdoc path uses). Never raw `iss`, and never a name the
/// certificate does not certify.
pub(crate) fn issuer_leaf_identity(leaf_der: &[u8]) -> Result<String> {
    let origins = issuer_leaf_san_origins(leaf_der)?.unwrap_or_default();
    if let Some(first) = origins.first() {
        return Ok(first.clone());
    }
    use sha2::Digest;
    let hash = sha2::Sha256::digest(leaf_der);
    Ok(format!("x509_hash:{}", crate::b64u(&hash)))
}

/// The issuer leaf's purpose check (issue #81): an attestation issuer's
/// certificate signs credentials — `digitalSignature` (and never
/// `nonRepudiation`-only, which real issuers use alongside), is not a
/// CA, and carries no EKU outside the allow-list (`serverAuth` is the
/// TLS-server case the report caught; an mdoc/SD-JWT issuer carries
/// none or `id-kp-critical`-free members).
pub(crate) fn check_issuer_leaf_purpose(leaf_der: &[u8]) -> Result<()> {
    use x509_cert::der::oid::ObjectIdentifier;
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    use x509_cert::ext::pkix::KeyUsages;

    let cert = x509_cert::Certificate::from_der(leaf_der)
        .map_err(|e| crate::error::malformed(format!("the issuer leaf does not parse: {e}")))?;
    let tbs = &cert.tbs_certificate;
    // A CA certificate is never an attestation leaf (BasicConstraints
    // decodes from the extensions; its absence means an end-entity).
    let bc_oid = ObjectIdentifier::new_unwrap("2.5.29.19");
    for extension in tbs.extensions.iter().flatten() {
        if extension.extn_id == bc_oid {
            let bc =
                x509_cert::ext::pkix::BasicConstraints::from_der(extension.extn_value.as_bytes())
                    .map_err(|e| {
                    crate::error::malformed(format!(
                        "the issuer leaf's BasicConstraints do not parse: {e}"
                    ))
                })?;
            if bc.ca {
                return Err(crate::error::policy(
                    "the issuer leaf is a CA certificate — not an attestation signer",
                ));
            }
        }
    }
    // KeyUsage decodes from the extensions (2.5.29.15) the same way.
    let ku_oid = ObjectIdentifier::new_unwrap("2.5.29.15");
    // RFC 5280 §4.2.1.3: keyUsage MAY be absent — an unconstrained leaf
    // is acceptable (the CA and EKU checks still apply). Present but
    // without digitalSignature is a refusal (a nonRepudiation-only or
    // keyEncipherment-only leaf is not an attestation signer).
    let key_usage_refused = tbs
        .extensions
        .iter()
        .flatten()
        .filter(|extension| extension.extn_id == ku_oid)
        .any(|extension| {
            x509_cert::ext::pkix::KeyUsage::from_der(extension.extn_value.as_bytes())
                .map(|ku| !ku.0.contains(KeyUsages::DigitalSignature))
                .unwrap_or(true)
        });
    if key_usage_refused {
        return Err(crate::error::policy(
            "the issuer leaf's keyUsage does not include digitalSignature",
        ));
    }
    // EKU: allow-list (RFC 5280 §4.2.1.12 — a certificate with an EKU is
    // restricted to its indicated purposes). An attestation issuer's
    // certificate carries no EKU (the unconstrained case), or purposes that
    // name document signing — `id-kp-documentSigning` (1.3.6.1.5.5.7.3.36,
    // the ISO 18013-5 document-signer profile the OIDF conformance issuer
    // uses) or `anyExtendedKeyUsage` (the explicit wildcard). Anything else
    // — `serverAuth` (the report's TLS case), `clientAuth`, `codeSigning`,
    // `emailProtection`, `timeStamping`, `ocspSigning`, or an unknown
    // purpose — is a restricted-purpose leaf and refuses: a certificate
    // restricted to a purpose other than signing documents cannot sign
    // credentials. Fail closed on the unknown (a registry, not this check,
    // holds the real issuer policy — go-trust #270).
    let eku_oid = ObjectIdentifier::new_unwrap("2.5.29.37");
    for extension in tbs.extensions.iter().flatten() {
        if extension.extn_id != eku_oid {
            continue;
        }
        let eku = ExtendedKeyUsage::from_der(extension.extn_value.as_bytes()).map_err(|e| {
            crate::error::malformed(format!("the issuer leaf's EKU does not parse: {e}"))
        })?;
        let allowed = [
            "1.3.6.1.5.5.7.3.36", // id-kp-documentSigning
            "2.5.29.37.0",        // anyExtendedKeyUsage
        ];
        if !eku
            .0
            .iter()
            .all(|purpose| allowed.iter().any(|a| purpose.to_string() == *a))
        {
            return Err(crate::error::policy(
                "the issuer leaf's EKU names purposes other than document signing — a certificate restricted to another purpose is not an attestation signer",
            ));
        }
    }
    Ok(())
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
