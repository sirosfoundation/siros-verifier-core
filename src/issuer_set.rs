//! Policy for a presentation that names several issuer certificates (the `zkp_req` `issuer_key_set`).
//!
//! The holder supplies up to eight Document Signer certificates and the proof is made under one of them. The
//! verifier never picks a key itself: it asks the trust layer about every element, then applies a policy to the
//! answers and verifies the proof only under keys the policy leaves usable.
//!
//! * [`IssuerSetPolicy::AllTrusted`] (the default posture): every element must be trusted now. One bad certificate
//!   in the set fails the presentation.
//! * [`IssuerSetPolicy::AtLeastOne`]: at least one element must be usable. This is what a key rollover needs: the
//!   set holds the new certificate and the old one that has only just expired. An element is usable if it is
//!   trusted now, or if it expired no more than `expired_grace_secs` ago **and** the trust layer says it was
//!   trusted at the moment it expired. Untrusted elements are ignored and never used to verify the proof.
//!
//! The "trusted at the moment it expired" question needs the trust layer to evaluate as of a time (`as_of` in the
//! request context). A trust layer that does not support it answers for "now", the old certificate stays untrusted,
//! and the grace never takes effect: the failure is closed, not open.
//!
//! Sans-IO: [`plan`] says what to ask, the driver asks, [`decide`] turns the answers into the usable keys.

use x509_cert::der::Decode;

use crate::mdoc::MdocIssuer;
use crate::trust::TrustQuery;
use crate::{Error, Result};

/// Limits from the `zkp_req` response rules (documented in siros-dc-matcher).
pub const MAX_ELEMENTS: usize = 8;
pub const MAX_ELEMENT_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerSetPolicy {
    AllTrusted,
    AtLeastOne {
        /// How long after `notAfter` an expired certificate may still be used, in seconds.
        expired_grace_secs: i64,
    },
}

#[derive(Clone, Debug)]
pub struct SetMember {
    pub der: Vec<u8>,
    /// The certificate's `notAfter`, unix seconds.
    pub not_after: i64,
}

/// Why a certificate's key cannot be used as a P-256 public input.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    /// The key is not an elliptic-curve key at all.
    NotEcdsa,
    /// An elliptic-curve key on another curve (the name or OID is carried).
    WrongCurve(String),
    /// The certificate's key does not parse.
    Malformed,
}

impl SetMember {
    /// The certificate's public key as a P-256 key. The circuits' arithmetic is over P-256, so a key on another curve
    /// cannot be a public input to them and is refused, not converted.
    pub fn p256_key(&self) -> std::result::Result<p256::PublicKey, KeyError> {
        use x509_cert::der::oid::ObjectIdentifier;
        const ID_EC_PUBLIC_KEY: ObjectIdentifier =
            ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
        const PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
        let cert = x509_cert::Certificate::from_der(&self.der).map_err(|_| KeyError::Malformed)?;
        let spki = &cert.tbs_certificate.subject_public_key_info;
        if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
            return Err(KeyError::NotEcdsa);
        }
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
            .ok_or(KeyError::Malformed)?;
        if curve != PRIME256V1 {
            return Err(KeyError::WrongCurve(curve.to_string()));
        }
        p256::PublicKey::from_sec1_bytes(spki.subject_public_key.raw_bytes())
            .map_err(|_| KeyError::Malformed)
    }
}

/// The questions to put to the trust layer for one element.
#[derive(Clone, Debug)]
pub struct MemberQueries {
    pub index: usize,
    pub now: TrustQuery,
    /// Present only when the policy allows a grace and the certificate expired within it.
    pub at_expiry: Option<TrustQuery>,
}

#[derive(Clone, Copy, Debug)]
pub struct MemberVerdict {
    pub trusted_now: bool,
    /// The answer to `at_expiry`, when one was asked.
    pub trusted_at_expiry: Option<bool>,
}

/// Check the set against the size limits and read each certificate's expiry.
pub fn parse_members(set: &[Vec<u8>]) -> Result<Vec<SetMember>> {
    if set.is_empty() {
        return Err(Error::Policy("issuer_key_set_empty".into()));
    }
    if set.len() > MAX_ELEMENTS {
        return Err(Error::Policy("issuer_key_set_too_many".into()));
    }
    set.iter()
        .map(|der| {
            if der.is_empty() {
                return Err(Error::Policy("issuer_key_empty".into()));
            }
            if der.len() > MAX_ELEMENT_BYTES {
                return Err(Error::Policy("issuer_key_too_large".into()));
            }
            let cert = x509_cert::Certificate::from_der(der)
                .map_err(|_| Error::Malformed("issuer_key_not_a_certificate".into()))?;
            let secs = cert
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs();
            Ok(SetMember {
                der: der.clone(),
                not_after: i64::try_from(secs)
                    .map_err(|_| Error::Malformed("issuer_key_validity".into()))?,
            })
        })
        .collect()
}

/// What to ask the trust layer. `role` and `doc_type` are the action and credential type of the request.
pub fn plan(
    members: &[SetMember],
    policy: IssuerSetPolicy,
    role: &str,
    doc_type: &str,
    now: i64,
) -> Vec<MemberQueries> {
    members
        .iter()
        .enumerate()
        .map(|(index, m)| {
            let issuer = MdocIssuer {
                x5c_der: vec![m.der.clone()],
            };
            let now_q = TrustQuery::for_mdoc_issuer(&issuer, role, doc_type);
            let at_expiry = match policy {
                IssuerSetPolicy::AtLeastOne { expired_grace_secs }
                    if expired_grace_secs > 0
                        && m.not_after < now
                        && now - m.not_after <= expired_grace_secs =>
                {
                    let mut q = now_q.clone();
                    // the last instant at which the certificate was still valid
                    q.as_of = Some(m.not_after - 1);
                    Some(q)
                }
                _ => None,
            };
            MemberQueries {
                index,
                now: now_q,
                at_expiry,
            }
        })
        .collect()
}

/// The indices of the elements the proof may be verified under. An error means the presentation is refused.
pub fn decide(
    policy: IssuerSetPolicy,
    members: &[SetMember],
    verdicts: &[MemberVerdict],
    now: i64,
) -> Result<Vec<usize>> {
    if verdicts.len() != members.len() {
        // a missing answer is never read as trust
        return Err(Error::Policy("issuer_set_verdict_mismatch".into()));
    }
    match policy {
        IssuerSetPolicy::AllTrusted => {
            if let Some(i) = verdicts.iter().position(|v| !v.trusted_now) {
                return Err(Error::Policy(format!("issuer_key_untrusted_{i}")));
            }
            Ok((0..members.len()).collect())
        }
        IssuerSetPolicy::AtLeastOne { expired_grace_secs } => {
            let usable: Vec<usize> = members
                .iter()
                .zip(verdicts)
                .enumerate()
                .filter(|(_, (m, v))| {
                    v.trusted_now
                        || (v.trusted_at_expiry == Some(true)
                            && expired_grace_secs > 0
                            && m.not_after < now
                            && now - m.not_after <= expired_grace_secs)
                })
                .map(|(i, _)| i)
                .collect();
            if usable.is_empty() {
                return Err(Error::Policy("no_trusted_issuer_key".into()));
            }
            Ok(usable)
        }
    }
}
