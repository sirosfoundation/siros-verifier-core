//! nym_auth rulebook constants and the pseudonym derivation.

use sha2::{Digest, Sha256};
use siros_verifier_core::{Error, Result};

pub const CONFIG_KNOWN_OFFENDER_MATCHING_SSC: &str = "known-offender-matching-ssc";
pub const CONFIG_KNOWN_OFFENDER_MATCHING_PSC: &str = "known-offender-matching-psc";
pub const CONFIG_ACCOUNT_RECOVERY_SSC: &str = "account-recovery-ssc";
pub const CONFIG_USER_MANAGED_XSITE_SSC: &str = "user-managed-pseudonym-xsite-ssc";

/// The proof systems, by the catalog alias that travels on the wire in `system_id`.
pub const SYSTEM_LONGFELLOW: &str = "urn:circuits:longfellow:nym_auth:v1";
pub const SYSTEM_VEGA: &str = "urn:circuits:vega:nym_auth:v1";

pub fn systems() -> [&'static str; 2] {
    [SYSTEM_LONGFELLOW, SYSTEM_VEGA]
}

/// Refuse a system id this build does not know. A system id selects which library checks the proof; an unknown one
/// is a statement about a verifier that does not exist here.
pub fn check_system_id(id: &str) -> Result<()> {
    if id.is_empty() {
        return Err(Error::Policy(format!(
            "no system_id; it names the proof system a circuit belongs to, one of {:?}",
            systems()
        )));
    }
    if !systems().contains(&id) {
        return Err(Error::Policy(format!(
            "{id:?} is not a nym_auth system_id; known ones are {:?}",
            systems()
        )));
    }
    Ok(())
}

/// Bytes of a pseudonym seed.
pub const SEED_BYTES: usize = 16;

const VERIFIER_ID_SEMANTIC: &str = "semantic_id:";
const VERIFIER_ID_X509_SAN_DNS: &str = "x509_san_dns:";

/// Rulebook v0.4 defines exactly two verifier id forms, `x509_san_dns:<name>` and `semantic_id:<id>`. Anything else
/// is refused instead of hashed: a value nobody agreed the meaning of derives a pseudonym no other implementation
/// reports, which matches nothing and reads as an innocent subject.
pub fn check_verifier_id(id: &str) -> Result<()> {
    if id.is_empty() {
        return Err(Error::Policy("no verifier_id".into()));
    }
    for prefix in [VERIFIER_ID_X509_SAN_DNS, VERIFIER_ID_SEMANTIC] {
        if id == prefix {
            return Err(Error::Policy(format!(
                "verifier_id {id:?} is the {} prefix with no identifier after it",
                prefix.trim_end_matches(':')
            )));
        }
        if id.starts_with(prefix) {
            return Ok(());
        }
    }
    let hint = if looks_like_dns_name(id) {
        format!("; it looks like a DNS name, so the verifier_id is probably \"{VERIFIER_ID_X509_SAN_DNS}{id}\"")
    } else {
        String::new()
    };
    Err(Error::Policy(format!(
        "verifier_id {id:?} starts with neither {VERIFIER_ID_X509_SAN_DNS:?} nor {VERIFIER_ID_SEMANTIC:?}, and \
         rulebook v0.4 defines no other form{hint}"
    )))
}

fn looks_like_dns_name(v: &str) -> bool {
    if v.is_empty() || v.contains([':', '/', ' ']) || !v.contains('.') {
        return false;
    }
    v.split('.').all(|label| {
        !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// SHA-256 of the verifier id, the circuits' `verifier_input`.
pub fn verifier_input(verifier_id: &str) -> Result<[u8; 32]> {
    check_verifier_id(verifier_id)?;
    Ok(Sha256::digest(verifier_id.as_bytes()).into())
}

const NULL_INPUT: [u8; 32] = [0u8; 32];

/// `SHA-256("nym_auth/v1/" || config || seed || prover_input || verifier_input)`.
pub fn pseudonym(
    config: &str,
    seed: &[u8],
    prover_input: &[u8],
    verifier_input: &[u8],
) -> Result<[u8; 32]> {
    if config.is_empty() {
        return Err(Error::Policy("no pseudonym configuration named".into()));
    }
    if seed.len() != SEED_BYTES {
        return Err(Error::Policy(format!(
            "a seed is {SEED_BYTES} bytes in this rulebook, got {}",
            seed.len()
        )));
    }
    if prover_input.len() != 32 || verifier_input.len() != 32 {
        return Err(Error::Policy(
            "prover_input and verifier_input must each be 32 bytes".into(),
        ));
    }
    let mut h = Sha256::new();
    h.update(b"nym_auth/v1/");
    h.update(config.as_bytes());
    h.update(seed);
    h.update(prover_input);
    h.update(verifier_input);
    Ok(h.finalize().into())
}

/// A known-offender-matching pseudonym for a verifier: the circuits' reference derivation, used by test provers.
pub fn known_offender_matching(config: &str, seed: &[u8], verifier_id: &str) -> Result<[u8; 32]> {
    if !matches!(
        config,
        CONFIG_KNOWN_OFFENDER_MATCHING_SSC | CONFIG_KNOWN_OFFENDER_MATCHING_PSC
    ) {
        return Err(Error::Policy(format!(
            "{config:?} is not a known-offender-matching configuration"
        )));
    }
    let vi = verifier_input(verifier_id)?;
    pseudonym(config, seed, &NULL_INPUT, &vi)
}
