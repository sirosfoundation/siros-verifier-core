//! Proof backends: one proof system's verifier.
//!
//! Both systems answer the same question (does this proof hold for the statement the verifier named, and what
//! pseudonym does it reveal), so the dispatch holds one of these and does not care which is behind it. What differs
//! is below the trait: how a circuit is loaded and what the native interface takes. This crate ships no backend: the
//! real ones wrap native proof libraries and are registered by the application, so the verification logic is testable
//! without a circuit or a toolchain.

use std::collections::BTreeMap;
use std::sync::Arc;

use subtle::ConstantTimeEq;

use crate::circuits::Entry;
use crate::refusal::{ZkpError, ZkpResult};
use crate::request::Request;

/// Why a backend did not accept a proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendError {
    /// The proof does not verify for these public inputs.
    DidNotVerify(String),
    /// The proof is sound and reveals a different pseudonym than the response claimed. A different fact from a proof
    /// that does not verify at all: the results do not match what it proves.
    PseudonymMismatch,
}

pub trait ProofBackend: Send + Sync {
    /// Check `proof` against `req` and the `claimed` pseudonym; return the pseudonym this verifier may use.
    ///
    /// The returned value is the ONLY pseudonym a caller may act on. The one in the holder's response is a claim until
    /// a proof has been checked against it, and that happens here.
    fn verify(&self, req: &Request, claimed: &[u8], proof: &[u8]) -> Result<Vec<u8>, BackendError>;
}

/// Compare a revealed pseudonym with the claimed one in constant time, for a backend whose interface REVEALS the
/// pseudonym rather than taking the claimed value and comparing internally. Constant time because the comparison is
/// between a secret-derived identifier and a value an attacker supplies.
pub fn check_claimed(revealed: &[u8], claimed: &[u8]) -> Result<(), BackendError> {
    if revealed.len() == claimed.len() && bool::from(revealed.ct_eq(claimed)) {
        Ok(())
    } else {
        Err(BackendError::PseudonymMismatch)
    }
}

/// What this crate must know about a proof system without loading it.
#[derive(Clone, Debug)]
pub struct SystemProfile {
    /// How many certificates the system's `issuer_key_set` carries. Longfellow takes exactly one (the Document
    /// Signer): the shared response shape allows up to eight because it describes every system, but the verifier
    /// knows which system it is verifying for, and on circuit semantics the circuit wins over the shared shape.
    pub issuer_key_set_min: usize,
    pub issuer_key_set_max: usize,
    /// Predicate functions the circuit can evaluate.
    pub supported_functions: Vec<String>,
}

impl SystemProfile {
    /// One certificate, `age_check` supported: the Longfellow circuits.
    pub fn single_issuer_age_check() -> Self {
        Self {
            issuer_key_set_min: 1,
            issuer_key_set_max: 1,
            supported_functions: vec![crate::functions::FUNCTION_AGE_CHECK.to_owned()],
        }
    }
}

/// Builds the verifier for an allowed entry and its (already checked) artifact bytes.
pub type BackendFactory =
    Arc<dyn Fn(&Entry, &[u8]) -> ZkpResult<Box<dyn ProofBackend>> + Send + Sync>;

/// The proof systems this build can verify: for each system id its profile and the way to load it. Unknown systems
/// are an error, never a fallback.
#[derive(Default)]
pub struct BackendRegistry {
    systems: BTreeMap<String, (SystemProfile, BackendFactory)>,
}

impl BackendRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<F>(
        &mut self,
        system_id: &str,
        profile: SystemProfile,
        factory: F,
    ) -> ZkpResult<()>
    where
        F: Fn(&Entry, &[u8]) -> ZkpResult<Box<dyn ProofBackend>> + Send + Sync + 'static,
    {
        crate::nym_auth::check_system_id(system_id).map_err(|e| ZkpError::fault(e.to_string()))?;
        if profile.issuer_key_set_min == 0
            || profile.issuer_key_set_min > profile.issuer_key_set_max
        {
            return Err(ZkpError::fault(format!(
                "system {system_id:?}: the issuer key set size range {}..={} is empty",
                profile.issuer_key_set_min, profile.issuer_key_set_max
            )));
        }
        self.systems
            .insert(system_id.to_owned(), (profile, Arc::new(factory)));
        Ok(())
    }

    pub fn profile(&self, system_id: &str) -> ZkpResult<&SystemProfile> {
        self.systems.get(system_id).map(|(p, _)| p).ok_or_else(|| {
            ZkpError::fault(format!(
                "this build has no verifier for proof system {system_id:?}; it has {:?}",
                self.systems.keys().collect::<Vec<_>>()
            ))
        })
    }

    pub fn factory(&self, system_id: &str) -> ZkpResult<&BackendFactory> {
        self.systems.get(system_id).map(|(_, f)| f).ok_or_else(|| {
            ZkpError::fault(format!(
                "this build has no verifier for proof system {system_id:?}"
            ))
        })
    }

    pub fn systems(&self) -> Vec<&str> {
        self.systems.keys().map(String::as_str).collect()
    }
}
