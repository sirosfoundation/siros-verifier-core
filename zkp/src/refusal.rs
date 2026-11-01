//! Refusals, with stable codes.
//!
//! A refused presentation is the wallet's business: a 4xx carrying a code a wallet author can branch on. Anything
//! else is this verifier failing to do its job (a circuit that will not load, no backend for a system) and stays a
//! fault, because telling a wallet author "your presentation is bad" when the fault is ours sends them hunting for
//! a defect that is not there. Shape refusals keep the shared validator's own code unchanged, so the vocabulary a
//! wallet sees is the one the matcher vectors publish.

use std::fmt;

pub const NO_PRESENTATION: &str = "zkp_req_no_presentation";
pub const PROOF_TIME_MISSING: &str = "zkp_req_proof_time_missing";
pub const PROOF_TIME_OUT_OF_RANGE: &str = "zkp_req_proof_time_out_of_range";
pub const WRONG_CHANNEL: &str = "zkp_req_wrong_channel";
pub const ISSUER_KEY_SET_EMPTY: &str = "zkp_req_issuer_key_set_empty";
pub const ISSUER_KEY_SET_SIZE: &str = "zkp_req_issuer_key_set_size";
pub const ISSUER_KEY_NOT_A_CERTIFICATE: &str = "zkp_req_issuer_key_not_a_certificate";
pub const ISSUER_NOT_TRUSTED: &str = "zkp_req_issuer_not_trusted";
pub const ISSUER_KEY_WRONG_CURVE: &str = "zkp_req_issuer_key_wrong_curve";
pub const ISSUER_KEY_NOT_ECDSA: &str = "zkp_req_issuer_key_not_ecdsa";
pub const PROOF_DID_NOT_VERIFY: &str = "zkp_req_proof_did_not_verify";
pub const PSEUDONYM_MISMATCH: &str = "zkp_req_pseudonym_mismatch";
pub const NO_PSEUDONYM: &str = "zkp_req_no_pseudonym_for_handle";
pub const NOTHING_CHECKED: &str = "zkp_req_nothing_checked";
pub const UNSATISFIABLE_REQUEST: &str = "zkp_req_unsatisfiable_request";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZkpError {
    /// The presentation is refused, under a stable code.
    Refused { code: String, detail: String },
    /// This verifier cannot judge a presentation (misconfiguration, a missing backend, a failing store).
    Fault(String),
}

impl ZkpError {
    pub fn refused(code: &str, detail: impl Into<String>) -> Self {
        Self::Refused {
            code: code.to_owned(),
            detail: detail.into(),
        }
    }

    pub fn fault(detail: impl Into<String>) -> Self {
        Self::Fault(detail.into())
    }

    /// The stable code of a refusal, `None` for a fault.
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Refused { code, .. } => Some(code),
            Self::Fault(_) => None,
        }
    }

    pub fn is_refusal(&self) -> bool {
        matches!(self, Self::Refused { .. })
    }
}

impl fmt::Display for ZkpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused { code, detail } => write!(f, "{code}: {detail}"),
            Self::Fault(d) => write!(f, "fault: {d}"),
        }
    }
}

impl std::error::Error for ZkpError {}

pub type ZkpResult<T> = std::result::Result<T, ZkpError>;
