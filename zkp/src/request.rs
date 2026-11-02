//! What a nym_auth circuit is verified against.
//!
//! Every field is the VERIFIER'S: Q comes from the issuer certificate the trust layer vouched for, T from a
//! prover-supplied `proof_time` that passed the verifier's tolerance, the predicate bounds from the verifier's own
//! request, the transcript from its own session, `verifier_input` from its own identity. None is read from the
//! holder's response, and the pseudonym is an OUTPUT. A verifier that took any of these from the response would be
//! checking a statement the holder chose.

use std::collections::BTreeSet;

use siros_verifier_core::{Error, Result};

use crate::functions::{
    CircuitInput, FunctionRegistry, FUNCTION_AGE_CHECK, INPUT_CUTOFF, INPUT_EARLIEST,
    NO_LOWER_BOUND, NO_UPPER_BOUND,
};
use crate::transcript;

#[derive(Clone, Debug)]
pub struct Request {
    /// Q: the issuer key the credential was signed with. P-256 by type.
    pub issuer_key: p256::PublicKey,
    /// T, unix seconds. The circuits take it as 20 ASCII bytes `YYYY-MM-DDThh:mm:ssZ`.
    pub now: i64,
    /// Predicate contributions, one per function.
    pub inputs: Vec<CircuitInput>,
    /// Function ids the selected circuit supports. Empty means none: a predicate is refused, never passed to a
    /// circuit that cannot evaluate it.
    pub supported_functions: Vec<String>,
    /// The session transcript (an unwrapped three-item CBOR array). `e2` is derived from it, never carried beside it:
    /// two independent fields could name one session in the seed and another in the digest.
    pub session_transcript: Vec<u8>,
    pub doc_type: String,
    /// SHA-256 of the verifier id (see [`crate::nym_auth::verifier_input`]).
    pub verifier_input: [u8; 32],
}

impl Request {
    /// The challenge digest this request binds the proof to.
    pub fn e2(&self) -> Result<[u8; 32]> {
        transcript::challenge_digest(&self.session_transcript, &self.doc_type)
    }

    /// Refuse a request a circuit cannot be verified against, or that would be verified against the wrong thing.
    pub fn check(&self, functions: &FunctionRegistry) -> Result<()> {
        if self.now <= 0 {
            return Err(Error::Policy(
                "no verification time; T is the proof's own time and a zero value would check validity against 1970".into(),
            ));
        }
        self.time_string()?;
        let mut seen = BTreeSet::new();
        for input in &self.inputs {
            if !seen.insert(input.function_id.as_str()) {
                // Two contributions from one function would fill the same circuit inputs twice, and the second
                // would silently win.
                return Err(Error::Policy(format!(
                    "function {:?} contributes twice",
                    input.function_id
                )));
            }
            functions.check_input(input)?;
            if !self.supported_functions.contains(&input.function_id) {
                return Err(Error::Policy(format!(
                    "the selected circuit does not support function {:?}; it supports {:?}",
                    input.function_id, self.supported_functions
                )));
            }
        }
        // Deriving e2 is the only check of the transcript's shape and of the docType, so a request is not checked
        // until it has run.
        self.e2()?;
        if self.verifier_input == [0u8; 32] {
            return Err(Error::Policy(
                "verifier_input is zero; the pseudonym would not be scoped to this verifier".into(),
            ));
        }
        Ok(())
    }

    /// Inclusive age bounds in the form the native circuits take.
    pub fn age_bounds(&self) -> (String, String) {
        let mut earliest = NO_LOWER_BOUND.to_owned();
        let mut cutoff = NO_UPPER_BOUND.to_owned();
        for input in &self.inputs {
            if input.function_id != FUNCTION_AGE_CHECK {
                continue;
            }
            for (name, value) in &input.values {
                let value = String::from_utf8_lossy(value).into_owned();
                match name.as_str() {
                    INPUT_EARLIEST => earliest = value,
                    INPUT_CUTOFF => cutoff = value,
                    _ => {}
                }
            }
        }
        (earliest, cutoff)
    }

    /// T as the circuits take it, in UTC.
    pub fn time_string(&self) -> Result<String> {
        siros_verifier_core::mdoc::format_utc(self.now).map_err(|_| {
            Error::Policy("this year cannot be written in the circuits' 20-byte time format".into())
        })
    }
}
