//! Vega's real `nym_auth` proof backend.
//!
//! The borrowed safe-Rust API verifies the statement and reveals its
//! pseudonym. The approved artifact is decompressed `(step, core)` R1CS
//! shapes, exactly as named by the circuit allowlist.

use p256::elliptic_curve::sec1::ToSec1Point;
use zk_cred_vega::nymauth_vega::engine::statement::{self, Keys, Statement};

use crate::backend::{check_claimed, BackendError, ProofBackend};
use crate::circuits::Entry;
use crate::nym_auth::{CONFIG_KNOWN_OFFENDER_MATCHING_SSC, SYSTEM_VEGA};
use crate::refusal::{ZkpError, ZkpResult};
use crate::request::Request;

pub struct VegaBackend {
    keys: Keys,
}

impl VegaBackend {
    pub fn from_entry(entry: &Entry, shapes: &[u8]) -> ZkpResult<Self> {
        if entry.system_id != SYSTEM_VEGA || entry.config != CONFIG_KNOWN_OFFENDER_MATCHING_SSC {
            return Err(ZkpError::fault(format!(
                "Vega nym_auth only supports {SYSTEM_VEGA} {CONFIG_KNOWN_OFFENDER_MATCHING_SSC}, not {} {}",
                entry.system_id, entry.config
            )));
        }
        let keys = Keys::from_shapes(shapes)
            .map_err(|e| ZkpError::fault(format!("loading the Vega nym_auth shapes: {e}")))?;
        Ok(Self { keys })
    }
}

impl ProofBackend for VegaBackend {
    fn verify(&self, req: &Request, claimed: &[u8], proof: &[u8]) -> Result<Vec<u8>, BackendError> {
        let point = req.issuer_key.to_sec1_point(false);
        let encoded = point.as_bytes();
        if encoded.len() != 65 || encoded[0] != 4 {
            return Err(BackendError::DidNotVerify(
                "issuer key is not an uncompressed P-256 point".into(),
            ));
        }
        let time = req
            .time_string()
            .map_err(|e| BackendError::DidNotVerify(e.to_string()))?;
        let (earliest, cutoff) = req.age_bounds();
        let challenge_digest = req
            .e2()
            .map_err(|e| BackendError::DidNotVerify(e.to_string()))?;
        let native = Statement {
            issuer_key_x: &encoded[1..33],
            issuer_key_y: &encoded[33..65],
            time: &time,
            earliest: &earliest,
            cutoff: &cutoff,
            challenge_digest: &challenge_digest,
            verifier_input: &req.verifier_input,
        };
        let revealed = statement::verify(&self.keys, &native, proof)
            .map_err(|e| BackendError::DidNotVerify(e.to_string()))?;
        check_claimed(&revealed, claimed)?;
        Ok(revealed.to_vec())
    }
}
