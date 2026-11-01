//! Longfellow's real `nym_auth` proof backend.
//!
//! The safe-Rust library and this adapter take the same verifier-owned
//! statement as the Go C ABI wrapper: issuer Q, T, inclusive age bounds,
//! challenge digest, verifier input, and the bare SessionTranscript.

use p256::elliptic_curve::sec1::ToSec1Point;
use zk_cred_longfellow::nymauth::{NymAuthCircuitParams, NymAuthRequest, NymAuthVerifier};

use crate::backend::{BackendError, ProofBackend};
use crate::circuits::Entry;
use crate::refusal::{ZkpError, ZkpResult};
use crate::request::Request;

pub struct LongfellowBackend {
    verifier: NymAuthVerifier,
}

impl LongfellowBackend {
    pub fn from_entry(entry: &Entry, circuit: &[u8]) -> ZkpResult<Self> {
        let params = NymAuthCircuitParams {
            block_enc_hash: entry.block_enc_hash as usize,
            block_enc_sig: entry.block_enc_sig as usize,
            hash_circuit_id: entry.hash_circuit_id.clone(),
            sig_circuit_id: entry.sig_circuit_id.clone(),
        };
        Self::with_params(circuit, &params)
    }

    pub fn with_params(circuit: &[u8], params: &NymAuthCircuitParams) -> ZkpResult<Self> {
        let verifier = NymAuthVerifier::new(circuit, params)
            .map_err(|e| ZkpError::fault(format!("loading the Longfellow circuit: {e}")))?;
        Ok(Self { verifier })
    }
}

impl ProofBackend for LongfellowBackend {
    fn verify(&self, req: &Request, claimed: &[u8], proof: &[u8]) -> Result<Vec<u8>, BackendError> {
        let point = req.issuer_key.to_sec1_point(false);
        let encoded = point.as_bytes();
        if encoded.len() != 65 || encoded[0] != 4 {
            return Err(BackendError::DidNotVerify(
                "issuer key is not an uncompressed P-256 point".into(),
            ));
        }
        let issuer_key_x = &encoded[1..33];
        let issuer_key_y = &encoded[33..65];
        let time = req
            .time_string()
            .map_err(|e| BackendError::DidNotVerify(e.to_string()))?;
        let (earliest, cutoff) = req.age_bounds();
        let challenge_digest = req
            .e2()
            .map_err(|e| BackendError::DidNotVerify(e.to_string()))?;
        let native = NymAuthRequest {
            issuer_key_x,
            issuer_key_y,
            time: &time,
            earliest: &earliest,
            cutoff: &cutoff,
            challenge_digest: &challenge_digest,
            verifier_input: &req.verifier_input,
            transcript_seed: &req.session_transcript,
        };
        self.verifier
            .verify(&native, claimed, proof)
            .map_err(|e| BackendError::DidNotVerify(e.to_string()))?;
        Ok(claimed.to_vec())
    }
}
