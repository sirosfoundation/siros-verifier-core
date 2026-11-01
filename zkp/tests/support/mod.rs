//! A test harness for zkp_req verification: a holder/prover that builds presentations, a MODEL circuit standing in for a
//! proof system (a keyed digest over exactly the public inputs, NOT cryptography), and the plumbing around them.
//! The model makes every binding rule observable: change any public input and the proof stops verifying.
#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use siros_dc_matcher_core::zkp_req::Plan;
use siros_verifier_core::issuer_set::{IssuerSetPolicy, MemberVerdict};
use siros_verifier_zkp::backend::*;
use siros_verifier_zkp::circuits::*;
use siros_verifier_zkp::functions::FunctionRegistry;
use siros_verifier_zkp::nym_auth::*;
use siros_verifier_zkp::refusal::ZkpResult;
use siros_verifier_zkp::verify::*;

pub use siros_verifier_zkp::testutil::*;

/// A fixture: the holder's statement, a verifier with the model registered, and counters.
pub struct Fx {
    pub verifier: ZkpVerifier,
    pub plan: Plan,
    pub loads: Arc<AtomicUsize>,
    pub cert: Vec<u8>,
    pub statement: Statement,
    _artifact: ArtifactFile,
}

pub struct Opts {
    pub policy: IssuerSetPolicy,
    pub issuer_key_set_max: usize,
    pub tolerance: Tolerance,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            policy: IssuerSetPolicy::AllTrusted,
            issuer_key_set_max: 1,
            tolerance: Tolerance::default(),
        }
    }
}

pub fn fx(opts: Opts) -> Fx {
    let (file, cfg) = artifact(b"a model circuit artifact");
    let allow = Allowlist::new(&CircuitsConfig {
        sources: vec![],
        allow: vec![cfg],
    })
    .unwrap();
    let loads = Arc::new(AtomicUsize::new(0));
    let mut reg = BackendRegistry::new();
    let l = loads.clone();
    let mut profile = SystemProfile::single_issuer_age_check();
    profile.issuer_key_set_max = opts.issuer_key_set_max;
    reg.register(
        SYSTEM_LONGFELLOW,
        profile,
        move |entry, _bytes| -> ZkpResult<Box<dyn ProofBackend>> {
            l.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(Model {
                config: entry.config.clone(),
            }))
        },
    )
    .unwrap();
    let verifier = ZkpVerifier::new(
        allow,
        Box::new(FsArtifactSource),
        FunctionRegistry::with_builtins(),
        reg,
        VerifierPolicy {
            role: "nym-attestation-provider".into(),
            issuer_set: opts.policy,
            tolerance: opts.tolerance,
        },
    )
    .unwrap();
    let cert = good_cert();
    let key = siros_verifier_core::issuer_set::parse_members(std::slice::from_ref(&cert)).unwrap()
        [0]
    .p256_key()
    .unwrap();
    Fx {
        verifier,
        plan: make_plan(&query(None, false), &[SYSTEM_LONGFELLOW]),
        loads,
        cert,
        statement: Statement {
            channel: dc_channel(),
            nonce: NONCE.into(),
            thumbprint: None,
            verifier_id: VERIFIER_ID.into(),
            issuer_key: key,
            proof_time: NOW - 5,
            age_earliest: "2008-10-10".into(),
            age_cutoff: "2013-10-09".into(),
            config: CONFIG.into(),
        },
        _artifact: file,
    }
}

impl Fx {
    /// A presentation exactly as an honest holder with `self.statement` would send it.
    pub fn honest(&self) -> Vec<u8> {
        self.present(
            &self.statement,
            std::slice::from_ref(&self.cert),
            &reference_pseudonym(&self.statement.verifier_id),
        )
    }
    pub fn present(&self, st: &Statement, key_set: &[Vec<u8>], claimed: &[u8]) -> Vec<u8> {
        presentation_cbor(
            SYSTEM_LONGFELLOW,
            &model_proof(st),
            key_set,
            Some(st.proof_time),
            claimed,
        )
    }
    pub fn exchange<'a>(&'a self, channel: &'a Channel, thumb: Option<&'a [u8]>) -> Exchange<'a> {
        Exchange {
            plan: &self.plan,
            channel,
            nonce: NONCE,
            reader_thumbprint: thumb,
            verifier_id: VERIFIER_ID,
            now: NOW,
        }
    }
}

pub fn trusted(n: usize) -> Vec<Vec<MemberVerdict>> {
    vec![vec![
        MemberVerdict {
            trusted_now: true,
            trusted_at_expiry: None
        };
        n
    ]]
}
