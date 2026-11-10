//! Verifying a `zkp_req` presentation, in two phases so the core stays free of input and output.
//!
//! 1. [`ZkpVerifier::begin`] checks everything that needs no trust answer: the response's shape and its binding to
//!    the request (the shared validator), the channel and its transcript, `proof_time` against the verifier's clock,
//!    the issuer key set against the system's limits. It returns [`Pending`], which lists the questions to put to the
//!    trust layer.
//! 2. The driver asks them (go-trust, through the receipt cache) and passes the answers to [`Pending::finish`], which
//!    applies the issuer-set policy, loads the circuit once, and asks the backend to verify the proof under each
//!    key the policy left usable.
//!
//! What the proof is measured against is the verifier's own, never the response's: the transcript from its session,
//! the verifier input from its identity, the predicate bounds from its request, the issuer key from a certificate the
//! trust layer vouched for, and T from a prover-supplied time that passed the verifier's tolerance. The pseudonym a
//! caller may act on is the one the backend RETURNED.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use base64::Engine;
use sha2::{Digest, Sha256};
use siros_dc_matcher_core::proof_time as matcher_time;
use siros_dc_matcher_core::zkp_req::{unsatisfiable, Params, Plan};
use siros_dc_matcher_core::zkp_req_response::{parse_response, Presentation, ResultValue};
use siros_verifier_core::issuer_set::{
    self, IssuerSetPolicy, KeyError, MemberQueries, MemberVerdict, SetMember,
};

use crate::backend::{BackendError, BackendRegistry, ProofBackend};
use crate::circuits::{check_artifact, Allowlist, ArtifactSource};
use crate::functions::{AgeCheck, CircuitInput, FunctionRegistry, FUNCTION_AGE_CHECK};
use crate::nym_auth;
use crate::refusal::{
    ZkpError, ZkpResult, ISSUER_KEY_NOT_A_CERTIFICATE, ISSUER_KEY_NOT_ECDSA, ISSUER_KEY_SET_SIZE,
    ISSUER_KEY_WRONG_CURVE, ISSUER_NOT_TRUSTED, NOTHING_CHECKED, NO_PSEUDONYM,
    PROOF_DID_NOT_VERIFY, PROOF_TIME_MISSING, PROOF_TIME_OUT_OF_RANGE, PSEUDONYM_MISMATCH,
};
use crate::request::Request;
use crate::transcript;

/// How a presentation reached this verifier. The channel decides the SessionTranscript, and the transcript is what
/// the proof is bound to, so this is not a detail: a wallet built only one handover, and verifying against the other
/// produces an opaque proof failure instead of a legible wiring error.
#[derive(Clone, Debug)]
pub enum Channel {
    /// Returned inside `navigator.credentials.get`.
    DcApi { origin: String },
    /// POSTed to `response_uri` by a wallet reached through a link or QR code.
    Redirect {
        client_id: String,
        response_uri: String,
        /// Whether the response was encrypted (`direct_post.jwt`). Required over a redirect: a pseudonym is a stable
        /// identifier for a person across that verifier's sessions, and one sent in the clear is readable by anything
        /// on the path.
        encrypted: bool,
    },
}

/// The window a prover-supplied `proof_time` must fall in. Recommendations by default, not protocol constants.
#[derive(Clone, Copy, Debug, serde::Deserialize)]
pub struct Tolerance {
    pub skew_secs: i64,
    pub max_age_secs: i64,
}

impl Default for Tolerance {
    fn default() -> Self {
        Self {
            skew_secs: matcher_time::RECOMMENDED_SKEW_SECS,
            max_age_secs: matcher_time::RECOMMENDED_MAX_AGE_SECS,
        }
    }
}

#[derive(Clone, Debug)]
pub struct VerifierPolicy {
    /// The trust layer's action name for these issuers.
    pub role: String,
    pub issuer_set: IssuerSetPolicy,
    pub tolerance: Tolerance,
}

/// What the verifier knows about the exchange, all of it its own.
pub struct Exchange<'a> {
    pub plan: &'a Plan,
    pub channel: &'a Channel,
    /// The request nonce this verifier issued.
    pub nonce: &'a str,
    /// RFC 7638 thumbprint of the response-encryption key. Required over a redirect.
    pub reader_thumbprint: Option<&'a [u8]>,
    /// What derivations name the verifier by (`VerifierIdentity::verifier_id`).
    pub verifier_id: &'a str,
    pub now: i64,
}

pub struct ZkpVerifier {
    allowlist: Allowlist,
    source: Box<dyn ArtifactSource>,
    functions: FunctionRegistry,
    backends: BackendRegistry,
    policy: VerifierPolicy,
    loaded: Mutex<HashMap<(String, String), Arc<dyn ProofBackend>>>,
}

struct Item {
    presentation: Presentation,
    proof_time_secs: i64,
    proof_time_text: String,
    members: Vec<SetMember>,
    queries: Vec<MemberQueries>,
}

/// A response that passed every check that needs no trust answer.
///
/// The verifier is held by `Arc` because the driver owns the choice of thread
/// for phase two: native proof verification is synchronous, so a driver runs
/// `finish` wherever synchronous work belongs (a blocking worker), and the
/// witness must carry the verifier's lifetime there. The core itself stays
/// sans-I/O and thread-agnostic.
pub struct Pending {
    verifier: Arc<ZkpVerifier>,
    plan: Plan,
    transcript: Vec<u8>,
    verifier_input: [u8; 32],
    /// The verifier's own clock at `begin`. The prover's T never moves the grace window.
    now: i64,
    items: Vec<Item>,
}

/// A presentation whose proof held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPresentation {
    pub system_id: String,
    /// The T the proof was checked against, as the prover spelled it.
    pub proof_time: String,
    /// Which issuer key verified, without putting a key in a log line.
    pub issuer_key_thumbprint: String,
    /// Handle to pseudonym, as the backend RETURNED them, never as the holder claimed them.
    pub pseudonyms: BTreeMap<String, Vec<u8>>,
    /// Handles whose predicate the proof asserts.
    pub satisfied: Vec<String>,
}

impl ZkpVerifier {
    pub fn new(
        allowlist: Allowlist,
        source: Box<dyn ArtifactSource>,
        functions: FunctionRegistry,
        backends: BackendRegistry,
        policy: VerifierPolicy,
    ) -> ZkpResult<Self> {
        // An allowed circuit with no backend to load it is a misconfiguration to find at startup.
        for entry in allowlist.allowed() {
            let system = entry.split(' ').next().unwrap_or_default();
            backends.profile(system)?;
        }
        Ok(Self {
            allowlist,
            source,
            functions,
            backends,
            policy,
            loaded: Mutex::new(HashMap::new()),
        })
    }

    pub fn policy(&self) -> &VerifierPolicy {
        &self.policy
    }

    /// Initialize every allowlisted backend, validating each artifact and native circuit eagerly.
    ///
    /// This is an explicit startup operation for long-lived services. Embedded callers retain lazy
    /// loading when they prefer lower memory use. Successful loads share the same per-verifier cache
    /// as request-time loading; failures are returned and remain retryable rather than being cached.
    /// No presentation, witness, proof result, or trust decision is prepared here.
    pub fn prewarm(&self) -> ZkpResult<()> {
        for entry in self.allowlist.entries() {
            self.backend(&entry.system_id, &entry.config)?;
        }
        Ok(())
    }

    /// Phase one. See the module documentation.
    ///
    /// Called on the `Arc` because the returned [`Pending`] carries the
    /// verifier's lifetime to wherever the driver runs phase two.
    pub fn begin(self: &Arc<Self>, ex: &Exchange, vp_token_json: &str) -> ZkpResult<Pending> {
        // The request this verifier sent must itself be satisfiable; a request that cannot be is a fault here, not a
        // wallet's defect.
        unsatisfiable(ex.plan).map_err(|e| {
            ZkpError::fault(format!(
                "this verifier's own request is unsatisfiable: {}",
                e.code()
            ))
        })?;

        // Shape, and binding to what THIS request offered. Nothing here is a verified fact yet.
        let presentations = parse_response(ex.plan, vp_token_json)
            .map_err(|e| ZkpError::refused(e.code(), e.to_string()))?;

        let doc_type = ex
            .plan
            .meta_doctype
            .as_deref()
            .ok_or_else(|| ZkpError::fault("the request names no doctype_value, so there is no trust policy to judge issuers under"))?;

        let transcript = match ex.channel {
            Channel::DcApi { origin } => transcript::session_transcript_dcapi(origin, ex.nonce, ex.reader_thumbprint),
            Channel::Redirect {
                client_id,
                response_uri,
                encrypted,
            } => {
                if !encrypted {
                    return Err(ZkpError::fault(
                        "this presentation arrived by redirect without response_mode direct_post.jwt; nym_auth \
                         requires it there, because a pseudonym sent to response_uri in the clear is readable by \
                         anything on the path",
                    ));
                }
                let thumb = ex.reader_thumbprint.ok_or_else(|| {
                    ZkpError::fault("no reader key thumbprint for a redirect session, so its transcript cannot be rebuilt")
                })?;
                transcript::session_transcript_redirect(client_id, ex.nonce, response_uri, thumb)
            }
        }
        .map_err(|e| ZkpError::fault(format!("cannot build the zkp_req session transcript: {e}")))?;

        let verifier_input = nym_auth::verifier_input(ex.verifier_id)
            .map_err(|e| ZkpError::fault(format!("verifier id: {e}")))?;

        let mut items = Vec::with_capacity(presentations.len());
        for p in presentations {
            // T first: it is the prover's, and a presentation whose T is outside this verifier's window is refused
            // before any work is done on its behalf.
            let text = p.proof_time.clone().ok_or_else(|| {
                ZkpError::refused(
                    PROOF_TIME_MISSING,
                    "the presentation carries no proof_time, so there is no T to verify against",
                )
            })?;
            let tol = self.policy.tolerance;
            matcher_time::check_tolerance(&text, ex.now, tol.skew_secs, tol.max_age_secs).map_err(|e| {
                // The deviation and the limit are in the detail: without them a wallet cannot tell a clock that is
                // wrong from a proof that is stale, and both arrive here.
                ZkpError::refused(
                    PROOF_TIME_OUT_OF_RANGE,
                    format!(
                        "proof_time {text} is outside this verifier's window ({}s skew into the future, {}s of age): {}",
                        tol.skew_secs,
                        tol.max_age_secs,
                        e.code()
                    ),
                )
            })?;
            let proof_time_secs = matcher_time::parse(&text)
                .map_err(|e| ZkpError::refused(PROOF_TIME_OUT_OF_RANGE, e.code()))?;

            let profile = self.backends.profile(&p.system_id)?;
            let n = p.issuer_key_set.len();
            if n < profile.issuer_key_set_min || n > profile.issuer_key_set_max {
                return Err(ZkpError::refused(
                    ISSUER_KEY_SET_SIZE,
                    format!(
                        "the issuer key set has {n} elements; the {} system takes {}..={}",
                        p.system_id, profile.issuer_key_set_min, profile.issuer_key_set_max
                    ),
                ));
            }
            let members = issuer_set::parse_members(&p.issuer_key_set).map_err(|e| match e {
                siros_verifier_core::Error::Malformed(_) => ZkpError::refused(
                    ISSUER_KEY_NOT_A_CERTIFICATE,
                    "an issuer key does not parse as a certificate",
                ),
                other => ZkpError::refused(ISSUER_KEY_SET_SIZE, other.to_string()),
            })?;
            let queries = issuer_set::plan(
                &members,
                self.policy.issuer_set,
                &self.policy.role,
                doc_type,
                ex.now,
            );
            items.push(Item {
                presentation: p,
                proof_time_secs,
                proof_time_text: text,
                members,
                queries,
            });
        }
        Ok(Pending {
            verifier: Arc::clone(self),
            plan: ex.plan.clone(),
            transcript,
            verifier_input,
            now: ex.now,
            items,
        })
    }

    /// The backend for a system and configuration, loaded once. Loading is the expensive step (a megabyte of artifact
    /// for one system, a verifier key derived from shapes for the other), and a loaded backend holds no interior
    /// state a second presentation could disturb.
    fn backend(&self, system_id: &str, config: &str) -> ZkpResult<Arc<dyn ProofBackend>> {
        let mut loaded = self.loaded.lock().expect("backends");
        let key = (system_id.to_owned(), config.to_owned());
        if let Some(b) = loaded.get(&key) {
            return Ok(b.clone());
        }
        let entry = self.allowlist.entry(system_id, config)?;
        let bytes = self.source.read(entry)?;
        check_artifact(entry, &bytes)?;
        // Dispatched on the ENTRY's system: the entry is the operator's statement about which library may open this
        // artifact. The two are equal here because the entry was looked up by that key.
        let backend: Arc<dyn ProofBackend> =
            Arc::from((self.backends.factory(&entry.system_id)?)(entry, &bytes)?);
        loaded.insert(key, backend.clone());
        Ok(backend)
    }
}

impl Pending {
    /// The questions to put to the trust layer, per presentation, in order.
    pub fn trust_queries(&self) -> Vec<&[MemberQueries]> {
        self.items.iter().map(|i| i.queries.as_slice()).collect()
    }

    /// Phase two. `verdicts[i][j]` is the answer for element `j` of presentation `i`.
    pub fn finish(self, verdicts: &[Vec<MemberVerdict>]) -> ZkpResult<Vec<VerifiedPresentation>> {
        let v = self.verifier.as_ref();
        if verdicts.len() != self.items.len() {
            return Err(ZkpError::fault(
                "one set of trust answers per presentation is required",
            ));
        }
        let mut out = Vec::with_capacity(self.items.len());
        for (item, answers) in self.items.iter().zip(verdicts) {
            out.push(self.verify_one(item, answers, v)?);
        }
        Ok(out)
    }

    fn verify_one(
        &self,
        item: &Item,
        answers: &[MemberVerdict],
        v: &ZkpVerifier,
    ) -> ZkpResult<VerifiedPresentation> {
        let p = &item.presentation;
        // The trust layer vouches for the keys before any of them is looked at.
        let usable = issuer_set::decide(v.policy.issuer_set, &item.members, answers, self.now)
            .map_err(|e| ZkpError::refused(ISSUER_NOT_TRUSTED, e.to_string()))?;
        let mut keys = Vec::with_capacity(usable.len());
        for &i in &usable {
            keys.push(item.members[i].p256_key().map_err(|e| match e {
                KeyError::NotEcdsa => ZkpError::refused(
                    ISSUER_KEY_NOT_ECDSA,
                    "the issuer certificate does not hold an elliptic-curve key",
                ),
                KeyError::WrongCurve(c) => ZkpError::refused(
                    ISSUER_KEY_WRONG_CURVE,
                    format!("the issuer key is on curve {c}, and the circuit takes P-256"),
                ),
                KeyError::Malformed => ZkpError::refused(
                    ISSUER_KEY_NOT_A_CERTIFICATE,
                    "the issuer key does not parse",
                ),
            })?);
        }

        let profile = v.backends.profile(&p.system_id)?;
        let inputs = self.circuit_inputs()?;

        let mut pseudonyms = BTreeMap::new();
        let mut thumb = String::new();
        let mut checked = 0usize;
        for f in self
            .plan
            .functions
            .iter()
            .filter(|f| f.function_id == "pseudonym")
        {
            let claimed = p
                .results
                .iter()
                .find_map(|(h, r)| match (h == &f.handle, r) {
                    (true, ResultValue::Pseudonym(b)) => Some(b.as_slice()),
                    _ => None,
                })
                .ok_or_else(|| {
                    ZkpError::refused(
                        NO_PSEUDONYM,
                        format!("no pseudonym for handle {:?}", f.handle),
                    )
                })?;
            // From the REQUEST: the configuration selects the circuit build and decides the pseudonym's domain
            // separator, so taking it from the response would let the holder choose which function it is measured by.
            let config = match &f.params {
                Params::Pseudonym {
                    config: Some(c), ..
                } if !c.is_empty() => c.as_str(),
                _ => {
                    return Err(ZkpError::fault(format!(
                        "the request item {:?} names no pseudonym configuration",
                        f.handle
                    )))
                }
            };
            let backend = v.backend(&p.system_id, config)?;

            let mut mismatch = 0usize;
            let mut verified: Option<(Vec<u8>, &p256::PublicKey)> = None;
            for key in &keys {
                let req = Request {
                    issuer_key: *key,
                    now: item.proof_time_secs,
                    inputs: inputs.clone(),
                    supported_functions: profile.supported_functions.clone(),
                    session_transcript: self.transcript.clone(),
                    doc_type: self.plan.meta_doctype.clone().unwrap_or_default(),
                    verifier_input: self.verifier_input,
                };
                req.check(&v.functions).map_err(|e| {
                    ZkpError::fault(format!("the circuit request cannot be built: {e}"))
                })?;
                match backend.verify(&req, claimed, &p.proof) {
                    Ok(revealed) => {
                        verified = Some((revealed, key));
                        break;
                    }
                    Err(BackendError::PseudonymMismatch) => mismatch += 1,
                    Err(BackendError::DidNotVerify(_)) => {}
                }
            }
            let Some((revealed, key)) = verified else {
                let code = if mismatch == keys.len() {
                    PSEUDONYM_MISMATCH
                } else {
                    PROOF_DID_NOT_VERIFY
                };
                return Err(ZkpError::refused(
                    code,
                    format!("the proof did not verify for handle {:?}", f.handle),
                ));
            };
            // Belt and braces: whatever the backend does internally, what leaves here equals what was claimed.
            if crate::backend::check_claimed(&revealed, claimed).is_err() {
                return Err(ZkpError::refused(
                    PSEUDONYM_MISMATCH,
                    format!(
                        "the proof reveals a different pseudonym than claimed for {:?}",
                        f.handle
                    ),
                ));
            }
            thumb = key_thumbprint(key);
            // The RETURNED value, never the claimed one.
            pseudonyms.insert(f.handle.clone(), revealed);
            checked += 1;
        }
        if checked == 0 {
            // Fail closed. The proof is one proof over the whole request, and the only way to check it is a pseudonym
            // item's verification: with none there is nothing checked and no way to say the predicates hold. A
            // predicate-only request is one this verifier must not send, and refuses here too because this is the
            // point that cannot be bypassed.
            return Err(ZkpError::refused(
                NOTHING_CHECKED,
                "this request asks only for predicates, and the proof is checked by verifying a pseudonym; a \
                 predicate-only request has no verification path, so its results cannot be accepted",
            ));
        }
        let satisfied = p
            .results
            .iter()
            .filter(|(_, r)| matches!(r, ResultValue::Predicate))
            .map(|(h, _)| h.clone())
            .collect();
        Ok(VerifiedPresentation {
            system_id: p.system_id.clone(),
            proof_time: item.proof_time_text.clone(),
            issuer_key_thumbprint: thumb,
            pseudonyms,
            satisfied,
        })
    }

    /// The predicate contributions, from the verifier's OWN request. Taking them from the response would be verifying
    /// a statement the holder chose.
    fn circuit_inputs(&self) -> ZkpResult<Vec<CircuitInput>> {
        let mut inputs = Vec::new();
        for f in &self.plan.functions {
            if f.function_id != FUNCTION_AGE_CHECK {
                continue;
            }
            let Params::AgeCheck { ge, le, extra } = &f.params else {
                return Err(ZkpError::fault(
                    "an age_check item carries no age parameters",
                ));
            };
            let text = |k: &str| -> ZkpResult<Option<String>> {
                match extra.get(k) {
                    None => Ok(None),
                    Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
                    Some(_) => Err(ZkpError::fault(format!(
                        "the {k:?} parameter of {:?} is not a string",
                        f.handle
                    ))),
                }
            };
            let check = AgeCheck {
                ge: ge.clone(),
                gt: text("gt")?,
                le: le.clone(),
                lt: text("lt")?,
            };
            let bounds = check
                .bounds()
                .map_err(|e| ZkpError::fault(format!("the age_check of {:?}: {e}", f.handle)))?;
            inputs.push(bounds.circuit_input());
        }
        Ok(inputs)
    }
}

fn key_thumbprint(k: &p256::PublicKey) -> String {
    let point = k.to_sec1_bytes();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(&point[..]))
}
