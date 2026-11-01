//! Test doubles for zkp_req verification: a holder/prover that builds presentations and a MODEL circuit standing in for
//! a proof system. The model is a keyed digest over exactly the public inputs, NOT cryptography: it exists so every
//! binding rule (nonce, origin, client id, response_uri, thumbprint, verifier id, issuer key, proof time, age bounds)
//! is observable, because changing any one of them stops the "proof" verifying. Enabled by the `testutil` feature.

use base64::Engine;
use ciborium::Value;
use sha2::{Digest, Sha256};
use siros_dc_matcher_core::zkp_req::{plan, Plan};
use siros_verifier_core::mdoc::format_utc;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::backend::*;
use crate::circuits::*;
use crate::nym_auth::*;
use crate::refusal::ZkpResult;
use crate::request::Request;
use crate::verify::Channel;

pub const NOW: i64 = 1_790_000_000;
pub const DOC: &str = "eu.europa.ec.eudi.nym_auth.1";
pub const QUERY_ID: &str = "nym_attestation";
pub const SEED: [u8; 16] = [9; 16];
pub const CONFIG: &str = CONFIG_KNOWN_OFFENDER_MATCHING_SSC;
pub const VERIFIER_ID: &str = "x509_san_dns:verifier.example";
pub const NONCE: &str = "pOA0oqEAhLnqug2r7Ve4tQ";
pub const ORIGIN: &str = "https://verifier.example";
pub const CLIENT_ID: &str = "x509_san_dns:verifier.example";
pub const RESPONSE_URI: &str = "https://verifier.example/verification/direct_post";
pub const THUMB: [u8; 32] = [0x11; 32];

pub fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

pub fn cert(name: &str, not_after: (i32, u8, u8), p384: bool) -> Vec<u8> {
    let alg = if p384 {
        &rcgen::PKCS_ECDSA_P384_SHA384
    } else {
        &rcgen::PKCS_ECDSA_P256_SHA256
    };
    let kp = rcgen::KeyPair::generate_for(alg).unwrap();
    let mut p = rcgen::CertificateParams::new(vec![name.to_owned()]).unwrap();
    p.not_before = rcgen::date_time_ymd(2020, 1, 1);
    p.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
    p.self_signed(&kp).unwrap().der().to_vec()
}

pub fn good_cert() -> Vec<u8> {
    cert("issuer.example", (2035, 1, 1), false)
}

pub fn query(extra_req: Option<&str>, only_age: bool) -> serde_json::Value {
    let pseud = r#"{"fn_id":"pseudonym","return":"nym-1","params":{"config":"known-offender-matching-ssc","ver":1,"prf":"sha-256"}}"#;
    let age =
        r#"{"fn_id":"age_check","return":"age-1","params":{"ge":"2008-10-10","le":"2013-10-09"}}"#;
    let items = match (only_age, extra_req) {
        (true, _) => age.to_owned(),
        (false, Some(x)) => format!("{pseud},{age},{x}"),
        (false, None) => format!("{pseud},{age}"),
    };
    serde_json::from_str(&format!(
        r#"{{"id":"{QUERY_ID}","format":"zkp_req","meta":{{"source_format":"mso_mdoc","doctype_value":"{DOC}"}},"_req":[{items}]}}"#
    ))
    .unwrap()
}

pub fn metadata(systems: &[&str]) -> serde_json::Value {
    serde_json::json!({"vp_formats_supported": {"zkp_req": {
        "proof_system_values": ["longfellow-libzk-v1"], "system_id_values": systems }}})
}

pub fn make_plan(q: &serde_json::Value, systems: &[&str]) -> Plan {
    plan(&q.to_string(), Some(&metadata(systems).to_string())).expect("plan")
}

pub fn dc_channel() -> Channel {
    Channel::DcApi {
        origin: ORIGIN.into(),
    }
}
pub fn redirect_channel(encrypted: bool) -> Channel {
    Channel::Redirect {
        client_id: CLIENT_ID.into(),
        response_uri: RESPONSE_URI.into(),
        encrypted,
    }
}

/// The public inputs a holder believes it is proving against.
#[derive(Clone)]
pub struct Statement {
    pub channel: Channel,
    pub nonce: String,
    pub thumbprint: Option<Vec<u8>>,
    pub verifier_id: String,
    pub issuer_key: p256::PublicKey,
    pub proof_time: i64,
    pub age_earliest: String,
    pub age_cutoff: String,
    pub config: String,
}

/// The digest the model circuit accepts as a proof for a statement.
pub fn model_proof(st: &Statement) -> Vec<u8> {
    let t = match &st.channel {
        Channel::DcApi { origin } => {
            crate::transcript::session_transcript_dcapi(origin, &st.nonce, st.thumbprint.as_deref())
        }
        Channel::Redirect {
            client_id,
            response_uri,
            ..
        } => crate::transcript::session_transcript_redirect(
            client_id,
            &st.nonce,
            response_uri,
            st.thumbprint.as_deref().unwrap_or(&[]),
        ),
    }
    .unwrap();
    model_digest(
        &crate::transcript::challenge_digest(&t, DOC).unwrap(),
        &st.issuer_key,
        &format_utc(st.proof_time).unwrap(),
        &verifier_input(&st.verifier_id).unwrap(),
        &st.age_earliest,
        &st.age_cutoff,
        &st.config,
    )
}

fn model_digest(
    e2: &[u8; 32],
    q: &p256::PublicKey,
    t: &str,
    vi: &[u8; 32],
    e: &str,
    c: &str,
    cfg: &str,
) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"model-circuit/v1");
    for part in [
        &e2[..],
        &q.to_sec1_bytes()[..],
        t.as_bytes(),
        &vi[..],
        e.as_bytes(),
        c.as_bytes(),
        cfg.as_bytes(),
    ] {
        h.update((part.len() as u32).to_be_bytes());
        h.update(part);
    }
    h.finalize().to_vec()
}

/// The model circuit: accepts exactly the proof [`model_proof`] makes, and reveals the reference pseudonym.
pub struct Model {
    pub config: String,
}

impl ProofBackend for Model {
    fn verify(&self, req: &Request, claimed: &[u8], proof: &[u8]) -> Result<Vec<u8>, BackendError> {
        let age = req.inputs.iter().find(|i| i.function_id == "age_check");
        let get = |k: &str| {
            age.map(|a| String::from_utf8_lossy(&a.values[k]).into_owned())
                .unwrap_or_default()
        };
        let want = model_digest(
            &req.e2()
                .map_err(|e| BackendError::DidNotVerify(e.to_string()))?,
            &req.issuer_key,
            &req.time_string()
                .map_err(|e| BackendError::DidNotVerify(e.to_string()))?,
            &req.verifier_input,
            &get("earliest"),
            &get("cutoff"),
            &self.config,
        );
        if proof != want {
            return Err(BackendError::DidNotVerify(
                "model circuit: public inputs differ".into(),
            ));
        }
        let revealed = pseudonym(&self.config, &SEED, &[0; 32], &req.verifier_input)
            .unwrap()
            .to_vec();
        check_claimed(&revealed, claimed)?;
        Ok(revealed)
    }
}

/// The reference pseudonym the model reveals for a verifier id.
pub fn reference_pseudonym(verifier_id: &str) -> Vec<u8> {
    known_offender_matching(CONFIG, &SEED, verifier_id)
        .unwrap()
        .to_vec()
}

pub fn presentation_cbor(
    system_id: &str,
    proof: &[u8],
    key_set: &[Vec<u8>],
    proof_time: Option<i64>,
    pseudonym: &[u8],
) -> Vec<u8> {
    presentation_cbor_with_age(system_id, proof, key_set, proof_time, pseudonym, true)
}

pub fn presentation_cbor_with_age(
    system_id: &str,
    proof: &[u8],
    key_set: &[Vec<u8>],
    proof_time: Option<i64>,
    pseudonym: &[u8],
    include_age: bool,
) -> Vec<u8> {
    let mut results = vec![(
        Value::Text("nym-1".into()),
        Value::Bytes(pseudonym.to_vec()),
    )];
    if include_age {
        results.push((Value::Text("age-1".into()), Value::Bool(true)));
    }
    let mut m = vec![
        (
            Value::Text("system_id".into()),
            Value::Text(system_id.into()),
        ),
        (Value::Text("proof".into()), Value::Bytes(proof.to_vec())),
        (
            Value::Text("issuer_key_set".into()),
            Value::Array(key_set.iter().map(|k| Value::Bytes(k.clone())).collect()),
        ),
        (Value::Text("results".into()), Value::Map(results)),
    ];
    if let Some(t) = proof_time {
        m.push((
            Value::Text("proof_time".into()),
            Value::Tag(0, Box::new(Value::Text(format_utc(t).unwrap()))),
        ));
    }
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(m), &mut out).unwrap();
    out
}

pub fn vp_token(presentations: &[Vec<u8>]) -> String {
    let arr: Vec<String> = presentations
        .iter()
        .map(|p| format!("\"{}\"", b64(p)))
        .collect();
    format!("{{\"{QUERY_ID}\":[{}]}}", arr.join(","))
}

pub struct ArtifactFile(pub std::path::PathBuf);
impl Drop for ArtifactFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub fn artifact(bytes: &[u8]) -> (ArtifactFile, CircuitConfig) {
    static N: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "siros-zkp-test-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::write(&path, bytes).unwrap();
    let sha: String = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    (
        ArtifactFile(path.clone()),
        CircuitConfig {
            system_id: SYSTEM_LONGFELLOW.into(),
            config: CONFIG.into(),
            hash_circuit_id: "aa11".into(),
            sig_circuit_id: "bb22".into(),
            block_enc_hash: 4,
            block_enc_sig: 7,
            artifact_path: path.to_string_lossy().into_owned(),
            artifact_id: String::new(),
            artifact_sha256: sha,
            artifact_bytes: bytes.len() as u64,
        },
    )
}

/// A backend registry with the model circuit registered for the Longfellow system id, counting loads.
pub fn model_registry(loads: Arc<AtomicUsize>, issuer_key_set_max: usize) -> BackendRegistry {
    let mut reg = BackendRegistry::new();
    let mut profile = SystemProfile::single_issuer_age_check();
    profile.issuer_key_set_max = issuer_key_set_max;
    reg.register(
        SYSTEM_LONGFELLOW,
        profile,
        move |entry, _bytes| -> ZkpResult<Box<dyn ProofBackend>> {
            loads.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(Model {
                config: entry.config.clone(),
            }))
        },
    )
    .expect("register the model");
    reg
}
