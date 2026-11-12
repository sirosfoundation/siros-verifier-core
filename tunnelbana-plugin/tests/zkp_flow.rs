//! A zkp_req (nym_auth) login through the gateway: browser starts, the wallet reads the signed request object and
//! answers with an encrypted zero-knowledge presentation, go-trust vouches for the issuer certificate, and the
//! pseudonym reaches the frontend as the subject. The wallet is simulated and the circuit is the MODEL circuit
//! (a digest over exactly the public inputs, not cryptography), so every binding is observable.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod common;
use common::ClockBumpingClaimStore;

use async_trait::async_trait;
use jose_rs::algorithm::{JweAlgorithm, JweEncryption};
use jose_rs::JoseHeader;
use serde_json::{json, Value};
use siros_verifier_core::issuer_set::IssuerSetPolicy;
use siros_verifier_core::testutil::*;
use siros_verifier_core_tunnelbana::*;
use siros_verifier_zkp::backend::{BackendError, BackendRegistry, ProofBackend, SystemProfile};
use siros_verifier_zkp::circuits::*;
use siros_verifier_zkp::functions::FunctionRegistry;
use siros_verifier_zkp::nym_auth::*;
use siros_verifier_zkp::refusal::ZkpResult;
use siros_verifier_zkp::request::Request;
use siros_verifier_zkp::testutil as zk;
use siros_verifier_zkp::verify::{Channel, Tolerance, VerifierPolicy, ZkpVerifier};
use tunnelbana_core::context::Context;
use tunnelbana_core::http::HttpRequestData;
use tunnelbana_core::internal::{InternalData, SubjectType};
use tunnelbana_core::plugin::{Backend, BackendAction};
use tunnelbana_core::state::State;

const T0: i64 = zk::NOW;

struct Pdp {
    permit: AtomicBool,
    calls: AtomicUsize,
}
#[async_trait]
impl PdpClient for Pdp {
    async fn evaluate(&self, _r: &Value) -> Result<Value, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(
            json!({"decision": self.permit.load(Ordering::SeqCst), "context": {"reason": {"registry": "wl"}}}),
        )
    }
}

struct Fx {
    b: VpBackend,
    pdp: Arc<Pdp>,
    issuer_cert: Vec<u8>,
    loads: Arc<AtomicUsize>,
    _artifact: zk::ArtifactFile,
}

#[derive(Default)]
struct CorruptStore {
    inner: MemoryFlowStore,
    corruption: Mutex<Option<(String, Option<String>)>>,
}

impl CorruptStore {
    fn set_origin(&self, id: &str, origin: Option<String>) {
        *self.corruption.lock().unwrap() = Some((id.to_owned(), origin));
    }

    fn altered(&self, flow: Flow) -> Flow {
        let Some((id, origin)) = &*self.corruption.lock().unwrap() else {
            return flow;
        };
        if flow.id != *id {
            return flow;
        }
        let mut altered = flow;
        let sealer =
            siros_verifier_core::session_seal::SessionSealer::from_master(&[41u8; 32], "vp")
                .unwrap();
        let mut session = sealer
            .unseal(&altered.sealed_session, altered.id.as_bytes())
            .unwrap();
        session.dc_api_origin = origin.clone();
        altered.sealed_session = sealer.seal(&session, altered.id.as_bytes()).unwrap();
        altered
    }
}

#[async_trait]
impl FlowStore for CorruptStore {
    async fn insert(&self, flow: Flow, now: i64) -> StoreResult<()> {
        self.inner.insert(flow, now).await
    }

    async fn get(&self, id: &str, now: i64) -> StoreResult<Option<Flow>> {
        self.inner
            .get(id, now)
            .await
            .map(|flow| flow.map(|flow| self.altered(flow)))
    }

    async fn claim(
        &self,
        id: &str,
        now: i64,
        claim_id: &str,
        lease_secs: i64,
    ) -> StoreResult<ClaimResult> {
        Ok(
            match self.inner.claim(id, now, claim_id, lease_secs).await? {
                ClaimResult::Claimed(flow) => ClaimResult::Claimed(Box::new(self.altered(*flow))),
                other => other,
            },
        )
    }

    async fn finish(
        &self,
        id: &str,
        now: i64,
        claim_id: &str,
        outcome: TerminalOutcome,
    ) -> StoreResult<FinishResult> {
        self.inner.finish(id, now, claim_id, outcome).await
    }

    async fn collect(&self, id: &str, now: i64) -> StoreResult<CollectResult> {
        self.inner.collect(id, now).await
    }
}

fn zcfg() -> Value {
    json!({
        "query": {
            "id": zk::QUERY_ID, "format": "zkp_req",
            "meta": {"source_format": "mso_mdoc", "doctype_value": zk::DOC},
            "_req": [
                {"fn_id": "pseudonym", "return": "nym-1", "params": {"config": "known-offender-matching-ssc", "ver": 1, "prf": "sha-256"}},
                {"fn_id": "age_check", "return": "age-1", "params": {"ge": "2008-10-10", "le": "2013-10-09"}}
            ]
        },
        "system_id_values": [SYSTEM_LONGFELLOW],
        "proof_system_values": ["longfellow-libzk-v1"],
        "role": "nym-attestation-provider",
        "verifier_id": "x509_san_dns:verifier.example",
        "subject_handle": "nym-1",
        "attribute_map": {"pseudonym": "nym-1", "ageOver": "age-1"},
        "auth_class_ref": "urn:eudi:loa:high"
    })
}

fn multi_zcfg() -> Value {
    let mut config = zcfg();
    let query = config["query"].clone();
    config
        .as_object_mut()
        .unwrap()
        .retain(|key, _| !matches!(key.as_str(), "query" | "subject_handle" | "attribute_map"));
    let mut pseudonym = query.clone();
    pseudonym["id"] = json!("nym_auth");
    pseudonym["_req"] = json!([query["_req"][0].clone()]);
    let mut age = query;
    age["id"] = json!("nym_auth");
    config["profiles"] = json!([
        {
            "query": pseudonym,
            "subject_handle": "nym-1",
            "attribute_map": {"pseudonym": "nym-1"}
        },
        {
            "query": age,
            "subject_handle": "nym-1",
            "attribute_map": {"pseudonym": "nym-1", "ageOver": "age-1"}
        }
    ]);
    config
}

fn build(zcfg: Value, verifier_id: Option<&str>) -> Result<Fx, String> {
    build_with_store(zcfg, verifier_id, None, None)
}

fn build_with_store(
    zcfg: Value,
    verifier_id: Option<&str>,
    store: Option<Arc<dyn FlowStore>>,
    fallback: Option<Value>,
) -> Result<Fx, String> {
    build_with_clock_store(
        zcfg,
        verifier_id,
        store.map(|s| {
            Arc::new(move |_: Arc<AtomicI64>| s.clone())
                as Arc<dyn Fn(Arc<AtomicI64>) -> Arc<dyn FlowStore>>
        }),
        fallback,
    )
}

/// Like [`build_with_store`], but the store factory receives the fixture
/// clock, so a store can advance it as its operations "take" time.
#[allow(clippy::type_complexity)]
fn build_with_clock_store(
    zcfg: Value,
    verifier_id: Option<&str>,
    store: Option<Arc<dyn Fn(Arc<AtomicI64>) -> Arc<dyn FlowStore>>>,
    fallback: Option<Value>,
) -> Result<Fx, String> {
    build_full(
        zcfg,
        verifier_id,
        store,
        fallback,
        (60, 45, 16),
        Arc::new(|loads| zk::model_registry(loads, 1)),
    )
}

/// The full fixture: the admission limits of the base configuration
/// (`lease, deadline, max_concurrent_verifications`) and the backend
/// registry factory, both injectable so the scheduling regressions can
/// observe where native verification runs and how it is admitted.
#[allow(clippy::type_complexity)]
fn build_full(
    zcfg: Value,
    verifier_id: Option<&str>,
    store: Option<Arc<dyn Fn(Arc<AtomicI64>) -> Arc<dyn FlowStore>>>,
    fallback: Option<Value>,
    limits: (i64, i64, usize),
    registry: Arc<dyn Fn(Arc<AtomicUsize>) -> BackendRegistry>,
) -> Result<Fx, String> {
    let store_factory = store;
    let (v_cert, v_key) = self_signed_ec("verifier.example", "ES256");
    let (artifact, circuit) = zk::artifact(b"a model circuit artifact");
    let allow = Allowlist::new(&CircuitsConfig {
        sources: vec![],
        allow: vec![circuit],
    })
    .map_err(|e| e.to_string())?;
    let loads = Arc::new(AtomicUsize::new(0));
    let verifier = ZkpVerifier::new(
        allow,
        Box::new(FsArtifactSource),
        FunctionRegistry::with_builtins(),
        registry(loads.clone()),
        VerifierPolicy {
            role: "nym-attestation-provider".into(),
            issuer_set: IssuerSetPolicy::AllTrusted,
            tolerance: Tolerance::default(),
        },
    )
    .map_err(|e| e.to_string())?;
    let pdp = Arc::new(Pdp {
        permit: AtomicBool::new(true),
        calls: AtomicUsize::new(0),
    });
    let gate = TrustGate::new(
        pdp.clone(),
        p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap(),
        "k1",
        "core",
        "tenant",
        "pdp",
        3600,
    );
    let clock = Arc::new(AtomicI64::new(T0));
    let injected_store = store_factory.as_ref().map(|factory| factory(clock.clone()));
    let c2 = clock.clone();
    let mut zcfg = zcfg;
    if let Some(verifier_id) = verifier_id {
        zcfg["verifier_id"] = serde_json::json!(verifier_id);
    }
    let cfg: ZkpBackendConfig = serde_json::from_value(zcfg).map_err(|e| e.to_string())?;
    let default_query = cfg
        .query
        .clone()
        .or_else(|| cfg.profiles.first().map(|profile| profile.query.clone()));
    let base = VpBackendConfig {
        dcql: fallback.unwrap_or_else(|| json!({"credentials": [default_query]})),
        attribute_map: BTreeMap::new(),
        subject_pointer: String::new(),
        role: cfg.role.clone(),
        mdoc_role: String::new(),
        request_ttl_secs: cfg.request_ttl_secs,
        request_uri_method: "get".into(),
        auth_class_ref: cfg.auth_class_ref.clone(),
        processing_lease_secs: limits.0,
        processing_deadline_secs: limits.1,
        max_concurrent_verifications: limits.2,
        status_list_key_source: siros_verifier_core::status_list::StatusListKeySource::default(),
    };
    let mut backend = VpBackend::new_with_zkp(
        "vp",
        "https://proxy.example/vp",
        base,
        cfg,
        gate,
        siros_verifier_core::oid4vp::software_signer(&v_key).unwrap(),
        vec![v_cert],
        verifier,
        Arc::new(move || c2.load(Ordering::SeqCst)),
    )
    .map_err(|e| e.to_string())?;
    if let Some(store) = injected_store {
        backend = backend.with_flow_store(store).with_session_sealer(
            siros_verifier_core::session_seal::SessionSealer::from_master(&[41u8; 32], "vp")
                .unwrap(),
        );
    }
    let b = backend;
    Ok(Fx {
        b,
        pdp,
        issuer_cert: zk::good_cert(),
        loads,
        _artifact: artifact,
    })
}

fn fx() -> Fx {
    build(zcfg(), None).unwrap()
}

/// A backend that holds its FIRST verify for a bounded span before answering
/// like the model; every later verify passes straight through. The hold is
/// what makes native verification's *scheduling* observable — and it is
/// time-bounded so no regression can hang a test waiting for a release.
/// Proof correctness itself is pinned by the native vector tests.
struct Gated {
    model: zk::Model,
    hold: Duration,
    held: AtomicBool,
    entered: Arc<AtomicUsize>,
    inflight: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

impl ProofBackend for Gated {
    fn verify(&self, req: &Request, claimed: &[u8], proof: &[u8]) -> Result<Vec<u8>, BackendError> {
        let running = self.inflight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(running, Ordering::SeqCst);
        self.entered.fetch_add(1, Ordering::SeqCst);
        if !self.held.swap(true, Ordering::SeqCst) {
            std::thread::sleep(self.hold);
        }
        let revealed = self.model.verify(req, claimed, proof)?;
        self.inflight.fetch_sub(1, Ordering::SeqCst);
        Ok(revealed)
    }
}

fn gated_registry(
    hold: Duration,
    entered: Arc<AtomicUsize>,
    inflight: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
) -> Arc<dyn Fn(Arc<AtomicUsize>) -> BackendRegistry> {
    Arc::new(move |loads| {
        let hold = hold;
        let entered = entered.clone();
        let inflight = inflight.clone();
        let peak = peak.clone();
        let mut reg = BackendRegistry::new();
        let mut profile = SystemProfile::single_issuer_age_check();
        profile.issuer_key_set_max = 1;
        reg.register(
            SYSTEM_LONGFELLOW,
            profile,
            move |entry, _bytes| -> ZkpResult<Box<dyn ProofBackend>> {
                loads.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(Gated {
                    model: zk::Model {
                        config: entry.config.clone(),
                    },
                    hold,
                    held: AtomicBool::new(false),
                    entered: entered.clone(),
                    inflight: inflight.clone(),
                    peak: peak.clone(),
                }))
            },
        )
        .expect("register the gated model");
        reg
    })
}

fn req(path: &str, method: &str) -> HttpRequestData {
    HttpRequestData {
        path: path.into(),
        method: method.into(),
        ..Default::default()
    }
}

async fn start(f: &Fx) -> (State, String) {
    start_query(f, &zcfg()["query"]).await
}

async fn start_query(f: &Fx, query: &Value) -> (State, String) {
    let mut ctx = Context::new(req("vp/start", "GET"), State::new());
    let mut request = InternalData::request("https://rp.example");
    request.set_attr(
        ui::DCQL_ATTRIBUTE,
        json!({"credentials": [query]}).to_string(),
    );
    let page = f.b.start_auth(&mut ctx, request).await.unwrap();
    assert!(String::from_utf8(page.body)
        .unwrap()
        .contains("openid4vp://cb"));
    let id = ctx.state.get_str(NS, FLOW_KEY).unwrap();
    (ctx.state, id)
}

async fn start_dc_api(f: &Fx) -> (State, String) {
    let mut ctx = Context::new(req("vp/start", "GET"), State::new());
    let mut request = InternalData::request(ui::DC_API_REQUESTER);
    request.set_attr(
        ui::DCQL_ATTRIBUTE,
        json!({"credentials": [zcfg()["query"].clone()]}).to_string(),
    );
    let launch = f.b.start_auth(&mut ctx, request).await.unwrap();
    let launch: Value = serde_json::from_slice(&launch.body).unwrap();
    assert!(launch["request"].is_string());
    let id = ctx.state.get_str(NS, FLOW_KEY).unwrap();
    (ctx.state, id)
}

async fn jar(f: &Fx, id: &str) -> Value {
    let mut ctx = Context::new(req(&format!("vp/request/{id}"), "GET"), State::new());
    let BackendAction::Respond(r) = f.b.handle_endpoint(&mut ctx, "request").await.unwrap() else {
        panic!()
    };
    let token = String::from_utf8(r.body).unwrap();
    let payload = jose_rs::base64url::decode(token.split('.').nth(1).unwrap()).unwrap();
    serde_json::from_slice(&payload).unwrap()
}

/// What the wallet sends for a request: one zkp presentation, built exactly as an honest wallet with `holder_key`
/// (the key the credential was signed under) would, answering the real request object.
fn wallet_body(
    payload: &Value,
    now: i64,
    holder_cert: &[u8],
    proof_key: &p256::PublicKey,
    prove_for: Option<&str>,
) -> (String, Vec<u8>) {
    wallet_body_with_options(
        payload,
        now,
        holder_cert,
        proof_key,
        prove_for,
        zk::QUERY_ID,
        true,
    )
}

fn wallet_body_with_options(
    payload: &Value,
    now: i64,
    holder_cert: &[u8],
    proof_key: &p256::PublicKey,
    prove_for: Option<&str>,
    query_id: &str,
    include_age: bool,
) -> (String, Vec<u8>) {
    let client_id = payload["client_id"].as_str().unwrap().to_owned();
    let nonce = payload["nonce"].as_str().unwrap().to_owned();
    let enc: jose_rs::jwk::Jwk =
        serde_json::from_value(payload["client_metadata"]["jwks"]["keys"][0].clone()).unwrap();
    let thumb =
        jose_rs::base64url::decode(&jose_rs::jwk::thumbprint::thumbprint_sha256(&enc).unwrap())
            .unwrap();
    let verifier_id = prove_for.unwrap_or("x509_san_dns:verifier.example");
    let channel = match payload["response_mode"].as_str().unwrap() {
        "direct_post.jwt" => Channel::Redirect {
            client_id,
            response_uri: payload["response_uri"].as_str().unwrap().to_owned(),
            encrypted: true,
        },
        "dc_api.jwt" => Channel::DcApi {
            origin: "https://proxy.example".into(),
        },
        mode => panic!("unexpected response mode {mode}"),
    };
    let st = zk::Statement {
        channel,
        nonce,
        thumbprint: Some(thumb),
        verifier_id: verifier_id.to_owned(),
        issuer_key: *proof_key,
        proof_time: now - 3,
        age_earliest: if include_age {
            "2008-10-10".into()
        } else {
            String::new()
        },
        age_cutoff: if include_age {
            "2013-10-09".into()
        } else {
            String::new()
        },
        config: zk::CONFIG.into(),
    };
    let pres = zk::presentation_cbor_with_age(
        SYSTEM_LONGFELLOW,
        &zk::model_proof(&st),
        &[holder_cert.to_vec()],
        Some(st.proof_time),
        &zk::reference_pseudonym("x509_san_dns:verifier.example"),
        include_age,
    );
    let body = json!({"vp_token": {query_id: [zk::b64(&pres)]}, "state": payload["state"]});
    let mut header = JoseHeader::for_jwe(JweAlgorithm::EcdhEs, JweEncryption::A128GCM);
    header.kid = enc.kid.clone();
    let jwe = jose_rs::jwe::compact::encrypt_with_jwk_header(
        &enc,
        header,
        body.to_string().as_bytes(),
        JweEncryption::A128GCM,
    )
    .unwrap();
    (
        jwe,
        zk::reference_pseudonym("x509_san_dns:verifier.example"),
    )
}

fn key_of(cert: &[u8]) -> p256::PublicKey {
    siros_verifier_core::issuer_set::parse_members(&[cert.to_vec()]).unwrap()[0]
        .p256_key()
        .unwrap()
}

async fn post(f: &Fx, id: &str, jwe: &str) -> (u16, String) {
    let mut r = req(&format!("vp/response/{id}"), "POST");
    r.form = BTreeMap::from([("response".to_string(), jwe.to_string())]);
    r.form_pairs = vec![("response".into(), jwe.into())];
    let mut ctx = Context::new(r, State::new());
    let BackendAction::Respond(resp) = f.b.handle_endpoint(&mut ctx, "response").await.unwrap()
    else {
        panic!()
    };
    (resp.status, String::from_utf8(resp.body).unwrap())
}

async fn complete(f: &Fx, state: &State) -> Result<BackendAction, String> {
    let mut ctx = Context::new(req("vp/complete", "GET"), state.clone());
    f.b.handle_endpoint(&mut ctx, "complete")
        .await
        .map_err(|e| e.to_string())
}

/// A refused flow completes to the failure page carrying its reason — never
/// the legacy bare `authentication error: <code>` string. `code` rides the page.
async fn assert_failure_page(f: &Fx, state: &State, code: &str) {
    match complete(f, state).await {
        Ok(BackendAction::Respond(response)) => {
            let body = String::from_utf8_lossy(&response.body).into_owned();
            assert!(
                body.contains("Presentation failed"),
                "not the failure page: {body}"
            );
            assert!(
                body.contains("class=\"siros-failure-description\""),
                "the page shows the reason: {body}"
            );
            assert!(body.contains(code), "the page carries {code}: {body}");
        }
        Ok(_) => panic!("a refused flow must complete to a page, not a success"),
        Err(e) => panic!("a refused flow must show its reason, got the error {e}"),
    }
}

#[tokio::test]
async fn a_pseudonym_login_reaches_the_frontend_as_a_pairwise_subject() {
    let f = fx();
    let (state, id) = start(&f).await;
    let payload = jar(&f, &id).await;
    assert!(
        payload["client_id"].as_str().unwrap() == "x509_san_dns:verifier.example",
        "the identity scheme decides the client id"
    );
    assert_eq!(
        payload["client_metadata"]["vp_formats_supported"]["zkp_req"]["system_id_values"][0],
        SYSTEM_LONGFELLOW
    );
    assert_eq!(payload["dcql_query"]["credentials"][0]["format"], "zkp_req");
    assert!(
        payload["client_metadata"]["vp_formats_supported"]
            .get("dc+sd-jwt")
            .is_none(),
        "only what this backend accepts is offered"
    );
    let (jwe, pseudonym) = wallet_body(&payload, T0, &f.issuer_cert, &key_of(&f.issuer_cert), None);
    assert_eq!(post(&f, &id, &jwe).await.0, 200);
    let BackendAction::AuthResponse(d) = complete(&f, &state).await.unwrap() else {
        panic!("expected auth response")
    };
    use base64::Engine;
    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    assert_eq!(d.subject_id.as_deref(), Some(b64(&pseudonym).as_str()));
    assert_eq!(d.subject_type, SubjectType::Pairwise);
    assert_eq!(d.attr_first("pseudonym"), Some(b64(&pseudonym).as_str()));
    assert_eq!(d.attr_first("ageOver"), Some("true"));
    assert_eq!(d.requester.as_deref(), Some("https://rp.example"));
    assert!(d.auth_info.issuer.as_deref().unwrap().starts_with("zkp:"));
    assert_eq!(
        d.auth_info.auth_class_ref.as_deref(),
        Some("urn:eudi:loa:high")
    );
    assert_eq!(
        f.pdp.calls.load(Ordering::SeqCst),
        1,
        "one issuer certificate, one trust question"
    );
    assert_eq!(f.loads.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_exhausted_budget_starts_no_zkp_verification() {
    // A claim round-trip that consumes the whole safe window finalizes the
    // refusal without polling: no trust evaluation and no circuit load —
    // the first poll of the ZKP path would already start both.
    let store: Arc<dyn Fn(Arc<AtomicI64>) -> Arc<dyn FlowStore>> = Arc::new(|clock| {
        Arc::new(ClockBumpingClaimStore {
            inner: MemoryFlowStore::default(),
            clock,
            advance: 59,
        })
    });
    let f = build_with_clock_store(zcfg(), None, Some(store), None).unwrap();
    let (state, id) = start(&f).await;
    let payload = jar(&f, &id).await;
    let (jwe, _pseudonym) =
        wallet_body(&payload, T0, &f.issuer_cert, &key_of(&f.issuer_cert), None);
    let (st, body) = post(&f, &id, &jwe).await;
    assert_eq!(st, 504, "{body}");
    let error: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(error["error"], "processing_deadline");
    assert_eq!(
        f.pdp.calls.load(Ordering::SeqCst),
        0,
        "no trust evaluation may start"
    );
    assert_eq!(
        f.loads.load(Ordering::SeqCst),
        0,
        "no circuit may be loaded"
    );
    assert_failure_page(&f, &state, "processing_deadline").await;
}

#[tokio::test]
async fn a_stalled_native_proof_does_not_stall_the_async_workers() {
    // Native proof verification is synchronous work: it runs on the blocking
    // pool, so a slow proof leaves the async workers free to serve every
    // other request. The probe — the completion endpoint of a second,
    // independent flow — answers while the first proof is still holding only
    // if the runtime was never blocked. If the native call ran inline on the
    // async worker, the probe would be starved for the whole hold.
    let entered = Arc::new(AtomicUsize::new(0));
    let inflight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let f = build_full(
        zcfg(),
        None,
        None,
        None,
        (60, 45, 16),
        gated_registry(
            Duration::from_millis(800),
            entered.clone(),
            inflight.clone(),
            peak.clone(),
        ),
    )
    .unwrap();
    let (state, id) = start(&f).await;
    let payload = jar(&f, &id).await;
    let (jwe, _pseudonym) =
        wallet_body(&payload, T0, &f.issuer_cert, &key_of(&f.issuer_cert), None);
    let (state2, _id2) = start(&f).await;
    let started = std::time::Instant::now();
    let mut posted = Box::pin(post(&f, &id, &jwe));
    // Let the response reach the native verify; the first proof now holds.
    while entered.load(Ordering::SeqCst) == 0 {
        tokio::time::timeout(Duration::from_millis(50), posted.as_mut())
            .await
            .expect_err("the first native verify holds; the POST cannot finish yet");
    }
    // The probe: pure async work on another flow, schedulable only while the
    // runtime's workers are free.
    let BackendAction::Respond(_page) =
        tokio::time::timeout(Duration::from_millis(300), complete(&f, &state2))
            .await
            .expect("the async workers stay free while a native proof is stalled")
            .unwrap_or_else(|e| panic!("a pending flow's completion endpoint answers: {e}"))
    else {
        panic!("a pending flow shows its waiting page")
    };
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "the probe answered only after the native verify finished: \
         {:?} elapsed — the verify ran on the async worker",
        started.elapsed()
    );
    let (status, body) = posted.await;
    assert_eq!(status, 200, "{body}");
    let BackendAction::AuthResponse(data) = complete(&f, &state).await.unwrap() else {
        panic!("expected auth response")
    };
    assert!(data.subject_id.is_some(), "the held proof verifies");
    assert_eq!(peak.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_abandoned_native_verify_keeps_its_crypto_slot() {
    // With one verification slot, a caller whose budget expires while its
    // native verify still runs is gone — but its job keeps the crypto slot.
    // The next response may claim and pass trust, and its native verify must
    // not start until the abandoned job finishes: never two at once.
    let entered = Arc::new(AtomicUsize::new(0));
    let inflight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let f = build_full(
        zcfg(),
        None,
        None,
        None,
        (10, 1, 1),
        gated_registry(
            Duration::from_millis(1800),
            entered.clone(),
            inflight.clone(),
            peak.clone(),
        ),
    )
    .unwrap();
    let (state, id) = start(&f).await;
    let payload = jar(&f, &id).await;
    let (jwe, _pseudonym) =
        wallet_body(&payload, T0, &f.issuer_cert, &key_of(&f.issuer_cert), None);
    let mut posted = Box::pin(post(&f, &id, &jwe));
    while entered.load(Ordering::SeqCst) == 0 {
        tokio::time::timeout(Duration::from_millis(50), posted.as_mut())
            .await
            .expect_err("the first native verify holds; the POST cannot finish yet");
    }
    // The caller's one-second budget expires while the proof still holds;
    // its decision is the deadline refusal.
    let (status, body) = posted.await;
    assert_eq!(status, 504, "{body}");
    let error: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(error["error"], "processing_deadline");
    // A second response on its own flow: the abandoned job still holds the
    // only crypto slot, so this verify must not start while it runs.
    let (state2, id2) = start(&f).await;
    let payload2 = jar(&f, &id2).await;
    let (jwe2, _p2) = wallet_body(&payload2, T0, &f.issuer_cert, &key_of(&f.issuer_cert), None);
    let mut posted2 = Box::pin(post(&f, &id2, &jwe2));
    tokio::time::timeout(Duration::from_millis(250), posted2.as_mut())
        .await
        .expect_err("the second verify must wait for the abandoned job's slot");
    assert_eq!(
        inflight.load(Ordering::SeqCst),
        1,
        "the abandoned job still holds the only crypto slot"
    );
    // The hold ends: the abandoned job finishes (its late decision is
    // discarded), the second acquires the freed slot and completes.
    let (status2, body2) = posted2.await;
    assert_eq!(status2, 200, "{body2}");
    assert_eq!(
        peak.load(Ordering::SeqCst),
        1,
        "never two native verifies at once"
    );
    let BackendAction::AuthResponse(data) = complete(&f, &state2).await.unwrap() else {
        panic!("expected auth response")
    };
    assert!(data.subject_id.is_some());
    // The abandoned flow stays refused: the page shows the reason.
    assert_failure_page(&f, &state, "processing_deadline").await;
}

#[tokio::test]
async fn a_pseudonym_login_over_dc_api_uses_the_dc_api_handover() {
    let f = fx();
    let (state, id) = start_dc_api(&f).await;
    let payload = jar(&f, &id).await;
    assert_eq!(payload["response_mode"], "dc_api.jwt");
    assert_eq!(
        payload["expected_origins"],
        json!(["https://proxy.example"])
    );
    assert!(payload.get("response_uri").is_none());
    // nym-auth-circuits SPEC section 3 binds a DC API proof to the calling
    // origin, nonce and encryption-key thumbprint, not response_uri/client_id.
    let (jwe, pseudonym) = wallet_body(&payload, T0, &f.issuer_cert, &key_of(&f.issuer_cert), None);
    let (status, body) = post(&f, &id, &jwe).await;
    assert_eq!(status, 200, "{body}");
    let BackendAction::AuthResponse(data) = complete(&f, &state).await.unwrap() else {
        panic!("expected auth response")
    };
    use base64::Engine;
    let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pseudonym);
    assert_eq!(data.subject_id.as_deref(), Some(expected.as_str()));
}

#[tokio::test]
async fn inconsistent_sealed_channels_are_refused_before_verification() {
    for (dc_api, origin) in [
        (false, Some("https://proxy.example".to_owned())),
        (true, None),
    ] {
        let store = Arc::new(CorruptStore::default());
        let f = build_with_store(zcfg(), None, Some(store.clone()), None).unwrap();
        let (state, id) = if dc_api {
            start_dc_api(&f).await
        } else {
            start(&f).await
        };
        store.set_origin(&id, origin);
        let payload = jar(&f, &id).await;
        let (jwe, _) = wallet_body(&payload, T0, &f.issuer_cert, &key_of(&f.issuer_cert), None);
        let (status, body) = post(&f, &id, &jwe).await;
        assert_eq!(status, 500, "{body}");
        assert!(body.contains("verifier_error"), "{body}");
        assert_failure_page(&f, &state, "verifier_error").await;
    }
}

#[tokio::test]
async fn enabling_zkp_preserves_sdjwt_request_dispatch() {
    let f = fx();
    let query = json!({"credentials": [{
        "id": "pid", "format": "dc+sd-jwt",
        "meta": {"vct_values": ["urn:eudi:pid:arf-1.8:1"]},
        "claims": [{"path": ["given_name"]}]
    }]});
    let mut request = InternalData::request("https://rp.example");
    request.set_attr(ui::DCQL_ATTRIBUTE, query.to_string());
    let mut ctx = Context::new(req("vp/start", "GET"), State::new());
    f.b.start_auth(&mut ctx, request).await.unwrap();
    let id = ctx.state.get_str(NS, FLOW_KEY).unwrap();
    let payload = jar(&f, &id).await;
    assert_eq!(payload["dcql_query"], query);
    assert!(payload["client_id"]
        .as_str()
        .unwrap()
        .starts_with("x509_hash:"));
    assert!(payload["client_metadata"]["vp_formats_supported"]
        .get("dc+sd-jwt")
        .is_some());
    assert!(payload["client_metadata"]["vp_formats_supported"]
        .get("zkp_req")
        .is_none());
}

#[tokio::test]
async fn pseudonym_and_age_profiles_are_independently_verified() {
    let f = build(multi_zcfg(), None).unwrap();
    let profiles = multi_zcfg()["profiles"].clone();
    for (index, include_age) in [(0, false), (1, true)] {
        let query = profiles[index]["query"].clone();
        let (state, id) = start_query(&f, &query).await;
        let payload = jar(&f, &id).await;
        assert_eq!(payload["dcql_query"]["credentials"][0], query);
        let (jwe, pseudonym) = wallet_body_with_options(
            &payload,
            T0,
            &f.issuer_cert,
            &key_of(&f.issuer_cert),
            None,
            "nym_auth",
            include_age,
        );
        let (status, body) = post(&f, &id, &jwe).await;
        assert_eq!(status, 200, "{body}");
        let BackendAction::AuthResponse(data) = complete(&f, &state).await.unwrap() else {
            panic!("expected auth response")
        };
        use base64::Engine;
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pseudonym);
        assert_eq!(data.subject_id.as_deref(), Some(expected.as_str()));
        assert_eq!(data.attr_first("pseudonym"), Some(expected.as_str()));
        assert_eq!(data.attr_first("ageOver"), include_age.then_some("true"));
    }
}

#[tokio::test]
async fn an_untrusted_issuer_certificate_is_refused_with_the_wallets_code() {
    let f = fx();
    f.pdp.permit.store(false, Ordering::SeqCst);
    let (state, id) = start(&f).await;
    let (jwe, _) = wallet_body(
        &jar(&f, &id).await,
        T0,
        &f.issuer_cert,
        &key_of(&f.issuer_cert),
        None,
    );
    let (status, body) = post(&f, &id, &jwe).await;
    assert_eq!(status, 400, "a refusal is the wallet's business");
    assert!(body.contains("zkp_req_issuer_not_trusted"), "{body}");
    // The description is the readable refusal reason, never a wrapped JSON
    // document: the wallet's error_description and the page both carry the
    // detail itself.
    let refusal: serde_json::Value = serde_json::from_str(&body).unwrap();
    let description = refusal["error_description"].as_str().unwrap();
    assert!(
        !description.contains("{\"error"),
        "the wallet-facing description must not wrap the reason in JSON: {body}"
    );
    assert_failure_page(&f, &state, "zkp_req_issuer_not_trusted").await;
}

#[tokio::test]
async fn a_proof_made_for_another_issuer_key_or_another_verifier_does_not_verify() {
    let f = fx();
    for (name, other_key, prove_for) in [
        (
            "another issuer key",
            Some(
                p256::SecretKey::from_slice(&[5u8; 32])
                    .unwrap()
                    .public_key(),
            ),
            None,
        ),
        (
            "another verifier id",
            None,
            Some("x509_san_dns:other.example"),
        ),
    ] {
        let (_state, id) = start(&f).await;
        let key = other_key.unwrap_or_else(|| key_of(&f.issuer_cert));
        let (jwe, _) = wallet_body(&jar(&f, &id).await, T0, &f.issuer_cert, &key, prove_for);
        let (status, body) = post(&f, &id, &jwe).await;
        assert_eq!(status, 400, "{name}");
        assert!(
            body.contains("zkp_req_proof_did_not_verify"),
            "{name}: {body}"
        );
    }
}

#[tokio::test]
async fn a_stale_proof_time_is_refused_before_any_circuit_is_loaded() {
    let f = fx();
    let (_state, id) = start(&f).await;
    let (jwe, _) = wallet_body(
        &jar(&f, &id).await,
        T0 - 700,
        &f.issuer_cert,
        &key_of(&f.issuer_cert),
        None,
    );
    let (status, body) = post(&f, &id, &jwe).await;
    assert_eq!(status, 400);
    assert!(body.contains("zkp_req_proof_time_out_of_range"), "{body}");
    assert_eq!(f.loads.load(Ordering::SeqCst), 0);
    assert_eq!(
        f.pdp.calls.load(Ordering::SeqCst),
        0,
        "and the trust layer was not troubled either"
    );
}

#[tokio::test]
async fn an_identity_that_is_not_a_rulebook_verifier_id_is_the_verifiers_fault_not_the_wallets() {
    // x509_hash is a fine client id for OpenID4VP and not a verifier id under rulebook v0.4
    let f = build(zcfg(), Some("x509_hash:not-a-rulebook-id")).unwrap();
    let mut ctx = Context::new(req("vp/start", "GET"), State::new());
    let error =
        f.b.start_auth(&mut ctx, InternalData::request("https://rp.example"))
            .await
            .err()
            .unwrap()
            .to_string();
    assert!(error.contains("request: malformed"), "{error}");
}

#[tokio::test]
async fn a_replay_and_a_response_for_another_flow_are_refused_as_for_any_format() {
    let f = fx();
    let (_s1, id1) = start(&f).await;
    let (_s2, id2) = start(&f).await;
    let (jwe1, _) = wallet_body(
        &jar(&f, &id1).await,
        T0,
        &f.issuer_cert,
        &key_of(&f.issuer_cert),
        None,
    );
    assert_eq!(post(&f, &id1, &jwe1).await.0, 200);
    assert_eq!(post(&f, &id1, &jwe1).await.0, 409, "replay");
    assert_eq!(
        post(&f, &id2, &jwe1).await.0,
        400,
        "a response for another flow does not decrypt or bind"
    );
}

#[test]
fn a_zkp_fallback_must_match_a_configured_profile() {
    let mut different = zcfg();
    different["query"]["id"] = json!("different");
    let different = json!({"credentials": [different["query"].clone()]});
    let mixed = json!({"credentials": [
        zcfg()["query"].clone(),
        {"id": "pid", "format": "dc+sd-jwt"}
    ]});
    let mut unsupported_root = json!({"credentials": [zcfg()["query"].clone()]});
    unsupported_root["unsupported"] = json!(true);

    for fallback in [different, mixed, unsupported_root] {
        assert!(
            build_with_store(zcfg(), None, None, Some(fallback.clone())).is_err(),
            "fallback must not bypass profile validation: {fallback}"
        );
    }
}

#[test]
fn the_configuration_is_checked_against_the_query_at_construction() {
    let bad = |mutate: &dyn Fn(&mut Value)| {
        let mut c = zcfg();
        mutate(&mut c);
        build(c, None).err().unwrap_or_else(|| "OK".into())
    };
    assert!(bad(&|c| c["subject_handle"] = json!("age-1")).contains("not a pseudonym handle"));
    assert!(bad(&|c| c["subject_handle"] = json!("nope")).contains("not a pseudonym handle"));
    assert!(
        bad(&|c| c["attribute_map"] = json!({"x": "no-such-handle"})).contains("no result handle")
    );
    assert!(bad(&|c| c["request_ttl_secs"] = json!(0)).contains("request_ttl_secs"));
    assert!(bad(&|c| c["request_ttl_secs"] = json!(901)).contains("request_ttl_secs"));
    assert!(
        bad(&|c| c["query"]["_req"] = json!([])).contains("zkp query"),
        "an empty request"
    );
    assert!(
        bad(&|c| c["query"]["claims"] = json!([{"path": ["x"]}])).contains("zkp query"),
        "claims have no meaning here"
    );
    assert!(
        bad(&|c| c["typo"] = json!(1)).contains("typo"),
        "unknown members are refused"
    );
    // a one-day age window is a birth-date oracle: unsatisfiable under the rulebook, caught before any wallet sees it
    assert!(bad(
        &|c| c["query"]["_req"][1]["params"] = json!({"ge": "2008-10-10", "le": "2008-10-11"})
    )
    .contains("cannot be satisfied"));
    assert_eq!(bad(&|_| {}), "OK");
}
