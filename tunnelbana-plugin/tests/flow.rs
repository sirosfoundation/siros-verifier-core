//! End-to-end flows through the tunnelbana Backend interface: browser start, wallet fetches the request object,
//! wallet posts the encrypted response, browser collects the result. The wallet is simulated; go-trust is mocked.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;

mod common;
use common::ClockBumpingClaimStore;

use async_trait::async_trait;
use serde_json::{json, Value};
use siros_verifier_core::session_seal::SessionSealer;
use siros_verifier_core::testutil::*;
use siros_verifier_core_tunnelbana::*;
use tunnelbana_core::context::Context;
use tunnelbana_core::http::HttpRequestData;
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{Backend, BackendAction};
use tunnelbana_core::state::State;

const T0: i64 = 1_800_000_000;

/// A permit as a real go-trust (b0ec45c, whitelist registry) returned it on 2026-10-26.
const REAL_PERMIT: &str = r#"{"decision":true,"context":{"reason":{"matched_list":"pid","registry":"wl","requested_credential_types":["urn:eudi:pid:1"],"resolution_ms":7,"role":"pid-provider","trust_path":"system_ca_pinned_hash","type":"whitelist","user":"trusted via whitelist (pid, pinned certificate hash, no chain validation)"},"trust_metadata":{"matched_list":"pid","registry":"wl","trust_framework":"whitelist","trust_path":"system_ca_pinned_hash"}}}"#;
const REAL_DENY: &str = r#"{"decision":false,"context":{"reason":{"error":"no registry returned positive match","registries_queried":1,"registry_results":[{"decision":false,"duration_ms":0,"reason":{"admin":"subject not in whitelist for action 'other-role'","error":"subject not in whitelist for action 'other-role'","registry":"wl","type":"whitelist","user":"subject not in whitelist for action 'other-role'"},"registry":"wl"}]}}}"#;
/// go-trust's always-trusted registry (`--registry always-trusted`), captured
/// live: an id, a reason object, and a `trust_data` entry WITHOUT timestamps —
/// the shape the conformance stack's PDP answers with. The whitelist's
/// REAL_PERMIT above predates it and carries neither id nor trust_data.
const REAL_ALWAYS_TRUSTED: &str = r#"{"decision":true,"context":{"id":"56e68ce4-6af0-45a0-a426-e4af9068fcc2","reason":{"registry":"always-trusted","resolution_ms":0,"type":"always_trusted","warning":"This registry always returns trusted - do not use in production"},"trust_data":[{"registry":"always-trusted"}]}}"#;

struct MockPdp {
    permit: AtomicBool,
    down: AtomicBool,
    calls: AtomicUsize,
    next_update_in: i64,
    /// Answer as go-trust's whitelist does (captured REAL_PERMIT): no
    /// context.id, no trust_data.
    go_trust_today: AtomicBool,
    /// Answer as go-trust's always-trusted registry does (captured
    /// REAL_ALWAYS_TRUSTED): id, reason, and timestamp-less trust_data.
    go_trust_always_trusted: AtomicBool,
    /// Accept the request and never answer, like a stalled endpoint.
    stall: AtomicBool,
}
#[async_trait]
impl PdpClient for MockPdp {
    async fn evaluate(&self, req: &Value) -> Result<Value, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.stall.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        if self.down.load(Ordering::SeqCst) {
            return Err("connect refused".into());
        }
        assert!(
            matches!(
                req["action"]["name"].as_str(),
                Some("pid-provider" | "status-list-signer")
            ),
            "role comes from config"
        );
        if self.go_trust_today.load(Ordering::SeqCst) {
            return Ok(serde_json::from_str(REAL_PERMIT).unwrap());
        }
        if self.go_trust_always_trusted.load(Ordering::SeqCst) {
            return Ok(serde_json::from_str(REAL_ALWAYS_TRUSTED).unwrap());
        }
        assert_eq!(req["resource"]["type"], "x5c");
        Ok(json!({"decision": self.permit.load(Ordering::SeqCst),
                  "context": {"id": format!("dec-{}", self.calls.load(Ordering::SeqCst)),
                              "trust_data": [{"registry": "etsi", "as_of": "2027-01-15T00:00:00Z",
                                              "next_update": next_update(self.next_update_in)}]}}))
    }
}

#[derive(Default)]
struct CountingStatusClient {
    calls: AtomicUsize,
    token: Option<String>,
}

#[async_trait]
impl StatusListClient for CountingStatusClient {
    async fn fetch(&self, _uri: &str) -> Result<String, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(token) = &self.token {
            return Ok(token.clone());
        }
        Err("unexpected status fetch".into())
    }
}

#[derive(Default)]
struct FinishFailingStore {
    inner: MemoryFlowStore,
}

#[async_trait]
impl FlowStore for FinishFailingStore {
    async fn insert(&self, flow: Flow, now: i64) -> StoreResult<()> {
        self.inner.insert(flow, now).await
    }

    async fn get(&self, id: &str, now: i64) -> StoreResult<Option<Flow>> {
        self.inner.get(id, now).await
    }

    async fn claim(
        &self,
        id: &str,
        now: i64,
        claim_id: &str,
        lease_secs: i64,
    ) -> StoreResult<ClaimResult> {
        self.inner.claim(id, now, claim_id, lease_secs).await
    }

    async fn finish(
        &self,
        _id: &str,
        _now: i64,
        _claim_id: &str,
        _outcome: TerminalOutcome,
    ) -> StoreResult<FinishResult> {
        Err(FlowStoreError("injected finish outage".into()))
    }

    async fn collect(&self, id: &str, now: i64) -> StoreResult<CollectResult> {
        self.inner.collect(id, now).await
    }
}

fn next_update(secs_after_t0: i64) -> String {
    // T0 = 2027-01-15T08:00:00Z
    let t = T0 + secs_after_t0;
    let days = t.div_euclid(86400);
    let rem = t.rem_euclid(86400);
    // civil from days (Hinnant)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

struct Fx {
    b: VpBackend,
    pdp: Arc<MockPdp>,
    clock: Arc<AtomicI64>,
    holder: jose_rs::jwk::Jwk,
    issued: Issued,
}

fn fx_with(next_update_in: i64) -> Fx {
    fx_full(next_update_in, "/family_name")
}
fn fx_full(next_update_in: i64, subject_pointer: &str) -> Fx {
    fx_with_method(next_update_in, subject_pointer, "get")
}

fn fx_with_method(next_update_in: i64, subject_pointer: &str, request_uri_method: &str) -> Fx {
    let cfg = pid_cfg(subject_pointer, request_uri_method, None, 16);
    assemble(cfg, mock_pdp(next_update_in, false), pid_parts())
}

/// The PID fixture: verifier and issuer keys, the holder key, and one issued
/// PID credential disclosing `given_name` and `family_name`.
/// The PID fixture: verifier and issuer keys, the holder key, and one issued
/// PID credential disclosing `given_name` and `family_name`.
struct Parts {
    v_cert: Vec<u8>,
    v_key: jose_rs::jwk::Jwk,
    holder: jose_rs::jwk::Jwk,
    issued: Issued,
}

fn pid_parts() -> Parts {
    let (v_cert, v_key) = self_signed_ec("verifier.example", "ES256");
    let (i_cert, i_key) = self_signed_ec("issuer.example", "ES256");
    let holder = ec_jwk("ES256", "holder");
    let mut spec = IssueSpec::new(json!({
        "iss": "https://issuer.example", "vct": "urn:eudi:pid:1", "iat": T0 - 10, "exp": T0 + 1_000_000,
        "given_name": "Ada", "family_name": "Lovelace", "address": {"locality": "London"},
    }));
    spec.holder_pub = Some(public_of(&holder));
    spec.x5c_der = vec![i_cert];
    spec.conceal = vec![vec![Seg::Key("given_name")], vec![Seg::Key("family_name")]];
    let issued = issue(&i_key, &spec).unwrap();
    Parts {
        v_cert,
        v_key,
        holder,
        issued,
    }
}

/// The single-credential backend configuration; `lease_and_deadline` sets
/// `processing_lease_secs` and `processing_deadline_secs` when present, and
/// `permits` sets `max_concurrent_verifications`.
fn pid_cfg(
    subject_pointer: &str,
    request_uri_method: &str,
    lease_and_deadline: Option<(i64, i64)>,
    permits: usize,
) -> VpBackendConfig {
    let mut cfg = json!({
        "dcql": {"credentials": [{"id": "pid", "format": "dc+sd-jwt",
                 "meta": {"vct_values": ["urn:eudi:pid:1"]},
                 "claims": [{"path": ["given_name"]}, {"path": ["family_name"]}]}]},
        "attribute_map": {"givenName": "/given_name", "sn": "/family_name", "l": "/address/locality", "missing": "/nope"},
        "subject_pointer": subject_pointer,
        "role": "pid-provider",
        "auth_class_ref": "urn:eudi:loa:high",
        "request_uri_method": request_uri_method,
        "max_concurrent_verifications": permits,
    });
    if let Some((lease, deadline)) = lease_and_deadline {
        cfg["processing_lease_secs"] = json!(lease);
        cfg["processing_deadline_secs"] = json!(deadline);
    }
    serde_json::from_value(cfg).unwrap()
}

/// A mock go-trust with the given freshness window that never answers when
/// `stall` is set.
fn mock_pdp(next_update_in: i64, stall: bool) -> Arc<MockPdp> {
    Arc::new(MockPdp {
        permit: AtomicBool::new(true),
        down: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
        next_update_in,
        go_trust_today: AtomicBool::new(false),
        go_trust_always_trusted: AtomicBool::new(false),
        stall: AtomicBool::new(stall),
    })
}

/// A backend whose PDP accepts requests and never answers, with the given
/// overall processing deadline in seconds.
fn fx_stalled(deadline: i64) -> Fx {
    let cfg = pid_cfg("/family_name", "get", Some((60, deadline)), 16);
    assemble(cfg, mock_pdp(100_000, true), pid_parts())
}

/// A trust gate over any PDP, with the same identity every fixture uses.
fn gate_over(pdp: Arc<dyn PdpClient>) -> TrustGate {
    TrustGate::new(
        pdp,
        p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap(),
        "k1",
        "core-1",
        "tenant-a",
        "https://pdp.example",
        3600,
    )
}

/// A fixture with an explicit shared clock, gate PDP, and flow store, for
/// the processing-budget and lease-window regressions; the trust gate uses
/// `gate_pdp` and `Fx.pdp` is the unrelated `fx_pdp` placeholder.
fn fx_with_parts(
    cfg: VpBackendConfig,
    gate_pdp: Arc<dyn PdpClient>,
    fx_pdp: Arc<MockPdp>,
    store: Arc<dyn FlowStore>,
    clock: Arc<AtomicI64>,
) -> Fx {
    assemble_parts(cfg, gate_pdp, fx_pdp, store, clock, pid_parts())
}

/// A PDP that answers with a permit but first busy-waits `spin`, like a
/// synchronous verification the async runtime cannot preempt.
struct BusyWaitPdp {
    spin: std::time::Duration,
}

#[async_trait]
impl PdpClient for BusyWaitPdp {
    async fn evaluate(&self, _request: &Value) -> Result<Value, String> {
        let until = std::time::Instant::now() + self.spin;
        while std::time::Instant::now() < until {
            std::hint::spin_loop();
        }
        Ok(json!({"decision": true,
                  "context": {"id": "dec-1",
                              "trust_data": [{"registry": "etsi", "as_of": "2027-01-15T00:00:00Z",
                                               "next_update": next_update(100_000)}]}}))
    }
}

/// A PDP that answers with a permit but first jumps the shared clock to
/// `jump_to`, as if the evaluation had run until then.
struct ClockJumpingPdp {
    clock: Arc<AtomicI64>,
    jump_to: i64,
}

#[async_trait]
impl PdpClient for ClockJumpingPdp {
    async fn evaluate(&self, _request: &Value) -> Result<Value, String> {
        self.clock.store(self.jump_to, Ordering::SeqCst);
        Ok(json!({"decision": true,
                  "context": {"id": "dec-1",
                              "trust_data": [{"registry": "etsi", "as_of": "2027-01-15T00:00:00Z",
                                               "next_update": next_update(100_000)}]}}))
    }
}
fn fx() -> Fx {
    fx_with(100_000)
}

/// The backend assembly every fixture shares: the given mock PDP, the clock,
/// the trust gate, and the service signer.
fn assemble(cfg: VpBackendConfig, pdp: Arc<MockPdp>, parts: Parts) -> Fx {
    assemble_parts(
        cfg,
        pdp.clone(),
        pdp,
        Arc::new(MemoryFlowStore::default()),
        Arc::new(AtomicI64::new(T0)),
        parts,
    )
}

/// The shared backend construction: the trust gate uses `gate_pdp`, `Fx.pdp`
/// is `fx_pdp`, and the flow store and clock are the caller's.
fn assemble_parts(
    cfg: VpBackendConfig,
    gate_pdp: Arc<dyn PdpClient>,
    fx_pdp: Arc<MockPdp>,
    store: Arc<dyn FlowStore>,
    clock: Arc<AtomicI64>,
    parts: Parts,
) -> Fx {
    let Parts {
        v_cert,
        v_key,
        holder,
        issued,
    } = parts;
    let c2 = clock.clone();
    let b = VpBackend::new(
        "vp",
        "https://proxy.example/vp",
        cfg,
        gate_over(gate_pdp),
        siros_verifier_core::oid4vp::software_signer(&v_key).unwrap(),
        vec![v_cert],
        Arc::new(move || c2.load(Ordering::SeqCst)),
    )
    .unwrap()
    .with_flow_store(store);
    Fx {
        b,
        pdp: fx_pdp,
        clock,
        holder,
        issued,
    }
}

/// A backend that requests two SD-JWT credentials from different issuers: a PID
/// (`urn:eudi:pid:1`) and a loyalty card (`urn:example:loyalty:1`) whose
/// `membership_level` claim has the given value. Returns the backend fixture
/// (holding the PID as `issued`) and the issued loyalty credential.
fn fx_multi_at(loyalty_level: Value, subject_pointer: &str) -> (Fx, Issued) {
    let (v_cert, v_key) = self_signed_ec("verifier.example", "ES256");
    let (i_cert, i_key) = self_signed_ec("issuer.example", "ES256");
    let (l_cert, l_key) = self_signed_ec("issuer2.example", "ES256");
    let holder = ec_jwk("ES256", "holder");
    let mut pid = IssueSpec::new(json!({
        "iss": "https://issuer.example", "vct": "urn:eudi:pid:1", "iat": T0 - 10, "exp": T0 + 1_000_000,
        "given_name": "Ada", "family_name": "Lovelace",
    }));
    pid.holder_pub = Some(public_of(&holder));
    pid.x5c_der = vec![i_cert];
    pid.conceal = vec![vec![Seg::Key("given_name")], vec![Seg::Key("family_name")]];
    let issued_pid = issue(&i_key, &pid).unwrap();

    let mut loyalty = IssueSpec::new(json!({
        "iss": "https://issuer2.example", "vct": "urn:example:loyalty:1", "iat": T0 - 10, "exp": T0 + 1_000_000,
        "membership_level": loyalty_level,
    }));
    loyalty.holder_pub = Some(public_of(&holder));
    loyalty.x5c_der = vec![l_cert];
    loyalty.conceal = vec![vec![Seg::Key("membership_level")]];
    let issued_loyalty = issue(&l_key, &loyalty).unwrap();

    let cfg: VpBackendConfig = serde_json::from_value(json!({
        "dcql": {"credentials": [
            {"id": "pid", "format": "dc+sd-jwt",
             "meta": {"vct_values": ["urn:eudi:pid:1"]},
             "claims": [{"path": ["family_name"]}]},
            {"id": "loyalty", "format": "dc+sd-jwt",
             "meta": {"vct_values": ["urn:example:loyalty:1"]},
             "claims": [{"path": ["membership_level"]}]}
        ]},
        "attribute_map": {"sn": "/family_name", "tier": "/membership_level", "kind": "/vct"},
        "subject_pointer": subject_pointer,
        "role": "pid-provider",
        "auth_class_ref": "urn:eudi:loa:high",
    }))
    .unwrap();
    (
        assemble(
            cfg,
            mock_pdp(100_000, false),
            Parts {
                v_cert,
                v_key,
                holder,
                issued: issued_pid,
            },
        ),
        issued_loyalty,
    )
}

fn fx_multi(loyalty_level: Value) -> (Fx, Issued) {
    fx_multi_at(loyalty_level, "/family_name")
}

/// The wallet answers with both of the multi-credential fixture's documents.
fn wallet_multi(f: &Fx, loyalty: &Issued, jar: &str) -> String {
    wallet_respond(
        jar,
        &f.holder,
        &[
            WalletCredential {
                id: "pid",
                issued: &f.issued,
                disclose: &[0, 1],
            },
            WalletCredential {
                id: "loyalty",
                issued: loyalty,
                disclose: &[0],
            },
        ],
        f.clock.load(Ordering::SeqCst),
    )
    .unwrap()
}

impl Fx {
    fn with_storage(self, store: Arc<dyn FlowStore>) -> Self {
        Self {
            b: self
                .b
                .with_flow_store(store)
                .with_session_sealer(SessionSealer::from_master(&[41u8; 32], "vp").unwrap()),
            pdp: self.pdp,
            clock: self.clock,
            holder: self.holder,
            issued: self.issued,
        }
    }
}

fn req(path: &str, method: &str) -> HttpRequestData {
    HttpRequestData {
        path: path.into(),
        method: method.into(),
        ..Default::default()
    }
}
fn respond_body(a: BackendAction) -> (u16, String) {
    match a {
        BackendAction::Respond(r) => (r.status, String::from_utf8(r.body).unwrap()),
        BackendAction::AuthResponse(_) => panic!("unexpected auth response"),
    }
}

/// Browser starts a flow; returns (cookie state, flow id).
async fn start(f: &Fx) -> (State, String) {
    let mut ctx = Context::new(req("vp/start", "GET"), State::new());
    let page =
        f.b.start_auth(&mut ctx, InternalData::request("https://rp.example"))
            .await
            .unwrap();
    let html = String::from_utf8(page.body).unwrap();
    assert!(
        html.contains("openid4vp://cb?client_id=x509_hash%3A"),
        "{html}"
    );
    assert!(html.contains("request_uri_method=get"));
    let id = ctx.state.get_str(NS, FLOW_KEY).unwrap();
    assert!(html.contains(&format!("vp%2Frequest%2F{id}")), "{html}");
    (ctx.state, id)
}
async fn fetch_jar(f: &Fx, id: &str) -> String {
    let mut ctx = Context::new(req(&format!("vp/request/{id}"), "GET"), State::new());
    let (st, body) = respond_body(f.b.handle_endpoint(&mut ctx, "request").await.unwrap());
    assert_eq!(st, 200);
    body
}

async fn start_post(f: &Fx) -> (State, String) {
    let mut ctx = Context::new(req("vp/start", "GET"), State::new());
    let html = String::from_utf8(
        f.b.start_auth(&mut ctx, InternalData::request("https://rp.example"))
            .await
            .unwrap()
            .body,
    )
    .unwrap();
    assert!(html.contains("request_uri_method=post"), "{html}");
    let id = ctx.state.get_str(NS, FLOW_KEY).unwrap();
    (ctx.state, id)
}

async fn fetch_jar_post(
    f: &Fx,
    id: &str,
    fields: Vec<(String, String)>,
) -> (u16, String, Vec<(String, String)>) {
    let mut request = req(&format!("vp/request/{id}"), "POST");
    request.form = fields.iter().cloned().collect();
    request.form_pairs = fields;
    let mut ctx = Context::new(request, State::new());
    let BackendAction::Respond(response) = f.b.handle_endpoint(&mut ctx, "request").await.unwrap()
    else {
        panic!("expected response")
    };
    (
        response.status,
        String::from_utf8(response.body).unwrap(),
        response.headers,
    )
}
fn wallet(f: &Fx, jar: &str) -> String {
    wallet_respond(
        jar,
        &f.holder,
        &[WalletCredential {
            id: "pid",
            issued: &f.issued,
            disclose: &[0, 1],
        }],
        f.clock.load(Ordering::SeqCst),
    )
    .unwrap()
}
async fn post(f: &Fx, id: &str, jwe: &str) -> (u16, String) {
    let mut r = req(&format!("vp/response/{id}"), "POST");
    r.form = BTreeMap::from([("response".to_string(), jwe.to_string())]);
    r.form_pairs = vec![("response".into(), jwe.into())];
    let mut ctx = Context::new(r, State::new());
    respond_body(f.b.handle_endpoint(&mut ctx, "response").await.unwrap())
}
async fn complete(f: &Fx, state: &State) -> Result<BackendAction, String> {
    let mut ctx = Context::new(req("vp/complete", "GET"), state.clone());
    f.b.handle_endpoint(&mut ctx, "complete")
        .await
        .map_err(|e| e.to_string())
}

#[tokio::test]
async fn happy_path_delivers_mapped_attributes_once() {
    let f = fx();
    let (state, id) = start(&f).await;
    // before the wallet answers, the browser is told to wait
    assert!(matches!(
        complete(&f, &state).await.unwrap(),
        BackendAction::Respond(_)
    ));
    let jar = fetch_jar(&f, &id).await;
    let (st, _) = post(&f, &id, &wallet(&f, &jar)).await;
    assert_eq!(st, 200);
    let BackendAction::AuthResponse(d) = complete(&f, &state).await.unwrap() else {
        panic!("expected auth response")
    };
    assert_eq!(d.requester.as_deref(), Some("https://rp.example"));
    assert_eq!(d.subject_id.as_deref(), Some("Lovelace"));
    assert_eq!(d.attr_first("givenName"), Some("Ada"));
    assert_eq!(d.attr_first("l"), Some("London"));
    assert!(!d.attributes.contains_key("missing"));
    assert_eq!(
        d.auth_info.auth_class_ref.as_deref(),
        Some("urn:eudi:loa:high")
    );
    assert_eq!(
        d.auth_info.issuer.as_deref(),
        Some("https://issuer.example")
    );
    // second collection fails: one-time
    assert!(complete(&f, &state).await.is_err());
}

#[tokio::test]
async fn every_verified_credential_s_claims_reach_the_result() {
    let (f, loyalty) = fx_multi(json!("gold"));
    let (state, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    let (st, body) = post(&f, &id, &wallet_multi(&f, &loyalty, &jar)).await;
    assert_eq!(st, 200, "{body}");
    let BackendAction::AuthResponse(d) = complete(&f, &state).await.unwrap() else {
        panic!("expected auth response")
    };
    assert_eq!(d.requester.as_deref(), Some("https://rp.example"));
    assert_eq!(d.subject_id.as_deref(), Some("Lovelace"));
    assert_eq!(
        d.auth_info.issuer.as_deref(),
        Some("https://issuer.example")
    );
    assert_eq!(d.attr_first("sn"), Some("Lovelace"));
    assert_eq!(
        d.attr_first("tier"),
        Some("gold"),
        "the second credential's claims must reach the result"
    );
    assert_eq!(
        d.attributes
            .get("kind")
            .map(|values| values.iter().map(String::as_str).collect::<Vec<_>>()),
        Some(vec!["urn:eudi:pid:1", "urn:example:loyalty:1"]),
        "a pointer both credentials carry accumulates in query order"
    );
}

#[tokio::test]
async fn the_subject_may_come_from_a_later_credential() {
    // the first credential has no /membership_level; the second one does
    let (f, loyalty) = fx_multi_at(json!("gold"), "/membership_level");
    let (state, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    let (st, body) = post(&f, &id, &wallet_multi(&f, &loyalty, &jar)).await;
    assert_eq!(st, 200, "{body}");
    let BackendAction::AuthResponse(d) = complete(&f, &state).await.unwrap() else {
        panic!("expected auth response")
    };
    assert_eq!(d.subject_id.as_deref(), Some("gold"));
}

#[tokio::test]
async fn the_subject_comes_from_the_first_credential_that_carries_it() {
    // both credentials carry /vct; the first one in query order must win
    let (f, loyalty) = fx_multi_at(json!("gold"), "/vct");
    let (state, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    let (st, body) = post(&f, &id, &wallet_multi(&f, &loyalty, &jar)).await;
    assert_eq!(st, 200, "{body}");
    let BackendAction::AuthResponse(d) = complete(&f, &state).await.unwrap() else {
        panic!("expected auth response")
    };
    assert_eq!(d.subject_id.as_deref(), Some("urn:eudi:pid:1"));
}

#[tokio::test]
async fn a_non_scalar_mapped_claim_in_any_credential_fails_the_flow() {
    let (f, loyalty) = fx_multi(json!({"level": "gold"}));
    let (state, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    let (st, _) = post(&f, &id, &wallet_multi(&f, &loyalty, &jar)).await;
    assert_eq!(st, 422);
    assert_eq!(
        complete(&f, &state).await.err().unwrap(),
        "authentication error: attribute_not_scalar"
    );
}

#[tokio::test]
async fn untrusted_issuer_fails_the_flow_and_no_attributes_leak() {
    let f = fx();
    f.pdp.permit.store(false, Ordering::SeqCst);
    let (state, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    let (st, body) = post(&f, &id, &wallet(&f, &jar)).await;
    assert_eq!(st, 403);
    let error: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(error["error"], "issuer_not_trusted");
    assert!(error["error_description"].is_string());
    assert!(!body.contains("Lovelace"));
    assert_eq!(
        complete(&f, &state).await.err().unwrap(),
        "authentication error: issuer_not_trusted"
    );
}

#[tokio::test]
async fn an_untrusted_issuer_cannot_trigger_status_network_activity() {
    let mut f = fx();
    f.pdp.permit.store(false, Ordering::SeqCst);
    let status = Arc::new(CountingStatusClient::default());
    let status_calls = status.clone();
    let (issuer_cert, issuer_key) = self_signed_ec("issuer.example", "ES256");
    let mut spec = IssueSpec::new(json!({
        "iss": "https://issuer.example", "vct": "urn:eudi:pid:1", "iat": T0 - 10,
        "exp": T0 + 1_000_000, "given_name": "Ada", "family_name": "Lovelace",
        "status": {"status_list": {"idx": 0, "uri": "https://status.example/list.jwt"}},
    }));
    spec.holder_pub = Some(public_of(&f.holder));
    spec.x5c_der = vec![issuer_cert];
    spec.conceal = vec![vec![Seg::Key("given_name")], vec![Seg::Key("family_name")]];
    f.issued = issue(&issuer_key, &spec).unwrap();
    f.b = f.b.with_status_list_client(status);

    let (state, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    let (st, body) = post(&f, &id, &wallet(&f, &jar)).await;
    assert_eq!(st, 403);
    let error: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(error["error"], "issuer_not_trusted");
    assert_eq!(status_calls.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        f.pdp.calls.load(Ordering::SeqCst),
        1,
        "only the issuer permit"
    );
    assert!(!body.contains("Lovelace"));
    assert!(complete(&f, &state).await.is_err());
}

#[tokio::test]
async fn malformed_status_structure_is_rejected_before_signer_evaluation() {
    let mut f = fx();
    let (status_cert, status_key) = self_signed_ec("status.example", "ES256");
    let claims = json!({
        "sub": "https://status.example/list.jwt", "iat": T0 - 10, "exp": T0 + 1_000,
        "status_list": {"bits": 0, "lst": ""},
    });
    let token = sign_raw(
        &status_key,
        "statuslist+jwt",
        &claims,
        std::slice::from_ref(&status_cert),
    );
    let status = Arc::new(CountingStatusClient {
        calls: AtomicUsize::new(0),
        token: Some(token),
    });
    let status_calls = status.clone();
    let (issuer_cert, issuer_key) = self_signed_ec("issuer.example", "ES256");
    let mut spec = IssueSpec::new(json!({
        "iss": "https://issuer.example", "vct": "urn:eudi:pid:1", "iat": T0 - 10,
        "exp": T0 + 1_000_000, "given_name": "Ada", "family_name": "Lovelace",
        "status": {"status_list": {"idx": 0, "uri": "https://status.example/list.jwt"}},
    }));
    spec.holder_pub = Some(public_of(&f.holder));
    spec.x5c_der = vec![issuer_cert];
    spec.conceal = vec![vec![Seg::Key("given_name")], vec![Seg::Key("family_name")]];
    f.issued = issue(&issuer_key, &spec).unwrap();
    f.b = f.b.with_status_list_client(status);

    let (state, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    let (st, body) = post(&f, &id, &wallet(&f, &jar)).await;
    assert_eq!(st, 400, "{body}");
    let error: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(error["error"], "invalid_status_list");
    assert_eq!(status_calls.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.pdp.calls.load(Ordering::SeqCst),
        1,
        "only the issuer permit"
    );
    assert!(!body.contains("Lovelace"));
    assert!(complete(&f, &state).await.is_err());
}

#[tokio::test]
async fn revoked_status_is_refused_after_the_signer_permit() {
    let mut f = fx();
    // RFC 1950: zlib-compressed single byte 0x01, independently produced.
    let claims = json!({
        "sub": "https://status.example/list.jwt", "iat": T0 - 10, "exp": T0 + 1_000,
        "status_list": {"bits": 1, "lst": "eJxjBAAAAgAC"},
    });
    let (status_cert, status_key) = self_signed_ec("status.example", "ES256");
    let token = sign_raw(
        &status_key,
        "statuslist+jwt",
        &claims,
        std::slice::from_ref(&status_cert),
    );
    let status = Arc::new(CountingStatusClient {
        calls: AtomicUsize::new(0),
        token: Some(token),
    });
    let status_calls = status.clone();
    let (issuer_cert, issuer_key) = self_signed_ec("issuer.example", "ES256");
    let mut spec = IssueSpec::new(json!({
        "iss": "https://issuer.example", "vct": "urn:eudi:pid:1", "iat": T0 - 10,
        "exp": T0 + 1_000_000, "given_name": "Ada", "family_name": "Lovelace",
        "status": {"status_list": {"idx": 0, "uri": "https://status.example/list.jwt"}},
    }));
    spec.holder_pub = Some(public_of(&f.holder));
    spec.x5c_der = vec![issuer_cert];
    spec.conceal = vec![vec![Seg::Key("given_name")], vec![Seg::Key("family_name")]];
    f.issued = issue(&issuer_key, &spec).unwrap();
    f.b = f.b.with_status_list_client(status);

    let (state, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    let (st, body) = post(&f, &id, &wallet(&f, &jar)).await;
    assert_eq!(st, 403, "{body}");
    let error: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(error["error"], "credential_revoked");
    assert_eq!(status_calls.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.pdp.calls.load(Ordering::SeqCst),
        2,
        "issuer and signer permits"
    );
    assert!(!body.contains("Lovelace"));
    assert!(complete(&f, &state).await.is_err());
}

#[tokio::test]
async fn pdp_down_with_cold_cache_fails_closed() {
    let f = fx();
    f.pdp.down.store(true, Ordering::SeqCst);
    let (state, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    assert_eq!(post(&f, &id, &wallet(&f, &jar)).await.0, 503);
    assert_eq!(
        complete(&f, &state).await.err().unwrap(),
        "authentication error: trust_unavailable"
    );
}

#[tokio::test]
async fn warm_receipt_survives_a_pdp_outage_until_it_expires() {
    let f = fx();
    // first login warms the receipt
    let (s1, id1) = start(&f).await;
    let jar = fetch_jar(&f, &id1).await;
    assert_eq!(post(&f, &id1, &wallet(&f, &jar)).await.0, 200);
    assert!(matches!(
        complete(&f, &s1).await.unwrap(),
        BackendAction::AuthResponse(_)
    ));
    assert_eq!(f.pdp.calls.load(Ordering::SeqCst), 1);

    // PDP goes away; the next login within the receipt's life still works without a call
    f.pdp.down.store(true, Ordering::SeqCst);
    f.clock.store(T0 + 600, Ordering::SeqCst); // fresh: refresh_after is T0 + 1800
    let (s2, id2) = start(&f).await;
    let jar = fetch_jar(&f, &id2).await;
    assert_eq!(post(&f, &id2, &wallet(&f, &jar)).await.0, 200);
    assert!(matches!(
        complete(&f, &s2).await.unwrap(),
        BackendAction::AuthResponse(_)
    ));
    assert_eq!(
        f.pdp.calls.load(Ordering::SeqCst),
        1,
        "fresh receipt: no PDP call"
    );

    // past refresh_after the gate tries the PDP, fails, and still uses the valid receipt
    f.clock.store(T0 + 2000, Ordering::SeqCst);
    let (s3, id3) = start(&f).await;
    let jar = fetch_jar(&f, &id3).await;
    assert_eq!(post(&f, &id3, &wallet(&f, &jar)).await.0, 200);
    assert!(matches!(
        complete(&f, &s3).await.unwrap(),
        BackendAction::AuthResponse(_)
    ));
    assert_eq!(
        f.pdp.calls.load(Ordering::SeqCst),
        2,
        "stale receipt: one refresh attempt"
    );

    // after exp the outage is no longer survivable
    f.clock.store(T0 + 3700, Ordering::SeqCst);
    let (_s4, id4) = start(&f).await;
    let jar = fetch_jar(&f, &id4).await;
    assert_eq!(post(&f, &id4, &wallet(&f, &jar)).await.0, 503);
}

#[tokio::test]
async fn receipt_lifetime_follows_trust_data_next_update() {
    let f = fx_with(900); // the registry's data expires 15 minutes from now
    let (s, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    assert_eq!(post(&f, &id, &wallet(&f, &jar)).await.0, 200);
    complete(&f, &s).await.unwrap();
    f.pdp.down.store(true, Ordering::SeqCst);
    f.clock.store(T0 + 901, Ordering::SeqCst);
    let (_s, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    assert_eq!(
        post(&f, &id, &wallet(&f, &jar)).await.0,
        503,
        "receipt must not outlive the trust data"
    );
}

#[tokio::test]
async fn replayed_wallet_response_is_rejected_and_does_not_double_deliver() {
    let f = fx();
    let (state, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    let jwe = wallet(&f, &jar);
    assert_eq!(post(&f, &id, &jwe).await.0, 200);
    assert_eq!(post(&f, &id, &jwe).await.0, 409);
    assert!(matches!(
        complete(&f, &state).await.unwrap(),
        BackendAction::AuthResponse(_)
    ));
}

#[tokio::test]
async fn a_stalled_pdp_fails_the_flow_within_the_processing_deadline() {
    let f = fx_stalled(1);
    let (state, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    let (st, body) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        post(&f, &id, &wallet(&f, &jar)),
    )
    .await
    .expect("the processing deadline must bound a stalled PDP");
    assert_eq!(st, 504, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(error["error"], "processing_deadline");
    assert_eq!(
        complete(&f, &state).await.err().unwrap(),
        "authentication error: processing_deadline",
        "the failure is terminal, not a hang until the lease"
    );
}

#[tokio::test]
async fn the_processing_budget_never_outlives_the_remaining_lease() {
    // A claim round-trip that consumes 50 of the lease's 60 seconds leaves a
    // five-second budget (deadline 55, minus the finalize reserve) even though
    // the configured deadline is 55.
    let clock = Arc::new(AtomicI64::new(T0));
    let store = Arc::new(ClockBumpingClaimStore {
        inner: MemoryFlowStore::default(),
        clock: clock.clone(),
        advance: 50,
    });
    let cfg = pid_cfg("/family_name", "get", Some((60, 55)), 16);
    let f = fx_with_parts(
        cfg,
        mock_pdp(100_000, true),
        mock_pdp(100_000, false),
        store,
        clock,
    );
    let (state, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    let (st, body) = tokio::time::timeout(
        std::time::Duration::from_secs(25),
        post(&f, &id, &wallet(&f, &jar)),
    )
    .await
    .expect("the budget must collapse to the lease's remaining time");
    assert_eq!(st, 504, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(error["error"], "processing_deadline");
    assert_eq!(
        complete(&f, &state).await.err().unwrap(),
        "authentication error: processing_deadline"
    );

    // With one second of lease left there is no safe processing window at
    // all: verification is never polled, so the stalled PDP is never called.
    let clock = Arc::new(AtomicI64::new(T0));
    let store = Arc::new(ClockBumpingClaimStore {
        inner: MemoryFlowStore::default(),
        clock: clock.clone(),
        advance: 59,
    });
    let cfg = pid_cfg("/family_name", "get", Some((60, 55)), 16);
    let gate_pdp = mock_pdp(100_000, true);
    let f = fx_with_parts(
        cfg,
        gate_pdp.clone(),
        mock_pdp(100_000, false),
        store,
        clock,
    );
    let (state, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    let (st, body) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        post(&f, &id, &wallet(&f, &jar)),
    )
    .await
    .expect("an exhausted window must finalize without polling");
    assert_eq!(st, 504, "{body}");
    assert_eq!(gate_pdp.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        complete(&f, &state).await.err().unwrap(),
        "authentication error: processing_deadline"
    );
}

#[tokio::test]
async fn a_synchronous_overrun_past_the_deadline_is_not_persisted() {
    // The PDP busy-waits two seconds: the one-second timer cannot preempt
    // synchronous code, so the decision completes past the deadline and must
    // not be accepted even though the lease window is still wide open.
    let clock = Arc::new(AtomicI64::new(T0));
    let pdp = Arc::new(BusyWaitPdp {
        spin: std::time::Duration::from_secs(2),
    });
    let cfg = pid_cfg("/family_name", "get", Some((60, 1)), 16);
    let f = fx_with_parts(
        cfg,
        pdp,
        mock_pdp(100_000, false),
        Arc::new(MemoryFlowStore::default()),
        clock,
    );
    let (state, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    let (st, body) = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        post(&f, &id, &wallet(&f, &jar)),
    )
    .await
    .expect("the overrun must still finish within the outer bound");
    assert_eq!(st, 504, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(error["error"], "processing_deadline");
    assert_eq!(
        complete(&f, &state).await.err().unwrap(),
        "authentication error: processing_deadline"
    );
}

#[tokio::test]
async fn a_queued_response_aborts_without_verifying_when_admission_is_full() {
    // Two backends share one admission slot. The holder (a 3s budget)
    // stalls at its PDP while holding the slot; the queued response (a 1s
    // budget on the other backend) expires while still queued — seconds
    // before the holder can ever release — so its verification provably
    // never starts, with no expiry-boundary race.
    let shared = Arc::new(tokio::sync::Semaphore::new(1));
    let holder_pdp = mock_pdp(100_000, true);
    let mut holder = fx_with_parts(
        pid_cfg("/family_name", "get", Some((60, 3)), 1),
        holder_pdp.clone(),
        mock_pdp(100_000, false),
        Arc::new(MemoryFlowStore::default()),
        Arc::new(AtomicI64::new(T0)),
    );
    holder.b = holder.b.with_verification_permits(shared.clone());
    let queued_pdp = mock_pdp(100_000, false);
    let mut queued = fx_with_parts(
        pid_cfg("/family_name", "get", Some((60, 1)), 1),
        queued_pdp.clone(),
        mock_pdp(100_000, false),
        Arc::new(MemoryFlowStore::default()),
        Arc::new(AtomicI64::new(T0)),
    );
    queued.b = queued.b.with_verification_permits(shared.clone());

    let (_s1, id1) = start(&holder).await;
    let jar1 = fetch_jar(&holder, &id1).await;
    let (_s2, id2) = start(&queued).await;
    let jar2 = fetch_jar(&queued, &id2).await;
    let jwe1 = wallet(&holder, &jar1);
    let jwe2 = wallet(&queued, &jar2);
    let (r1, r2) = tokio::join!(
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            post(&holder, &id1, &jwe1)
        ),
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            post(&queued, &id2, &jwe2)
        ),
    );
    let (st1, body1) = r1.expect("the stalled holder must still finish");
    let (st2, body2) = r2.expect("the queued response must finish");
    assert_eq!(st1, 504, "{body1}");
    assert_eq!(st2, 504, "{body2}");
    assert_eq!(
        holder_pdp.calls.load(Ordering::SeqCst),
        1,
        "the admitted holder reaches its trust evaluation"
    );
    assert_eq!(
        queued_pdp.calls.load(Ordering::SeqCst),
        0,
        "the queued response expires before the holder can release, so its verification never starts"
    );
    // The dead callers release their admissions: a fresh response is
    // admitted and completes.
    let (state, id) = start(&queued).await;
    let jar = fetch_jar(&queued, &id).await;
    let (st, body) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        post(&queued, &id, &wallet(&queued, &jar)),
    )
    .await
    .expect("a fresh response must be admitted after its predecessors died");
    assert_eq!(st, 200, "{body}");
    assert!(matches!(
        complete(&queued, &state).await.unwrap(),
        BackendAction::AuthResponse(_)
    ));
}

#[tokio::test]
async fn a_decision_past_the_claims_safe_window_is_not_persisted() {
    // The PDP answers with a permit, but only after jumping the clock to the
    // lease deadline: the completed decision arrives past the safe window
    // and the deadline refusal is what gets persisted.
    let clock = Arc::new(AtomicI64::new(T0));
    let pdp = Arc::new(ClockJumpingPdp {
        clock: clock.clone(),
        jump_to: T0 + 60,
    });
    let cfg = pid_cfg("/family_name", "get", None, 16);
    let f = fx_with_parts(
        cfg,
        pdp,
        mock_pdp(100_000, false),
        Arc::new(MemoryFlowStore::default()),
        clock,
    );
    let (state, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    let (st, body) = post(&f, &id, &wallet(&f, &jar)).await;
    assert_eq!(st, 504, "{body}");
    let error: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(error["error"], "processing_deadline");
    assert_eq!(
        complete(&f, &state).await.err().unwrap(),
        "authentication error: processing_deadline"
    );
}

#[tokio::test]
async fn a_wallet_retry_recovers_a_flow_whose_runner_died_mid_processing() {
    let store = Arc::new(MemoryFlowStore::default());
    let f = fx().with_storage(store.clone());
    let (state, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    let jwe = wallet(&f, &jar);
    // The first runner claimed the response slot and died mid-processing;
    // its one-second lease expires while the browser keeps waiting.
    assert!(matches!(
        store.claim(&id, T0, "dead-claim", 1).await.unwrap(),
        ClaimResult::Claimed(_)
    ));
    f.clock.store(T0 + 2, Ordering::SeqCst);
    // The wallet's retry re-claims the expired lease and re-drives the flow.
    assert_eq!(post(&f, &id, &jwe).await.0, 200);
    assert_eq!(
        post(&f, &id, &jwe).await.0,
        409,
        "replay protection is intact after recovery"
    );
    assert!(matches!(
        complete(&f, &state).await.unwrap(),
        BackendAction::AuthResponse(_)
    ));
}

#[tokio::test]
async fn two_replicas_share_the_complete_flow_and_replay_guard() {
    let store = Arc::new(MemoryFlowStore::default());
    let a = fx().with_storage(store.clone());
    let b = fx().with_storage(store);
    let (state, id) = start(&a).await;
    let jar = fetch_jar(&b, &id).await;
    let jwe = wallet(&a, &jar);
    assert_eq!(post(&b, &id, &jwe).await.0, 200);
    assert!(matches!(
        complete(&b, &state).await.unwrap(),
        BackendAction::AuthResponse(_)
    ));
    assert_eq!(post(&a, &id, &jwe).await.0, 409);
}

#[tokio::test]
async fn concurrent_replica_responses_and_collections_each_have_one_winner() {
    let store = Arc::new(MemoryFlowStore::default());
    let a = fx().with_storage(store.clone());
    let b = fx().with_storage(store);
    let (state, id) = start(&a).await;
    let jar = fetch_jar(&b, &id).await;
    let jwe = wallet(&a, &jar);
    let (first, second) = tokio::join!(post(&a, &id, &jwe), post(&b, &id, &jwe));
    let mut statuses = [first.0, second.0];
    statuses.sort_unstable();
    assert_eq!(statuses, [200, 409]);

    let (first, second) = tokio::join!(complete(&a, &state), complete(&b, &state));
    let delivered = [first, second]
        .into_iter()
        .filter(|result| matches!(result, Ok(BackendAction::AuthResponse(_))))
        .count();
    assert_eq!(delivered, 1);
}

#[tokio::test]
async fn a_failed_final_result_write_never_delivers_authentication() {
    let f = fx().with_storage(Arc::new(FinishFailingStore::default()));
    let (state, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    let jwe = wallet(&f, &jar);
    assert_eq!(post(&f, &id, &jwe).await.0, 503);
    assert!(matches!(
        complete(&f, &state).await.unwrap(),
        BackendAction::Respond(_)
    ));
    assert_eq!(post(&f, &id, &jwe).await.0, 409);
}

#[tokio::test]
async fn response_for_another_flow_does_not_verify() {
    let f = fx();
    let (_s1, id1) = start(&f).await;
    let (s2, id2) = start(&f).await;
    let jwe_for_1 = wallet(&f, &fetch_jar(&f, &id1).await);
    // posted to flow 2: wrong nonce/state/key for that session
    assert_eq!(post(&f, &id2, &jwe_for_1).await.0, 400);
    assert!(complete(&f, &s2).await.is_err());
}

#[tokio::test]
async fn only_the_starting_browser_can_collect() {
    let f = fx();
    let (_state, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    assert_eq!(post(&f, &id, &wallet(&f, &jar)).await.0, 200);
    // an attacker's browser has no cookie, or a cookie for a different flow
    assert!(complete(&f, &State::new()).await.is_err());
    let (other, _) = start(&f).await;
    assert!(
        matches!(
            complete(&f, &other).await.unwrap(),
            BackendAction::Respond(_)
        ),
        "other flow still pending"
    );
}

#[tokio::test]
async fn expired_flow_is_not_answerable_or_collectable() {
    let f = fx();
    let (state, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    let jwe = wallet(&f, &jar);
    f.clock.store(T0 + 301, Ordering::SeqCst);
    assert_eq!(post(&f, &id, &jwe).await.0, 400);
    assert!(complete(&f, &state).await.is_err());
}

#[tokio::test]
async fn flow_ids_are_validated_and_unknown_ids_get_nothing() {
    let f = fx();
    for bad in [
        "short",
        "../../etc/passwd/xxxxxxxxxxxxxx",
        &"a".repeat(65),
        "AAAAAAAAAAAAAAAA!",
    ] {
        let mut ctx = Context::new(req(&format!("vp/request/{bad}"), "GET"), State::new());
        let e =
            f.b.handle_endpoint(&mut ctx, "request")
                .await
                .err()
                .expect("rejected")
                .to_string();
        assert!(
            e.contains("flow id"),
            "{bad}: rejected for the wrong reason: {e}"
        );
    }
    let mut ctx = Context::new(
        req("vp/request/AAAAAAAAAAAAAAAAAAAAAA", "GET"),
        State::new(),
    );
    assert!(f.b.handle_endpoint(&mut ctx, "request").await.is_err());
    let mut r = req("vp/response/AAAAAAAAAAAAAAAAAAAAAA", "POST");
    r.form = BTreeMap::from([("response".to_string(), "x".to_string())]);
    let mut ctx = Context::new(r, State::new());
    let (st, _) = respond_body(f.b.handle_endpoint(&mut ctx, "response").await.unwrap());
    assert_eq!(st, 404);
}

#[tokio::test]
async fn get_on_the_response_endpoint_is_refused() {
    let f = fx();
    let (_s, id) = start(&f).await;
    let mut ctx = Context::new(req(&format!("vp/response/{id}"), "GET"), State::new());
    assert_eq!(
        respond_body(f.b.handle_endpoint(&mut ctx, "response").await.unwrap()).0,
        405
    );
}

#[tokio::test]
async fn missing_response_parameter_fails_the_flow() {
    let f = fx();
    let (state, id) = start(&f).await;
    let mut ctx = Context::new(req(&format!("vp/response/{id}"), "POST"), State::new());
    assert_eq!(
        respond_body(f.b.handle_endpoint(&mut ctx, "response").await.unwrap()).0,
        400
    );
    assert_eq!(
        complete(&f, &state).await.err().unwrap(),
        "authentication error: missing_response"
    );
}

#[tokio::test]
async fn duplicate_response_parameters_are_rejected() {
    let f = fx();
    let (state, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    let jwe = wallet(&f, &jar);
    let mut request = req(&format!("vp/response/{id}"), "POST");
    // RFC 6749 section 3.1 prohibits repeated request/response parameters.
    // Keep the last value valid so accepting last-write-wins would succeed.
    request.form = BTreeMap::from([("response".to_string(), jwe.clone())]);
    request.form_pairs = vec![
        ("response".into(), "a-different-response".into()),
        ("response".into(), jwe),
    ];
    let mut ctx = Context::new(request, State::new());
    let (status, body) = respond_body(f.b.handle_endpoint(&mut ctx, "response").await.unwrap());
    assert_eq!(status, 400);
    let error: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(error["error"], "duplicate_response");
    assert_eq!(
        complete(&f, &state).await.err().unwrap(),
        "authentication error: duplicate_response"
    );
}

#[test]
fn routes_cover_the_flow_endpoints_and_nothing_else() {
    let f = fx();
    let routes = f.b.register_endpoints();
    let m = |p: &str| routes.iter().find(|r| r.matches(p)).map(|r| r.id.clone());
    assert_eq!(
        m("vp/request/AAAAAAAAAAAAAAAAAAAAAA").as_deref(),
        Some("request")
    );
    assert_eq!(
        m("vp/response/AAAAAAAAAAAAAAAAAAAAAA").as_deref(),
        Some("response")
    );
    assert_eq!(m("vp/status").as_deref(), Some("status"));
    assert_eq!(m("vp/complete").as_deref(), Some("complete"));
    assert_eq!(m("vp/request/short"), None);
    assert_eq!(m("other/complete"), None);
    assert_eq!(m("vp/complete/extra"), None);
}

fn backend_with_config(cfg: VpBackendConfig) -> Result<VpBackend, tunnelbana_core::Error> {
    let (v_cert, v_key) = self_signed_ec("v.example", "ES256");
    let gate = TrustGate::new(
        Arc::new(NoPdp),
        p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap(),
        "k",
        "i",
        "a",
        "p",
        60,
    );
    VpBackend::new(
        "vp",
        "https://p/vp",
        cfg,
        gate,
        siros_verifier_core::oid4vp::software_signer(&v_key).unwrap(),
        vec![v_cert],
        system_clock(),
    )
}

#[test]
fn config_rejects_unknown_fields_and_bad_pointers() {
    assert!(serde_json::from_value::<VpBackendConfig>(
        json!({"dcql": {}, "attribute_map": {}, "subject_pointer": "/a", "role": "r", "typo": 1})
    )
    .is_err());
    let mk = |sp: &str, ttl: i64| {
        let cfg: VpBackendConfig = serde_json::from_value(json!({
            "dcql": {"credentials": [{"id": "pid", "format": "dc+sd-jwt"}]},
            "attribute_map": {}, "subject_pointer": sp, "role": "r", "request_ttl_secs": ttl
        }))
        .unwrap();
        backend_with_config(cfg)
    };
    assert!(
        mk("family_name", 300).is_err(),
        "pointer without leading slash"
    );
    assert!(mk("/family_name", 0).is_err());
    assert!(mk("/family_name", 901).is_err());
    assert!(mk("/family_name", 300).is_ok());
}

#[test]
fn processing_lease_is_bounded() {
    let mk = |lease: i64| {
        let cfg: VpBackendConfig = serde_json::from_value(json!({
            "dcql": {"credentials": [{"id": "pid", "format": "dc+sd-jwt"}]},
            "attribute_map": {}, "subject_pointer": "/family_name", "role": "r",
            "processing_lease_secs": lease, "processing_deadline_secs": 1
        }))
        .unwrap();
        backend_with_config(cfg)
    };
    let refusal = |lease: i64| {
        mk(lease)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "OK".into())
    };
    assert!(refusal(0).contains("processing_lease_secs"));
    assert!(refusal(901).contains("processing_lease_secs"));
    // The deadline must stay strictly shorter than the lease and the lease
    // must exceed the flow-store write bound, so six seconds is the smallest
    // lease that fits.
    assert!(mk(1).is_err());
    assert!(mk(5).is_err());
    assert!(mk(6).is_ok());
    assert!(mk(900).is_ok());
}

#[test]
fn processing_deadline_is_bounded() {
    let mk = |lease: i64, deadline: i64| {
        let cfg: VpBackendConfig = serde_json::from_value(json!({
            "dcql": {"credentials": [{"id": "pid", "format": "dc+sd-jwt"}]},
            "attribute_map": {}, "subject_pointer": "/family_name", "role": "r",
            "processing_lease_secs": lease, "processing_deadline_secs": deadline
        }))
        .unwrap();
        backend_with_config(cfg)
    };
    let refusal = |lease: i64, deadline: i64| {
        mk(lease, deadline)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "OK".into())
    };
    assert!(refusal(60, 0).contains("processing_deadline_secs"));
    assert!(refusal(60, 901).contains("processing_deadline_secs"));
    assert!(refusal(60, 60).contains("processing_deadline_secs"));
    assert!(
        refusal(60, 56).contains("processing_deadline_secs"),
        "the deadline must leave room for the flow-store write bound"
    );
    assert!(mk(60, 55).is_ok());
}

#[test]
fn verification_concurrency_is_bounded() {
    let mk = |permits: usize| {
        let cfg: VpBackendConfig = serde_json::from_value(json!({
            "dcql": {"credentials": [{"id": "pid", "format": "dc+sd-jwt"}]},
            "attribute_map": {}, "subject_pointer": "/family_name", "role": "r",
            "max_concurrent_verifications": permits
        }))
        .unwrap();
        backend_with_config(cfg)
    };
    let refusal = |permits: usize| {
        mk(permits)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "OK".into())
    };
    assert!(refusal(0).contains("max_concurrent_verifications"));
    assert!(refusal(513).contains("max_concurrent_verifications"));
    assert!(mk(1).is_ok());
    assert!(mk(512).is_ok());
}

#[test]
fn default_dcql_is_validated_at_construction() {
    let cfg: VpBackendConfig = serde_json::from_value(json!({
        "dcql": {"credentials": []},
        "attribute_map": {}, "subject_pointer": "/family_name", "role": "r"
    }))
    .unwrap();
    assert!(matches!(
        backend_with_config(cfg),
        Err(tunnelbana_core::Error::Config(_))
    ));
}

#[test]
fn zkp_fallback_requires_specialized_construction() {
    let cfg: VpBackendConfig = serde_json::from_value(json!({
        "dcql": {"credentials": [{
            "id": "nym", "format": "zkp_req",
            "meta": {"source_format": "mso_mdoc", "doctype_value": "eu.europa.ec.eudi.nym_auth.1"},
            "_req": [{"fn_id": "pseudonym", "return": "nym-1", "params": {
                "config": "known-offender-matching-ssc", "ver": 1, "prf": "sha-256"
            }}]
        }]},
        "attribute_map": {}, "subject_pointer": "/family_name", "role": "r"
    }))
    .unwrap();
    assert!(matches!(
        backend_with_config(cfg),
        Err(tunnelbana_core::Error::Config(_))
    ));
}

#[tokio::test]
async fn no_pdp_configured_denies_everything() {
    let g = TrustGate::new(
        Arc::new(NoPdp),
        p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap(),
        "k",
        "i",
        "a",
        "p",
        60,
    );
    assert_eq!(
        g.permits(&json!({"x": 1}), T0).await.unwrap_err(),
        "pdp_not_configured"
    );
}

#[test]
fn authzen_response_parsing_is_strict() {
    let ok = json!({"decision": true, "context": {"id": "d1", "trust_data": [{"registry": "etsi", "as_of": "2027-01-15T00:00:00Z", "next_update": "2027-01-16T00:00:00Z"}]}});
    let a = parse_authzen_response(&ok).unwrap();
    assert!(a.decision);
    assert_eq!(
        a.trust_data[0].next_update.unwrap() - a.trust_data[0].as_of.unwrap(),
        86400
    );
    assert!(
        parse_authzen_response(&json!({"decision": "true", "context": {"id": "d"}})).is_err(),
        "decision must be a boolean"
    );
    assert!(
        parse_authzen_response(&json!({"decision": true, "context": {"id": 5}})).is_err(),
        "a non-string id is malformed, not absent"
    );
    assert!(
        parse_authzen_response(&json!({"decision": true, "context": {"id": ""}})).is_err(),
        "an empty id is malformed, not absent"
    );
    let bounded = parse_authzen_response(&json!({"decision": true, "context": {"id": "d", "trust_data": [{"next_update": "2027-01-16T00:00:00Z"}]}})).unwrap();
    assert_eq!(bounded.trust_data[0].as_of, None);
    assert_eq!(
        bounded.trust_data[0].next_update, a.trust_data[0].next_update,
        "a registry may bound validity without stating when its data was taken"
    );
    assert!(parse_authzen_response(
        &json!({"decision": true, "context": {"id": "d", "trust_data": [{"as_of": "garbage"}]}})
    )
    .is_err());
}

#[tokio::test]
async fn pending_flow_past_its_expiry_is_dropped_not_waited_on() {
    let f = fx();
    let (state, _id) = start(&f).await;
    assert!(matches!(
        complete(&f, &state).await.unwrap(),
        BackendAction::Respond(_)
    ));
    f.clock.store(T0 + 301, Ordering::SeqCst);
    assert_eq!(
        complete(&f, &state).await.err().unwrap(),
        "authentication error: flow_expired"
    );
    // and the flow is gone
    assert_eq!(
        complete(&f, &state).await.err().unwrap(),
        "authentication error: unknown_flow"
    );
}

#[tokio::test]
async fn wallet_gets_a_no_store_request_object() {
    let f = fx();
    let (_s, id) = start(&f).await;
    let mut ctx = Context::new(req(&format!("vp/request/{id}"), "GET"), State::new());
    let BackendAction::Respond(r) = f.b.handle_endpoint(&mut ctx, "request").await.unwrap() else {
        panic!()
    };
    let h = |n: &str| {
        r.headers
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(h("content-type"), Some("application/oauth-authz-req+jwt"));
    assert_eq!(h("cache-control"), Some("no-store"));
}

#[tokio::test]
async fn a_credential_without_the_subject_claim_fails_for_that_reason() {
    let f = fx_full(100_000, "/no_such_claim");
    let (state, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    assert_eq!(post(&f, &id, &wallet(&f, &jar)).await.0, 422);
    assert_eq!(
        complete(&f, &state).await.err().unwrap(),
        "authentication error: subject_claim_missing"
    );
}

#[test]
fn real_go_trust_answers_parse_without_id_or_freshness() {
    let p = parse_authzen_response(&serde_json::from_str(REAL_PERMIT).unwrap()).unwrap();
    assert!(p.decision);
    assert!(p.id.starts_with("local-") && p.id.len() > 10);
    assert!(p.trust_data.is_empty());
    assert!(!p.reasons.is_empty());
    let d = parse_authzen_response(&serde_json::from_str(REAL_DENY).unwrap()).unwrap();
    assert!(!d.decision);
    // a decision with no context at all is still a valid answer
    assert!(parse_authzen_response(&json!({"decision": true}))
        .unwrap()
        .id
        .starts_with("local-"));
    // local ids are unique per answer
    let again = parse_authzen_response(&serde_json::from_str(REAL_PERMIT).unwrap()).unwrap();
    assert_ne!(p.id, again.id);
}

#[test]
fn real_always_trusted_answers_parse_with_timestampless_trust_data() {
    // Captured live from the conformance stack's PDP. The first live run of
    // the OIDF plan 503'd every crypto-valid presentation because the parser
    // demanded an `as_of` per trust_data entry; this body must parse, with
    // the absent timestamps recorded as `None` rather than rejected.
    let a = parse_authzen_response(&serde_json::from_str(REAL_ALWAYS_TRUSTED).unwrap()).unwrap();
    assert!(a.decision);
    assert_eq!(a.id, "56e68ce4-6af0-45a0-a426-e4af9068fcc2");
    assert_eq!(a.trust_data.len(), 1);
    assert_eq!(a.trust_data[0].registry, "always-trusted");
    assert_eq!(a.trust_data[0].as_of, None);
    assert_eq!(a.trust_data[0].next_update, None);
    assert!(
        !a.reasons.is_empty(),
        "the reason object's keys are the reasons"
    );
}

#[tokio::test]
async fn post_request_uri_binds_the_wallet_nonce() {
    let store = Arc::new(MemoryFlowStore::default());
    let f = fx_with_method(100_000, "/family_name", "post").with_storage(store);
    let (_state, id) = start_post(&f).await;
    let expected_nonce = "expected-wallet-nonce".to_owned();
    let (status, jar, headers) = fetch_jar_post(
        &f,
        &id,
        vec![("wallet_nonce".into(), expected_nonce.clone())],
    )
    .await;
    assert_eq!(status, 200);
    assert!(headers
        .iter()
        .any(|(name, value)| name == "content-type" && value == "application/oauth-authz-req+jwt"));
    let payload: Value = serde_json::from_slice(
        &jose_rs::base64url::decode(jar.split('.').nth(1).unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(payload["wallet_nonce"], expected_nonce);

    assert_eq!(
        fetch_jar_post(&f, &id, vec![]).await.0,
        400,
        "a missing nonce is refused"
    );
    let (status, reissued, _) =
        fetch_jar_post(&f, &id, vec![("wallet_nonce".into(), "wrong".into())]).await;
    assert_eq!(status, 200, "the wallet's posted nonce is echoed");
    let payload: Value = serde_json::from_slice(
        &jose_rs::base64url::decode(reissued.split('.').nth(1).unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(payload["wallet_nonce"], "wrong");
    assert_eq!(
        fetch_jar_post(
            &f,
            &id,
            vec![
                ("wallet_nonce".into(), expected_nonce.clone()),
                ("wallet_nonce".into(), expected_nonce.clone()),
            ],
        )
        .await
        .0,
        400,
        "a duplicated nonce is refused"
    );
    assert_eq!(
        fetch_jar_post(&f, &id, vec![("other".into(), expected_nonce)])
            .await
            .0,
        400,
        "an unknown form field is refused"
    );
    for malformed in [String::new(), "bad nonce".into(), "x".repeat(257)] {
        let mut request = req(&format!("vp/request/{id}"), "POST");
        request.form = BTreeMap::from([("wallet_nonce".into(), malformed.clone())]);
        request.form_pairs = vec![("wallet_nonce".into(), malformed)];
        let mut ctx = Context::new(request, State::new());
        assert!(
            f.b.handle_endpoint(&mut ctx, "request").await.is_err(),
            "a malformed nonce is refused"
        );
    }
    let mut ctx = Context::new(req(&format!("vp/request/{id}"), "PUT"), State::new());
    let (status, _) = respond_body(f.b.handle_endpoint(&mut ctx, "request").await.unwrap());
    assert_eq!(status, 405, "unsupported request methods are refused");
    let mut ctx = Context::new(req(&format!("vp/request/{id}"), "GET"), State::new());
    let (status, _) = respond_body(f.b.handle_endpoint(&mut ctx, "request").await.unwrap());
    assert_eq!(status, 200, "GET remains available alongside POST");
    assert_eq!(post(&f, &id, &wallet(&f, &jar)).await.0, 200);
}

#[tokio::test]
async fn without_freshness_data_the_receipt_is_capped_at_the_default_lifetime() {
    let f = fx();
    f.pdp.go_trust_today.store(true, Ordering::SeqCst);
    let (s, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    assert_eq!(post(&f, &id, &wallet(&f, &jar)).await.0, 200);
    complete(&f, &s).await.unwrap();
    assert_eq!(f.pdp.calls.load(Ordering::SeqCst), 1);
    // PDP down: the receipt (5 minutes, not the tenant's 60) still covers a login inside its life...
    f.pdp.down.store(true, Ordering::SeqCst);
    f.clock.store(T0 + 100, Ordering::SeqCst);
    let (s, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    assert_eq!(post(&f, &id, &wallet(&f, &jar)).await.0, 200);
    complete(&f, &s).await.unwrap();
    // ...and no longer once it has lapsed, although the tenant ceiling is an hour.
    f.clock.store(T0 + 301, Ordering::SeqCst);
    let (_s, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    assert_eq!(post(&f, &id, &wallet(&f, &jar)).await.0, 503);
}

#[tokio::test]
async fn a_permit_over_timestampless_trust_data_still_completes_the_flow() {
    // go-trust's always-trusted registry reports trust_data without any
    // timestamps. That is trust data with no freshness bound, so the permit
    // must parse, the receipt must record the absent instants as null, and
    // the receipt lives the tenant ceiling — unlike the no-trust_data case
    // above, which the conservative default lifetime caps.
    let f = fx();
    f.pdp.go_trust_always_trusted.store(true, Ordering::SeqCst);
    let (s, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    assert_eq!(post(&f, &id, &wallet(&f, &jar)).await.0, 200);
    assert!(matches!(
        complete(&f, &s).await.unwrap(),
        BackendAction::AuthResponse(_)
    ));
    // The receipt (tenant ceiling 3600, not the 300 default) covers a second
    // login while the PDP is down.
    f.pdp.down.store(true, Ordering::SeqCst);
    f.clock.store(T0 + 400, Ordering::SeqCst);
    let (s, id) = start(&f).await;
    let jar = fetch_jar(&f, &id).await;
    assert_eq!(post(&f, &id, &wallet(&f, &jar)).await.0, 200);
    assert!(matches!(
        complete(&f, &s).await.unwrap(),
        BackendAction::AuthResponse(_)
    ));
    assert_eq!(
        f.pdp.calls.load(Ordering::SeqCst),
        1,
        "the second login rides the receipt, not the (down) PDP"
    );
}

/// Against a real go-trust. Skipped unless GT_URL (evaluation endpoint) and GT_REQUEST_DIR are set:
///   GT_URL=http://127.0.0.1:6411/evaluation GT_REQUEST_DIR=<dir with request.json, request_other.json> \
///   cargo test --features http -- --ignored live_go_trust
#[cfg(feature = "http")]
#[tokio::test]
#[ignore]
async fn live_go_trust() {
    let (Ok(url), Ok(dir)) = (std::env::var("GT_URL"), std::env::var("GT_REQUEST_DIR")) else {
        return;
    };
    let pdp = Arc::new(HttpPdp::new(&url, None, std::time::Duration::from_secs(5)).unwrap());
    let gate = TrustGate::new(
        pdp,
        p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap(),
        "k",
        "i",
        "a",
        &url,
        3600,
    );
    let read = |n: &str| {
        serde_json::from_str::<Value>(&std::fs::read_to_string(format!("{dir}/{n}")).unwrap())
            .unwrap()
    };
    assert!(
        gate.permits(&read("request.json"), T0).await.unwrap(),
        "pinned issuer is trusted"
    );
    assert!(
        !gate.permits(&read("request_other.json"), T0).await.unwrap(),
        "other role is denied"
    );
}

#[cfg(feature = "http")]
#[test]
fn http_pdp_endpoint_validation() {
    let t = std::time::Duration::from_secs(1);
    assert!(HttpPdp::new("https://pdp.example/evaluation", None, t).is_ok());
    assert!(HttpPdp::new("http://127.0.0.1:6001/evaluation", None, t).is_ok());
    assert!(HttpPdp::new_allow_http("http://go-trust-allow:6001/evaluation", None, t).is_ok());
    assert!(
        HttpPdp::new("http://pdp.example/evaluation", None, t).is_err(),
        "plain http to a remote host"
    );
    assert!(
        HttpPdp::new("http://127.0.0.1.evil.example/evaluation", None, t).is_err(),
        "lookalike host"
    );
    assert!(HttpPdp::new("ftp://pdp.example/", None, t).is_err());
    assert!(HttpPdp::new("not a url", None, t).is_err());
}

/// One-shot HTTP server: answers the first request with `raw`, returns (url, captured request text).
#[cfg(feature = "http")]
async fn one_shot(raw: &'static str) -> (String, tokio::task::JoinHandle<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/evaluation", l.local_addr().unwrap());
    let h = tokio::spawn(async move {
        let (mut sock, _) = l.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let n = sock.read(&mut buf).await.unwrap();
        sock.write_all(raw.as_bytes()).await.unwrap();
        let _ = sock.shutdown().await;
        String::from_utf8_lossy(&buf[..n]).into_owned()
    });
    (url, h)
}

/// Sends `raw` (nothing at all when it is empty) and then leaves the
/// connection open, so a client that collects the whole body instead of
/// enforcing the limit early — or that has no request deadline — will fail.
#[cfg(feature = "http")]
async fn stalled_response(raw: &'static str) -> (String, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/evaluation", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = vec![0u8; 8192];
        let _ = socket.read(&mut request).await.unwrap();
        socket.write_all(raw.as_bytes()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    });
    (url, handle)
}

/// Local HTTPS response server for the status-list transport itself.
#[cfg(feature = "http")]
async fn https_response(raw: &'static str, stall: bool) -> (String, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::rustls::pki_types::PrivateKeyDer;

    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(signing_key.serialize_der().into()),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "https://localhost:{}/status.jwt",
        listener.local_addr().unwrap().port()
    );
    let handle = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = acceptor.accept(socket).await.unwrap();
        let mut request = vec![0u8; 8192];
        let _ = socket.read(&mut request).await.unwrap();
        socket.write_all(raw.as_bytes()).await.unwrap();
        if stall {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        } else {
            let _ = socket.shutdown().await;
        }
    });
    (url, handle)
}

#[cfg(feature = "http")]
#[tokio::test]
async fn http_pdp_status_body_redirect_and_bearer() {
    let t = std::time::Duration::from_secs(2);
    let ok = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 17\r\nconnection: close\r\n\r\n{\"decision\":true}";
    let (url, h) = one_shot(ok).await;
    let v = HttpPdp::new(&url, Some("tok".into()), t)
        .unwrap()
        .evaluate(&json!({"a": 1}))
        .await
        .unwrap();
    assert_eq!(v["decision"], true);
    let seen = h.await.unwrap().to_lowercase();
    assert!(seen.starts_with("post /evaluation"), "{seen}");
    assert!(seen.contains("authorization: bearer tok"), "{seen}");
    assert!(seen.contains("content-type: application/json"));

    let (url, _h) = one_shot(
        "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        HttpPdp::new(&url, None, t)
            .unwrap()
            .evaluate(&json!({}))
            .await
            .unwrap_err(),
        "pdp status 500"
    );

    let (url, _h) = one_shot("HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:1/evil\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
    assert_eq!(
        HttpPdp::new(&url, None, t)
            .unwrap()
            .evaluate(&json!({}))
            .await
            .unwrap_err(),
        "pdp status 302",
        "redirects are not followed"
    );

    let (url, _h) =
        one_shot("HTTP/1.1 200 OK\r\ncontent-length: 8\r\nconnection: close\r\n\r\nnot json").await;
    assert!(HttpPdp::new(&url, None, t)
        .unwrap()
        .evaluate(&json!({}))
        .await
        .unwrap_err()
        .contains("not json"));

    // nothing listening: an error, never a decision
    assert!(HttpPdp::new("http://127.0.0.1:1/evaluation", None, t)
        .unwrap()
        .evaluate(&json!({}))
        .await
        .unwrap_err()
        .contains("unreachable"));
}

#[cfg(feature = "http")]
#[tokio::test]
async fn http_pdp_refuses_oversized_responses() {
    let body = format!("{{\"decision\":true}}{}", " ".repeat(1_100_000)); // valid JSON, so only the limit can reject it
    let raw: &'static str = Box::leak(
        format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_boxed_str(),
    );
    let (url, _h) = one_shot(raw).await;
    let e = HttpPdp::new(&url, None, std::time::Duration::from_secs(5))
        .unwrap()
        .evaluate(&json!({}))
        .await
        .unwrap_err();
    assert_eq!(e, "pdp response too large");
}

#[cfg(feature = "http")]
#[tokio::test]
async fn http_pdp_accepts_a_body_at_the_exact_limit() {
    let mut body = json!({"decision": true}).to_string();
    body.extend(std::iter::repeat_n(' ', (1 << 20) - body.len()));
    let raw: &'static str = Box::leak(
        format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_boxed_str(),
    );
    let (url, _handle) = one_shot(raw).await;
    let answer = HttpPdp::new(&url, None, std::time::Duration::from_secs(2))
        .unwrap()
        .evaluate(&json!({}))
        .await
        .unwrap();
    assert_eq!(answer["decision"], true);
}

#[cfg(feature = "http")]
#[tokio::test]
async fn http_pdp_enforces_limits_before_end_of_body() {
    let declared: &'static str = Box::leak(
        format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            (1 << 20) + 1
        )
        .into_boxed_str(),
    );
    let (url, _handle) = stalled_response(declared).await;
    let error = HttpPdp::new(&url, None, std::time::Duration::from_millis(100))
        .unwrap()
        .evaluate(&json!({}))
        .await
        .unwrap_err();
    assert_eq!(error, "pdp response too large");

    let oversized_chunk = "x".repeat((1 << 20) + 1);
    let streamed: &'static str = Box::leak(
        format!(
            "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n{:x}\r\n{}\r\n",
            oversized_chunk.len(),
            oversized_chunk
        )
        .into_boxed_str(),
    );
    let (url, _handle) = stalled_response(streamed).await;
    let error = HttpPdp::new(&url, None, std::time::Duration::from_millis(100))
        .unwrap()
        .evaluate(&json!({}))
        .await
        .unwrap_err();
    assert_eq!(error, "pdp response too large");
}

#[cfg(feature = "http")]
#[tokio::test]
async fn a_never_responding_pdp_fails_within_its_request_deadline() {
    let (url, _handle) = stalled_response("").await;
    let pdp = HttpPdp::new(&url, None, std::time::Duration::from_millis(150)).unwrap();
    let error = tokio::time::timeout(std::time::Duration::from_secs(3), pdp.evaluate(&json!({})))
        .await
        .expect("the request deadline must bound a stalled PDP")
        .unwrap_err();
    assert!(error.starts_with("pdp unreachable"), "{error}");
}

#[cfg(feature = "http")]
#[tokio::test]
async fn a_never_responding_status_endpoint_fails_within_its_request_deadline() {
    let (url, _handle) = https_response("", true).await;
    let client = ReqwestStatusListClient::new_allow_invalid_certificates_for_testing(
        std::time::Duration::from_millis(150),
    )
    .unwrap();
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(3), client.fetch(&url))
        .await
        .expect("the request deadline must bound a stalled status endpoint");
    assert!(outcome.is_err(), "{:?}", outcome.ok());
}

#[cfg(feature = "http")]
#[tokio::test]
async fn status_list_rejects_userinfo_before_dialing() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let client = ReqwestStatusListClient::new_allow_invalid_certificates_for_testing(
        std::time::Duration::from_secs(2),
    )
    .unwrap();
    for userinfo in ["user", "user:pass", ":pass"] {
        let uri = format!("https://{userinfo}@127.0.0.1:{port}/status.jwt");
        let error = client.fetch(&uri).await.unwrap_err();
        assert_eq!(error, "status_list_uri_not_allowed", "{uri}");
    }
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
            .await
            .is_err(),
        "credential-bearing status URLs must not reach the network"
    );
}

#[cfg(feature = "http")]
#[tokio::test]
async fn status_list_enforces_body_limits_over_https() {
    let exact = "x".repeat(64 * 1024);
    let raw: &'static str = Box::leak(
        format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{exact}",
            exact.len()
        )
        .into_boxed_str(),
    );
    let (url, _handle) = https_response(raw, false).await;
    let body = ReqwestStatusListClient::new_allow_invalid_certificates_for_testing(
        std::time::Duration::from_secs(2),
    )
    .unwrap()
    .fetch(&url)
    .await
    .unwrap();
    assert_eq!(body.len(), 64 * 1024);

    let declared: &'static str = Box::leak(
        format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            (64 * 1024) + 1
        )
        .into_boxed_str(),
    );
    let (url, _handle) = https_response(declared, true).await;
    let error = ReqwestStatusListClient::new_allow_invalid_certificates_for_testing(
        std::time::Duration::from_secs(2),
    )
    .unwrap()
    .fetch(&url)
    .await
    .unwrap_err();
    assert_eq!(error, "status_list_response_too_large");

    let oversized_chunk = "x".repeat((64 * 1024) + 1);
    let streamed: &'static str = Box::leak(
        format!(
            "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n{:x}\r\n{}\r\n",
            oversized_chunk.len(), oversized_chunk
        )
        .into_boxed_str(),
    );
    let (url, _handle) = https_response(streamed, true).await;
    let error = ReqwestStatusListClient::new_allow_invalid_certificates_for_testing(
        std::time::Duration::from_secs(2),
    )
    .unwrap()
    .fetch(&url)
    .await
    .unwrap_err();
    assert_eq!(error, "status_list_response_too_large");
}

#[cfg(feature = "http")]
#[tokio::test]
async fn status_list_rejects_non_public_addresses_before_dialing() {
    let client = ReqwestStatusListClient::new(std::time::Duration::from_secs(2)).unwrap();
    for uri in [
        "https://127.0.0.1/status.jwt",
        "https://10.0.0.1/status.jwt",
        "https://172.16.0.1/status.jwt",
        "https://192.168.0.1/status.jwt",
        "https://169.254.0.1/status.jwt",
        "https://100.64.0.1/status.jwt",
        "https://192.0.2.1/status.jwt",
        "https://192.88.99.1/status.jwt",
        "https://224.0.0.1/status.jwt",
        "https://[ff02::1]/status.jwt",
        "https://[::ffff:224.0.0.1]/status.jwt",
        "https://[::1]/status.jwt",
        "https://[fc00::1]/status.jwt",
        "https://[fe80::1]/status.jwt",
        "https://[64:ff9b:1::1]/status.jwt",
        "https://[64:ff9b::a00:1]/status.jwt",
        "https://[64:ff9b::a9fe:a9fe]/status.jwt",
        "https://[fec0::1]/status.jwt",
        "https://[5f00::1]/status.jwt",
        "https://[2001:db8::1]/status.jwt",
        "https://[3fff::1]/status.jwt",
        "https://[100:0:0:1::1]/status.jwt",
        "https://[2002::1]/status.jwt",
        "https://[::ffff:127.0.0.1]/status.jwt",
        "https://[::ffff:10.0.0.1]/status.jwt",
    ] {
        let error = client.fetch(uri).await.unwrap_err();
        assert_eq!(error, "status_list_no_public_address", "{uri}");
    }

    // IANA globally reachable exceptions are not rejected by the broad parent blocks.
    let global_client = ReqwestStatusListClient::new(std::time::Duration::from_millis(1)).unwrap();
    for uri in [
        "https://192.0.0.9/status.jwt",
        "https://192.0.0.10/status.jwt",
        "https://[64:ff9b::808:808]/status.jwt",
        "https://[2001:1::1]/status.jwt",
        "https://[2001:1::3]/status.jwt",
        "https://[2001:3::1]/status.jwt",
        "https://[2001:4:112::1]/status.jwt",
        "https://[2001:20::1]/status.jwt",
        "https://[2001:30::1]/status.jwt",
    ] {
        let error = global_client.fetch(uri).await.unwrap_err();
        assert_ne!(error, "status_list_no_public_address", "{uri}");
    }

    // A hostname is checked at resolution time, not merely by its spelling.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let uri = format!(
        "https://localhost:{}/status.jwt",
        listener.local_addr().unwrap().port()
    );
    let error = client.fetch(&uri).await.unwrap_err();
    assert!(
        error.contains("status_list_no_public_address"),
        "unexpected resolution error: {error}"
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
            .await
            .is_err(),
        "the resolver must not dial a private address returned for localhost"
    );
}

#[cfg(feature = "http")]
#[tokio::test]
async fn local_conformance_client_dials_private_literal_addresses() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let uri = format!(
        "https://127.0.0.1:{}/status.jwt",
        listener.local_addr().unwrap().port()
    );
    let client = ReqwestStatusListClient::new_allow_invalid_certificates_for_testing(
        std::time::Duration::from_secs(2),
    )
    .unwrap();
    let request = tokio::spawn(async move { client.fetch(&uri).await });

    let (socket, _) = tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept())
        .await
        .expect("the local-conformance client must reach its private fixture")
        .unwrap();
    drop(socket);
    let error = request.await.unwrap().unwrap_err();
    assert_ne!(error, "status_list_no_public_address");
}
