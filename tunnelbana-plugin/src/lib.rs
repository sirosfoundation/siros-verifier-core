//! Spike 4: an OpenID4VP verifier as a tunnelbana `Backend`.
//!
//! The verifier core (`siros_verifier_core`) stays protocol-neutral. This crate is the gateway facade: it turns a
//! tunnelbana authentication request into an OpenID4VP request, serves the signed request object to the
//! wallet, accepts the wallet's `direct_post.jwt` response, asks go-trust (through the receipt cache) whether
//! each issuer is trusted, and hands the result back to the proxy as `InternalData`.
//!
//! Wallet traffic arrives out of band (the wallet POSTs to the proxy, not the browser), so flow results live in
//! a server-side [`FlowStore`]. The browser only holds an opaque flow id in the sealed state cookie.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use siros_verifier_core::oid4vp::{self, RequestConfig};
use siros_verifier_core::receipt::{
    self, Cache, IssuePolicy, Lookup, PdpAnswer, TrustData, Verifier,
};
use siros_verifier_core::sdjwt::X5cLeaf;
use siros_verifier_core::session_seal::SessionSealer;
use tunnelbana_core::context::Context;
use tunnelbana_core::internal::{AuthenticationInformation, InternalData};
use tunnelbana_core::plugin::{Backend, BackendAction, BuildContext, Registry, Route};

pub mod ts11;
pub mod ui;
use tunnelbana_core::{Error, Response, Result};

pub const NS: &str = "VP_BACKEND";
pub const FLOW_KEY: &str = "flow_id";

// ---- configuration -------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VpBackendConfig {
    /// DCQL query sent to the wallet.
    pub dcql: Value,
    /// Internal attribute name -> JSON pointer into the verified claims (for example `/family_name`).
    pub attribute_map: BTreeMap<String, String>,
    /// Pointer of the claim used as `subject_id`.
    pub subject_pointer: String,
    /// go-trust `action.name` for issuers of this backend.
    pub role: String,
    /// go-trust action for mdoc IACA evaluation (defaults to `mdoc-issuer`).
    #[serde(default = "default_mdoc_role")]
    pub mdoc_role: String,
    #[serde(default = "default_ttl")]
    pub request_ttl_secs: i64,
    /// Reported as `auth_class_ref`.
    #[serde(default)]
    pub auth_class_ref: Option<String>,
}

fn default_mdoc_role() -> String {
    "mdoc-issuer".into()
}

fn default_ttl() -> i64 {
    300
}

// ---- seams ---------------------------------------------------------------------------------

/// The one outbound call: an AuthZEN evaluation against the tenant's go-trust.
/// (tunnelbana's `HttpClient` has only `get` and `post_form`, so a JSON POST needs this seam or an addition upstream.)
#[async_trait]
pub trait PdpClient: Send + Sync {
    async fn evaluate(&self, request: &Value) -> std::result::Result<Value, String>;
}

/// Used when no PDP is configured: every evaluation fails, so every presentation is rejected.
pub struct NoPdp;

#[async_trait]
impl PdpClient for NoPdp {
    async fn evaluate(&self, _request: &Value) -> std::result::Result<Value, String> {
        Err("pdp_not_configured".into())
    }
}

/// A real AuthZEN client over HTTP(S): POST `{endpoint}` with the evaluation request. The endpoint is tenant
/// configuration and is never derived from wallet or credential input.
#[cfg(feature = "http")]
pub struct HttpPdp {
    client: reqwest::Client,
    endpoint: String,
    bearer: Option<String>,
}

#[cfg(feature = "http")]
impl HttpPdp {
    /// `endpoint` is the full evaluation URL, for example `https://pdp.example/evaluation`.
    /// Plain http is accepted only for loopback, so a production config cannot downgrade the PDP link.
    pub fn new(
        endpoint: &str,
        bearer: Option<String>,
        timeout: std::time::Duration,
    ) -> std::result::Result<Self, String> {
        Self::build(endpoint, bearer, timeout, false)
    }

    /// Explicit escape hatch for a trusted local development network. Do not use this for a
    /// production PDP connection; production configurations must use HTTPS or loopback.
    pub fn new_allow_http(
        endpoint: &str,
        bearer: Option<String>,
        timeout: std::time::Duration,
    ) -> std::result::Result<Self, String> {
        Self::build(endpoint, bearer, timeout, true)
    }

    fn build(
        endpoint: &str,
        bearer: Option<String>,
        timeout: std::time::Duration,
        allow_http: bool,
    ) -> std::result::Result<Self, String> {
        let url = reqwest::Url::parse(endpoint).map_err(|e| format!("pdp endpoint: {e}"))?;
        let loopback = matches!(
            url.host_str(),
            Some("127.0.0.1") | Some("localhost") | Some("[::1]")
        );
        if url.scheme() != "https" && !(url.scheme() == "http" && (loopback || allow_http)) {
            return Err("pdp endpoint must be https (http only for loopback)".into());
        }
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            client,
            endpoint: endpoint.to_owned(),
            bearer,
        })
    }
}

#[cfg(feature = "http")]
#[async_trait]
impl PdpClient for HttpPdp {
    async fn evaluate(&self, request: &Value) -> std::result::Result<Value, String> {
        let mut rb = self.client.post(&self.endpoint).json(request);
        if let Some(b) = &self.bearer {
            rb = rb.bearer_auth(b);
        }
        let resp = rb
            .send()
            .await
            .map_err(|e| format!("pdp unreachable: {}", e.without_url()))?;
        if !resp.status().is_success() {
            return Err(format!("pdp status {}", resp.status().as_u16()));
        }
        let body = resp.bytes().await.map_err(|e| e.to_string())?;
        if body.len() > 1 << 20 {
            return Err("pdp response too large".into());
        }
        siros_verifier_core::json_strict::from_slice(&body)
            .map_err(|_| "pdp response is not json".into())
    }
}

pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    })
}

enum Outcome {
    Pending,
    Done(InternalData),
    Failed(String),
}

struct Flow {
    jar: String,
    /// The response-decryption key is stored only inside this sealed session.
    sealed_session: String,
    expires_at: i64,
    requester: Option<String>,
    attribute_map: BTreeMap<String, String>,
    subject_pointer: String,
    outcome: Outcome,
    /// Set when a wallet response has been accepted for processing; a second response is a replay.
    responded: bool,
}

fn is_expired(flow: &Flow, now: i64) -> bool {
    matches!(flow.outcome, Outcome::Pending) && now >= flow.expires_at
}

/// Server-side flow state, keyed by an unguessable id. In-process only: a deployment with more than one
/// instance needs a shared implementation (tunnelbana's own caches are process-local too).
#[derive(Default)]
pub struct FlowStore {
    flows: Mutex<HashMap<String, Flow>>,
}

// ---- trust gate ----------------------------------------------------------------------------

/// go-trust behind the receipt cache: a fresh receipt answers without the network, a stale one is refreshed when
/// the PDP is reachable and used otherwise, a miss needs the PDP, and any failure denies.
pub struct TrustGate {
    pdp: Arc<dyn PdpClient>,
    key: p256::ecdsa::SigningKey,
    verifier: Verifier,
    kid: String,
    iss: String,
    aud: String,
    pdp_id: String,
    max_ttl: i64,
    /// Lifetime cap when the PDP reports no `trust_data` (today's go-trust): nothing bounds the receipt except this.
    no_freshness_ttl: i64,
    cache: Mutex<Cache>,
}

impl TrustGate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pdp: Arc<dyn PdpClient>,
        key: p256::ecdsa::SigningKey,
        kid: &str,
        iss: &str,
        aud: &str,
        pdp_id: &str,
        max_ttl: i64,
    ) -> Self {
        let mut keys = HashMap::new();
        keys.insert(kid.to_owned(), p256::ecdsa::VerifyingKey::from(&key));
        Self {
            pdp,
            key,
            verifier: Verifier {
                keys,
                iss: iss.into(),
                aud: aud.into(),
                skew: 60,
            },
            kid: kid.into(),
            iss: iss.into(),
            aud: aud.into(),
            pdp_id: pdp_id.into(),
            max_ttl,
            no_freshness_ttl: 300,
            cache: Mutex::new(Cache::new(60)),
        }
    }

    pub fn with_no_freshness_ttl(mut self, secs: i64) -> Self {
        self.no_freshness_ttl = secs;
        self
    }

    pub async fn permits(&self, request: &Value, now: i64) -> std::result::Result<bool, String> {
        let looked = self
            .cache
            .lock()
            .expect("cache")
            .get(&self.verifier, request, now)
            .map_err(|e| e.to_string())?;
        let fallback = match looked {
            Lookup::Fresh(r) => return Ok(r.decision),
            Lookup::Stale(r) => Some(r),
            Lookup::Miss => None,
        };
        match self.refresh(request, now).await {
            Ok(decision) => Ok(decision),
            // PDP unreachable or answered badly: a still-valid stale receipt may be used, nothing else.
            Err(_) if fallback.is_some() => Ok(fallback.expect("checked").decision),
            Err(e) => Err(e),
        }
    }

    async fn refresh(&self, request: &Value, now: i64) -> std::result::Result<bool, String> {
        let raw = self.pdp.evaluate(request).await?;
        let answer = parse_authzen_response(&raw)?;
        let pol = IssuePolicy {
            iss: &self.iss,
            aud: &self.aud,
            kid: &self.kid,
            pdp: &self.pdp_id,
            max_ttl: if answer.trust_data.is_empty() {
                self.max_ttl.min(self.no_freshness_ttl)
            } else {
                self.max_ttl
            },
            deny_ttl: 300,
            refresh_num: 1,
            refresh_den: 2,
        };
        let jws =
            receipt::issue(&self.key, &pol, request, &answer, now).map_err(|e| e.to_string())?;
        // Verify what we are about to rely on, the same way every later cache hit will.
        let r = self
            .verifier
            .verify(&jws, request, now)
            .map_err(|e| e.to_string())?;
        self.cache
            .lock()
            .expect("cache")
            .put(request, jws)
            .map_err(|e| e.to_string())?;
        Ok(r.decision)
    }
}

/// AuthZEN response -> [`PdpAnswer`]. `decision` must be a boolean. Everything in `context` is optional, because
/// go-trust today returns neither `context.id` nor `trust_data`: a missing id gets a local one (`local-...`), and
/// missing freshness data is handled by the gate's conservative default lifetime, not by guessing here.
pub fn parse_authzen_response(v: &Value) -> std::result::Result<PdpAnswer, String> {
    let decision = v
        .get("decision")
        .and_then(Value::as_bool)
        .ok_or("pdp_decision_missing")?;
    let ctx = v.get("context");
    let id = match ctx.and_then(|c| c.get("id")) {
        None | Some(Value::Null) => format!("local-{}", new_flow_id()),
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        Some(_) => return Err("pdp_context_id_invalid".into()),
    };
    let mut trust_data = vec![];
    if let Some(a) = ctx
        .and_then(|c| c.get("trust_data"))
        .and_then(Value::as_array)
    {
        for t in a {
            let ts = |k: &str| {
                t.get(k)
                    .and_then(Value::as_str)
                    .map(siros_verifier_core::mdoc::parse_utc)
                    .transpose()
                    .map_err(|e| e.to_string())
            };
            trust_data.push(TrustData {
                registry: t
                    .get("registry")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                as_of: ts("as_of")?.ok_or("trust_data_as_of_missing")?,
                next_update: ts("next_update")?,
            });
        }
    }
    let reasons = ctx
        .and_then(|c| c.get("reason"))
        .map(|r| match r {
            Value::String(s) => vec![s.clone()],
            Value::Object(o) => o.keys().cloned().collect(),
            _ => vec![],
        })
        .unwrap_or_default();
    Ok(PdpAnswer {
        decision,
        id,
        reasons,
        trust_data,
    })
}

// ---- the backend ---------------------------------------------------------------------------

pub struct VpBackend {
    name: String,
    module_base: String,
    cfg: VpBackendConfig,
    store: FlowStore,
    sealer: SessionSealer,
    gate: TrustGate,
    signer: kryptering::SoftwareSigner,
    chain_der: Vec<Vec<u8>>,
    clock: Clock,
}

fn request_profile(
    request: &InternalData,
    defaults: &VpBackendConfig,
) -> Result<(Value, BTreeMap<String, String>, String)> {
    let Some(raw) = request.attr_first(ui::DCQL_ATTRIBUTE) else {
        return Ok((
            defaults.dcql.clone(),
            defaults.attribute_map.clone(),
            defaults.subject_pointer.clone(),
        ));
    };
    if raw.len() > 64 * 1024 {
        return Err(Error::BadRequest("DCQL exceeds 64 KiB".into()));
    }
    let dcql = siros_verifier_core::json_strict::from_slice(raw.as_bytes())
        .map_err(|_| Error::BadRequest("DCQL is not valid strict JSON".into()))?;
    oid4vp::validate_dcql_query(&dcql).map_err(|e| Error::BadRequest(e.to_string()))?;

    let mut attributes = BTreeMap::new();
    let mut subject_pointer = None;
    for credential in dcql["credentials"]
        .as_array()
        .expect("validated credentials")
    {
        for claim in credential
            .get("claims")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let path = claim["path"].as_array().expect("validated claim path");
            let pointer = format!(
                "/{}",
                path.iter()
                    .filter_map(|segment| {
                        segment
                            .as_str()
                            .map(|segment| segment.replace('~', "~0").replace('/', "~1"))
                    })
                    .collect::<Vec<_>>()
                    .join("/")
            );
            if subject_pointer.is_none() {
                subject_pointer = Some(pointer.clone());
            }
            let base = claim
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
                .or_else(|| {
                    path.iter()
                        .rev()
                        .find_map(|segment| segment.as_str().map(str::to_owned))
                })
                .expect("validated non-empty path");
            let mut name = base.clone();
            let mut suffix = 2;
            while attributes.contains_key(&name) {
                name = format!("{base}_{suffix}");
                suffix += 1;
            }
            attributes.insert(name, pointer);
        }
    }
    if attributes.is_empty() {
        return Ok((
            dcql,
            defaults.attribute_map.clone(),
            defaults.subject_pointer.clone(),
        ));
    }
    Ok((dcql, attributes, subject_pointer.expect("a claim path")))
}

impl VpBackend {
    pub fn new(
        name: &str,
        module_base: &str,
        cfg: VpBackendConfig,
        gate: TrustGate,
        signer: kryptering::SoftwareSigner,
        chain_der: Vec<Vec<u8>>,
        clock: Clock,
    ) -> Result<Self> {
        if cfg.request_ttl_secs <= 0 || cfg.request_ttl_secs > 900 {
            return Err(Error::Config("request_ttl_secs must be 1..=900".into()));
        }
        for (k, p) in cfg
            .attribute_map
            .iter()
            .chain([(&"subject".to_string(), &cfg.subject_pointer)])
        {
            if !p.is_empty() && !p.starts_with('/') {
                return Err(Error::Config(format!(
                    "attribute {k}: pointer must start with '/'"
                )));
            }
        }
        Ok(Self {
            name: name.into(),
            module_base: module_base.into(),
            cfg,
            store: FlowStore::default(),
            sealer: SessionSealer::from_master(&random_master(), name)
                .map_err(|e| Error::Internal(format!("session sealer: {}", e.code())))?,
            gate,
            signer,
            chain_der,
            clock,
        })
    }

    /// Override the per-tenant sealing key. Shared-store deployments must construct every
    /// instance from the same high-entropy master secret and tenant name.
    pub fn with_session_sealer(mut self, sealer: SessionSealer) -> Self {
        self.sealer = sealer;
        self
    }

    fn flow_id_from_path(&self, ctx: &Context, prefix: &str) -> Result<String> {
        let want = format!("{}/{}/", self.name, prefix);
        let id = ctx
            .path()
            .strip_prefix(&want)
            .ok_or_else(|| Error::BadRequest("path".into()))?;
        if id.len() < 16
            || id.len() > 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Error::BadRequest("flow id".into()));
        }
        Ok(id.to_owned())
    }

    fn map_attributes(
        &self,
        claims: &serde_json::Map<String, Value>,
        issuer: String,
        attribute_map: &BTreeMap<String, String>,
        subject_pointer: &str,
    ) -> std::result::Result<InternalData, String> {
        let root = Value::Object(claims.clone());
        let scalar = |v: &Value| -> std::result::Result<Vec<String>, String> {
            match v {
                Value::String(s) => Ok(vec![s.clone()]),
                Value::Bool(_) | Value::Number(_) => Ok(vec![v.to_string()]),
                Value::Array(a) => a.iter().map(scalar_one).collect(),
                _ => Err("attribute_not_scalar".into()),
            }
        };
        fn scalar_one(v: &Value) -> std::result::Result<String, String> {
            match v {
                Value::String(s) => Ok(s.clone()),
                Value::Bool(_) | Value::Number(_) => Ok(v.to_string()),
                _ => Err("attribute_not_scalar".into()),
            }
        }
        let mut data = InternalData {
            auth_info: AuthenticationInformation {
                auth_class_ref: self.cfg.auth_class_ref.clone(),
                issuer: Some(issuer),
                ..Default::default()
            },
            ..Default::default()
        };
        // Missing mapped claims are absent attributes, not errors; the DCQL query decides what is required.
        for (internal, ptr) in attribute_map {
            if let Some(v) = root.pointer(ptr) {
                data.attributes.insert(internal.clone(), scalar(v)?);
            }
        }
        let subject = root
            .pointer(subject_pointer)
            .ok_or("subject_claim_missing")?;
        data.subject_id = Some(scalar_one(subject)?);
        Ok(data)
    }

    async fn fail(&self, id: &str, code: &str) {
        if let Some(f) = self.store.flows.lock().expect("flows").get_mut(id) {
            f.outcome = Outcome::Failed(code.to_owned());
        }
    }

    async fn on_wallet_response(&self, ctx: &mut Context) -> Result<Response> {
        let id = self.flow_id_from_path(ctx, "response")?;
        if ctx.request.method != "POST" {
            return Ok(Response::text(405, "method not allowed"));
        }
        let now = (self.clock)();
        // Take what we need and mark the flow answered in one step, so a replay cannot run twice.
        let (sealed_session, requester, attribute_map, subject_pointer) = {
            let mut flows = self.store.flows.lock().expect("flows");
            let Some(f) = flows.get_mut(&id) else {
                return Ok(Response::text(404, "unknown flow"));
            };
            if f.responded {
                return Ok(Response::text(409, "response already received"));
            }
            f.responded = true;
            (
                f.sealed_session.clone(),
                f.requester.clone(),
                f.attribute_map.clone(),
                f.subject_pointer.clone(),
            )
        };
        let session = match self.sealer.unseal(&sealed_session, id.as_bytes()) {
            Ok(s) => s,
            Err(e) => {
                self.fail(&id, e.code()).await;
                return Ok(Response::text(500, "stored session cannot be opened"));
            }
        };
        let Some(jwe) = ctx.request.form.get("response").cloned() else {
            self.fail(&id, "missing_response").await;
            return Ok(Response::text(400, "missing response"));
        };
        let verified = match oid4vp::process_response(&session, &jwe, now, &X5cLeaf) {
            Ok(v) => v,
            Err(e) => {
                self.fail(&id, e.code()).await;
                return Ok(Response::text(400, "invalid response"));
            }
        };
        // Every presented credential's issuer must be trusted; a single denial fails the flow.
        let mut result: Option<InternalData> = None;
        for p in &verified {
            let q = p
                .verified
                .trust_query(&self.cfg.role, &self.cfg.mdoc_role)
                .to_authzen();
            match self.gate.permits(&q, now).await {
                Ok(true) => {}
                Ok(false) => {
                    self.fail(&id, "issuer_not_trusted").await;
                    return Ok(Response::text(403, "issuer not trusted"));
                }
                Err(e) => {
                    tracing_noop(&e);
                    self.fail(&id, "trust_unavailable").await;
                    return Ok(Response::text(503, "trust evaluation unavailable"));
                }
            }
            if result.is_none() {
                let claims = p
                    .verified
                    .claims()
                    .map_err(|e| Error::Internal(format!("claims: {e}")))?;
                match self.map_attributes(
                    &claims,
                    p.verified.issuer_id(),
                    &attribute_map,
                    &subject_pointer,
                ) {
                    Ok(mut d) => {
                        d.requester = requester.clone();
                        result = Some(d);
                    }
                    Err(code) => {
                        self.fail(&id, &code).await;
                        return Ok(Response::text(422, "cannot map attributes"));
                    }
                }
            }
        }
        let Some(data) = result else {
            self.fail(&id, "no_presentation").await;
            return Ok(Response::text(400, "no presentation"));
        };
        if let Some(f) = self.store.flows.lock().expect("flows").get_mut(&id) {
            f.outcome = Outcome::Done(data);
        }
        Response::json(&serde_json::json!({}))
    }

    fn status(&self, ctx: &Context) -> Result<BackendAction> {
        let id = ctx
            .state
            .get_str(NS, FLOW_KEY)
            .ok_or_else(|| Error::Authn("no_flow".into()))?;
        let now = (self.clock)();
        let mut flows = self.store.flows.lock().expect("flows");
        let Some(f) = flows.get_mut(&id) else {
            return Ok(BackendAction::Respond(Response::json(
                &serde_json::json!({"status": "unknown"}),
            )?));
        };
        let status = match &f.outcome {
            _ if is_expired(f, now) => {
                flows.remove(&id);
                "expired"
            }
            Outcome::Pending => "pending",
            Outcome::Failed(_) => "failed",
            Outcome::Done(_) => "done",
        };
        Ok(BackendAction::Respond(Response::json(
            &serde_json::json!({
                "status": status,
                "complete_uri": format!("{}/complete", self.module_base),
            }),
        )?))
    }

    fn complete(&self, ctx: &Context) -> Result<BackendAction> {
        // Only the browser that started the flow can collect the result.
        let id = ctx
            .state
            .get_str(NS, FLOW_KEY)
            .ok_or_else(|| Error::Authn("no_flow".into()))?;
        let now = (self.clock)();
        let mut flows = self.store.flows.lock().expect("flows");
        let Some(f) = flows.get_mut(&id) else {
            return Err(Error::Authn("unknown_flow".into()));
        };
        match &f.outcome {
            _ if is_expired(f, now) => {
                flows.remove(&id);
                Err(Error::Authn("flow_expired".into()))
            }
            Outcome::Pending => Ok(BackendAction::Respond(waiting_page(&self.module_base))),
            Outcome::Failed(code) => {
                let code = code.clone();
                flows.remove(&id);
                Err(Error::Authn(code))
            }
            Outcome::Done(_) => {
                // One-time collection.
                let Some(Flow {
                    outcome: Outcome::Done(data),
                    ..
                }) = flows.remove(&id)
                else {
                    unreachable!()
                };
                Ok(BackendAction::AuthResponse(data))
            }
        }
    }
}

fn tracing_noop(_e: &str) {}

fn pct(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn waiting_page(module_base: &str) -> Response {
    Response::html(format!(
        "<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=\"2;url={}/complete\"><p>Waiting for your wallet…</p>",
        html_escape(module_base)
    ))
}

fn qr_page(module_base: &str, link: &str) -> Result<Response> {
    let code = qrcode::QrCode::new(link.as_bytes())
        .map_err(|e| Error::Internal(format!("QR encoding failed: {e}")))?;
    let svg = code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(320, 320)
        .build();
    let body = format!(
        r#"<h1>Scan with your wallet</h1>
<p>Scan this QR code with the SIROS demo wallet. If the wallet is installed on this device, you can open the request directly.</p>
<div style="display:grid;place-items:center;background:white;padding:16px;border-radius:12px">{svg}</div>
<p><a href="{}">Open your wallet</a></p>
<p>This page checks for completion automatically.</p>
<meta http-equiv="refresh" content="3;url={}/complete">"#,
        ui::html_escape(link),
        ui::html_escape(module_base),
    );
    Ok(Response::html(ui::page("Scan with your wallet", &body)))
}

fn qr_svg(link: &str) -> Result<String> {
    let code = qrcode::QrCode::new(link.as_bytes())
        .map_err(|e| Error::Internal(format!("QR encoding failed: {e}")))?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(320, 320)
        .build())
}

fn qr_response(module_base: &str, link: &str) -> Result<Response> {
    Response::json(&serde_json::json!({
        "authorization_request": link,
        "qr_code": qr_svg(link)?,
        "status_uri": format!("{module_base}/status"),
    }))
}

fn dc_api_response(module_base: &str, response_uri: &str, jar: &str) -> Result<Response> {
    Response::json(&serde_json::json!({
        "request": jar,
        "response_uri": response_uri,
        "status_uri": format!("{module_base}/status"),
        "complete_uri": format!("{module_base}/complete"),
    }))
}

fn random_master() -> [u8; 32] {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("OS randomness");
    key
}

fn new_flow_id() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("OS randomness");
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

#[async_trait]
impl Backend for VpBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn register_endpoints(&self) -> Vec<Route> {
        let id = "[A-Za-z0-9_-]{16,64}";
        vec![
            Route::new(&format!("{}/request/{id}", self.name), "request"),
            Route::new(&format!("{}/response/{id}", self.name), "response"),
            Route::exact(format!("{}/status", self.name), "status"),
            Route::exact(format!("{}/complete", self.name), "complete"),
        ]
    }

    async fn start_auth(&self, ctx: &mut Context, request: InternalData) -> Result<Response> {
        let now = (self.clock)();
        let id = new_flow_id();
        let (dcql_query, attribute_map, subject_pointer) = request_profile(&request, &self.cfg)?;
        let cfg = RequestConfig {
            response_uri: format!("{}/response/{id}", self.module_base),
            dcql_query,
            ttl_secs: self.cfg.request_ttl_secs,
        };
        let dc_api = request.requester.as_deref() == Some(ui::DC_API_REQUESTER);
        let (jar, session) = if dc_api {
            let base = self
                .module_base
                .strip_suffix(&format!("/{}", self.name))
                .unwrap_or(&self.module_base);
            oid4vp::create_dc_api_request(&cfg, &self.signer, "ES256", &self.chain_der, now, base)
        } else {
            oid4vp::create_request(&cfg, &self.signer, "ES256", &self.chain_der, now)
        }
        .map_err(|e| Error::Internal(format!("request: {}", e.code())))?;
        let client_id = session.client_id.clone();
        let expires_at = session.expires_at;
        let sealed_session = self
            .sealer
            .seal(&session, id.as_bytes())
            .map_err(|e| Error::Internal(format!("session seal: {}", e.code())))?;
        self.store.flows.lock().expect("flows").insert(
            id.clone(),
            Flow {
                jar: jar.clone(),
                sealed_session,
                expires_at,
                requester: request.requester.clone(),
                attribute_map,
                subject_pointer,
                outcome: Outcome::Pending,
                responded: false,
            },
        );
        ctx.state.set_str(NS, FLOW_KEY, id.clone());
        let request_uri = format!("{}/request/{id}", self.module_base);
        let scheme = request
            .attr_first(ui::SCHEME_ATTRIBUTE)
            .unwrap_or("openid4vp");
        if !matches!(scheme, "openid4vp" | "haip" | "haip-vp" | "mdoc-openid4vp") {
            return Err(Error::BadRequest("unsupported wallet URI scheme".into()));
        }
        let link = format!(
            "{scheme}://cb?client_id={}&request_uri={}&request_uri_method=get",
            pct(&client_id),
            pct(&request_uri)
        );
        if dc_api {
            dc_api_response(&self.module_base, &cfg.response_uri, &jar)
        } else if request.requester.as_deref() == Some(ui::QR_REQUESTER) {
            qr_response(&self.module_base, &link)
        } else {
            qr_page(&self.module_base, &link)
        }
    }

    async fn handle_endpoint(&self, ctx: &mut Context, route_id: &str) -> Result<BackendAction> {
        match route_id {
            "request" => {
                let id = self.flow_id_from_path(ctx, "request")?;
                let flows = self.store.flows.lock().expect("flows");
                let f = flows
                    .get(&id)
                    .ok_or_else(|| Error::BadRequest("unknown flow".into()))?;
                Ok(BackendAction::Respond(
                    Response::new(200)
                        .with_header("content-type", "application/oauth-authz-req+jwt")
                        .with_header("cache-control", "no-store")
                        .with_body(f.jar.clone().into_bytes()),
                ))
            }
            "response" => Ok(BackendAction::Respond(self.on_wallet_response(ctx).await?)),
            "status" => self.status(ctx),
            "complete" => self.complete(ctx),
            other => Err(Error::NoBoundEndpoint(other.into())),
        }
    }
}

// ---- registry ------------------------------------------------------------------------------

/// Registers the `openid4vp` backend type. Construction from config needs key material and a PDP client, which the
/// registry's plain-function constructor cannot carry, so this registers a constructor that fails with a clear
/// error. Applications build [`VpBackend::new`] directly until tunnelbana's `Registry` accepts closures for backends.
pub fn register(registry: &mut Registry) {
    registry.register_backend("openid4vp", |_bx: &BuildContext| {
        Err(Error::Config("openid4vp backend must be constructed with VpBackend::new (needs keys and a PDP client)".into()))
    });
}

#[cfg(test)]
mod page_tests {
    use super::*;

    #[test]
    fn qr_page_has_a_local_qr_and_wallet_fallback() {
        let response = qr_page(
            "https://verifier.example/vp",
            "openid4vp://cb?client_id=x&request_uri=https%3A%2F%2Fverifier.example%2Fvp%2Frequest%2F1234567890abcdef",
        )
        .unwrap();
        let html = String::from_utf8(response.body).unwrap();
        assert!(html.contains("<svg"));
        assert!(html.contains("openid4vp://cb"));
        assert!(html.contains("/vp/complete"));
    }

    #[test]
    fn launch_responses_carry_everything_the_js_library_needs() {
        let response = dc_api_response(
            "https://verifier.example/vp",
            "https://verifier.example/vp/response/1234567890abcdef",
            "header.payload.signature",
        )
        .unwrap();
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["request"], "header.payload.signature");
        assert_eq!(
            body["response_uri"],
            "https://verifier.example/vp/response/1234567890abcdef"
        );
        assert_eq!(body["status_uri"], "https://verifier.example/vp/status");
        assert_eq!(body["complete_uri"], "https://verifier.example/vp/complete");

        let response = qr_response(
            "https://verifier.example/vp",
            "haip-vp://cb?client_id=x&request_uri=https%3A%2F%2Fverifier.example%2Fvp%2Frequest%2F1234567890abcdef",
        )
        .unwrap();
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body["authorization_request"]
            .as_str()
            .unwrap()
            .starts_with("haip-vp://cb"));
        assert!(body["qr_code"].as_str().unwrap().contains("<svg"));
        assert_eq!(body["status_uri"], "https://verifier.example/vp/status");
    }

    fn test_defaults() -> VpBackendConfig {
        serde_json::from_value(serde_json::json!({
            "dcql": {"credentials": []},
            "attribute_map": {"givenname": "/given_name"},
            "subject_pointer": "/family_name",
            "role": "pid-provider"
        }))
        .unwrap()
    }

    #[test]
    fn custom_dcql_drives_result_mapping_and_subject() {
        let mut request = InternalData::request("ui");
        request.set_attr(
            ui::DCQL_ATTRIBUTE,
            serde_json::to_string(&serde_json::json!({
                "credentials": [{"id": "pid", "format": "dc+sd-jwt", "claims": [
                    {"id": "display_name", "path": ["given_name"]},
                    {"path": ["address", "street_address"]}
                ]}]
            }))
            .unwrap(),
        );
        let (_, attributes, subject) = request_profile(&request, &test_defaults()).unwrap();
        assert_eq!(attributes["display_name"], "/given_name");
        assert_eq!(attributes["street_address"], "/address/street_address");
        assert_eq!(subject, "/given_name");
    }

    #[test]
    fn custom_dcql_rejects_duplicate_json_and_unsupported_queries() {
        let mut request = InternalData::request("ui");
        request.set_attr(ui::DCQL_ATTRIBUTE, r#"{"credentials":[],"credentials":[]}"#);
        assert!(request_profile(&request, &test_defaults()).is_err());
        request.set_attr(ui::DCQL_ATTRIBUTE, r#"{"credentials":[]}"#);
        assert!(request_profile(&request, &test_defaults()).is_err());
        request.set_attr(
            ui::DCQL_ATTRIBUTE,
            r#"{"credentials":[{"id":"pid","format":"mso_mdoc"}]}"#,
        );
        assert!(request_profile(&request, &test_defaults()).is_err());
    }
}
