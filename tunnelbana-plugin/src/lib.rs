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
#[cfg(feature = "http")]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

#[cfg(feature = "http")]
use ipnet::{Ipv4Net, Ipv6Net};

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use siros_verifier_core::oid4vp::{self, RequestConfig};
use siros_verifier_core::receipt::{
    self, Cache, IssuePolicy, Lookup, PdpAnswer, TrustData, Verifier,
};
use siros_verifier_core::sdjwt::{CryptoVerified, X5cLeaf};
use siros_verifier_core::session_seal::SessionSealer;
use siros_verifier_core::trust::TrustQuery;
use siros_verifier_zkp::refusal::ZkpError;
use siros_verifier_zkp::verify::{Channel, Exchange, VerifiedPresentation, ZkpVerifier};
use tunnelbana_core::context::Context;
use tunnelbana_core::internal::{AuthenticationInformation, InternalData, SubjectType};
use tunnelbana_core::plugin::{Backend, BackendAction, BuildContext, Registry, Route};

pub mod flow;
pub mod ts11;
pub mod ui;
pub use flow::{
    ClaimResult, CollectResult, FinishResult, Flow, FlowStore, FlowStoreError, MemoryFlowStore,
    Outcome, StoreResult, TerminalOutcome, FLOW_RETENTION_GRACE_SECS, FLOW_SCHEMA_VERSION,
    FLOW_STORE_WRITE_BOUND_SECS,
};
use tunnelbana_core::{Error, Response, Result};

pub const NS: &str = "VP_BACKEND";
pub const FLOW_KEY: &str = "flow_id";

#[cfg(feature = "http")]
const STATUS_LIST_MAX_BYTES: usize = 64 * 1024;
#[cfg(feature = "http")]
const PDP_MAX_BYTES: usize = 1 << 20;

#[cfg(feature = "http")]
async fn read_response_bounded(
    mut response: reqwest::Response,
    limit: usize,
    refusal: &str,
) -> std::result::Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(refusal.into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        body.len()
            .checked_add(chunk.len())
            .filter(|length| *length <= limit)
            .ok_or_else(|| refusal.to_owned())?;
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(feature = "http")]
#[derive(Clone)]
struct PublicInternetResolver;

// IANA special-purpose registries, last updated 2025-10-09. A matching
// globally reachable exception precedes its non-global parent. Everything not
// listed is ordinary public address space for this egress policy.
#[cfg(feature = "http")]
const fn v4(ip: [u8; 4], prefix: u8, global: bool) -> (Ipv4Net, bool) {
    (
        Ipv4Net::new_assert(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]), prefix),
        global,
    )
}

#[cfg(feature = "http")]
const fn v6(ip: [u16; 8], prefix: u8, global: bool) -> (Ipv6Net, bool) {
    (
        Ipv6Net::new_assert(
            Ipv6Addr::new(ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7]),
            prefix,
        ),
        global,
    )
}

#[cfg(feature = "http")]
const IPV4_SPECIAL: &[(Ipv4Net, bool)] = &[
    v4([192, 0, 0, 9], 32, true),
    v4([192, 0, 0, 10], 32, true),
    v4([0, 0, 0, 0], 8, false),
    v4([10, 0, 0, 0], 8, false),
    v4([100, 64, 0, 0], 10, false),
    v4([127, 0, 0, 0], 8, false),
    v4([169, 254, 0, 0], 16, false),
    v4([172, 16, 0, 0], 12, false),
    v4([192, 0, 0, 0], 24, false),
    v4([192, 0, 2, 0], 24, false),
    v4([192, 88, 99, 0], 24, false),
    v4([192, 168, 0, 0], 16, false),
    v4([198, 18, 0, 0], 15, false),
    v4([198, 51, 100, 0], 24, false),
    v4([203, 0, 113, 0], 24, false),
    v4([224, 0, 0, 0], 4, false),
    v4([240, 0, 0, 0], 4, false),
    v4([255, 255, 255, 255], 32, false),
];

#[cfg(feature = "http")]
const IPV6_SPECIAL: &[(Ipv6Net, bool)] = &[
    v6([0x2001, 1, 0, 0, 0, 0, 0, 1], 128, true),
    v6([0x2001, 1, 0, 0, 0, 0, 0, 2], 128, true),
    v6([0x2001, 1, 0, 0, 0, 0, 0, 3], 128, true),
    v6([0x2001, 3, 0, 0, 0, 0, 0, 0], 32, true),
    v6([0x2001, 4, 0x0112, 0, 0, 0, 0, 0], 48, true),
    v6([0x2001, 0x20, 0, 0, 0, 0, 0, 0], 28, true),
    v6([0x2001, 0x30, 0, 0, 0, 0, 0, 0], 28, true),
    v6([0, 0, 0, 0, 0, 0, 0, 1], 128, false),
    v6([0, 0, 0, 0, 0, 0, 0, 0], 128, false),
    v6([0, 0, 0, 0, 0, 0xffff, 0, 0], 96, false),
    v6([0, 0, 0, 0, 0, 0, 0, 0], 96, false),
    v6([0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48, false),
    v6([0x100, 0, 0, 0, 0, 0, 0, 0], 64, false),
    v6([0x100, 0, 0, 1, 0, 0, 0, 0], 64, false),
    v6([0x2001, 0, 0, 0, 0, 0, 0, 0], 23, false),
    v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32, false),
    v6([0x2002, 0, 0, 0, 0, 0, 0, 0], 16, false),
    v6([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20, false),
    v6([0x5f00, 0, 0, 0, 0, 0, 0, 0], 16, false),
    v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7, false),
    v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10, false),
    v6([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10, false),
    v6([0xff00, 0, 0, 0, 0, 0, 0, 0], 8, false),
];

// RFC 6052 §2.1: the Well-Known Prefix carries the destination IPv4
// address in the final 32 bits, so it needs the same egress policy.
#[cfg(feature = "http")]
const NAT64_WKP: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 96);

#[cfg(feature = "http")]
fn is_public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => IPV4_SPECIAL
            .iter()
            .find(|(network, _)| network.contains(&ip))
            .is_none_or(|(_, globally_reachable)| *globally_reachable),
        std::net::IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_public_ip(std::net::IpAddr::V4(mapped));
            }
            if NAT64_WKP.contains(&ip) {
                let octets = ip.octets();
                return is_public_ip(std::net::IpAddr::V4(Ipv4Addr::new(
                    octets[12], octets[13], octets[14], octets[15],
                )));
            }
            IPV6_SPECIAL
                .iter()
                .find(|(network, _)| network.contains(&ip))
                .is_none_or(|(_, globally_reachable)| *globally_reachable)
        }
    }
}

#[cfg(feature = "http")]
impl reqwest::dns::Resolve for PublicInternetResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let resolved = tokio::task::spawn_blocking(move || {
                use std::net::ToSocketAddrs;
                (host.as_str(), 0).to_socket_addrs()
            })
            .await
            .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { Box::new(error) })?
            .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { Box::new(error) })?;
            let addresses: Vec<std::net::SocketAddr> = resolved
                .filter(|address| is_public_ip(address.ip()))
                .collect();
            if addresses.is_empty() {
                return Err("status_list_no_public_address".into());
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(feature = "http")]
fn status_request_error(error: reqwest::Error) -> String {
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        if cause.to_string().contains("status_list_no_public_address") {
            return "status_list_no_public_address".into();
        }
        source = cause.source();
    }
    error.to_string()
}

// ---- configuration -------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VpBackendConfig {
    /// Fallback DCQL query sent to the wallet, validated during construction.
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
    /// Method advertised for request object retrieval. GET remains the default;
    /// POST echoes the wallet's `wallet_nonce` in a re-signed request object.
    #[serde(default = "default_request_uri_method")]
    pub request_uri_method: String,
    /// Reported as `auth_class_ref`.
    #[serde(default)]
    pub auth_class_ref: Option<String>,
    /// Seconds a runner holds the wallet-response processing lease. When the
    /// lease expires without a terminal result (for example after a runner
    /// crash), a retrying wallet re-claims the slot and re-drives
    /// verification. Replay protection and one-time collection are unchanged.
    #[serde(default = "default_processing_lease")]
    pub processing_lease_secs: i64,
    /// Overall seconds to spend processing one claimed wallet response;
    /// must be strictly shorter than the lease. On expiry the flow fails
    /// closed with `processing_deadline` while the claim is still held, so
    /// a stalled PDP or status-list endpoint cannot hang a presentation.
    #[serde(default = "default_processing_deadline")]
    pub processing_deadline_secs: i64,
    /// Adapter-owned cap on concurrently running response verifications.
    /// A caller whose budget expires while queued is aborted before its
    /// verification job starts; a detached job holds its permit until it
    /// finishes, so sustained overload cannot accumulate unbounded work.
    #[serde(default = "default_max_concurrent_verifications")]
    pub max_concurrent_verifications: usize,
}

fn default_mdoc_role() -> String {
    "mdoc-issuer".into()
}

fn default_request_uri_method() -> String {
    "get".into()
}

fn default_ttl() -> i64 {
    300
}

fn default_processing_lease() -> i64 {
    60
}

fn default_processing_deadline() -> i64 {
    45
}

fn default_max_concurrent_verifications() -> usize {
    16
}

/// The terminal decision for one claimed wallet response: the outcome to
/// persist plus the wallet-facing response. Built by the cancellable
/// verification phase and finalized by the caller in a single bounded write,
/// so a cancelled verification can never replace or duplicate a terminal
/// outcome.
struct Decision {
    outcome: TerminalOutcome,
    response: Response,
}

impl Decision {
    fn failed(code: &str, response: Response) -> Result<Self> {
        let status = response.status;
        let description = String::from_utf8_lossy(&response.body).into_owned();
        let mut response = Response::json(&serde_json::json!({
            "error": code,
            "error_description": description,
        }))?;
        response.status = status;
        Ok(Self {
            outcome: TerminalOutcome::Failed(code.to_owned()),
            response,
        })
    }

    fn done(result: String) -> Result<Self> {
        Ok(Self {
            outcome: TerminalOutcome::Done(result),
            response: Response::json(&serde_json::json!({}))?,
        })
    }
}

/// Configuration of a `zkp_req` (nym_auth) backend.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkpBackendConfig {
    /// The legacy single `zkp_req` credential query. New configurations may
    /// instead use `profiles` for multiple independently validated presets.
    #[serde(default)]
    pub query: Option<Value>,
    #[serde(default)]
    pub profiles: Vec<ZkpProfileConfig>,
    pub system_id_values: Vec<String>,
    #[serde(default)]
    pub proof_system_values: Vec<String>,
    /// go-trust `action.name` for attestation issuers.
    pub role: String,
    #[serde(default = "default_ttl")]
    pub request_ttl_secs: i64,
    /// Pseudonym handle for the legacy single-query form.
    #[serde(default)]
    pub subject_handle: String,
    /// Internal attribute name -> result handle.
    #[serde(default)]
    pub attribute_map: BTreeMap<String, String>,
    #[serde(default)]
    pub auth_class_ref: Option<String>,
    /// Rulebook verifier identity (`x509_san_dns:` or `semantic_id:`), which
    /// is deliberately distinct from the OpenID4VP x509_hash client ID.
    pub verifier_id: String,
}

/// One independently validated `zkp_req` preset.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkpProfileConfig {
    pub query: Value,
    /// Pseudonym handle that becomes `subject_id`.
    pub subject_handle: String,
    /// Internal attribute name -> result handle.
    #[serde(default)]
    pub attribute_map: BTreeMap<String, String>,
}

// ---- seams ---------------------------------------------------------------------------------

/// The one outbound call: an AuthZEN evaluation against the tenant's go-trust.
/// (tunnelbana's `HttpClient` has only `get` and `post_form`, so a JSON POST needs this seam or an addition upstream.)
#[async_trait]
pub trait PdpClient: Send + Sync {
    async fn evaluate(&self, request: &Value) -> std::result::Result<Value, String>;
}

/// Fetches a JWT status list without doing trust evaluation. The caller still
/// verifies the token and asks go-trust about its signer.
#[async_trait]
pub trait StatusListClient: Send + Sync {
    async fn fetch(&self, uri: &str) -> std::result::Result<String, String>;
}

/// Bounded HTTPS status-list transport for the gateway.
#[cfg(feature = "http")]
pub struct ReqwestStatusListClient {
    client: reqwest::Client,
    public_addresses_only: bool,
}

#[cfg(feature = "http")]
impl ReqwestStatusListClient {
    pub fn new(timeout: std::time::Duration) -> std::result::Result<Self, String> {
        Self::build(timeout, false)
    }

    /// Local conformance testing only. Disables certificate validation and the
    /// public-address egress restriction. Never use this for a real deployment.
    pub fn new_allow_invalid_certificates_for_testing(
        timeout: std::time::Duration,
    ) -> std::result::Result<Self, String> {
        Self::build(timeout, true)
    }

    fn build(
        timeout: std::time::Duration,
        allow_invalid_certificates: bool,
    ) -> std::result::Result<Self, String> {
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .no_proxy()
            .danger_accept_invalid_certs(allow_invalid_certificates);
        if !allow_invalid_certificates {
            builder = builder.dns_resolver(Arc::new(PublicInternetResolver));
        }
        let client = builder.build().map_err(|e| e.to_string())?;
        Ok(Self {
            client,
            public_addresses_only: !allow_invalid_certificates,
        })
    }
}

#[cfg(feature = "http")]
#[async_trait]
impl StatusListClient for ReqwestStatusListClient {
    async fn fetch(&self, uri: &str) -> std::result::Result<String, String> {
        let url = reqwest::Url::parse(uri).map_err(|_| "status_list_invalid_uri")?;
        if url.scheme() != "https" {
            return Err("status_list_uri_not_https".into());
        }
        if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
            return Err("status_list_uri_not_allowed".into());
        }
        if self.public_addresses_only {
            if let Some(host) = url.host_str() {
                let host = host.trim_start_matches('[').trim_end_matches(']');
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    if !is_public_ip(ip) {
                        return Err("status_list_no_public_address".into());
                    }
                }
            }
        }
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(status_request_error)?;
        if !response.status().is_success() {
            return Err(format!("status_list_http_{}", response.status()));
        }
        let body = read_response_bounded(
            response,
            STATUS_LIST_MAX_BYTES,
            "status_list_response_too_large",
        )
        .await?;
        String::from_utf8(body).map_err(|_| "status_list_not_utf8".into())
    }
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
            .no_proxy()
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
        let body = read_response_bounded(resp, PDP_MAX_BYTES, "pdp response too large").await?;
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
    /// Lifetime cap when the PDP reports no `trust_data`: nothing bounds the receipt except this.
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

/// AuthZEN response -> [`PdpAnswer`]. `decision` must be a boolean. Everything in `context` is optional, and so is
/// every timestamp inside `trust_data`: go-trust registries differ — its whitelist answers with no `context.id` and
/// no `trust_data`, and its always-trusted registry answers with an id, a reason, and a `trust_data` entry that
/// carries no timestamps. What is present must be well-formed: an id must be a non-empty string, a `trust_data`
/// entry must be an object, and a timestamp must be a string that parses — a present value of the wrong type is
/// malformed, never silently absent. Lifetime is the gate's call, not this parser's: an answer with no `trust_data`
/// at all gets the gate's conservative default lifetime, while timestamp-less entries are still trust data and the
/// receipt lives the tenant ceiling, clamped by any `next_update` that is present.
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
        for entry in a {
            // An entry that is not an object is malformed evidence, not empty
            // evidence: reject the whole answer rather than receipt a
            // placeholder entry.
            let Value::Object(fields) = entry else {
                return Err("trust_data_entry_not_object".into());
            };
            // A timestamp may be omitted (go-trust's always-trusted registry
            // carries none), but one that is present must be a string that
            // parses — a present non-string value is malformed, not absent,
            // the same distinction the context.id check makes.
            let ts = |k: &str| -> std::result::Result<Option<i64>, String> {
                match fields.get(k) {
                    None | Some(Value::Null) => Ok(None),
                    Some(Value::String(s)) => siros_verifier_core::mdoc::parse_utc(s)
                        .map(Some)
                        .map_err(|e| e.to_string()),
                    Some(_) => Err("trust_data_timestamp_not_string".into()),
                }
            };
            trust_data.push(TrustData {
                registry: fields
                    .get("registry")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                as_of: ts("as_of")?,
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
    store: Arc<dyn FlowStore>,
    /// Adapter-owned admission cap for concurrent response verifications.
    verification_permits: Arc<tokio::sync::Semaphore>,
    /// The same cap for the cryptographic verification jobs themselves:
    /// a permit is held inside the blocking job until it finishes, so
    /// detached (caller-abandoned) jobs and the blocking pool's queue can
    /// never hold more than the configured number.
    crypto_permits: Arc<tokio::sync::Semaphore>,
    sealer: SessionSealer,
    gate: TrustGate,
    signer: kryptering::SoftwareSigner,
    chain_der: Vec<Vec<u8>>,
    clock: Clock,
    status_list_client: Option<Arc<dyn StatusListClient>>,
    /// Optional `zkp_req` support. Each flow selects its format from its DCQL.
    zkp: Option<ZkpMode>,
}

struct ZkpMode {
    cfg: ZkpBackendConfig,
    verifier: ZkpVerifier,
    profiles: Vec<ZkpProfile>,
    vp_formats: Value,
}

struct ZkpProfile {
    cfg: ZkpProfileConfig,
    plan: siros_dc_matcher_core::zkp_req::Plan,
}

impl ZkpMode {
    fn new(zcfg: ZkpBackendConfig, verifier: ZkpVerifier) -> Result<Self> {
        let mut offered = serde_json::json!({ "system_id_values": zcfg.system_id_values });
        if !zcfg.proof_system_values.is_empty() {
            offered["proof_system_values"] = serde_json::json!(zcfg.proof_system_values);
        }
        let vp_formats = serde_json::json!({ "zkp_req": offered });
        let metadata = serde_json::json!({ "vp_formats_supported": vp_formats }).to_string();
        let mut configs = Vec::new();
        if let Some(query) = zcfg.query.clone() {
            configs.push(ZkpProfileConfig {
                query,
                subject_handle: zcfg.subject_handle.clone(),
                attribute_map: zcfg.attribute_map.clone(),
            });
        }
        configs.extend(zcfg.profiles.clone());
        if configs.is_empty() {
            return Err(Error::Config(
                "at least one zkp_req query profile is required".into(),
            ));
        }
        let mut profiles: Vec<ZkpProfile> = Vec::with_capacity(configs.len());
        for cfg in configs {
            let dcql = Self::dcql(&cfg);
            if profiles
                .iter()
                .any(|profile| Self::dcql(&profile.cfg) == dcql)
            {
                return Err(Error::Config(
                    "two zkp_req profiles contain the same query".into(),
                ));
            }
            let plan =
                siros_dc_matcher_core::zkp_req::plan(&cfg.query.to_string(), Some(&metadata))
                    .map_err(|e| Error::Config(format!("zkp query: {}", e.code())))?;
            siros_dc_matcher_core::zkp_req::unsatisfiable(&plan).map_err(|e| {
                Error::Config(format!("zkp query cannot be satisfied: {}", e.code()))
            })?;
            let handles: Vec<&str> = plan.functions.iter().map(|f| f.handle.as_str()).collect();
            let pseudonyms: Vec<&str> = plan
                .functions
                .iter()
                .filter(|f| f.function_id == "pseudonym")
                .map(|f| f.handle.as_str())
                .collect();
            if !pseudonyms.contains(&cfg.subject_handle.as_str()) {
                return Err(Error::Config(format!(
                    "subject_handle {:?} is not a pseudonym handle of the query ({pseudonyms:?})",
                    cfg.subject_handle
                )));
            }
            for (k, h) in &cfg.attribute_map {
                if !handles.contains(&h.as_str()) {
                    return Err(Error::Config(format!(
                        "attribute {k}: no result handle {h:?} in the query"
                    )));
                }
            }
            profiles.push(ZkpProfile { cfg, plan });
        }
        Ok(Self {
            cfg: zcfg,
            verifier,
            profiles,
            vp_formats,
        })
    }

    fn dcql(cfg: &ZkpProfileConfig) -> Value {
        serde_json::json!({ "credentials": [cfg.query] })
    }

    fn default_profile(&self) -> &ZkpProfile {
        &self.profiles[0]
    }

    fn profile_for_query(&self, query: &Value) -> Option<&ZkpProfile> {
        self.profiles
            .iter()
            .find(|profile| Self::dcql(&profile.cfg) == *query)
    }
}

fn is_zkp_query(query: &Value) -> bool {
    query
        .get("credentials")
        .and_then(Value::as_array)
        .is_some_and(|credentials| {
            credentials.iter().any(|credential| {
                credential.get("format").and_then(Value::as_str) == Some("zkp_req")
            })
        })
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
        Self::new_inner(
            name,
            module_base,
            cfg,
            gate,
            signer,
            chain_der,
            clock,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        name: &str,
        module_base: &str,
        cfg: VpBackendConfig,
        gate: TrustGate,
        signer: kryptering::SoftwareSigner,
        chain_der: Vec<Vec<u8>>,
        clock: Clock,
        zkp_validated: bool,
    ) -> Result<Self> {
        if is_zkp_query(&cfg.dcql) && !zkp_validated {
            return Err(Error::Config(
                "zkp_req fallback requires specialized validation".into(),
            ));
        }
        if !is_zkp_query(&cfg.dcql) {
            oid4vp::validate_dcql_query(&cfg.dcql)
                .map_err(|e| Error::Config(format!("dcql: {e}")))?;
        }
        if cfg.request_ttl_secs <= 0 || cfg.request_ttl_secs > 900 {
            return Err(Error::Config("request_ttl_secs must be 1..=900".into()));
        }
        if cfg.processing_lease_secs <= 0 || cfg.processing_lease_secs > 900 {
            return Err(Error::Config(
                "processing_lease_secs must be 1..=900 (the deadline \
                 accommodation below enforces the effective minimum of the \
                 flow-store write bound plus one second)"
                    .into(),
            ));
        }
        // The write-bound accommodation below (deadline + bound <= lease, with
        // deadline >= 1) already forces the lease above the write bound, so
        // no separate lease floor is needed.
        if cfg.processing_deadline_secs <= 0 || cfg.processing_deadline_secs > 900 {
            return Err(Error::Config(
                "processing_deadline_secs must be 1..=900".into(),
            ));
        }
        if cfg.processing_deadline_secs + FLOW_STORE_WRITE_BOUND_SECS > cfg.processing_lease_secs {
            return Err(Error::Config(
                "processing_deadline_secs must leave room for the flow-store write bound".into(),
            ));
        }
        if cfg.max_concurrent_verifications == 0 || cfg.max_concurrent_verifications > 512 {
            return Err(Error::Config(
                "max_concurrent_verifications must be 1..=512".into(),
            ));
        }
        if !matches!(cfg.request_uri_method.as_str(), "get" | "post") {
            return Err(Error::Config(
                "request_uri_method must be get or post".into(),
            ));
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
        let verification_permits = Arc::new(tokio::sync::Semaphore::new(
            cfg.max_concurrent_verifications,
        ));
        let crypto_permits = Arc::new(tokio::sync::Semaphore::new(
            cfg.max_concurrent_verifications,
        ));
        Ok(Self {
            name: name.into(),
            module_base: module_base.into(),
            cfg,
            store: Arc::new(MemoryFlowStore::default()),
            verification_permits,
            crypto_permits,
            sealer: SessionSealer::from_master(&random_master(), name)
                .map_err(|e| Error::Internal(format!("session sealer: {}", e.code())))?,
            gate,
            signer,
            chain_der,
            clock,
            status_list_client: None,
            zkp: None,
        })
    }

    /// A `zkp_req` backend. Responses are verified by `verifier`, with every
    /// attestation issuer judged through the same trust gate as other formats.
    #[allow(clippy::too_many_arguments)]
    pub fn new_zkp(
        name: &str,
        module_base: &str,
        zcfg: ZkpBackendConfig,
        gate: TrustGate,
        signer: kryptering::SoftwareSigner,
        chain_der: Vec<Vec<u8>>,
        verifier: ZkpVerifier,
        clock: Clock,
    ) -> Result<Self> {
        let mode = ZkpMode::new(zcfg, verifier)?;
        let cfg = VpBackendConfig {
            dcql: ZkpMode::dcql(&mode.default_profile().cfg),
            attribute_map: BTreeMap::new(),
            subject_pointer: String::new(),
            role: mode.cfg.role.clone(),
            mdoc_role: String::new(),
            request_ttl_secs: mode.cfg.request_ttl_secs,
            request_uri_method: default_request_uri_method(),
            auth_class_ref: mode.cfg.auth_class_ref.clone(),
            processing_lease_secs: default_processing_lease(),
            processing_deadline_secs: default_processing_deadline(),
            max_concurrent_verifications: default_max_concurrent_verifications(),
        };
        let mut backend =
            Self::new_inner(name, module_base, cfg, gate, signer, chain_der, clock, true)?;
        backend.zkp = Some(mode);
        Ok(backend)
    }

    /// Construct a backend with ZKP support and a fallback validated against
    /// the configured profiles. Non-ZKP fallbacks remain valid alongside ZKP.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_zkp(
        name: &str,
        module_base: &str,
        cfg: VpBackendConfig,
        zcfg: ZkpBackendConfig,
        gate: TrustGate,
        signer: kryptering::SoftwareSigner,
        chain_der: Vec<Vec<u8>>,
        verifier: ZkpVerifier,
        clock: Clock,
    ) -> Result<Self> {
        let mode = ZkpMode::new(zcfg, verifier)?;
        Self::validate_zkp_fallback(&mode, &cfg.dcql)?;
        let mut backend =
            Self::new_inner(name, module_base, cfg, gate, signer, chain_der, clock, true)?;
        backend.zkp = Some(mode);
        Ok(backend)
    }

    fn validate_zkp_fallback(mode: &ZkpMode, dcql: &Value) -> Result<()> {
        // A ZKP fallback must be exactly one of the queries just validated.
        // Non-ZKP fallbacks remain valid alongside ZKP and are checked in `new`.
        if is_zkp_query(dcql) && mode.profile_for_query(dcql).is_none() {
            return Err(Error::Config(
                "fallback DCQL must match a configured zkp_req profile".into(),
            ));
        }
        Ok(())
    }

    /// Add `zkp_req` alongside the backend's existing SD-JWT/mdoc profiles.
    /// The configured query is the only ZK query accepted from the UI.
    pub fn with_zkp(mut self, zcfg: ZkpBackendConfig, verifier: ZkpVerifier) -> Result<Self> {
        let mode = ZkpMode::new(zcfg, verifier)?;
        Self::validate_zkp_fallback(&mode, &self.cfg.dcql)?;
        self.zkp = Some(mode);
        Ok(self)
    }

    /// Inject shared flow/replay storage. Every replica must use the same store.
    pub fn with_flow_store(mut self, store: Arc<dyn FlowStore>) -> Self {
        self.store = store;
        self
    }

    /// Share the verification-admission pool with other backend instances:
    /// one admission budget across every backend that receives it.
    pub fn with_verification_permits(mut self, permits: Arc<tokio::sync::Semaphore>) -> Self {
        self.verification_permits = permits;
        self
    }

    /// Override the per-tenant sealing key. Shared-store deployments must construct every
    /// instance from the same high-entropy master secret and tenant name.
    pub fn with_session_sealer(mut self, sealer: SessionSealer) -> Self {
        self.sealer = sealer;
        self
    }

    /// Enable bounded HTTPS status-list retrieval for SD-JWT credentials that
    /// carry a `status.status_list` reference.
    pub fn with_status_list_client(mut self, client: Arc<dyn StatusListClient>) -> Self {
        self.status_list_client = Some(client);
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

    /// Append one verified credential's claims to the result. Each pointer is
    /// resolved against this credential's own claims, and a matched value
    /// becomes an additional value of the attribute. The subject is set by the
    /// first credential that carries the subject pointer.
    fn merge_attributes(
        claims_root: &Value,
        data: &mut InternalData,
        attribute_map: &BTreeMap<String, String>,
        subject_pointer: &str,
    ) -> std::result::Result<(), String> {
        let scalar_one = |v: &Value| -> std::result::Result<String, String> {
            match v {
                Value::String(s) => Ok(s.clone()),
                Value::Bool(_) | Value::Number(_) => Ok(v.to_string()),
                _ => Err("attribute_not_scalar".into()),
            }
        };
        let scalar = |v: &Value| -> std::result::Result<Vec<String>, String> {
            match v {
                Value::String(s) => Ok(vec![s.clone()]),
                Value::Bool(_) | Value::Number(_) => Ok(vec![v.to_string()]),
                Value::Array(a) => a.iter().map(&scalar_one).collect(),
                _ => Err("attribute_not_scalar".into()),
            }
        };
        // Missing mapped claims are absent attributes, not errors; the DCQL query decides what is required.
        for (internal, ptr) in attribute_map {
            if let Some(v) = claims_root.pointer(ptr) {
                data.attributes
                    .entry(internal.clone())
                    .or_default()
                    .extend(scalar(v)?);
            }
        }
        if data.subject_id.is_none() {
            if let Some(v) = claims_root.pointer(subject_pointer) {
                data.subject_id = Some(scalar_one(v)?);
            }
        }
        Ok(())
    }

    async fn finish_response(
        &self,
        id: &str,
        claim_id: &str,
        outcome: TerminalOutcome,
        response: Response,
    ) -> Result<Response> {
        match self
            .store
            .finish(id, (self.clock)(), claim_id, outcome)
            .await
        {
            Ok(FinishResult::Finished) => Ok(response),
            Ok(FinishResult::Conflict) => Ok(Response::text(409, "flow completion conflict")),
            Err(_) => Ok(Response::text(503, "flow store unavailable")),
        }
    }

    /// Seconds reserved at the end of every lease for the single terminal
    /// write; the stores never take longer ([`FLOW_STORE_WRITE_BOUND_SECS`]).
    const FINALIZE_RESERVE_SECS: i64 = FLOW_STORE_WRITE_BOUND_SECS;

    /// The monotonic processing budget in seconds: the configured deadline,
    /// never taking more of the lease than leaves room for the terminal
    /// write. Zero or negative when the claim's safe window is exhausted.
    fn processing_budget(deadline_secs: i64, lease_until: i64, now: i64) -> i64 {
        let remaining = lease_until.saturating_sub(now);
        deadline_secs.min(remaining.saturating_sub(Self::FINALIZE_RESERVE_SECS))
    }

    /// The deadline refusal every expired budget converges on.
    fn deadline_decision() -> Result<Decision> {
        Decision::failed(
            "processing_deadline",
            Response::text(504, "processing deadline exceeded"),
        )
    }

    async fn check_sd_jwt_status(
        &self,
        verified: &CryptoVerified,
        now: i64,
    ) -> std::result::Result<(), (String, u16)> {
        let Some(reference) = &verified.status else {
            return Ok(());
        };
        let Some(client) = &self.status_list_client else {
            return Err(("status_list_unavailable".into(), 503));
        };
        let token = client
            .fetch(&reference.uri)
            .await
            .map_err(|_| ("status_list_unavailable".to_owned(), 503))?;
        let token =
            siros_verifier_core::status_list::verify_token(&token, &reference.uri, &X5cLeaf, now)
                .map_err(|_| ("invalid_status_list".to_owned(), 400))?;
        let status = siros_verifier_core::status_list::status_at(&token, reference)
            .map_err(|_| ("invalid_status_list".to_owned(), 400))?;
        let query = TrustQuery::for_issuer(&token.issuer, "status-list-signer", "status-list");
        match self.gate.permits(&query.to_authzen(), now).await {
            Ok(true) => {}
            Ok(false) => return Err(("status_list_signer_not_trusted".into(), 403)),
            Err(_) => return Err(("trust_unavailable".into(), 503)),
        }
        if status != 0 {
            return Err(("credential_revoked".into(), 403));
        }
        Ok(())
    }

    async fn on_wallet_response(&self, ctx: &mut Context) -> Result<Response> {
        let id = self.flow_id_from_path(ctx, "response")?;
        if ctx.request.method != "POST" {
            return Ok(Response::text(405, "method not allowed"));
        }
        let now = (self.clock)();
        let claim_id = new_flow_id();
        let flow = match self
            .store
            .claim(&id, now, &claim_id, self.cfg.processing_lease_secs)
            .await
        {
            Ok(ClaimResult::Claimed(flow)) => *flow,
            Ok(ClaimResult::Unknown) => return Ok(Response::text(404, "unknown flow")),
            Ok(ClaimResult::Expired) => return Ok(Response::text(400, "expired flow")),
            Ok(ClaimResult::Replay) => {
                return Ok(Response::text(409, "response already received"));
            }
            Err(_) => return Ok(Response::text(503, "flow store unavailable")),
        };
        // The budget never takes more of the lease than leaves room to
        // persist the terminal outcome while this claim is still held; a
        // stalled PDP or status endpoint cannot hang a presentation.
        let lease_until = flow.lease_until;
        // The budget never takes more of the lease than leaves room for the
        // terminal write; an exhausted window (budget <= 0) is finalized
        // without polling: the first poll of the ZKP path would already
        // reach trust evaluation and native verification.
        let budget = Self::processing_budget(
            self.cfg.processing_deadline_secs,
            lease_until,
            (self.clock)(),
        );
        let started = std::time::Instant::now();
        let deadline = std::time::Duration::from_secs(budget.max(0) as u64);
        let decided = if budget <= 0 {
            Self::deadline_decision()?
        } else {
            match tokio::time::timeout(deadline, self.process_claim(ctx, id.clone(), now, flow))
                .await
            {
                Ok(decided) => decided?,
                Err(_) => Self::deadline_decision()?,
            }
        };
        // A synchronous verification overrun can complete the decision after
        // the budget passed; such a decision is never accepted.
        let decision = if started.elapsed() > deadline {
            Self::deadline_decision()?
        } else {
            decided
        };
        // The lease guard: a decision is persisted only while the claim
        // still owns its safe window.
        let decision = if (self.clock)() + Self::FINALIZE_RESERVE_SECS >= lease_until {
            Self::deadline_decision()?
        } else {
            decision
        };
        // Single bounded terminal write, outside the cancellable verification
        // phase: a cancelled verification can never replace or duplicate a
        // committed terminal outcome.
        self.finish_response(&id, &claim_id, decision.outcome, decision.response)
            .await
    }

    /// Decide the terminal outcome for one claimed wallet response without
    /// touching the store. The caller bounds the whole step with the
    /// processing budget and performs the single terminal write.
    async fn process_claim(
        &self,
        ctx: &mut Context,
        id: String,
        now: i64,
        flow: Flow,
    ) -> Result<Decision> {
        let Flow {
            sealed_session,
            requester,
            attribute_map,
            subject_pointer,
            ..
        } = flow;
        // One verification admission per response, held for the whole
        // pipeline (crypto, trust, status, mapping — every format including
        // ZKP): a caller whose budget expires while queued is dropped before
        // any work starts, and the permit is released when its future drops,
        // so sustained overload cannot accumulate unbounded verification
        // work. The millisecond crypto job a dropped caller leaves on the
        // blocking pool is bounded by that pool.
        let _admission = match self.verification_permits.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => {
                return Decision::failed("verifier_error", Response::text(500, "verifier error"));
            }
        };
        let session = match self.sealer.unseal(&sealed_session, id.as_bytes()) {
            Ok(s) => s,
            Err(e) => {
                return Decision::failed(
                    e.code(),
                    Response::text(500, "stored session cannot be opened"),
                );
            }
        };
        // RFC 6749 section 3.1 prohibits repeated request/response parameters.
        // The HTTP adapter preserves form pairs so this boundary must not
        // silently accept a last-write-wins interpretation.
        if ctx
            .request
            .form_pairs
            .iter()
            .filter(|(name, _)| name == "response")
            .count()
            > 1
        {
            return Decision::failed(
                "duplicate_response",
                Response::text(400, "duplicate response"),
            );
        }
        let Some(jwe) = ctx.request.form.get("response").cloned() else {
            return Decision::failed("missing_response", Response::text(400, "missing response"));
        };
        if is_zkp_query(&session.dcql_query) {
            let Some(z) = &self.zkp else {
                return Decision::failed("verifier_error", Response::text(500, "verifier error"));
            };
            return self
                .on_zkp_response(&id, z, &session, &jwe, requester, now)
                .await;
        }
        // Synchronous cryptographic verification runs on the blocking pool so
        // it cannot stall the async workers polling other requests. Its
        // permit moves into the job and is held until the job finishes —
        // even a caller-abandoned job keeps its slot, so neither the
        // running set nor the pool's queue can exceed the cap.
        let crypto_permit = match self.crypto_permits.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => {
                return Decision::failed("verifier_error", Response::text(500, "verifier error"));
            }
        };
        let verified = match tokio::task::spawn_blocking(move || {
            let _held = crypto_permit;
            oid4vp::process_response(&session, &jwe, now, &X5cLeaf)
        })
        .await
        {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                return Decision::failed(e.code(), Response::text(400, "invalid response"));
            }
            Err(_) => {
                return Decision::failed("verifier_error", Response::text(500, "verifier error"));
            }
        };
        // Every presented credential's issuer must be trusted; a single denial fails the flow.
        if verified.is_empty() {
            return Decision::failed("no_presentation", Response::text(400, "no presentation"));
        }
        // One result carries every verified document: the first credential names the
        // issuer, and each credential's mapped claims are appended in query order.
        let mut data = InternalData {
            auth_info: AuthenticationInformation {
                auth_class_ref: self.cfg.auth_class_ref.clone(),
                issuer: Some(verified[0].verified.issuer_id()),
                ..Default::default()
            },
            ..Default::default()
        };
        data.requester = requester.clone();
        for p in &verified {
            let q = p
                .verified
                .trust_query(&self.cfg.role, &self.cfg.mdoc_role)
                .to_authzen();
            match self.gate.permits(&q, now).await {
                Ok(true) => {}
                Ok(false) => {
                    return Decision::failed(
                        "issuer_not_trusted",
                        Response::text(403, "issuer not trusted"),
                    );
                }
                Err(e) => {
                    tracing_noop(&e);
                    return Decision::failed(
                        "trust_unavailable",
                        Response::text(503, "trust evaluation unavailable"),
                    );
                }
            }
            if let oid4vp::VerifiedCredential::SdJwt(credential) = &p.verified {
                if let Err((code, status)) = self.check_sd_jwt_status(credential, now).await {
                    return Decision::failed(&code, Response::text(status, &code));
                }
            }
            let claims = match p.verified.claims() {
                Ok(claims) => claims,
                Err(_) => {
                    return Decision::failed(
                        "claims_unavailable",
                        Response::text(422, "cannot read claims"),
                    );
                }
            };
            let claims_root = Value::Object(claims);
            if let Err(code) =
                Self::merge_attributes(&claims_root, &mut data, &attribute_map, &subject_pointer)
            {
                return Decision::failed(&code, Response::text(422, "cannot map attributes"));
            }
        }
        if data.subject_id.is_none() {
            return Decision::failed(
                "subject_claim_missing",
                Response::text(422, "cannot map attributes"),
            );
        }
        let sealed_result = match self
            .sealer
            .seal_json(&data, format!("result:{id}").as_bytes())
        {
            Ok(result) => result,
            Err(e) => {
                return Decision::failed(e.code(), Response::text(500, "result cannot be sealed"));
            }
        };
        Decision::done(sealed_result)
    }

    async fn on_zkp_response(
        &self,
        id: &str,
        z: &ZkpMode,
        session: &oid4vp::Session,
        jwe: &str,
        requester: Option<String>,
        now: i64,
    ) -> Result<Decision> {
        let opened = match oid4vp::open_response(session, jwe, now) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(code = e.code(), error = %e, token_bytes = jwe.len(), "zkp response envelope rejected");
                return Decision::failed(e.code(), Response::text(400, "invalid response"));
            }
        };
        let Some(profile) = z.profile_for_query(&session.dcql_query) else {
            return Decision::failed("verifier_error", Response::text(500, "verifier error"));
        };
        let thumbprint =
            match jose_rs::jwk::thumbprint::thumbprint_sha256(&session.enc_key.to_public_jwk())
                .and_then(|encoded| jose_rs::base64url::decode(&encoded))
            {
                Ok(t) => t,
                Err(_) => {
                    return Decision::failed(
                        "verifier_error",
                        Response::text(500, "verifier error"),
                    );
                }
            };
        let channel = match (
            session.response_mode.as_str(),
            session.dc_api_origin.as_deref(),
        ) {
            ("direct_post.jwt", None) => Channel::Redirect {
                client_id: session.client_id.clone(),
                response_uri: session.response_uri.clone(),
                encrypted: true,
            },
            ("dc_api.jwt", Some(origin)) => Channel::DcApi {
                origin: origin.to_owned(),
            },
            _ => {
                return Decision::failed("verifier_error", Response::text(500, "verifier error"));
            }
        };
        let exchange = Exchange {
            plan: &profile.plan,
            channel: &channel,
            nonce: &session.nonce,
            reader_thumbprint: Some(&thumbprint),
            verifier_id: &z.cfg.verifier_id,
            now,
        };
        let pending = match z.verifier.begin(&exchange, &opened.vp_token_text()) {
            Ok(p) => p,
            Err(e) => return self.zkp_failure(&e),
        };
        let mut verdicts = Vec::new();
        for queries in pending.trust_queries() {
            let mut per = Vec::with_capacity(queries.len());
            for q in queries {
                let now_ok = self.gate.permits(&q.now.to_authzen(), now).await;
                let at_expiry = match &q.at_expiry {
                    Some(x) => Some(self.gate.permits(&x.to_authzen(), now).await),
                    None => None,
                };
                match (now_ok, at_expiry) {
                    (Ok(trusted_now), None) => {
                        per.push(siros_verifier_core::issuer_set::MemberVerdict {
                            trusted_now,
                            trusted_at_expiry: None,
                        })
                    }
                    (Ok(trusted_now), Some(Ok(at))) => {
                        per.push(siros_verifier_core::issuer_set::MemberVerdict {
                            trusted_now,
                            trusted_at_expiry: Some(at),
                        })
                    }
                    _ => {
                        return Decision::failed(
                            "trust_unavailable",
                            Response::text(503, "trust evaluation unavailable"),
                        );
                    }
                }
            }
            verdicts.push(per);
        }
        let verified = match pending.finish(&verdicts) {
            Ok(v) => v,
            Err(e) => return self.zkp_failure(&e),
        };
        let Some(first) = verified.first() else {
            return Decision::failed("no_presentation", Response::text(400, "no presentation"));
        };
        let mut data = match self.map_zkp(z, profile, first) {
            Ok(d) => d,
            Err(code) => {
                return Decision::failed(&code, Response::text(422, "cannot map attributes"));
            }
        };
        data.requester = requester;
        let sealed_result = match self
            .sealer
            .seal_json(&data, format!("result:{id}").as_bytes())
        {
            Ok(result) => result,
            Err(e) => {
                return Decision::failed(e.code(), Response::text(500, "result cannot be sealed"));
            }
        };
        Decision::done(sealed_result)
    }

    fn map_zkp(
        &self,
        z: &ZkpMode,
        profile: &ZkpProfile,
        presentation: &VerifiedPresentation,
    ) -> std::result::Result<InternalData, String> {
        use base64::Engine;
        let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let mut data = InternalData {
            auth_info: AuthenticationInformation {
                auth_class_ref: z.cfg.auth_class_ref.clone(),
                issuer: Some(format!(
                    "zkp:{}:{}",
                    presentation.system_id, presentation.issuer_key_thumbprint
                )),
                ..Default::default()
            },
            subject_type: SubjectType::Pairwise,
            ..Default::default()
        };
        for (name, handle) in &profile.cfg.attribute_map {
            if let Some(pseudonym) = presentation.pseudonyms.get(handle) {
                data.attributes
                    .insert(name.clone(), vec![encode(pseudonym)]);
            } else if presentation.satisfied.contains(handle) {
                data.attributes.insert(name.clone(), vec!["true".into()]);
            }
        }
        let subject = presentation
            .pseudonyms
            .get(&profile.cfg.subject_handle)
            .ok_or_else(|| "no_pseudonym_for_handle".to_owned())?;
        data.subject_id = Some(encode(subject));
        Ok(data)
    }

    fn zkp_failure(&self, e: &ZkpError) -> Result<Decision> {
        match e {
            ZkpError::Refused { code, detail } => {
                let body = serde_json::to_vec(&serde_json::json!({
                    "error": code,
                    "error_description": detail,
                }))
                .unwrap_or_else(|_| b"{\"error\":\"zkp_req\"}".to_vec());
                Decision::failed(
                    code,
                    Response::new(400)
                        .with_header("content-type", "application/json")
                        .with_body(body),
                )
            }
            ZkpError::Fault(_) => {
                Decision::failed("verifier_error", Response::text(500, "verifier error"))
            }
        }
    }

    async fn status(&self, ctx: &Context) -> Result<BackendAction> {
        let id = ctx
            .state
            .get_str(NS, FLOW_KEY)
            .ok_or_else(|| Error::Authn("no_flow".into()))?;
        let now = (self.clock)();
        let flow = match self.store.get(&id, now).await {
            Ok(flow) => flow,
            Err(_) => {
                return Ok(BackendAction::Respond(Response::text(
                    503,
                    "flow store unavailable",
                )));
            }
        };
        let Some(flow) = flow else {
            return Ok(BackendAction::Respond(Response::json(
                &serde_json::json!({"status": "unknown"}),
            )?));
        };
        let status = match &flow.outcome {
            _ if flow.expired(now) => "expired",
            Outcome::Pending | Outcome::Processing(_) => "pending",
            Outcome::Failed(_) => "failed",
            Outcome::Done(_) => "done",
            Outcome::Collected => "unknown",
        };
        Ok(BackendAction::Respond(Response::json(
            &serde_json::json!({
                "status": status,
                "complete_uri": format!("{}/complete", self.module_base),
            }),
        )?))
    }

    async fn complete(&self, ctx: &Context) -> Result<BackendAction> {
        // Only the browser that started the flow can collect the result.
        let id = ctx
            .state
            .get_str(NS, FLOW_KEY)
            .ok_or_else(|| Error::Authn("no_flow".into()))?;
        let now = (self.clock)();
        match self.store.collect(&id, now).await {
            Ok(CollectResult::Unknown) => Err(Error::Authn("unknown_flow".into())),
            Ok(CollectResult::Pending) => {
                Ok(BackendAction::Respond(waiting_page(&self.module_base)))
            }
            Ok(CollectResult::Expired) => Err(Error::Authn("flow_expired".into())),
            Ok(CollectResult::Failed(code)) => Err(Error::Authn(code)),
            Ok(CollectResult::Done(sealed_result)) => {
                let data: InternalData = self
                    .sealer
                    .unseal_json(&sealed_result, format!("result:{id}").as_bytes())
                    .map_err(|e| {
                        Error::Internal(format!("stored result cannot be opened: {}", e.code()))
                    })?;
                Ok(BackendAction::AuthResponse(data))
            }
            Err(_) => Ok(BackendAction::Respond(Response::text(
                503,
                "flow store unavailable",
            ))),
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
    let body = format!(
        r#"<h1>Waiting for your wallet</h1>
<div class="siros-spinner" role="status" aria-label="Verification in progress"></div>
<p>This page will show the verified response or an error when the presentation finishes.</p>
<meta http-equiv="refresh" content="2;url={}/complete">"#,
        html_escape(module_base)
    );
    Response::html(ui::page("Waiting for your wallet", &body))
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
        let scheme = request
            .attr_first(ui::SCHEME_ATTRIBUTE)
            .unwrap_or("openid4vp");
        if !matches!(scheme, "openid4vp" | "haip" | "haip-vp" | "mdoc-openid4vp") {
            return Err(Error::BadRequest("unsupported wallet URI scheme".into()));
        }
        let (dcql_query, attribute_map, subject_pointer) = request_profile(&request, &self.cfg)?;
        let zkp = if is_zkp_query(&dcql_query) {
            let mode = self.zkp.as_ref().ok_or_else(|| {
                Error::BadRequest("zkp_req is not configured for this backend".into())
            })?;
            if mode.profile_for_query(&dcql_query).is_none() {
                return Err(Error::BadRequest(
                    "only a configured zkp_req preset is supported".into(),
                ));
            }
            Some(mode)
        } else {
            None
        };
        let request_uri_method = self.cfg.request_uri_method.clone();
        let cfg = RequestConfig {
            response_uri: format!("{}/response/{id}", self.module_base),
            dcql_query,
            ttl_secs: self.cfg.request_ttl_secs,
            vp_formats_supported: zkp.map(|z| z.vp_formats.clone()),
            client_id: zkp.map(|z| z.cfg.verifier_id.clone()),
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
        let flow = Flow {
            id: id.clone(),
            schema_version: FLOW_SCHEMA_VERSION,
            jar: jar.clone(),
            sealed_session,
            expires_at,
            retain_until: expires_at.saturating_add(FLOW_RETENTION_GRACE_SECS),
            lease_until: 0,
            requester: request.requester.clone(),
            attribute_map,
            subject_pointer,
            outcome: Outcome::Pending,
        };
        if self.store.insert(flow, now).await.is_err() {
            return Ok(Response::text(503, "flow store unavailable"));
        }
        ctx.state.set_str(NS, FLOW_KEY, id.clone());
        let request_uri = format!("{}/request/{id}", self.module_base);
        let link = format!(
            "{scheme}://cb?client_id={}&request_uri={}&request_uri_method={request_uri_method}",
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
                let now = (self.clock)();
                let flow = match self.store.get(&id, now).await {
                    Ok(flow) => flow,
                    Err(_) => {
                        return Ok(BackendAction::Respond(Response::text(
                            503,
                            "flow store unavailable",
                        )));
                    }
                };
                let Some(flow) = flow else {
                    return Err(Error::BadRequest("unknown flow".into()));
                };
                if !matches!(&flow.outcome, Outcome::Pending) {
                    return Err(Error::BadRequest("unknown flow".into()));
                }
                if flow.expired(now) {
                    return Err(Error::BadRequest("expired flow".into()));
                }
                if !matches!(ctx.request.method.as_str(), "GET" | "POST") {
                    return Ok(BackendAction::Respond(Response::text(
                        405,
                        "method not allowed",
                    )));
                }
                let mut jar = flow.jar;
                if ctx.request.method == "POST" {
                    let pair_count = if ctx.request.form_pairs.is_empty() {
                        ctx.request.form.len()
                    } else {
                        ctx.request.form_pairs.len()
                    };
                    let nonce = ctx.request.form.get("wallet_nonce").cloned();
                    if pair_count != 1 || nonce.is_none() {
                        let mut response = Response::json(&serde_json::json!({
                            "error": "invalid_wallet_nonce",
                            "error_description": "exactly one wallet_nonce is required",
                        }))?;
                        response.status = 400;
                        return Ok(BackendAction::Respond(response));
                    }
                    jar = oid4vp::reissue_request_with_wallet_nonce(
                        &jar,
                        &nonce.unwrap_or_default(),
                        &self.signer,
                        &self.chain_der,
                    )
                    .map_err(|e| Error::BadRequest(e.to_string()))?;
                }
                Ok(BackendAction::Respond(
                    Response::new(200)
                        .with_header("content-type", "application/oauth-authz-req+jwt")
                        .with_header("cache-control", "no-store")
                        .with_body(jar.into_bytes()),
                ))
            }
            "response" => Ok(BackendAction::Respond(self.on_wallet_response(ctx).await?)),
            "status" => self.status(ctx).await,
            "complete" => self.complete(ctx).await,
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
    fn complete_page_shows_a_neutral_spinner_while_pending() {
        let response = waiting_page("https://verifier.example/vp");
        let html = String::from_utf8(response.body).unwrap();
        assert!(html.contains("class=\"siros-spinner\""));
        assert!(html.contains("Verification in progress"));
        assert!(html.contains("/vp/complete"));
        assert!(html.contains("navbar-brand"));
        assert!(!html.contains("siros-pulse"));
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
