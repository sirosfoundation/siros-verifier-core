//! The same flow, but through tunnelbana's real `Proxy::run`: its router, its sealed state cookie and its
//! request/response pipeline, with a minimal frontend standing in for OIDC/SAML.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};
use siros_verifier_core::testutil::*;
use siros_verifier_core_tunnelbana::*;
use tunnelbana_core::context::Context;
use tunnelbana_core::http::{HttpRequestData, Response};
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{Frontend, FrontendAction, Route};
use tunnelbana_core::proxy::Proxy;
use tunnelbana_core::state::StateSealer;

const T0: i64 = 1_800_000_000;
/// The sealer prefixes the cookie with `__Host-` while `Secure` is on.
const COOKIE: &str = "__Host-TB_STATE";

struct Pdp {
    permit: AtomicBool,
    calls: AtomicUsize,
}
#[async_trait]
impl PdpClient for Pdp {
    async fn evaluate(&self, _req: &Value) -> Result<Value, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        // exactly what go-trust returns today: no id, no freshness data
        Ok(
            json!({"decision": self.permit.load(Ordering::SeqCst), "context": {"reason": {"registry": "wl"}}}),
        )
    }
}

/// Stands in for an OIDC/SAML frontend: `fe/login` starts authentication; the result is rendered as JSON.
struct TestFrontend;
#[async_trait]
impl Frontend for TestFrontend {
    fn name(&self) -> &str {
        "fe"
    }
    fn register_endpoints(&self, _b: &[String]) -> Vec<Route> {
        vec![Route::exact("fe/login", "login")]
    }
    async fn handle_endpoint(
        &self,
        _ctx: &mut Context,
        _route: &str,
    ) -> tunnelbana_core::Result<FrontendAction> {
        Ok(FrontendAction::StartAuth {
            request: InternalData::request("https://rp.example"),
            target_backend: None,
        })
    }
    async fn handle_authn_response(
        &self,
        _ctx: &mut Context,
        r: InternalData,
    ) -> tunnelbana_core::Result<Response> {
        Response::json(
            &json!({"sub": r.subject_id, "requester": r.requester, "attributes": r.attributes, "issuer": r.auth_info.issuer}),
        )
    }
    async fn handle_backend_error(
        &self,
        _ctx: &mut Context,
        e: &tunnelbana_core::Error,
    ) -> tunnelbana_core::Result<Response> {
        Ok(Response::text(401, format!("denied: {e}")))
    }
}

struct World {
    proxy: Proxy,
    pdp: Arc<Pdp>,
    clock: Arc<AtomicI64>,
    holder: jose_rs::jwk::Jwk,
    issued: Issued,
}

fn world() -> World {
    let (v_cert, v_key) = self_signed_ec("verifier.example", "ES256");
    let (i_cert, i_key) = self_signed_ec("issuer.example", "ES256");
    let holder = ec_jwk("ES256", "holder");
    let mut spec = IssueSpec::new(
        json!({"iss": "https://issuer.example", "vct": "urn:eudi:pid:1", "iat": T0 - 10,
        "exp": T0 + 1_000_000, "given_name": "Ada", "family_name": "Lovelace"}),
    );
    spec.holder_pub = Some(public_of(&holder));
    spec.x5c_der = vec![i_cert];
    spec.conceal = vec![vec![Seg::Key("given_name")], vec![Seg::Key("family_name")]];
    let issued = issue(&i_key, &spec).unwrap();
    let cfg: VpBackendConfig = serde_json::from_value(json!({
        "dcql": {"credentials": [{"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:1"]},
                 "claims": [{"path": ["given_name"]}, {"path": ["family_name"]}]}]},
        "attribute_map": {"givenName": "/given_name"}, "subject_pointer": "/family_name", "role": "pid-provider",
    })).unwrap();
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
    let c2 = clock.clone();
    let backend = VpBackend::new(
        "vp",
        "https://proxy.example/vp",
        cfg,
        gate,
        siros_verifier_core::oid4vp::software_signer(&v_key).unwrap(),
        vec![v_cert],
        Arc::new(move || c2.load(Ordering::SeqCst)),
    )
    .unwrap();
    let sealer = StateSealer::new("a-32-byte-or-longer-test-secret!!", "TB_STATE");
    let proxy = Proxy::new(
        vec![Box::new(TestFrontend)],
        vec![Box::new(backend)],
        vec![],
        sealer,
    );
    World {
        proxy,
        pdp,
        clock,
        holder,
        issued,
    }
}

fn get(path: &str, cookie: Option<&str>) -> HttpRequestData {
    let mut r = HttpRequestData {
        path: path.into(),
        method: "GET".into(),
        ..Default::default()
    };
    if let Some(c) = cookie {
        r.cookies.insert(COOKIE.into(), c.into());
    }
    r
}
fn cookie_of(r: &Response) -> Option<String> {
    r.headers
        .iter()
        .filter(|(k, _)| k == "set-cookie")
        .map(|(_, v)| v)
        .find_map(|v| {
            let (name, rest) = v.split_once('=')?;
            (name == COOKIE).then(|| rest.split(';').next().unwrap().to_string())
        })
}
fn flow_id(html: &str) -> String {
    let i = html.find("vp%2Frequest%2F").expect("request uri in link") + "vp%2Frequest%2F".len();
    html[i..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

/// Browser starts; returns (cookie, flow id).
async fn login(w: &World) -> (String, String) {
    let r = w.proxy.run(get("fe/login", None)).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let cookie = cookie_of(&r).expect("state cookie set");
    (cookie, flow_id(&String::from_utf8(r.body).unwrap()))
}
async fn wallet_posts(w: &World, id: &str) -> Response {
    let jar = w.proxy.run(get(&format!("vp/request/{id}"), None)).await;
    assert_eq!(jar.status, 200);
    assert!(jar
        .headers
        .iter()
        .any(|(k, v)| k == "content-type" && v == "application/oauth-authz-req+jwt"));
    let jwe = wallet_respond(
        &String::from_utf8(jar.body).unwrap(),
        &w.holder,
        &[WalletCredential {
            id: "pid",
            issued: &w.issued,
            disclose: &[0, 1],
        }],
        w.clock.load(Ordering::SeqCst),
    )
    .unwrap();
    let mut r = HttpRequestData {
        path: format!("vp/response/{id}"),
        method: "POST".into(),
        ..Default::default()
    };
    r.form = BTreeMap::from([("response".to_string(), jwe.clone())]);
    r.form_pairs = vec![("response".into(), jwe)];
    w.proxy.run(r).await
}

#[tokio::test]
async fn full_login_through_the_real_proxy() {
    let w = world();
    let (cookie, id) = login(&w).await;
    // browser polls while the wallet has not answered
    let waiting = w.proxy.run(get("vp/complete", Some(&cookie))).await;
    assert_eq!(waiting.status, 200);
    assert!(String::from_utf8_lossy(&waiting.body).contains("Waiting"));
    let cookie = cookie_of(&waiting).unwrap_or(cookie);
    let pending = w.proxy.run(get("vp/status", Some(&cookie))).await;
    let pending: Value = serde_json::from_slice(&pending.body).unwrap();
    assert_eq!(pending["status"], "pending");

    assert_eq!(wallet_posts(&w, &id).await.status, 200);

    let ready = w.proxy.run(get("vp/status", Some(&cookie))).await;
    let ready: Value = serde_json::from_slice(&ready.body).unwrap();
    assert_eq!(ready["status"], "done");
    let done = w.proxy.run(get("vp/complete", Some(&cookie))).await;
    assert_eq!(done.status, 200, "{}", String::from_utf8_lossy(&done.body));
    let v: Value = serde_json::from_slice(&done.body).unwrap();
    assert_eq!(v["sub"], "Lovelace");
    assert_eq!(v["requester"], "https://rp.example");
    assert_eq!(v["attributes"]["givenName"], json!(["Ada"]));
    assert_eq!(v["issuer"], "https://issuer.example");
    assert_eq!(w.pdp.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn untrusted_issuer_reaches_the_frontend_as_an_error() {
    let w = world();
    w.pdp.permit.store(false, Ordering::SeqCst);
    let (cookie, id) = login(&w).await;
    assert_eq!(wallet_posts(&w, &id).await.status, 403);
    let r = w.proxy.run(get("vp/complete", Some(&cookie))).await;
    // This flow was initiated by the OIDC frontend (the RP's client id is
    // the requester), so the refusal keeps the protocol error: the frontend
    // must be able to return the authorization error — and the RP's original
    // state — to the waiting relying party. The human-readable failure page
    // is the browser-launched (UI requester) flow's surface.
    assert_eq!(r.status, 401, "{}", String::from_utf8_lossy(&r.body));
    let body = String::from_utf8(r.body).unwrap();
    assert!(body.contains("issuer_not_trusted"), "{body}");
    assert!(!body.contains("Lovelace") && !body.contains("Ada"));
}

#[tokio::test]
async fn a_second_collection_gets_nothing() {
    let w = world();
    let (cookie, id) = login(&w).await;
    assert_eq!(wallet_posts(&w, &id).await.status, 200);
    assert_eq!(
        w.proxy.run(get("vp/complete", Some(&cookie))).await.status,
        200
    );
    assert_eq!(
        w.proxy.run(get("vp/complete", Some(&cookie))).await.status,
        401
    );
}

#[tokio::test]
async fn a_forged_or_missing_state_cookie_cannot_collect() {
    let w = world();
    let (cookie, id) = login(&w).await;
    assert_eq!(wallet_posts(&w, &id).await.status, 200);
    assert_ne!(w.proxy.run(get("vp/complete", None)).await.status, 200);
    let mut forged = cookie.clone();
    forged.push_str("AA");
    assert_ne!(
        w.proxy.run(get("vp/complete", Some(&forged))).await.status,
        200
    );
    let mut flipped = cookie.into_bytes();
    let n = flipped.len() / 2;
    flipped[n] = if flipped[n] == b'A' { b'B' } else { b'A' };
    assert_ne!(
        w.proxy
            .run(get(
                "vp/complete",
                Some(&String::from_utf8(flipped).unwrap())
            ))
            .await
            .status,
        200
    );
}

#[tokio::test]
async fn the_router_only_serves_the_documented_paths() {
    let w = world();
    for p in [
        "vp/nothing",
        "vp/request",
        "vp/request/short",
        "vp/complete/extra",
        "vp/response/../x",
    ] {
        let r = w.proxy.run(get(p, None)).await;
        assert!(r.status >= 400, "{p} -> {}", r.status);
    }
}
