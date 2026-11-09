//! The HA/overload leg of the soak: a dev-only wallet-and-load harness that
//! drives the REAL running service over HTTP — start a presentation, fetch
//! the request object, answer as a genuine SD-JWT wallet, post the encrypted
//! response, and collect the verified result — sustained, past the admission
//! budget, across every configured replica, against shared MongoDB.
//!
//! It also serves the loopback go-trust stand-in the service is pointed at
//! (the explicitly supported plain-HTTP loopback PDP mode): every evaluation
//! is answered with the configured verdict.
//!
//! Every transient failure is recovered, never abandoned, because the soak
//! exists to prove recovery: a 503 (store unavailable, an election in
//! progress) is counted and retried at every step; a connection failure
//! fails over to the survivor mid-flow (any replica can complete any flow);
//! and a 409 on the response POST does NOT assume a terminal result — the
//! killed replica may still hold a live processing lease, so the JWE is kept
//! and re-posted past the lease window until the flow is re-claimed and
//! re-driven, or collected if it was already terminal.
//!
//! The end-of-run verdict holds the service to:
//!   - every ACCEPTED flow (200 or 409 on the response POST) completes
//!     exactly once — completed must equal accepted;
//!   - no flow ever shows its verified result twice (sampled re-collection);
//!   - completions resume after the last connect failure.
//!
//! Run against the soak stack (docs/design/SOAK.md):
//!   cargo run -p siros-verifier-service --example soak_driver --release -- \
//!       --replicas http://127.0.0.1:9001,http://127.0.0.1:9002 \
//!       --users 32 --duration 300 --pdp 127.0.0.1:6001

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jose_rs::jwk::Jwk;
use serde_json::json;
use siros_verifier_core::testutil::{
    issue, public_of, self_signed_ec, wallet_respond, IssueSpec, Issued, Seg, WalletCredential,
};

/// What the driver asks for, matching the credential it presents and the
/// soak backend's own query.
const DCQL: &str = r#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["given_name"]},{"path":["family_name"]}]}]}"#;

/// How long a step rides out a store-unavailable window (a MongoDB election
/// finishes well inside the service's five-second write bound; this is the
/// bounded patience, not a hang).
const STORE_RETRY: Duration = Duration::from_secs(30);
/// How long the response/collect phase allows a killed replica's processing
/// lease to expire and the flow to be re-driven: the lease window plus the
/// processing deadline, with margin.
const RECOVERY: Duration = Duration::from_secs(150);
/// How long a pending flow's processing lease can outlive a dead runner
/// before the wallet's retry re-claims it: the configured lease plus margin.
const LEASE_WINDOW: Duration = Duration::from_secs(65);

/// A step's failure kind.
enum Step {
    /// Network-level: the replica may be worth failing over from.
    Network,
    /// 503 from the service: the store is unavailable (an election); retry.
    StoreUnavailable,
    /// An unexpected answer: the flow is dead.
    Gone,
}

#[derive(Default)]
struct Stats {
    started: AtomicU64,
    accepted: AtomicU64,
    answered_200: AtomicU64,
    replay_409: AtomicU64,
    re_driven: AtomicU64,
    store_503: AtomicU64,
    connect_failovers: AtomicU64,
    completed: AtomicU64,
    /// Flows the service terminally refused (fail-closed): reached an
    /// explicit terminal refusal, not an abandonment.
    refused: AtomicU64,
    /// Accepted flows that never reached any terminal state inside the
    /// recovery window. This is the violation the verdict exists to catch.
    abandoned: AtomicU64,
    /// Flows that never got their response accepted (start or request-object
    /// phase failures). No HA guarantee applies to a flow that was never
    /// created or never served a request object.
    not_accepted: AtomicU64,
    duplicate_completions: AtomicU64,
    /// Why the first few refused/abandoned flows failed, verbatim.
    details: std::sync::Mutex<Vec<String>>,
}

impl Stats {
    fn note(&self, detail: String) {
        let mut details = self.details.lock().unwrap();
        if details.len() < 20 {
            details.push(detail);
        }
    }
}

fn main() {
    let mut replicas: Vec<String> = vec!["http://127.0.0.1:9001".into()];
    let mut users = 16;
    let mut duration = Duration::from_secs(120);
    let mut pdp_bind = "127.0.0.1:6001".to_string();
    let mut pdp_permit = true;
    let mut report_every = Duration::from_secs(15);
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().unwrap_or_else(|| usage(&flag));
        match flag.as_str() {
            "--replicas" => replicas = value().split(',').map(str::to_owned).collect(),
            "--users" => users = value().parse().unwrap(),
            "--duration" => duration = Duration::from_secs(value().parse().unwrap()),
            "--pdp" => pdp_bind = value(),
            "--pdp-permit" => pdp_permit = value().parse().unwrap(),
            "--report" => report_every = Duration::from_secs(value().parse().unwrap()),
            _ => usage(&flag),
        }
    }
    assert!(users > 0, "at least one user");
    assert!(!replicas.is_empty(), "at least one replica");

    serve_pdp(&pdp_bind, pdp_permit);

    // One issuer, one holder, one credential — presented fresh (nonce-bound)
    // for every flow, exactly as a real wallet re-presents its credential.
    let (issuer_cert, issuer_key) = self_signed_ec("issuer.example", "ES256");
    let (_holder_cert, holder) = self_signed_ec("holder.example", "ES256");
    let mut spec = IssueSpec::new(json!({
        "iss": "https://issuer.example", "vct": "urn:eudi:pid:1",
        "iat": now(), "exp": now() + 86_400 * 365,
        "given_name": "Ada", "family_name": "Lovelace",
    }));
    spec.holder_pub = Some(public_of(&holder));
    spec.x5c_der = vec![issuer_cert];
    spec.conceal = vec![vec![Seg::Key("given_name")], vec![Seg::Key("family_name")]];
    let issued = Arc::new(issue(&issuer_key, &spec).expect("issue the soak credential"));

    let client = Arc::new(
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(90))
            .build()
            .expect("client"),
    );

    let stats = Arc::new(Stats::default());
    let suspect_until: Vec<Arc<AtomicU64>> = (0..replicas.len())
        .map(|_| Arc::new(AtomicU64::new(0)))
        .collect();
    let last_completion = Arc::new(AtomicU64::new(0));
    let last_connect_failure = Arc::new(AtomicU64::new(0));

    println!(
        "soak_driver: {users} user(s), {}s, replicas: {}",
        duration.as_secs(),
        replicas.join(", ")
    );
    let began = Instant::now();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let mut workers = Vec::new();
        for user in 0..users {
            let client = client.clone();
            let stats = stats.clone();
            let issued = issued.clone();
            let holder = holder.clone();
            let replicas = replicas.clone();
            let suspect_until = suspect_until.clone();
            let last_completion = last_completion.clone();
            let last_connect_failure = last_connect_failure.clone();
            workers.push(tokio::spawn(async move {
                drive_user(
                    user,
                    began,
                    duration,
                    &client,
                    &stats,
                    &issued,
                    &holder,
                    &replicas,
                    &suspect_until,
                    &last_completion,
                    &last_connect_failure,
                )
                .await;
            }));
        }
        let progress = {
            let stats = stats.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(report_every).await;
                    println!(
                        "[{:>4}s] started={} accepted={} completed={} refused={} abandoned={} not-accepted={} 503={} failovers={} duplicates={}",
                        began.elapsed().as_secs(),
                        stats.started.load(Ordering::SeqCst),
                        stats.accepted.load(Ordering::SeqCst),
                        stats.completed.load(Ordering::SeqCst),
                        stats.refused.load(Ordering::SeqCst),
                        stats.abandoned.load(Ordering::SeqCst),
                        stats.not_accepted.load(Ordering::SeqCst),
                        stats.store_503.load(Ordering::SeqCst),
                        stats.connect_failovers.load(Ordering::SeqCst),
                        stats.duplicate_completions.load(Ordering::SeqCst),
                    );
                }
            })
        };
        for worker in workers {
            worker.await.expect("worker");
        }
        progress.abort();
    });

    report(
        &stats,
        began.elapsed(),
        &last_completion,
        &last_connect_failure,
    );
}

/// One virtual user: presentations back to back until the soak window ends.
#[allow(clippy::too_many_arguments)]
async fn drive_user(
    user: usize,
    began: Instant,
    duration: Duration,
    client: &reqwest::Client,
    stats: &Stats,
    issued: &Issued,
    holder: &Jwk,
    replicas: &[String],
    suspect_until: &[Arc<AtomicU64>],
    last_completion: &AtomicU64,
    last_connect_failure: &AtomicU64,
) {
    let mut replica = user % replicas.len();
    let mut flows: u64 = 0;
    while began.elapsed() < duration {
        flows += 1;
        let sampled = flows.is_multiple_of(10);
        let outcome = one_flow(
            client,
            stats,
            issued,
            holder,
            replicas,
            &mut replica,
            suspect_until,
            last_completion,
            last_connect_failure,
            sampled,
        )
        .await;
        match outcome {
            Outcome::Completed => {
                stats.completed.fetch_add(1, Ordering::SeqCst);
            }
            Outcome::Refused => {
                stats.refused.fetch_add(1, Ordering::SeqCst);
            }
            Outcome::Abandoned => {
                stats.abandoned.fetch_add(1, Ordering::SeqCst);
            }
            Outcome::NotAccepted => {
                stats.not_accepted.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

enum Outcome {
    /// The verified result was delivered.
    Completed,
    /// The service terminally refused the flow (fail-closed): an explicit
    /// refusal, recorded with its reason.
    Refused,
    /// An accepted flow that reached no terminal state inside the recovery
    /// window — the violation the verdict exists to catch.
    Abandoned,
    /// The flow never got its response accepted (start or request phase).
    NotAccepted,
}

#[allow(clippy::too_many_arguments)]
async fn one_flow(
    client: &reqwest::Client,
    stats: &Stats,
    issued: &Issued,
    holder: &Jwk,
    replicas: &[String],
    replica: &mut usize,
    suspect_until: &[Arc<AtomicU64>],
    last_completion: &AtomicU64,
    last_connect_failure: &AtomicU64,
    sampled: bool,
) -> Outcome {
    stats.started.fetch_add(1, Ordering::SeqCst);
    pick_replica(replicas, replica, suspect_until);
    let mut base = replicas[*replica].clone();
    let flow_began = Instant::now();

    // 1. Start: the thin UI entry, exactly as a browser does. A 503 here is
    //    a store hiccup — the attempt created no flow — so count it and
    //    start again.
    let (flow_id, cookie) = loop {
        match start_flow(client, &base).await {
            Ok(found) => break found,
            Err(Step::StoreUnavailable) => {
                stats.store_503.fetch_add(1, Ordering::SeqCst);
                if flow_began.elapsed() > STORE_RETRY {
                    return Outcome::NotAccepted;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(Step::Network) => {
                mark_suspect(&suspect_until[*replica], last_connect_failure);
                stats.connect_failovers.fetch_add(1, Ordering::SeqCst);
                if replicas.len() < 2 || !switch_replica(replicas, replica, &mut base) {
                    return Outcome::NotAccepted;
                }
            }
            Err(Step::Gone) => return Outcome::NotAccepted,
        }
    };

    // 2. The request object — any replica can serve it: shared flow state.
    //    Same 503 patience, same flow id.
    let store_deadline = Instant::now() + STORE_RETRY;
    let request_object = loop {
        match get_request_object(client, &base, &flow_id).await {
            Ok(jar) => break jar,
            Err(Step::StoreUnavailable) => {
                stats.store_503.fetch_add(1, Ordering::SeqCst);
                if Instant::now() > store_deadline {
                    return Outcome::NotAccepted;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(Step::Network) => {
                mark_suspect(&suspect_until[*replica], last_connect_failure);
                stats.connect_failovers.fetch_add(1, Ordering::SeqCst);
                if replicas.len() < 2 || !switch_replica(replicas, replica, &mut base) {
                    return Outcome::NotAccepted;
                }
            }
            Err(Step::Gone) => return Outcome::NotAccepted,
        }
    };

    // 3. The wallet answers, bound to this session's nonce.
    let jwe = match wallet_respond(&request_object, holder, &present(issued), now()) {
        Ok(jwe) => jwe,
        Err(_) => return Outcome::NotAccepted,
    };

    // 4. Post the encrypted response and collect the result. A 409 does NOT
    //    mean a terminal result exists: a killed replica may still hold a
    //    live processing lease. So the JWE is kept, and while collecting, the
    //    POST is retried (throttled) past the lease window until the flow is
    //    re-claimed and re-driven (200) or already terminal (the collection
    //    delivers).
    let mut accepted = false;
    let mut saw_replay = false;
    let mut pending_since: Option<Instant> = None;
    let mut next_repost = Instant::now();
    let recovery_deadline = Instant::now() + RECOVERY;
    loop {
        if Instant::now() > recovery_deadline {
            stats.note(format!("flow {flow_id}: recovery window expired"));
            return Outcome::Abandoned;
        }
        if !accepted {
            match post_response(client, &base, &flow_id, &jwe).await {
                Ok(200) => {
                    stats.answered_200.fetch_add(1, Ordering::SeqCst);
                    stats.accepted.fetch_add(1, Ordering::SeqCst);
                    accepted = true;
                }
                Ok(409) => {
                    stats.replay_409.fetch_add(1, Ordering::SeqCst);
                    stats.accepted.fetch_add(1, Ordering::SeqCst);
                    accepted = true;
                    saw_replay = true;
                    next_repost = Instant::now() + Duration::from_secs(2);
                }
                Ok(503) => {
                    stats.store_503.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    continue;
                }
                Ok(status) => {
                    stats.note(format!("flow {flow_id}: POST refused {status}"));
                    return Outcome::Refused;
                }
                Err(Step::Network) => {
                    mark_suspect(&suspect_until[*replica], last_connect_failure);
                    stats.connect_failovers.fetch_add(1, Ordering::SeqCst);
                    if replicas.len() < 2 || !switch_replica(replicas, replica, &mut base) {
                        return Outcome::NotAccepted;
                    }
                    continue;
                }
                // post_response maps a 503 to its status, so these are
                // unreachable here; exhaustiveness requires them.
                Err(Step::StoreUnavailable) | Err(Step::Gone) => return Outcome::Refused,
            }
        } else if (saw_replay || pending_past_lease(&pending_since))
            && Instant::now() >= next_repost
        {
            // A flow still pending past its processing lease — whether its
            // POST was a 409 whose runner died, or a 200 whose processing
            // was killed — is recovered by the WALLET'S RETRY: a re-POST
            // past the lease window re-claims the slot and re-drives
            // verification. Send it, throttled.
            next_repost = Instant::now() + Duration::from_secs(2);
            match post_response(client, &base, &flow_id, &jwe).await {
                Ok(200) => {
                    stats.re_driven.fetch_add(1, Ordering::SeqCst);
                    saw_replay = false;
                    pending_since = None;
                }
                Ok(409) => {}
                Ok(503) => {
                    stats.store_503.fetch_add(1, Ordering::SeqCst);
                }
                Ok(status) => {
                    stats.note(format!("flow {flow_id}: re-POST refused {status}"));
                    return Outcome::Refused;
                }
                Err(Step::Network) => {
                    mark_suspect(&suspect_until[*replica], last_connect_failure);
                    stats.connect_failovers.fetch_add(1, Ordering::SeqCst);
                    if replicas.len() < 2 || !switch_replica(replicas, replica, &mut base) {
                        stats.note(format!("flow {flow_id}: no survivor mid-recovery"));
                        return Outcome::Abandoned;
                    }
                }
                Err(Step::StoreUnavailable) | Err(Step::Gone) => return Outcome::Refused,
            }
        }

        // 5. Collect whenever the flow has been accepted: pending -> verified
        //    result, exactly once. 503s are ridden out; a connection failure
        //    fails over with the same state cookie.
        if accepted {
            match get_complete(client, &base, &cookie).await {
                Ok((_, body)) if body.contains("Credential verified") => {
                    last_completion.store(now_millis(), Ordering::SeqCst);
                    if sampled {
                        // Exactly-once, sampled: collecting again must NOT
                        // show the verified result a second time.
                        if let Ok((_, again)) = get_complete(client, &base, &cookie).await {
                            if again.contains("Credential verified") {
                                stats.duplicate_completions.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                    return Outcome::Completed;
                }
                Ok((status, body)) if body.contains("Presentation failed") => {
                    stats.note(format!(
                        "flow {flow_id}: refused at collect {status}: {}",
                        snippet(&body)
                    ));
                    return Outcome::Refused;
                }
                Ok((503, _)) => {
                    stats.store_503.fetch_add(1, Ordering::SeqCst);
                }
                Ok((_, body)) if body.contains("Waiting for your wallet") => {
                    // Still pending: remember since when, so the wallet's
                    // lease-recovery re-post fires past the lease window.
                    pending_since.get_or_insert(Instant::now());
                }
                Ok((status, body)) => {
                    // A non-pending answer we cannot classify as terminal:
                    // treat it as an abandonment so it is never silently
                    // passed.
                    stats.note(format!(
                        "flow {flow_id}: collect {status} not pending, not terminal: {}",
                        snippet(&body)
                    ));
                    return Outcome::Abandoned;
                }
                Err(Step::Network) => {
                    mark_suspect(&suspect_until[*replica], last_connect_failure);
                    stats.connect_failovers.fetch_add(1, Ordering::SeqCst);
                    if replicas.len() < 2 || !switch_replica(replicas, replica, &mut base) {
                        stats.note(format!("flow {flow_id}: no survivor at collect"));
                        return Outcome::Abandoned;
                    }
                }
                // get_complete maps a 503 to its status, so these are
                // unreachable here; exhaustiveness requires them.
                Err(Step::StoreUnavailable) | Err(Step::Gone) => return Outcome::Abandoned,
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        } else {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

async fn start_flow(client: &reqwest::Client, base: &str) -> Result<(String, String), Step> {
    let response = client
        .post(format!("{base}/ui/start/qr"))
        .form(&[("dcql", DCQL), ("scheme", "openid4vp")])
        .send()
        .await
        .map_err(network)?;
    let status = response.status().as_u16();
    let cookies: Vec<String> = response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .map(str::trim)
        .filter(|pair| pair.contains('='))
        .map(str::to_owned)
        .collect();
    let page = response.text().await.map_err(network)?;
    if status == 503 {
        return Err(Step::StoreUnavailable);
    }
    if status != 200 {
        return Err(Step::Gone);
    }
    let id = extract_flow_id(&page).ok_or(Step::Gone)?;
    Ok((id, cookies.join("; ")))
}

/// The QR page carries the authorization request with the percent-encoded
/// request URI: openid4vp://cb?...request_uri=...%2Fvp%2Frequest%2F<id>...
fn extract_flow_id(page: &str) -> Option<String> {
    const MARKER: &str = "vp%2Frequest%2F";
    let start = page.find(MARKER)? + MARKER.len();
    let id: String = page[start..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    (id.len() >= 16).then_some(id)
}

async fn get_request_object(
    client: &reqwest::Client,
    base: &str,
    flow_id: &str,
) -> Result<String, Step> {
    let response = client
        .get(format!("{base}/vp/request/{flow_id}"))
        .send()
        .await
        .map_err(network)?;
    let status = response.status().as_u16();
    let body = response.text().await.map_err(network)?;
    if status == 503 {
        return Err(Step::StoreUnavailable);
    }
    if status != 200 || body.split('.').count() != 3 {
        return Err(Step::Gone);
    }
    Ok(body)
}

async fn post_response(
    client: &reqwest::Client,
    base: &str,
    flow_id: &str,
    jwe: &str,
) -> Result<u16, Step> {
    let response = client
        .post(format!("{base}/vp/response/{flow_id}"))
        .form(&[("response", jwe)])
        .send()
        .await
        .map_err(network)?;
    Ok(response.status().as_u16())
}

async fn get_complete(
    client: &reqwest::Client,
    base: &str,
    cookie: &str,
) -> Result<(u16, String), Step> {
    let mut request = client.get(format!("{base}/vp/complete"));
    if !cookie.is_empty() {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    let response = request.send().await.map_err(network)?;
    let status = response.status().as_u16();
    let body = response.text().await.map_err(network)?;
    Ok((status, body))
}

fn present(issued: &Issued) -> [WalletCredential<'_>; 1] {
    [WalletCredential {
        id: "pid",
        issued,
        disclose: &[0, 1],
    }]
}

fn network(_: reqwest::Error) -> Step {
    Step::Network
}

/// Has a pending flow been waiting longer than a processing lease lasts?
fn pending_past_lease(pending_since: &Option<Instant>) -> bool {
    pending_since.is_some_and(|since| since.elapsed() > LEASE_WINDOW)
}

fn pick_replica(replicas: &[String], current: &mut usize, suspect_until: &[Arc<AtomicU64>]) {
    if replicas.len() < 2 {
        return;
    }
    if suspect_until[*current].load(Ordering::SeqCst) > now_millis() {
        *current = (*current + 1) % replicas.len();
    }
}

/// Switch to the other replica and update the base URL. Returns false when
/// there is no survivor worth switching to.
fn switch_replica(replicas: &[String], current: &mut usize, base: &mut String) -> bool {
    if replicas.len() < 2 {
        return false;
    }
    *current = (*current + 1) % replicas.len();
    *base = replicas[*current].clone();
    true
}

fn mark_suspect(slot: &AtomicU64, last_connect_failure: &AtomicU64) {
    slot.store(now_millis() + 2_000, Ordering::SeqCst);
    last_connect_failure.store(now_millis(), Ordering::SeqCst);
}

fn report(
    stats: &Stats,
    wall: Duration,
    last_completion: &AtomicU64,
    last_connect_failure: &AtomicU64,
) {
    let started = stats.started.load(Ordering::SeqCst);
    let accepted = stats.accepted.load(Ordering::SeqCst);
    let completed = stats.completed.load(Ordering::SeqCst);
    let refused = stats.refused.load(Ordering::SeqCst);
    let abandoned = stats.abandoned.load(Ordering::SeqCst);
    let not_accepted = stats.not_accepted.load(Ordering::SeqCst);
    println!("\n=== soak_driver summary ({:.0}s) ===", wall.as_secs_f64());
    println!("started:            {started}");
    println!(
        "accepted:           {accepted}  (200: {}, 409: {})",
        stats.answered_200.load(Ordering::SeqCst),
        stats.replay_409.load(Ordering::SeqCst)
    );
    println!(
        "re-driven after lease expiry: {}",
        stats.re_driven.load(Ordering::SeqCst)
    );
    println!(
        "store 503 retried:  {}",
        stats.store_503.load(Ordering::SeqCst)
    );
    println!(
        "connect failovers:  {}",
        stats.connect_failovers.load(Ordering::SeqCst)
    );
    println!("completed:          {completed}");
    println!("refused (terminal): {refused}");
    println!("abandoned:          {abandoned}");
    println!("never accepted:     {not_accepted}");
    let duplicates = stats.duplicate_completions.load(Ordering::SeqCst);
    println!("duplicate results:  {duplicates}");
    let recovered =
        last_completion.load(Ordering::SeqCst) >= last_connect_failure.load(Ordering::SeqCst);
    println!("completions resumed after the last connect failure: {recovered}");
    // Every accepted flow must reach a terminal state exactly once — a
    // verified result or an explicit refusal — and none may be abandoned:
    // a PASS that masks an abandoned accepted flow is not a pass.
    let all_terminal = completed + refused == accepted;
    println!("every accepted flow reached a terminal state: {all_terminal}");
    for detail in stats.details.lock().unwrap().iter() {
        println!("  why: {detail}");
    }
    let pass = duplicates == 0 && completed > 0 && recovered && abandoned == 0 && all_terminal;
    println!("VERDICT: {}", if pass { "PASS" } else { "FAIL" });
    if !pass {
        std::process::exit(1);
    }
}

/// The first heading of a page, for failure evidence. The pages are one
/// long line, so this extracts the heading window instead of the line.
fn snippet(body: &str) -> String {
    match body.find("<h1>") {
        Some(at) => {
            let rest = &body[at..];
            let end = rest.find("</h1>").map(|e| e + 5).unwrap_or(80);
            rest.chars().take(end).collect()
        }
        None => body.chars().take(80).collect(),
    }
}

/// The loopback go-trust stand-in: accept, read one request, answer with the
/// fixed AuthZEN verdict, close. Connection-per-request is fine at soak
/// evaluation volumes.
fn serve_pdp(bind: &str, permit: bool) {
    let listener = match TcpListener::bind(bind) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("soak_driver: cannot bind the PDP stand-in on {bind}: {e}");
            std::process::exit(1);
        }
    };
    let body = format!(r#"{{"decision":{permit},"context":{{"reason":{{"registry":"soak"}}}}}}"#);
    println!("soak_driver: PDP stand-in on http://{bind}/evaluation -> decision={permit}");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let body = body.clone();
            std::thread::spawn(move || {
                // Read exactly one request: headers, then Content-Length bytes.
                let mut seen = Vec::new();
                let mut buffer = [0u8; 8192];
                let body_at = loop {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            seen.extend_from_slice(&buffer[..n]);
                            if let Some(at) = find_header_end(&seen) {
                                break at;
                            }
                        }
                    }
                };
                let headers = String::from_utf8_lossy(&seen[..body_at]).to_ascii_lowercase();
                let length: usize = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                while seen.len() < body_at + length {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&buffer[..n]),
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.shutdown(std::net::Shutdown::Both);
            });
        }
    });
}

fn find_header_end(seen: &[u8]) -> Option<usize> {
    seen.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|at| at + 4)
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn usage(flag: &str) -> ! {
    eprintln!("unknown or incomplete flag: {flag}");
    eprintln!(
        "usage: soak_driver --replicas URL[,URL..] --users N --duration SECS [--pdp BIND] [--pdp-permit BOOL] [--report SECS]"
    );
    std::process::exit(2);
}
