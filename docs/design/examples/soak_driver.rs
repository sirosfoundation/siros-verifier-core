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
//! Invariants it holds the service to, reported at the end:
//!   - a flow that was answered 200 completes exactly once (sampled);
//!   - a connect failure on one replica is served by the other (shared flow
//!     state — any replica can complete any flow);
//!   - store-unavailable answers during a MongoDB failover are retried and
//!     followed by resumed completions.
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

/// A step's failure kind: network-level (a replica worth failing over from)
/// or an unexpected answer (the flow is dead, count it and move on).
enum Step {
    Network,
    Gone,
}

#[derive(Default)]
struct Stats {
    started: AtomicU64,
    answered_200: AtomicU64,
    replay_409: AtomicU64,
    store_503: AtomicU64,
    connect_failovers: AtomicU64,
    completed: AtomicU64,
    failed: AtomicU64,
    duplicate_completions: AtomicU64,
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
                        "[{:>4}s] started={} answered={} completed={} failed={} 503={} failovers={} duplicates={}",
                        began.elapsed().as_secs(),
                        stats.started.load(Ordering::SeqCst),
                        stats.answered_200.load(Ordering::SeqCst),
                        stats.completed.load(Ordering::SeqCst),
                        stats.failed.load(Ordering::SeqCst),
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
            Outcome::Failed | Outcome::Network => {
                stats.failed.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

enum Outcome {
    Completed,
    Failed,
    Network,
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

    // 1. Start: the thin UI entry, exactly as a browser does.
    let (flow_id, cookie) = match start_flow(client, &base).await {
        Ok(found) => found,
        Err(Step::Network) => {
            mark_suspect(&suspect_until[*replica], last_connect_failure);
            stats.connect_failovers.fetch_add(1, Ordering::SeqCst);
            return Outcome::Network;
        }
        Err(Step::Gone) => return Outcome::Failed,
    };

    // 2. The request object — any replica can serve it: shared flow state.
    let request_object = match get_request_object(client, &base, &flow_id).await {
        Ok(jar) => jar,
        Err(Step::Network) => {
            mark_suspect(&suspect_until[*replica], last_connect_failure);
            stats.connect_failovers.fetch_add(1, Ordering::SeqCst);
            if replicas.len() < 2 {
                return Outcome::Network;
            }
            *replica = (*replica + 1) % replicas.len();
            base = replicas[*replica].clone();
            match get_request_object(client, &base, &flow_id).await {
                Ok(jar) => jar,
                Err(_) => return Outcome::Network,
            }
        }
        Err(Step::Gone) => return Outcome::Failed,
    };

    // 3. The wallet answers, bound to this session's nonce.
    let jwe = match wallet_respond(&request_object, holder, &present(issued), now()) {
        Ok(jwe) => jwe,
        Err(_) => return Outcome::Failed,
    };

    // 4. Post the encrypted response, riding out a MongoDB failover.
    let mut answered = false;
    for attempt in 0..16 {
        match post_response(client, &base, &flow_id, &jwe).await {
            Ok(200) => {
                stats.answered_200.fetch_add(1, Ordering::SeqCst);
                answered = true;
                break;
            }
            Ok(409) => {
                // Already received — the flow stands; go collect.
                stats.replay_409.fetch_add(1, Ordering::SeqCst);
                answered = true;
                break;
            }
            Ok(503) => {
                stats.store_503.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Ok(_) => return Outcome::Failed,
            Err(Step::Network) => {
                mark_suspect(&suspect_until[*replica], last_connect_failure);
                stats.connect_failovers.fetch_add(1, Ordering::SeqCst);
                if attempt + 1 == 16 || replicas.len() < 2 {
                    return Outcome::Network;
                }
                *replica = (*replica + 1) % replicas.len();
                base = replicas[*replica].clone();
            }
            Err(Step::Gone) => return Outcome::Failed,
        }
    }
    if !answered {
        return Outcome::Network;
    }

    // 5. Collect: pending -> verified result, exactly once.
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        match get_complete(client, &base, &cookie).await {
            Ok((_status, body)) if body.contains("Credential verified") => {
                last_completion.store(now_millis(), Ordering::SeqCst);
                if sampled {
                    // Exactly-once, sampled: collecting again must NOT show
                    // the verified result a second time.
                    if let Ok((_, again)) = get_complete(client, &base, &cookie).await {
                        if again.contains("Credential verified") {
                            stats.duplicate_completions.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
                return Outcome::Completed;
            }
            Ok((_status, body)) if body.contains("Presentation failed") => {
                return Outcome::Failed;
            }
            Ok((status, _)) if status != 200 => return Outcome::Failed,
            Ok(_) => {}
            Err(Step::Network) => return Outcome::Network,
            Err(Step::Gone) => return Outcome::Failed,
        }
        if Instant::now() > deadline {
            return Outcome::Failed;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
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

fn pick_replica(replicas: &[String], current: &mut usize, suspect_until: &[Arc<AtomicU64>]) {
    if replicas.len() < 2 {
        return;
    }
    if suspect_until[*current].load(Ordering::SeqCst) > now_millis() {
        *current = (*current + 1) % replicas.len();
    }
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
    let completed = stats.completed.load(Ordering::SeqCst);
    println!("\n=== soak_driver summary ({:.0}s) ===", wall.as_secs_f64());
    println!("started:            {started}");
    println!(
        "answered 200:       {}",
        stats.answered_200.load(Ordering::SeqCst)
    );
    println!(
        "replay (409):       {}",
        stats.replay_409.load(Ordering::SeqCst)
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
    println!(
        "failed:             {}",
        stats.failed.load(Ordering::SeqCst)
    );
    let duplicates = stats.duplicate_completions.load(Ordering::SeqCst);
    println!("duplicate results:  {duplicates}");
    let recovered =
        last_completion.load(Ordering::SeqCst) >= last_connect_failure.load(Ordering::SeqCst);
    println!("completions resumed after the last connect failure: {recovered}");
    let pass = duplicates == 0 && completed > 0 && recovered;
    println!("VERDICT: {}", if pass { "PASS" } else { "FAIL" });
    if !pass {
        std::process::exit(1);
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
