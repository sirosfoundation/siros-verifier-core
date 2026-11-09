//! Sustained native nym_auth verification: the genuine Longfellow circuit and
//! proof vector, verified in a loop under the same admission shape the
//! service gives native verification (a bounded set of concurrent blocking
//! workers). This is the native leg of the HA soak — it measures what the
//! release record needs about the native hot path under sustained load:
//! throughput, latency drift, and resident-memory growth.
//!
//! Run (release — the debug build measures nothing):
//!   cargo run -p siros-verifier-zkp --example soak_native --release -- \
//!       --duration 120 --workers 8

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use siros_verifier_zkp::backend::ProofBackend;
use siros_verifier_zkp::functions::{AgeCheck, FUNCTION_AGE_CHECK};
use siros_verifier_zkp::longfellow::LongfellowBackend;
use siros_verifier_zkp::request::Request;
use zk_cred_longfellow::nymauth::NymAuthCircuitParams;

/// The genuine fixture shared with the native vector tests.
const FIXTURE: &str = include_str!("../../../zkp/testdata/nymauth/fixture.json");
const CIRCUIT: &[u8] = include_bytes!("../../../zkp/testdata/nymauth/mdoc-circuits.zst");
const PROOF: &[u8] = include_bytes!("../../../zkp/testdata/nymauth/mdoc-proof.bin");

fn main() {
    let mut duration = Duration::from_secs(60);
    let mut workers = 8;
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().unwrap_or_else(|| usage(&flag));
        match flag.as_str() {
            "--duration" => duration = Duration::from_secs(value().parse().unwrap()),
            "--workers" => workers = value().parse().unwrap(),
            _ => usage(&flag),
        }
    }

    let document: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let params = NymAuthCircuitParams {
        block_enc_hash: document["block_enc_hash"].as_u64().unwrap() as usize,
        block_enc_sig: document["block_enc_sig"].as_u64().unwrap() as usize,
        hash_circuit_id: document["hash_circuit_id"].as_str().unwrap().into(),
        sig_circuit_id: document["sig_circuit_id"].as_str().unwrap().into(),
    };
    let circuit = zstd::decode_all(std::io::Cursor::new(CIRCUIT)).unwrap();
    let backend = LongfellowBackend::with_params(&circuit, &params).unwrap();
    let (request, claimed) = request_from(&document);

    // Sanity gates before any timing: the tool refuses to run at all if the
    // genuine vector does not verify, and if mutations are not refused.
    assert_eq!(
        backend.verify(&request, &claimed, PROOF).unwrap(),
        claimed,
        "the genuine vector must verify before any soaking"
    );
    assert!(
        backend.verify(&request, &[0u8; 32], PROOF).is_err(),
        "a wrong claimed pseudonym must be refused"
    );
    let mut tampered = PROOF.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(
        backend.verify(&request, &claimed, &tampered).is_err(),
        "a tampered proof must be refused"
    );

    println!(
        "soak_native: genuine Longfellow vector, {workers} concurrent workers, {}s",
        duration.as_secs()
    );
    let rss_start = rss_kib();

    let latencies: Arc<Mutex<Vec<Duration>>> = Arc::new(Mutex::new(Vec::new()));
    let verified = Arc::new(AtomicU64::new(0));
    let refused = Arc::new(AtomicU64::new(0));
    let started = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let backend = &backend;
            let request = &request;
            let claimed = claimed.clone();
            let latencies = latencies.clone();
            let verified = verified.clone();
            let refused = refused.clone();
            scope.spawn(move || {
                while started.elapsed() < duration {
                    let before = Instant::now();
                    match backend.verify(request, &claimed, PROOF) {
                        Ok(revealed) if revealed == claimed => {
                            verified.fetch_add(1, Ordering::SeqCst);
                        }
                        Ok(_) => {
                            refused.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(_) => {
                            refused.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    latencies.lock().unwrap().push(before.elapsed());
                }
            });
        }
    });
    let wall = started.elapsed();

    let total = verified.load(Ordering::SeqCst);
    let refused = refused.load(Ordering::SeqCst);
    // The samples in arrival order: the drift must compare the run's first
    // half against its second half chronologically, so the split happens
    // BEFORE any sorting (sorting first would compare the fast half of the
    // distribution with the slow half, which says nothing about time).
    let chronological: Vec<Duration> = Arc::try_unwrap(latencies).unwrap().into_inner().unwrap();
    let mut all = chronological.clone();
    all.sort_unstable();
    let at = |p: f64| -> u128 {
        all.get((all.len() as f64 * p) as usize)
            .unwrap_or(&Duration::ZERO)
            .as_millis()
    };
    let max = all.last().map(|d| d.as_millis()).unwrap_or(0);
    let median_of = |mut half: Vec<Duration>| -> f64 {
        half.sort_unstable();
        half[half.len() / 2].as_secs_f64()
    };
    let half = chronological.len() / 2;
    let drift = if half == 0 || chronological.len() == half {
        0.0
    } else {
        let a = median_of(chronological[..half].to_vec());
        let b = median_of(chronological[half..].to_vec());
        if a == 0.0 {
            0.0
        } else {
            (b - a) / a * 100.0
        }
    };

    println!(
        "verified:  {total} ({:.1}/s)",
        total as f64 / wall.as_secs_f64()
    );
    println!("refused:   {refused} (must be 0)");
    println!(
        "p50/p95/p99/max: {}ms / {}ms / {}ms / {}ms",
        at(0.50),
        at(0.95),
        at(0.99),
        max
    );
    println!("median drift first half -> last half: {drift:.1}%");
    println!("rss: {} KiB -> {} KiB", rss_start, rss_kib());
    if refused > 0 {
        println!("FAIL: verification results changed under sustained load");
        std::process::exit(1);
    }
}

fn usage(flag: &str) -> ! {
    eprintln!("unknown or incomplete flag: {flag}");
    eprintln!("usage: soak_native [--duration SECS] [--workers N]");
    std::process::exit(2);
}

/// Resident memory of this process, from the kernel (Linux).
fn rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                let rest = line.strip_prefix("VmRSS:")?.trim_start();
                rest.split_whitespace().next()?.parse().ok()
            })
        })
        .unwrap_or(0)
}

/// The request and claimed pseudonym exactly as the native vector tests
/// build them (zkp/tests/support/native.rs, which is test-only).
fn request_from(document: &serde_json::Value) -> (Request, Vec<u8>) {
    let hex = |value: &str| -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    };
    let mut sec1 = vec![4u8];
    sec1.extend_from_slice(&hex(document["issuer_key_x"].as_str().unwrap()));
    sec1.extend_from_slice(&hex(document["issuer_key_y"].as_str().unwrap()));
    let age = AgeCheck {
        le: Some(document["cutoff"].as_str().unwrap().into()),
        ..Default::default()
    };
    let request = Request {
        issuer_key: p256::PublicKey::from_sec1_bytes(&sec1).unwrap(),
        now: siros_verifier_core::mdoc::parse_utc(document["time"].as_str().unwrap()).unwrap(),
        inputs: vec![age.bounds().unwrap().circuit_input()],
        supported_functions: vec![FUNCTION_AGE_CHECK.into()],
        session_transcript: hex(document["session_transcript"].as_str().unwrap()),
        doc_type: document["doc_type"].as_str().unwrap().into(),
        verifier_input: hex(document["verifier_input"].as_str().unwrap())
            .try_into()
            .unwrap(),
    };
    (request, hex(document["pseudonym"].as_str().unwrap()))
}
