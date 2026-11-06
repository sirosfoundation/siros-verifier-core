use p256::ecdsa::{SigningKey, VerifyingKey};
use serde_json::{json, Value};
use siros_verifier_core::receipt::*;
use std::collections::HashMap;

const NOW: i64 = 1_790_000_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}
fn req() -> Value {
    json!({"subject":{"type":"key","id":"x5t#S256:abc"},"resource":{"type":"x5c","id":"x5t#S256:abc","key":["MIIB"]},
           "action":{"name":"pid-provider","parameters":{"credential_types":["eu.europa.ec.eudi.pid.1"]}}})
}
fn answer() -> PdpAnswer {
    PdpAnswer {
        decision: true,
        id: "dec-1".into(),
        reasons: vec!["listed".into()],
        trust_data: vec![TrustData {
            registry: "etsi".into(),
            as_of: NOW - 100,
            next_update: Some(NOW + 100_000),
        }],
    }
}
fn pol<'a>() -> IssuePolicy<'a> {
    IssuePolicy {
        iss: "core-1",
        aud: "tenant-a",
        kid: "k1",
        pdp: "https://pdp.example",
        max_ttl: 3600,
        deny_ttl: 300,
        refresh_num: 1,
        refresh_den: 2,
    }
}
fn verifier() -> Verifier {
    let mut keys = HashMap::new();
    keys.insert("k1".to_string(), VerifyingKey::from(&key(1)));
    Verifier {
        keys,
        iss: "core-1".into(),
        aud: "tenant-a".into(),
        skew: 60,
    }
}
fn issued() -> String {
    issue(&key(1), &pol(), &req(), &answer(), NOW).unwrap()
}
fn err(r: siros_verifier_core::Result<Receipt>) -> String {
    r.err()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "OK".into())
}
fn b64(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap()
}
fn b64e(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
/// Re-sign arbitrary header/claims with the genuine key, to isolate one rule at a time.
fn forge(mutate_h: impl Fn(&mut Value), mutate_c: impl Fn(&mut Value)) -> String {
    use p256::ecdsa::signature::Signer;
    let j = issued();
    let p: Vec<&str> = j.split('.').collect();
    let (mut h, mut c): (Value, Value) = (
        serde_json::from_slice(&b64(p[0])).unwrap(),
        serde_json::from_slice(&b64(p[1])).unwrap(),
    );
    mutate_h(&mut h);
    mutate_c(&mut c);
    let si = format!(
        "{}.{}",
        b64e(&canonical_json(&h).unwrap()),
        b64e(&canonical_json(&c).unwrap())
    );
    let s: p256::ecdsa::Signature = key(1).sign(si.as_bytes());
    format!("{si}.{}", b64e(&s.to_bytes()))
}

// ---- RFC 8785 ----
#[test]
fn rfc8785_sorting_is_utf16_not_utf8() {
    // RFC 8785 section 3.2.3: the emoji (UTF-16 d83d de00) must sort before U+FB33 (UTF-16 fb33),
    // although its UTF-8 bytes sort after.
    let mut m = serde_json::Map::new();
    for (k, v) in [
        ("\u{20ac}", "Euro"),
        ("\r", "CR"),
        ("\u{fb33}", "Dalet"),
        ("1", "One"),
        ("\u{1F600}", "Emoji"),
        ("\u{80}", "Ctl"),
        ("\u{f6}", "O"),
    ] {
        m.insert(k.to_string(), json!(v));
    }
    let out = String::from_utf8(canonical_json(&Value::Object(m)).unwrap()).unwrap();
    assert_eq!(
        out,
        "{\"\\r\":\"CR\",\"1\":\"One\",\"\u{80}\":\"Ctl\",\"\u{f6}\":\"O\",\"\u{20ac}\":\"Euro\",\"\u{1F600}\":\"Emoji\",\"\u{fb33}\":\"Dalet\"}"
    );
}
#[test]
fn rfc8785_string_escaping_example() {
    // RFC 8785 section 3.2.2: the string member of the example
    let v = json!({"literals": [null, true, false], "string": "\u{20ac}$\u{0f}\nA'B\"\\\\\"/"});
    assert_eq!(
        String::from_utf8(canonical_json(&v).unwrap()).unwrap(),
        "{\"literals\":[null,true,false],\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
    );
}
#[test]
fn floats_are_refused() {
    assert!(canonical_json(&json!({"n": 1.5})).is_err());
}
#[test]
fn key_order_does_not_change_the_hash() {
    let a: Value = serde_json::from_str(r#"{"a":1,"b":{"c":2,"d":3}}"#).unwrap();
    let b: Value = serde_json::from_str(r#"{"b":{"d":3,"c":2},"a":1}"#).unwrap();
    assert_eq!(req_sha256(&a).unwrap(), req_sha256(&b).unwrap());
}

// ---- verification rules ----
#[test]
fn issued_receipt_verifies() {
    let r = verifier().verify(&issued(), &req(), NOW + 10).unwrap();
    assert!(r.decision);
    assert_eq!(r.jti, "dec-1");
    assert_eq!(r.exp, NOW + 3600);
    assert_eq!(r.refresh_after, NOW + 1800);
}
#[test]
fn rule1_unpinned_key_and_bad_signature() {
    let other = issue(&key(2), &pol(), &req(), &answer(), NOW).unwrap();
    assert!(err(verifier().verify(&other, &req(), NOW)).contains("receipt_signature"));
    let mut v = verifier();
    v.keys.clear();
    assert!(err(v.verify(&issued(), &req(), NOW)).contains("unknown_kid"));
    let j = issued();
    let mut bytes = j.into_bytes();
    let n = bytes.len();
    bytes[n - 3] = if bytes[n - 3] == b'A' { b'B' } else { b'A' };
    assert!(verifier()
        .verify(&String::from_utf8(bytes).unwrap(), &req(), NOW)
        .is_err());
}
#[test]
fn rule1_alg_and_extra_headers() {
    assert!(
        err(verifier().verify(&forge(|h| h["alg"] = json!("none"), |_| {}), &req(), NOW))
            .contains("alg_not_es256")
    );
    assert!(err(verifier().verify(
        &forge(|h| h["jku"] = json!("https://evil"), |_| {}),
        &req(),
        NOW
    ))
    .contains("header_member_jku"));
}
#[test]
fn rule2_typ_iss_aud() {
    assert!(
        err(verifier().verify(&forge(|h| h["typ"] = json!("JWT"), |_| {}), &req(), NOW))
            .contains("typ")
    );
    assert!(
        err(verifier().verify(&forge(|_| {}, |c| c["iss"] = json!("other")), &req(), NOW))
            .contains("iss")
    );
    assert!(err(verifier().verify(
        &forge(|_| {}, |c| c["aud"] = json!("tenant-b")),
        &req(),
        NOW
    ))
    .contains("aud"));
}
#[test]
fn rule3_receipt_is_bound_to_its_request() {
    let mut other = req();
    other["action"]["name"] = json!("verifier");
    assert!(err(verifier().verify(&issued(), &other, NOW)).contains("req_sha256"));
    // a different chain
    let mut other = req();
    other["resource"]["key"] = json!(["MIIC"]);
    assert!(err(verifier().verify(&issued(), &other, NOW)).contains("req_sha256"));
}
#[test]
fn rule4_time_window() {
    assert!(err(verifier().verify(&issued(), &req(), NOW + 3601)).contains("expired"));
    assert!(err(verifier().verify(&issued(), &req(), NOW - 61)).contains("not_yet_valid"));
    // skew tolerance on nbf only
    verifier().verify(&issued(), &req(), NOW - 59).unwrap();
    verifier().verify(&issued(), &req(), NOW + 3600).unwrap();
}
#[test]
fn rule5_denials_are_carried_not_confused_with_errors() {
    let mut a = answer();
    a.decision = false;
    let j = issue(&key(1), &pol(), &req(), &a, NOW).unwrap();
    let r = verifier().verify(&j, &req(), NOW).unwrap();
    assert!(!r.decision);
    assert_eq!(r.exp, NOW + 300, "denials are shorter");
}

// ---- issuing ----
#[test]
fn ttl_is_clamped_by_trust_data_next_update() {
    let mut a = answer();
    a.trust_data.push(TrustData {
        registry: "lote".into(),
        as_of: NOW,
        next_update: Some(NOW + 500),
    });
    let r = verifier()
        .verify(
            &issue(&key(1), &pol(), &req(), &a, NOW).unwrap(),
            &req(),
            NOW,
        )
        .unwrap();
    assert_eq!(r.exp, NOW + 500);
    assert_eq!(r.refresh_after, NOW + 250);
}
#[test]
fn stale_trust_data_is_refused_not_receipted() {
    let mut a = answer();
    a.trust_data[0].next_update = Some(NOW);
    assert!(issue(&key(1), &pol(), &req(), &a, NOW)
        .unwrap_err()
        .to_string()
        .contains("trust_data_stale"));
}
#[test]
fn tenant_ceiling_applies_to_denials_too() {
    let mut p = pol();
    p.max_ttl = 100;
    let mut a = answer();
    a.decision = false;
    let r = verifier()
        .verify(&issue(&key(1), &p, &req(), &a, NOW).unwrap(), &req(), NOW)
        .unwrap();
    assert_eq!(r.exp, NOW + 100);
}

// ---- cache and clock ----
#[test]
fn cache_fresh_stale_expired() {
    let v = verifier();
    let mut c = Cache::new(60);
    assert_eq!(c.get(&v, &req(), NOW).unwrap(), Lookup::Miss);
    c.put(&req(), issued()).unwrap();
    assert!(matches!(
        c.get(&v, &req(), NOW + 10).unwrap(),
        Lookup::Fresh(_)
    ));
    assert!(matches!(
        c.get(&v, &req(), NOW + 1800).unwrap(),
        Lookup::Stale(_)
    ));
    assert_eq!(c.get(&v, &req(), NOW + 4000).unwrap(), Lookup::Miss);
    assert!(c.is_empty(), "expired entry evicted");
}
#[test]
fn cache_is_bounded() {
    let v = verifier();
    let mut c = Cache::new(60).with_max_entries(4);
    let mut requests = vec![];
    for i in 0..10 {
        let mut r = req();
        r["subject"]["id"] = json!(format!("x5t#S256:abc{i}"));
        let jws = issue(&key(1), &pol(), &r, &answer(), NOW).unwrap();
        c.put(&r, jws).unwrap();
        requests.push(r);
    }
    assert_eq!(c.len(), 4, "the cache is bounded by its capacity");
    assert_eq!(
        c.get(&v, &requests[0], NOW).unwrap(),
        Lookup::Miss,
        "the oldest entry was evicted"
    );
    assert!(
        matches!(c.get(&v, &requests[9], NOW).unwrap(), Lookup::Fresh(_)),
        "the newest entry is still usable"
    );
}
#[test]
fn cache_order_survives_get_eviction_and_re_put() {
    let v = verifier();
    let mut c = Cache::new(60).with_max_entries(3);
    let named = |tag: &str| {
        let mut r = req();
        r["subject"]["id"] = json!(format!("x5t#S256:{tag}"));
        r
    };
    let a = named("a");
    let b = named("b");
    let cc = named("c");
    let d = named("d");
    let e = named("e");
    for r in [&a, &b, &cc] {
        c.put(r, issue(&key(1), &pol(), r, &answer(), NOW).unwrap())
            .unwrap();
    }
    // replace b with a receipt signed by an unpinned key: the failed verify
    // evicts b from both the entries and the eviction order
    c.put(&b, issue(&key(2), &pol(), &b, &answer(), NOW).unwrap())
        .unwrap();
    assert_eq!(c.get(&v, &b, NOW).unwrap(), Lookup::Miss);
    assert_eq!(c.len(), 2);
    // re-putting b replaces it without evicting and without leaving a stale
    // order slot ahead of b's live position
    c.put(&b, issue(&key(1), &pol(), &b, &answer(), NOW).unwrap())
        .unwrap();
    assert_eq!(c.len(), 3, "re-put at capacity replaces, it does not evict");
    c.put(&d, issue(&key(1), &pol(), &d, &answer(), NOW).unwrap())
        .unwrap();
    c.put(&e, issue(&key(1), &pol(), &e, &answer(), NOW).unwrap())
        .unwrap();
    assert_eq!(c.len(), 3);
    // a and c are the oldest live entries and are the eviction victims; the
    // re-inserted b is newer than both and survives
    assert_eq!(c.get(&v, &a, NOW).unwrap(), Lookup::Miss);
    assert_eq!(c.get(&v, &cc, NOW).unwrap(), Lookup::Miss);
    assert!(matches!(c.get(&v, &b, NOW).unwrap(), Lookup::Fresh(_)));
}
#[test]
fn cache_capacity_zero_disables_caching() {
    let v = verifier();
    let mut c = Cache::new(60).with_max_entries(0);
    c.put(&req(), issued()).unwrap();
    assert!(c.is_empty());
    assert_eq!(c.get(&v, &req(), NOW).unwrap(), Lookup::Miss);
}
#[test]
fn cache_rejects_a_receipt_stored_under_the_wrong_request() {
    let v = verifier();
    let mut c = Cache::new(60);
    let mut other = req();
    other["action"]["name"] = json!("verifier");
    // poison: a receipt for `req` filed under `other`'s hash
    c.put(&other, issued()).unwrap();
    assert_eq!(c.get(&v, &other, NOW).unwrap(), Lookup::Miss);
}
#[test]
fn cache_hit_reverifies_so_key_rotation_takes_effect() {
    let mut v = verifier();
    let mut c = Cache::new(60);
    c.put(&req(), issued()).unwrap();
    assert!(matches!(c.get(&v, &req(), NOW).unwrap(), Lookup::Fresh(_)));
    v.keys.clear(); // the pin was rotated away
    assert_eq!(c.get(&v, &req(), NOW + 1).unwrap(), Lookup::Miss);
}
#[test]
fn clock_rollback_cannot_resurrect_an_expired_receipt() {
    let v = verifier();
    let mut c = Cache::new(60);
    c.put(&req(), issued()).unwrap();
    assert!(matches!(
        c.get(&v, &req(), NOW + 3000).unwrap(),
        Lookup::Stale(_)
    ));
    // device clock rolled back to before issue time
    assert!(c
        .get(&v, &req(), NOW)
        .unwrap_err()
        .to_string()
        .contains("clock_rolled_back"));
    // small jitter inside the skew is tolerated, and never moves time backwards
    assert!(matches!(
        c.get(&v, &req(), NOW + 2990).unwrap(),
        Lookup::Stale(_)
    ));
    assert_eq!(c.get(&v, &req(), NOW + 3700).unwrap(), Lookup::Miss);
}

#[test]
fn structural_limits() {
    assert!(
        err(verifier().verify(&format!("{}.x", issued()), &req(), NOW)).contains("receipt_parts")
    );
    let big = "a".repeat(17 * 1024);
    assert!(err(verifier().verify(&big, &req(), NOW)).contains("receipt_too_large"));
}

#[test]
fn clock_cannot_be_ratcheted_back_in_small_steps() {
    let mut m = Monotonic::new(60);
    assert_eq!(m.observe(3000).unwrap(), 3000);
    assert_eq!(
        m.observe(2950).unwrap(),
        3000,
        "jitter inside skew never lowers the mark"
    );
    assert!(
        m.observe(2900).is_err(),
        "each step is within skew of the last, but not of the mark"
    );
}

/// Differential test against Go's jsontext.Value.Canonicalize (RFC 8785), see tools/jcs-go.
/// Inputs with floating-point syntax are the one deliberate difference: Rust refuses them.
#[test]
fn canonical_form_and_hash_match_go() {
    let golden: Vec<Value> =
        serde_json::from_str(include_str!("vectors/jcs_go_golden.json")).unwrap();
    assert!(golden.len() >= 15);
    let (mut agreed, mut refused) = (0, 0);
    for g in &golden {
        let input = g["input"].as_str().unwrap();
        let v: Value = serde_json::from_str(input).unwrap();
        match canonical_json(&v) {
            Ok(c) => {
                assert_eq!(
                    String::from_utf8(c).unwrap(),
                    g["canonical"].as_str().unwrap(),
                    "input {input}"
                );
                assert_eq!(
                    req_sha256(&v).unwrap(),
                    g["sha256"].as_str().unwrap(),
                    "input {input}"
                );
                agreed += 1;
            }
            Err(e) => {
                let m = e.to_string();
                if m.contains("canonical_json_float") {
                    let b = input.as_bytes();
                    let float_syntax = b.windows(3).any(|w| {
                        w[0].is_ascii_digit()
                            && (w[1] == b'.' || w[1] == b'e' || w[1] == b'E')
                            && w[2].is_ascii_digit()
                    });
                    assert!(float_syntax, "refused a non-float: {input}");
                } else {
                    // Go rounds to a double here; we refuse instead of reproducing the rounding.
                    assert!(m.contains("canonical_json_integer_range"), "{input}: {m}");
                    assert_ne!(
                        g["canonical"].as_str().unwrap(),
                        input.replace(' ', ""),
                        "Go did not round: {input}"
                    );
                }
                refused += 1;
            }
        }
    }
    assert_eq!((agreed, refused), (golden.len() - 5, 5)); // 3 float inputs, 2 integer inputs beyond 2^53
}
