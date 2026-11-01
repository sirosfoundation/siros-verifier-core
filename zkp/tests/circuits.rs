//! The circuit allowlist: what an operator may configure, and the artifact checks (ported from SUNET/vc's circuits).
mod support;

use sha2::{Digest, Sha256};
use siros_verifier_zkp::circuits::*;
use siros_verifier_zkp::nym_auth::*;
use siros_verifier_zkp::refusal::ZkpError;

fn sha(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

fn longfellow() -> CircuitConfig {
    CircuitConfig {
        system_id: SYSTEM_LONGFELLOW.into(),
        config: CONFIG_KNOWN_OFFENDER_MATCHING_SSC.into(),
        hash_circuit_id: "aa11".into(),
        sig_circuit_id: "bb22".into(),
        block_enc_hash: 4,
        block_enc_sig: 7,
        artifact_path: "/nonexistent/circuit.bin".into(),
        artifact_id: String::new(),
        artifact_sha256: sha(b"x"),
        artifact_bytes: 1,
    }
}

fn vega() -> CircuitConfig {
    CircuitConfig {
        system_id: SYSTEM_VEGA.into(),
        hash_circuit_id: String::new(),
        sig_circuit_id: String::new(),
        block_enc_hash: 0,
        block_enc_sig: 0,
        ..longfellow()
    }
}

fn cfg(allow: Vec<CircuitConfig>) -> CircuitsConfig {
    CircuitsConfig {
        sources: vec![],
        allow,
    }
}

fn err(r: Result<Allowlist, ZkpError>) -> String {
    r.err()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "OK".into())
}

#[test]
fn a_valid_allowlist_resolves_and_lists_sorted() {
    let a = Allowlist::new(&cfg(vec![vega(), longfellow()])).unwrap();
    assert_eq!(
        a.allowed(),
        vec![
            format!("{SYSTEM_LONGFELLOW} {CONFIG_KNOWN_OFFENDER_MATCHING_SSC}"),
            format!("{SYSTEM_VEGA} {CONFIG_KNOWN_OFFENDER_MATCHING_SSC}"),
        ]
    );
    assert_eq!(
        a.entry(SYSTEM_VEGA, CONFIG_KNOWN_OFFENDER_MATCHING_SSC)
            .unwrap()
            .system_id,
        SYSTEM_VEGA
    );
    assert!(
        a.entry(SYSTEM_VEGA, CONFIG_KNOWN_OFFENDER_MATCHING_PSC)
            .is_err(),
        "no circuit for that configuration"
    );
    assert!(a
        .entry("urn:other", CONFIG_KNOWN_OFFENDER_MATCHING_SSC)
        .is_err());
}

#[test]
fn two_systems_for_one_configuration_are_two_entries_not_a_clash() {
    Allowlist::new(&cfg(vec![longfellow(), vega()])).expect("a verifier may offer both systems");
}

#[test]
fn a_second_build_for_one_system_and_configuration_is_refused_not_resolved_by_order() {
    let e = err(Allowlist::new(&cfg(vec![longfellow(), longfellow()])));
    assert!(e.contains("a second circuit is allowed"), "{e}");
}

#[test]
fn unknown_systems_and_configurations_are_refused() {
    let mut c = longfellow();
    c.system_id = "urn:circuits:other:nym_auth:v1".into();
    assert!(err(Allowlist::new(&cfg(vec![c]))).contains("not a nym_auth system_id"));
    let mut c = longfellow();
    c.config = "account-recovery-ssc".into();
    assert!(
        err(Allowlist::new(&cfg(vec![c]))).contains("not a known-offender-matching configuration")
    );
    let mut c = longfellow();
    c.system_id.clear();
    assert!(Allowlist::new(&cfg(vec![c])).is_err());
}

#[test]
fn longfellow_needs_all_four_parameters_and_they_must_make_sense() {
    let mut c = longfellow();
    c.hash_circuit_id.clear();
    assert!(err(Allowlist::new(&cfg(vec![c]))).contains("hash_circuit_id is empty"));
    let mut c = longfellow();
    c.sig_circuit_id = "zz".into();
    assert!(err(Allowlist::new(&cfg(vec![c]))).contains("sig_circuit_id is not hex"));
    let mut c = longfellow();
    c.sig_circuit_id = c.hash_circuit_id.clone();
    assert!(err(Allowlist::new(&cfg(vec![c]))).contains("are the same"));
    let mut c = longfellow();
    c.block_enc_hash = 0;
    assert!(err(Allowlist::new(&cfg(vec![c]))).contains("block_enc_hash is zero"));
    let mut c = longfellow();
    c.block_enc_sig = 0;
    assert!(err(Allowlist::new(&cfg(vec![c]))).contains("block_enc_sig is zero"));
}

#[test]
fn vega_refuses_longfellow_parameters_because_nothing_would_ever_check_them() {
    for (what, f) in [
        (
            "hash_circuit_id",
            Box::new(|c: &mut CircuitConfig| c.hash_circuit_id = "aa".into())
                as Box<dyn Fn(&mut CircuitConfig)>,
        ),
        (
            "sig_circuit_id",
            Box::new(|c| c.sig_circuit_id = "bb".into()),
        ),
        ("block_enc_hash", Box::new(|c| c.block_enc_hash = 1)),
        ("block_enc_sig", Box::new(|c| c.block_enc_sig = 1)),
    ] {
        let mut c = vega();
        f(&mut c);
        let e = err(Allowlist::new(&cfg(vec![c])));
        assert!(
            e.contains(what) && e.contains("Longfellow parameter"),
            "{what}: {e}"
        );
    }
}

#[test]
fn the_artifact_statement_must_be_complete_and_consistent() {
    let mut c = longfellow();
    c.artifact_sha256 = "abc".into();
    assert!(err(Allowlist::new(&cfg(vec![c]))).contains("64-character hex"));
    let mut c = longfellow();
    c.artifact_sha256 = "z".repeat(64);
    assert!(err(Allowlist::new(&cfg(vec![c]))).contains("64-character hex"));
    let mut c = longfellow();
    c.artifact_bytes = 0;
    assert!(err(Allowlist::new(&cfg(vec![c]))).contains("artifact_bytes must be positive"));
    let mut c = longfellow();
    c.artifact_path.clear();
    assert!(
        err(Allowlist::new(&cfg(vec![c]))).contains("exactly one of artifact_path and artifact_id")
    );
    let mut c = longfellow();
    c.artifact_id = "catalog-id".into();
    assert!(
        err(Allowlist::new(&cfg(vec![c]))).contains("exactly one of artifact_path and artifact_id")
    );
    // an id with nowhere to fetch it from
    let mut c = longfellow();
    c.artifact_path.clear();
    c.artifact_id = "catalog-id".into();
    assert!(
        err(Allowlist::new(&cfg(vec![c.clone()]))).contains("no circuits.sources are configured")
    );
    let with_source = CircuitsConfig {
        sources: vec!["https://catalog.example/".into()],
        allow: vec![c],
    };
    Allowlist::new(&with_source).expect("an id with a source is accepted");
}

#[test]
fn catalog_sources_must_be_http_urls_with_a_host() {
    for bad in [
        "ftp://x.example/",
        "catalog.example",
        "https://",
        "https:///path",
        "",
    ] {
        let c = CircuitsConfig {
            sources: vec![bad.into()],
            allow: vec![],
        };
        assert!(Allowlist::new(&c).is_err(), "{bad:?}");
    }
    for ok in ["https://catalog.example/", "http://localhost:8080/c"] {
        Allowlist::new(&CircuitsConfig {
            sources: vec![ok.into()],
            allow: vec![],
        })
        .unwrap();
    }
}

#[test]
fn unknown_configuration_members_are_refused_at_parse_time() {
    let r: Result<CircuitsConfig, _> = serde_json::from_str(r#"{"allow": [], "typo": 1}"#);
    assert!(r.is_err());
    let r: Result<CircuitConfig, _> = serde_json::from_str(
        r#"{"system_id":"x","config":"y","artifact_sha256":"z","artifact_bytes":1,"artifact_pathh":"/p"}"#,
    );
    assert!(r.is_err(), "a misspelled member must not be ignored");
}

#[test]
fn artifact_bytes_are_checked_against_the_entrys_own_statement() {
    let bytes = b"circuit bytes";
    let mut c = longfellow();
    c.artifact_sha256 = sha(bytes);
    c.artifact_bytes = bytes.len() as u64;
    let a = Allowlist::new(&cfg(vec![c])).unwrap();
    let entry = a
        .entry(SYSTEM_LONGFELLOW, CONFIG_KNOWN_OFFENDER_MATCHING_SSC)
        .unwrap();
    check_artifact(entry, bytes).unwrap();
    let e = check_artifact(entry, b"circuit byteX")
        .unwrap_err()
        .to_string();
    assert!(e.contains("hashes to"), "same length, other content: {e}");
    let e = check_artifact(entry, b"circuit").unwrap_err().to_string();
    assert!(e.contains("is 7 bytes; the allowlist says 13"), "{e}");
    let e = check_artifact(entry, b"circuit bytes!")
        .unwrap_err()
        .to_string();
    assert!(e.contains("is 14 bytes"), "{e}");
}

#[test]
fn the_file_source_reads_at_most_one_byte_past_the_declared_length() {
    let (file, mut c) = support::artifact(b"0123456789");
    c.artifact_bytes = 4; // the operator declared 4 bytes; the file has 10
    c.artifact_sha256 = sha(b"0123");
    let a = Allowlist::new(&cfg(vec![c])).unwrap();
    let entry = a
        .entry(SYSTEM_LONGFELLOW, CONFIG_KNOWN_OFFENDER_MATCHING_SSC)
        .unwrap();
    let got = FsArtifactSource.read(entry).unwrap();
    assert_eq!(got.len(), 5, "declared length plus one: enough to see it is too long, not enough to hash it as if it fit");
    assert!(
        check_artifact(entry, &got).is_err(),
        "a too-long artifact is refused, not truncated and hashed"
    );
    drop(file);
    // a missing file is a fault with the path's context, and a catalog id is not resolved
    let a = Allowlist::new(&cfg(vec![longfellow()])).unwrap();
    let e = FsArtifactSource
        .read(
            a.entry(SYSTEM_LONGFELLOW, CONFIG_KNOWN_OFFENDER_MATCHING_SSC)
                .unwrap(),
        )
        .unwrap_err();
    assert!(!e.is_refusal());
    let mut c = longfellow();
    c.artifact_path.clear();
    c.artifact_id = "cid".into();
    let a = Allowlist::new(&CircuitsConfig {
        sources: vec!["https://c.example/".into()],
        allow: vec![c],
    })
    .unwrap();
    let e = FsArtifactSource
        .read(
            a.entry(SYSTEM_LONGFELLOW, CONFIG_KNOWN_OFFENDER_MATCHING_SSC)
                .unwrap(),
        )
        .unwrap_err();
    assert!(e.to_string().contains("cannot resolve yet"), "{e}");
}

#[test]
fn a_wrong_artifact_is_a_fault_found_at_first_use() {
    // allowed with one digest, the file holds another
    let (file, mut c) = support::artifact(b"the real artifact");
    c.artifact_sha256 = sha(b"a different artifact");
    let allow = Allowlist::new(&cfg(vec![c])).unwrap();
    let mut reg = siros_verifier_zkp::backend::BackendRegistry::new();
    reg.register(
        SYSTEM_LONGFELLOW,
        siros_verifier_zkp::backend::SystemProfile::single_issuer_age_check(),
        |_, _| panic!("a circuit that failed its digest must never reach a loader"),
    )
    .unwrap();
    let v = siros_verifier_zkp::verify::ZkpVerifier::new(
        allow,
        Box::new(FsArtifactSource),
        siros_verifier_zkp::functions::FunctionRegistry::with_builtins(),
        reg,
        siros_verifier_zkp::verify::VerifierPolicy {
            role: "r".into(),
            issuer_set: siros_verifier_core::issuer_set::IssuerSetPolicy::AllTrusted,
            tolerance: Default::default(),
        },
    )
    .unwrap();
    let f = support::fx(support::Opts::default());
    let plan = f.plan.clone();
    let ch = support::dc_channel();
    let ex = siros_verifier_zkp::verify::Exchange {
        plan: &plan,
        channel: &ch,
        nonce: support::NONCE,
        reader_thumbprint: None,
        verifier_id: support::VERIFIER_ID,
        now: support::NOW,
    };
    let pending = v.begin(&ex, &support::vp_token(&[f.honest()])).unwrap();
    let e = pending.finish(&support::trusted(1)).unwrap_err();
    assert!(
        !e.is_refusal(),
        "an operator's artifact problem is not the wallet's: {e}"
    );
    assert!(e.to_string().contains("hashes to"), "{e}");
    drop(file);
}

#[test]
fn an_allowed_system_with_no_registered_backend_is_found_at_startup() {
    let (_f, c) = support::artifact(b"x");
    let allow = Allowlist::new(&cfg(vec![c])).unwrap();
    let r = siros_verifier_zkp::verify::ZkpVerifier::new(
        allow,
        Box::new(FsArtifactSource),
        siros_verifier_zkp::functions::FunctionRegistry::with_builtins(),
        siros_verifier_zkp::backend::BackendRegistry::new(),
        siros_verifier_zkp::verify::VerifierPolicy {
            role: "r".into(),
            issuer_set: siros_verifier_core::issuer_set::IssuerSetPolicy::AllTrusted,
            tolerance: Default::default(),
        },
    );
    assert!(r.is_err());
}
