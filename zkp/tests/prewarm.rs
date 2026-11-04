mod support;

use siros_verifier_zkp::backend::*;
use siros_verifier_zkp::circuits::*;
use siros_verifier_zkp::functions::FunctionRegistry;
use siros_verifier_zkp::nym_auth::*;
use siros_verifier_zkp::refusal::*;
use siros_verifier_zkp::verify::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use support::*;

fn policy() -> VerifierPolicy {
    VerifierPolicy {
        role: "r".into(),
        issuer_set: siros_verifier_core::issuer_set::IssuerSetPolicy::AllTrusted,
        tolerance: Default::default(),
    }
}

fn verifier_with<F>(allow: Allowlist, factory: F) -> ZkpVerifier
where
    F: Fn(&Entry, &[u8]) -> ZkpResult<Box<dyn ProofBackend>> + Send + Sync + 'static,
{
    let mut registry = BackendRegistry::new();
    registry
        .register(
            SYSTEM_LONGFELLOW,
            SystemProfile::single_issuer_age_check(),
            factory,
        )
        .unwrap();
    ZkpVerifier::new(
        allow,
        Box::new(FsArtifactSource),
        FunctionRegistry::with_builtins(),
        registry,
        policy(),
    )
    .unwrap()
}

#[test]
fn prewarm_loads_every_allowed_entry_and_reuses_successes() {
    let (_lf, longfellow) = artifact(b"longfellow");
    let (_vf, mut vega) = artifact(b"vega");
    vega.system_id = SYSTEM_VEGA.into();
    vega.hash_circuit_id.clear();
    vega.sig_circuit_id.clear();
    vega.block_enc_hash = 0;
    vega.block_enc_sig = 0;
    let allow = Allowlist::new(&CircuitsConfig {
        sources: vec![],
        allow: vec![longfellow, vega],
    })
    .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut registry = BackendRegistry::new();
    for system in [SYSTEM_LONGFELLOW, SYSTEM_VEGA] {
        let calls = calls.clone();
        registry
            .register(
                system,
                SystemProfile::single_issuer_age_check(),
                move |entry, _| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(Box::new(Model {
                        config: entry.config.clone(),
                    }))
                },
            )
            .unwrap();
    }
    let verifier = ZkpVerifier::new(
        allow,
        Box::new(FsArtifactSource),
        FunctionRegistry::with_builtins(),
        registry,
        policy(),
    )
    .unwrap();

    verifier.prewarm().unwrap();
    verifier.prewarm().unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn concurrent_prewarm_is_single_flight_per_verifier() {
    let (_file, config) = artifact(b"shared");
    let allow = Allowlist::new(&CircuitsConfig {
        sources: vec![],
        allow: vec![config],
    })
    .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_in_factory = calls.clone();
    let verifier = Arc::new(verifier_with(allow, move |entry, _| {
        calls_in_factory.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(50));
        Ok(Box::new(Model {
            config: entry.config.clone(),
        }))
    }));

    let threads: Vec<_> = (0..8)
        .map(|_| {
            let verifier = verifier.clone();
            std::thread::spawn(move || verifier.prewarm())
        })
        .collect();
    for thread in threads {
        thread.join().unwrap().unwrap();
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn a_failed_prewarm_is_not_cached_and_can_be_retried() {
    let (_file, config) = artifact(b"retry");
    let allow = Allowlist::new(&CircuitsConfig {
        sources: vec![],
        allow: vec![config],
    })
    .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_in_factory = calls.clone();
    let verifier = verifier_with(allow, move |entry, _| {
        let attempt = calls_in_factory.fetch_add(1, Ordering::SeqCst);
        if attempt == 0 {
            Err(ZkpError::fault("transient native initialization failure"))
        } else {
            Ok(Box::new(Model {
                config: entry.config.clone(),
            }))
        }
    });

    verifier.prewarm().unwrap_err();
    verifier.prewarm().unwrap();
    verifier.prewarm().unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn loaded_backends_are_isolated_per_verifier_instance() {
    let (_file, config) = artifact(b"isolated");
    let allow = || {
        Allowlist::new(&CircuitsConfig {
            sources: vec![],
            allow: vec![config.clone()],
        })
        .unwrap()
    };
    let first_calls = Arc::new(AtomicUsize::new(0));
    let second_calls = Arc::new(AtomicUsize::new(0));
    let first = verifier_with(allow(), {
        let calls = first_calls.clone();
        move |entry, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(Model {
                config: entry.config.clone(),
            }))
        }
    });
    let second = verifier_with(allow(), {
        let calls = second_calls.clone();
        move |entry, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(Model {
                config: entry.config.clone(),
            }))
        }
    });

    first.prewarm().unwrap();
    second.prewarm().unwrap();

    assert_eq!(first_calls.load(Ordering::SeqCst), 1);
    assert_eq!(second_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn prewarm_rejects_a_wrong_artifact_before_calling_the_factory() {
    let (file, mut config) = artifact(b"actual bytes");
    config.artifact_sha256 = "00".repeat(32);
    let allow = Allowlist::new(&CircuitsConfig {
        sources: vec![],
        allow: vec![config],
    })
    .unwrap();
    let verifier = verifier_with(allow, |_, _| {
        panic!("a wrong artifact must never reach native initialization")
    });

    let error = verifier.prewarm().unwrap_err();
    assert!(error.to_string().contains("hashes to"), "{error}");
    drop(file);
}
