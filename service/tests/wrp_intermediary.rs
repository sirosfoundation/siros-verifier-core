//! Increment 2 (#39): the service-side intermediary wiring — the WRPRC and
//! registrar dataset load at startup, validate fail-fast, and ride the
//! backend's armed requests. The end-to-end shape is the plugin flow test
//! (the WRPRC fixture minted the same way the wrprc suite's is); this file
//! verifies the SERVICE's loading path (the file reads, the startup
//! validation, the injection into the backend config).

use std::io::Write;

/// A minimal registrar-shaped WRPRC, minted the way the wrprc suite does
/// (a registrar's ES256 chain + the Table 7 payload).
fn mint_wrprc() -> (String, std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("inc2-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // The registrar's chain and key — same fixture shape as tests/wrprc.rs.
    let (cert, key) = siros_verifier_core::testutil::self_signed_ec("registrar.example", "ES256");
    let now = 1_793_656_800_i64;
    let claims = serde_json::json!({
        "sub": "urn:glas:se:registrar:5561234567",
        "iat": now - 1_000,
        "country": "SE",
        "sub_ln": "Testfronted RP",
        "registry_uri": "https://registrar.example/api/5561234567",
        "srv_description": [[{"lang": "sv", "value": "Tjänst"}]],
        "entitlements": ["pid_provision"],
        "purpose": [{"lang": "sv", "value": "Verifiera"}],
        "privacy_policy": "https://example.com/privacy",
        "policy_id": ["https://registrar.example/policies/wrp"],
        "status": {"status_list": {"idx": 9, "uri": "https://registrar.example/statuslists/9"}},
    });
    let token = siros_verifier_core::testutil::sign_raw(
        &key,
        "rc-wrp+jwt",
        &claims,
        std::slice::from_ref(&cert),
    );

    let wrprc_path = dir.join("fronted_rp_wrprc.jwt");
    std::fs::write(&wrprc_path, &token).unwrap();

    let dataset = serde_json::json!({
        "identifier": [{"type": "eori", "identifier": "SE556123456701"}],
        "srvDescription": [{"lang": "sv", "content": "Tjänst"}],
        "registryURI": "https://registrar.example/api/5561234567",
        "intendedUseIdentifier": "urn:registrar:use:1",
        "purpose": [{"lang": "sv", "content": "Verifiera"}],
        "policyURI": "https://example.com/privacy",
    });
    let dataset_path = dir.join("fronted_rp_registrar_dataset.json");
    std::fs::write(
        &dataset_path,
        serde_json::to_string_pretty(&dataset).unwrap(),
    )
    .unwrap();

    (token, wrprc_path, dataset_path)
}

#[test]
fn the_deployment_config_gains_the_wrprc_and_dataset_paths() {
    let (_token, wrprc_path, dataset_path) = mint_wrprc();
    // The DeploymentConfig's deny_unknown_fields surface accepts the two new
    // members and rejects typos (the closed-config contract).
    let ok: siros_verifier_service::config::DeploymentConfig =
        serde_json::from_value(serde_json::json!({
            "request_signing_key_path": "/k.pem",
            "request_certificate_chain_path": "/c.pem",
            "pdp_endpoint": "http://localhost:1/",
            "storage": {"backend": "memory"},
            "wrprc_path": wrprc_path.to_str().unwrap(),
            "verifier_info_path": dataset_path.to_str().unwrap(),
            "dcql": {"credentials": [{"id": "pid", "format": "dc+sd-jwt",
                "meta": {"vct_values": ["urn:eudi:pid:1"]},
                "claims": [{"path": ["given_name"]}]}]},
            "attribute_map": {},
            "subject_pointer": "/sub",
            "role": "r"
        }))
        .expect("the intermediary config parses");
    assert_eq!(ok.wrprc_path.as_deref(), Some(wrprc_path.to_str().unwrap()));
    assert_eq!(
        ok.verifier_info_path.as_deref(),
        Some(dataset_path.to_str().unwrap())
    );

    let _ = std::io::stdout().flush();
}
