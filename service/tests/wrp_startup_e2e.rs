//! Increment 2 (#39): the SERVICE BINARY's startup — the WRPRC and registrar
//! dataset load from files, validate fail-fast, and REFUSE to boot on
//! malformed inputs. Exercises the actual binary (the same pattern as
//! startup.rs), not just the library parsers.

use std::net::TcpListener;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

fn setup_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("inc2-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["verifier.example".to_string()])
        .unwrap()
        .self_signed(&kp)
        .unwrap();
    std::fs::write(dir.join("key.pem"), kp.serialize_pem()).unwrap();
    std::fs::write(dir.join("chain.pem"), cert.pem()).unwrap();
    dir
}

fn write_config(dir: &std::path::Path, extra: &str) -> std::path::PathBuf {
    let config_path = dir.join("proxy.toml");
    let config = format!(
        r#"
        base_url = "https://verifier.example"
        state_encryption_key = "a-32-byte-or-longer-test-secret!!"
        cookie_secure = false

        [[frontend]]
        type = "ui"
        name = "ui"

        [[frontend]]
        type = "oidc"
        name = "OIDC"
          [frontend.config]
          signing_key_path = "{key}"
          signing_algorithm = "ES256"

        [[backend]]
        type = "openid4vp"
        name = "vp"
          [backend.config]
          request_signing_key_path = "{key}"
          request_certificate_chain_path = "{chain}"
          pdp_endpoint = "http://go-trust-allow:6001/evaluation"
          allow_insecure_http = true
          role = "pid-provider"
          dcql = {{ credentials = [{{ id = "pid", format = "dc+sd-jwt",
            claims = [{{ path = ["given_name"] }}] }}] }}
          attribute_map = {{}}
          subject_pointer = "/sub"

{extra}
          [backend.config.storage]
          backend = "memory"
    "#,
        key = dir.join("key.pem").display(),
        chain = dir.join("chain.pem").display(),
        extra = extra,
    );
    std::fs::write(&config_path, config).unwrap();
    config_path
}

fn mint_wrprc(iat: i64) -> String {
    let (cert, key) = siros_verifier_core::testutil::self_signed_ec("registrar.example", "ES256");
    let claims = serde_json::json!({
        "sub": "urn:glas:se:registrar:5561234567",
        "iat": iat,
        "country": "SE",
        "sub_ln": "Testfronted RP",
        "registry_uri": "https://registrar.example/api/5561234567",
        "srv_description": [[{"lang": "sv", "value": "Tjänst"}]],
        "entitlements": ["pid_provision"],
        "privacy_policy": "https://example.com/privacy",
    });
    siros_verifier_core::testutil::sign_raw(
        &key,
        "rc-wrp+jwt",
        &claims,
        std::slice::from_ref(&cert),
    )
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn expect_exit_before_healthy(dir: &std::path::Path, config_path: &std::path::PathBuf) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut child = Command::new(env!("CARGO_BIN_EXE_siros-verifier-service"))
        .arg(config_path)
        .env("TUNNELBANA_BIND", address.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    // Wait for the child to exit with a failure (it should refuse to boot).
    let status = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the service exits within 30s");
    assert!(
        !status.success(),
        "the service must refuse to boot, but exited successfully: {status}"
    );
    let _ = dir;
}

async fn expect_healthy(dir: &std::path::Path, config_path: &std::path::PathBuf) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut child = Command::new(env!("CARGO_BIN_EXE_siros-verifier-service"))
        .arg(config_path)
        .env("TUNNELBANA_BIND", address.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("service exited before becoming healthy: {status}");
            }
            if let Ok(response) = client.get(format!("http://{address}/health")).send().await {
                if response.status().is_success() {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the service becomes healthy");
    let _ = child.kill().await;
    let _ = dir;
}

#[tokio::test]
async fn a_valid_intermediary_config_boots_and_becomes_healthy() {
    let dir = setup_dir("valid-control");
    let wrprc = mint_wrprc(now() - 100);
    std::fs::write(dir.join("wrprc.jwt"), &wrprc).unwrap();
    std::fs::write(
        dir.join("dataset.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "identifier": [{"type": "eori", "identifier": "SE556123456701"}],
            "srvDescription": [{"lang": "sv", "content": "Tjänst"}],
            "registryURI": "https://registrar.example/api/5561234567",
            "intendedUseIdentifier": "urn:registrar:use:1",
            "purpose": [{"lang": "sv", "content": "Verifiera"}],
            "policyURI": "https://example.com/privacy",
        }))
        .unwrap(),
    )
    .unwrap();
    let extra = format!(
        "          wrprc_path = \"{}\"\n          verifier_info_path = \"{}\"\n",
        dir.join("wrprc.jwt").display(),
        dir.join("dataset.json").display(),
    );
    let config_path = write_config(&dir, &extra);
    expect_healthy(&dir, &config_path).await;
}

#[tokio::test]
async fn a_malformed_wrprc_file_refuses_to_boot() {
    let dir = setup_dir("malformed");
    std::fs::write(dir.join("wrprc.jwt"), "this is not a jwt").unwrap();
    let extra = format!(
        "          wrprc_path = \"{}\"\n",
        dir.join("wrprc.jwt").display()
    );
    let config_path = write_config(&dir, &extra);
    expect_exit_before_healthy(&dir, &config_path).await;
}

#[tokio::test]
async fn a_future_dated_wrprc_file_refuses_to_boot() {
    let dir = setup_dir("future");
    let wrprc = mint_wrprc(now() + 120);
    std::fs::write(dir.join("wrprc.jwt"), &wrprc).unwrap();
    let extra = format!(
        "          wrprc_path = \"{}\"\n",
        dir.join("wrprc.jwt").display()
    );
    let config_path = write_config(&dir, &extra);
    expect_exit_before_healthy(&dir, &config_path).await;
}

#[tokio::test]
async fn an_expired_wrprc_file_refuses_to_boot() {
    let dir = setup_dir("expired");
    let (cert, key) = siros_verifier_core::testutil::self_signed_ec("registrar.example", "ES256");
    let claims = serde_json::json!({
        "sub": "urn:glas:se:registrar:5561234567",
        "iat": now() - 10_000,
        "exp": now() - 1,
        "registry_uri": "https://registrar.example/api/5561234567",
        "srv_description": [[{"lang": "sv", "value": "Tjänst"}]],
        "entitlements": ["pid_provision"],
        "privacy_policy": "https://example.com/privacy",
    });
    let wrprc = siros_verifier_core::testutil::sign_raw(
        &key,
        "rc-wrp+jwt",
        &claims,
        std::slice::from_ref(&cert),
    );
    std::fs::write(dir.join("wrprc.jwt"), &wrprc).unwrap();
    let extra = format!(
        "          wrprc_path = \"{}\"\n",
        dir.join("wrprc.jwt").display()
    );
    let config_path = write_config(&dir, &extra);
    expect_exit_before_healthy(&dir, &config_path).await;
}

#[tokio::test]
async fn an_invalid_dataset_file_refuses_to_boot() {
    let dir = setup_dir("bad-dataset");
    let wrprc = mint_wrprc(now() - 100);
    std::fs::write(dir.join("wrprc.jwt"), &wrprc).unwrap();
    std::fs::write(dir.join("dataset.json"), r#"{"identifier": []}"#).unwrap();
    let extra = format!(
        "          wrprc_path = \"{}\"\n          verifier_info_path = \"{}\"\n",
        dir.join("wrprc.jwt").display(),
        dir.join("dataset.json").display(),
    );
    let config_path = write_config(&dir, &extra);
    expect_exit_before_healthy(&dir, &config_path).await;
}

#[tokio::test]
async fn an_inline_wrprc_member_refuses_to_boot() {
    let dir = setup_dir("inline");
    let extra = "          wrprc = \"some-inline-value\"\n".to_owned();
    let config_path = write_config(&dir, &extra);
    expect_exit_before_healthy(&dir, &config_path).await;
}

#[tokio::test]
async fn an_unreadable_wrprc_path_refuses_to_boot() {
    let dir = setup_dir("unreadable");
    let missing = dir.join("does-not-exist.jwt");
    let extra = format!("          wrprc_path = \"{}\"\n", missing.display());
    let config_path = write_config(&dir, &extra);
    expect_exit_before_healthy(&dir, &config_path).await;
}
