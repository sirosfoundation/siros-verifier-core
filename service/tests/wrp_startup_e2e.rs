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

        [logging]
        level = "info"
        format = "json"

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

/// Assert the service refuses to boot, with the expected refusal kind in
/// stderr — not just any failure (a broken key file would also fail, and
/// would not prove the WRPRC validation fired).
async fn expect_refusal(dir: &std::path::Path, config_path: &std::path::PathBuf, expected: &str) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut child = Command::new(env!("CARGO_BIN_EXE_siros-verifier-service"))
        .arg(config_path)
        .env("TUNNELBANA_BIND", address.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let (status, stderr) = tokio::time::timeout(Duration::from_secs(30), async {
        // Read stderr concurrently with the exit poll: the pipe is drained
        // in a spawned task so a chatty boot cannot deadlock on a full pipe.
        use tokio::io::AsyncReadExt;
        let mut stderr_pipe = child.stderr.take().unwrap();
        let read_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            let _ = stderr_pipe.read_to_end(&mut buf).await;
            buf
        });
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        let _ = child.wait().await;
        let stderr = read_task.await.unwrap_or_default();
        (status, stderr)
    })
    .await
    .expect("the service exits within 30s");
    assert!(
        !status.success(),
        "the service must refuse to boot, but exited successfully: {status}"
    );
    let stderr = String::from_utf8_lossy(&stderr);
    assert!(
        stderr.contains(expected),
        "the refusal must be {expected:?}, but stderr was:\n{stderr}"
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
    expect_refusal(&dir, &config_path, "wrprc_token_shape").await;
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
    expect_refusal(&dir, &config_path, "wrprc_iat_future").await;
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
    expect_refusal(&dir, &config_path, "wrprc_expired").await;
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
    expect_refusal(&dir, &config_path, "verifier_info_missing_identifier").await;
}

#[tokio::test]
async fn an_inline_wrprc_member_refuses_to_boot() {
    let dir = setup_dir("inline");
    let extra = "          wrprc = \"some-inline-value\"\n".to_owned();
    let config_path = write_config(&dir, &extra);
    expect_refusal(&dir, &config_path, "use `wrprc_path`").await;
}

#[tokio::test]
async fn an_unreadable_wrprc_path_refuses_to_boot() {
    let dir = setup_dir("unreadable");
    let missing = dir.join("does-not-exist.jwt");
    let extra = format!("          wrprc_path = \"{}\"\n", missing.display());
    let config_path = write_config(&dir, &extra);
    expect_refusal(&dir, &config_path, "reading WRPRC").await;
}

/// The service-to-backend injection, end to end through the real binary: the
/// files the service loads at startup are the members the served request
/// carries. Reverting either assignment in `build_openid4vp_backend` (the
/// WRPRC or the registrar dataset) fails this test — the request object the
/// wallet fetches would omit the configured data.
#[tokio::test]
async fn the_served_request_carries_the_configured_wrprc_and_dataset() {
    let dir = setup_dir("injection");
    let wrprc = mint_wrprc(now() - 100);
    std::fs::write(dir.join("wrprc.jwt"), &wrprc).unwrap();
    let dataset = serde_json::json!({
        "identifier": [{"type": "eori", "identifier": "SE556123456701"}],
        "srvDescription": [{"lang": "sv", "content": "Tjänst"}],
        "registryURI": "https://registrar.example/api/5561234567",
        "intendedUseIdentifier": "urn:registrar:use:1",
        "purpose": [{"lang": "sv", "content": "Verifiera"}],
        "policyURI": "https://example.com/privacy",
    });
    std::fs::write(
        dir.join("dataset.json"),
        serde_json::to_string_pretty(&dataset).unwrap(),
    )
    .unwrap();
    let extra = format!(
        "          wrprc_path = \"{}\"\n          verifier_info_path = \"{}\"\n",
        dir.join("wrprc.jwt").display(),
        dir.join("dataset.json").display(),
    );
    let config_path = write_config(&dir, &extra);

    // Boot the actual binary.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut child = Command::new(env!("CARGO_BIN_EXE_siros-verifier-service"))
        .arg(&config_path)
        .env("TUNNELBANA_BIND", address.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    // Drain stdout concurrently and keep it: the service's tracing logs
    // (the presentation's telemetry line among them) are asserted at the
    // end.
    use tokio::io::AsyncReadExt;
    let mut stdout_pipe = child.stdout.take().unwrap();
    let stdout_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf).await;
        buf
    });
    let base = format!("http://{address}");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("service exited before becoming healthy: {status}");
            }
            if let Ok(response) = client.get(format!("{base}/health")).send().await {
                if response.status().is_success() {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the service becomes healthy");

    // Initiate a presentation through the UI frontend, as the browser's
    // QR invocation does.
    let start = client
        .post(format!("{base}/ui/start/qr"))
        .form(&[("scheme", "openid4vp")])
        .send()
        .await
        .expect("the start request");
    assert_eq!(start.status(), 200);
    let page = start.text().await.expect("the start page");
    // The QR's launch URL carries the percent-encoded request URI; the flow
    // id it ends with is what the wallet's request fetch needs.
    const MARKER: &str = "vp%2Frequest%2F";
    let start_at = page.find(MARKER).expect("the QR carries the request URI") + MARKER.len();
    let id: String = page[start_at..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    assert!(id.len() >= 16, "a flow id, found {id:?}");

    // The wallet's fetch — cookieless by design: the QR is scanned by a
    // different device than the one that started the flow.
    let response = client
        .get(format!("{base}/vp/request/{id}"))
        .send()
        .await
        .expect("the request-object fetch");
    assert_eq!(response.status(), 200);
    let request_object = response.text().await.expect("the request object");

    // Decode the request object's payload and assert BOTH injected members.
    let segment = request_object
        .split('.')
        .nth(1)
        .expect("the request object is a JWS");
    let payload: serde_json::Value = serde_json::from_slice(
        &jose_rs::base64url::decode(segment).expect("the payload segment decodes"),
    )
    .expect("the payload is JSON");
    let verifier_info = payload["verifier_info"]
        .as_array()
        .expect("the served request carries verifier_info");
    let dataset_element = verifier_info
        .iter()
        .find(|e| e["format"] == "registrar_dataset")
        .expect("the registrar_dataset element");
    assert_eq!(
        dataset_element["data"], dataset,
        "the registrar dataset rides the request"
    );
    let registration_element = verifier_info
        .iter()
        .find(|e| e["format"] == "registration_cert")
        .expect("the registration_cert element");
    let data = registration_element["data"]
        .as_str()
        .expect("the registration_cert data is base64url text");
    let decoded = jose_rs::base64url::decode(data).expect("the registration_cert decodes");
    assert_eq!(
        String::from_utf8(decoded).expect("the registration_cert is utf-8"),
        wrprc,
        "the registration_cert data is the byte-exact WRPRC from the file"
    );
    // A wallet response POST drives the full processing pipeline — even a
    // refusal exercises claim, admission, and the terminal write — so the
    // per-presentation telemetry line is asserted end to end through the
    // real binary.
    let refused = client
        .post(format!("{base}/vp/response/{id}"))
        .form(&[("response", "not-a-jwe")])
        .send()
        .await
        .expect("the response POST");
    assert_eq!(refused.status(), 400);
    let _ = child.kill().await;
    // The per-presentation telemetry: exactly ONE completion event for the
    // flow, carrying the refusal the wallet actually received and every
    // numeric timing field — parsed from the JSON log, so the assertions do
    // not depend on display formatting.
    let stdout_bytes = stdout_task.await.unwrap_or_default();
    let log = String::from_utf8_lossy(&stdout_bytes);
    let events: Vec<serde_json::Value> = log
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|entry| {
            entry
                .get("fields")
                .and_then(|f| f.get("message"))
                .and_then(|m| m.as_str())
                == Some("wallet response processed")
        })
        .collect();
    assert_eq!(
        events.len(),
        1,
        "exactly one completion event; the log was:\n{log}"
    );
    let event = events[0].get("fields").cloned().expect("the event fields");
    let result = event
        .get("result")
        .and_then(|r| r.as_str())
        .expect("the result field");
    assert_ne!(result, "ok", "the refusal must not be logged as a success");
    assert!(!result.is_empty(), "the refusal result must be present");
    for field in [
        "total_ms",
        "claim_ms",
        "admission_ms",
        "unseal_ms",
        "crypto_ms",
        "trust_ms",
        "status_ms",
        "status_fetch_ms",
        "finalize_ms",
    ] {
        assert!(
            event.get(field).is_some_and(|v| v.is_number()),
            "the {field} timing field must be numeric; the event was {event}"
        );
    }
}
