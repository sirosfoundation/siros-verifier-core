use std::net::TcpListener;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

#[tokio::test]
async fn builds_the_real_oidc_frontend_and_custom_backend() {
    let dir = std::env::temp_dir().join(format!(
        "siros-verifier-service-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["verifier.example".to_string()])
        .unwrap()
        .self_signed(&kp)
        .unwrap();
    std::fs::write(dir.join("key.pem"), kp.serialize_pem()).unwrap();
    std::fs::write(dir.join("chain.pem"), cert.pem()).unwrap();
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
            claims = [{{ path = ["given_name"] }}, {{ path = ["family_name"] }}] }}] }}
          attribute_map = {{}}
          subject_pointer = "/sub"

          [backend.config.storage]
          backend = "memory"

          [backend.config.zkp]
          query = {{ id = "nym_attestation", format = "zkp_req",
            meta = {{ source_format = "mso_mdoc", doctype_value = "eu.europa.ec.eudi.nym_auth.1" }},
            _req = [
              {{ fn_id = "pseudonym", return = "nym-1", params = {{
                config = "known-offender-matching-ssc", ver = 1, prf = "sha-256" }} }},
              {{ fn_id = "age_check", return = "age-1", params = {{
                ge = "2008-10-10", le = "2013-10-09" }} }},
            ] }}
          system_id_values = ["urn:circuits:longfellow:nym_auth:v1"]
          proof_system_values = ["longfellow-libzk-v1"]
          role = "mdoc-issuer"
          verifier_id = "x509_san_dns:verifier.example"
          subject_handle = "nym-1"
          attribute_map = {{ pseudonym = "nym-1", ageOver = "age-1" }}
          auth_class_ref = "urn:eudi:loa:high"

          [backend.config.zkp.circuits]
          sources = []

          [[backend.config.zkp.circuits.allow]]
          system_id = "urn:circuits:longfellow:nym_auth:v1"
          config = "known-offender-matching-ssc"
          hash_circuit_id = "5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729"
          sig_circuit_id = "00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb"
          block_enc_hash = 6983
          block_enc_sig = 4679
          artifact_path = "{dir}/nymauth.bin"
          artifact_sha256 = "92dd42fdf99673249eec33c7d07850bd9da66fbdab01ef26391e04c8341c1b7f"
          artifact_bytes = 1062842
    "#,
        dir = dir.display(),
        key = dir.join("key.pem").display(),
        chain = dir.join("chain.pem").display()
    );
    std::fs::write(&config_path, config).unwrap();
    let artifact =
        zstd::decode_all(&include_bytes!("../../zkp/testdata/nymauth/mdoc-circuits.zst")[..])
            .expect("decode the genuine Longfellow circuit used by the startup prewarm test");
    assert_eq!(artifact.len(), 1_062_842);
    std::fs::write(dir.join("nymauth.bin"), artifact).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut child = Command::new(env!("CARGO_BIN_EXE_siros-verifier-service"))
        .arg(&config_path)
        .env("TUNNELBANA_BIND", address.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let healthy = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("service exited before becoming healthy: {status}");
            }
            if let Ok(response) = client.get(format!("http://{address}/health")).send().await {
                if response.status().is_success() {
                    assert_eq!(
                        response.json::<serde_json::Value>().await.unwrap(),
                        serde_json::json!({"status": "ok"})
                    );
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    let _ = child.kill().await;
    let _ = child.wait().await;
    let _ = std::fs::remove_dir_all(&dir);
    healthy.expect("service did not become healthy within 60 seconds");
}
