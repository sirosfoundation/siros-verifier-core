//! SIROS circuit-catalog downloads, with a local HTTP mirror for deterministic tests.
mod support;

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use siros_verifier_zkp::catalog::CatalogArtifactSource;
use siros_verifier_zkp::circuits::{
    Allowlist, ArtifactSource, CircuitConfig, CircuitsConfig, Entry,
};
use siros_verifier_zkp::nym_auth::{CONFIG_KNOWN_OFFENDER_MATCHING_SSC, SYSTEM_LONGFELLOW};

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn entry(id: &str, plain: &[u8]) -> Entry {
    Entry {
        system_id: SYSTEM_LONGFELLOW.into(),
        config: CONFIG_KNOWN_OFFENDER_MATCHING_SSC.into(),
        hash_circuit_id: "aa11".into(),
        sig_circuit_id: "bb22".into(),
        block_enc_hash: 4,
        block_enc_sig: 7,
        path: String::new(),
        id: id.into(),
        sha256: sha(plain),
        bytes: plain.len() as u64,
    }
}

fn descriptor(entry: &Entry, served: &[u8], compression: &str, plain: &[u8]) -> Value {
    let digest = sha(served);
    let mut artifact = json!({
        "url": format!("/v1/artifacts/sha256/{digest}"),
        "hash": format!("sha256:{digest}"),
        "size": served.len(),
        "compression": compression,
        "mediaType": if compression == "zstd" { "application/zstd" } else { "application/octet-stream" }
    });
    if compression == "zstd" {
        artifact["uncompressed"] =
            json!({"hash": format!("sha256:{}", sha(plain)), "size": plain.len()});
    }
    json!({
        "id": entry.id,
        "aliases": [SYSTEM_LONGFELLOW],
        "system": "longfellow-nymauth",
        "proofSystem": "longfellow-libzk-v1",
        "published": true,
        "status": "active",
        "params": {
            "configuration": entry.config,
            "hash_circuit_id": entry.hash_circuit_id,
            "sig_circuit_id": entry.sig_circuit_id,
            "block_enc_hash": entry.block_enc_hash.to_string(),
            "block_enc_sig": entry.block_enc_sig
        },
        "artifact": artifact
    })
}

#[derive(Clone)]
struct Reply {
    status: u16,
    body: Vec<u8>,
    location: Option<String>,
}

impl Reply {
    fn ok(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            body,
            location: None,
        }
    }

    fn json(value: Value) -> Self {
        Self::ok(serde_json::to_vec(&value).unwrap())
    }

    fn status(status: u16) -> Self {
        Self {
            status,
            body: Vec::new(),
            location: None,
        }
    }

    fn redirect(location: &str) -> Self {
        Self {
            status: 301,
            body: Vec::new(),
            location: Some(location.into()),
        }
    }
}

struct Mirror {
    base: String,
    requests: Arc<Mutex<Vec<String>>>,
    thread: Option<JoinHandle<()>>,
}

impl Mirror {
    fn new(routes: Vec<(String, Reply)>, hits: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let routes: BTreeMap<String, Reply> = routes.into_iter().collect();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let thread = std::thread::spawn(move || {
            for _ in 0..hits {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut buffer = [0u8; 2048];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let count = stream.read(&mut buffer).unwrap();
                    assert!(count > 0, "client closed an incomplete request");
                    request.extend_from_slice(&buffer[..count]);
                    assert!(request.len() < 16 * 1024);
                }
                let text = String::from_utf8(request).unwrap();
                let path = text.split_whitespace().nth(1).unwrap().to_owned();
                seen.lock().unwrap().push(path.clone());
                let reply = routes
                    .get(&path)
                    .cloned()
                    .unwrap_or_else(|| Reply::status(404));
                let mut headers = format!(
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    reply.status,
                    reply.body.len()
                );
                if let Some(location) = reply.location {
                    headers.push_str(&format!("Location: {location}\r\n"));
                }
                headers.push_str("\r\n");
                stream.write_all(headers.as_bytes()).unwrap();
                stream.write_all(&reply.body).unwrap();
            }
        });
        Self {
            base,
            requests,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        self.base.clone()
    }

    fn finish(mut self) -> Vec<String> {
        self.thread.take().unwrap().join().unwrap();
        Arc::try_unwrap(self.requests)
            .unwrap()
            .into_inner()
            .unwrap()
    }
}

fn paths(entry: &Entry, served: &[u8]) -> (String, String) {
    (
        format!("/v1/circuits/{}.json", entry.id),
        format!("/v1/artifacts/sha256/{}", sha(served)),
    )
}

#[test]
fn a_zstd_catalog_artifact_is_hash_checked_and_decompressed() {
    let plain = b"a real circuit after zstd decoding";
    let served = zstd::encode_all(Cursor::new(plain), 1).unwrap();
    let mut entry = entry("nymauth-longfellow-mdoc-v1", plain);
    entry.hash_circuit_id = "AA11".into();
    let (descriptor_path, artifact_path) = paths(&entry, &served);
    let mut document = descriptor(&entry, &served, "zstd", plain);
    document["params"]["hash_circuit_id"] = json!("aa11");
    let mirror = Mirror::new(
        vec![
            (descriptor_path, Reply::json(document)),
            (artifact_path, Reply::ok(served)),
        ],
        2,
    );
    let source = CatalogArtifactSource::new(&[mirror.url()]).unwrap();
    assert_eq!(source.read(&entry).unwrap(), plain);
    let requests = mirror.finish();
    assert!(requests[0].ends_with("nymauth-longfellow-mdoc-v1.json"));
    assert!(requests[1].starts_with("/v1/artifacts/sha256/"));
}

#[test]
fn an_alias_redirect_and_an_uncompressed_artifact_work() {
    let plain = b"uncompressed catalog circuit";
    let served = plain.to_vec();
    let requested = entry("alias", plain);
    let canonical = entry("canonical", plain);
    let (_, artifact_path) = paths(&requested, &served);
    let mut canonical_document = descriptor(&canonical, &served, "none", plain);
    canonical_document["aliases"] = json!(["alias"]);
    let mirror = Mirror::new(
        vec![
            (
                "/v1/circuits/alias.json".into(),
                Reply::redirect("/v1/circuits/canonical.json"),
            ),
            (
                "/v1/circuits/canonical.json".into(),
                Reply::json(canonical_document),
            ),
            (artifact_path, Reply::ok(served)),
        ],
        3,
    );
    let source = CatalogArtifactSource::new(&[mirror.url()]).unwrap();
    assert_eq!(source.read(&requested).unwrap(), plain);
    assert_eq!(
        mirror.finish(),
        vec![
            "/v1/circuits/alias.json".to_string(),
            "/v1/circuits/canonical.json".to_string(),
            mirror_artifact_path(plain)
        ]
    );
}

fn mirror_artifact_path(bytes: &[u8]) -> String {
    format!("/v1/artifacts/sha256/{}", sha(bytes))
}

#[test]
fn mirrors_are_tried_in_order_without_relaxing_the_operator_pin() {
    let plain = b"the same catalog on two mirrors";
    let served = zstd::encode_all(Cursor::new(plain), 1).unwrap();
    let entry = entry("circuit", plain);
    let (descriptor_path, artifact_path) = paths(&entry, &served);
    let first = Mirror::new(vec![(descriptor_path.clone(), Reply::status(503))], 1);
    let second = Mirror::new(
        vec![
            (
                descriptor_path,
                Reply::json(descriptor(&entry, &served, "zstd", plain)),
            ),
            (artifact_path, Reply::ok(served)),
        ],
        2,
    );
    let source = CatalogArtifactSource::new(&[first.url(), second.url()]).unwrap();
    assert_eq!(source.read(&entry).unwrap(), plain);
    first.finish();
    second.finish();
}

#[test]
fn a_tampered_compressed_artifact_is_refused() {
    let plain = b"circuit";
    let served = zstd::encode_all(Cursor::new(plain), 1).unwrap();
    let entry = entry("circuit", plain);
    let (descriptor_path, artifact_path) = paths(&entry, &served);
    let mut tampered = served.clone();
    tampered[0] ^= 1;
    let mirror = Mirror::new(
        vec![
            (
                descriptor_path,
                Reply::json(descriptor(&entry, &served, "zstd", plain)),
            ),
            (artifact_path, Reply::ok(tampered)),
        ],
        2,
    );
    let source = CatalogArtifactSource::new(&[mirror.url()]).unwrap();
    let error = source.read(&entry).unwrap_err().to_string();
    assert!(error.contains("compressed artifact hashes"), "{error}");
    mirror.finish();
}

#[test]
fn catalog_metadata_cannot_override_the_allowlist() {
    let actual = b"actual circuit";
    let expected = b"different circuit";
    let served = zstd::encode_all(Cursor::new(actual), 1).unwrap();
    let entry = entry("circuit", expected);
    let (descriptor_path, artifact_path) = paths(&entry, &served);
    let mirror = Mirror::new(
        vec![
            (
                descriptor_path,
                Reply::json(descriptor(&entry, &served, "zstd", actual)),
            ),
            (artifact_path, Reply::ok(served)),
        ],
        2,
    );
    let source = CatalogArtifactSource::new(&[mirror.url()]).unwrap();
    let error = source.read(&entry).unwrap_err().to_string();
    assert!(error.contains("allowlist"), "{error}");
    mirror.finish();
}

#[test]
fn an_off_catalog_artifact_url_is_rejected_before_it_is_fetched() {
    let plain = b"circuit";
    let served = plain.to_vec();
    let entry = entry("circuit", plain);
    let (descriptor_path, _) = paths(&entry, &served);
    let mut document = descriptor(&entry, &served, "none", plain);
    document["artifact"]["url"] = json!("https://evil.example/artifact");
    let mirror = Mirror::new(vec![(descriptor_path, Reply::json(document))], 1);
    let source = CatalogArtifactSource::new(&[mirror.url()]).unwrap();
    let error = source.read(&entry).unwrap_err().to_string();
    assert!(error.contains("off-catalog URLs are refused"), "{error}");
    assert_eq!(mirror.finish(), vec!["/v1/circuits/circuit.json"]);
}

#[test]
fn invalid_ids_and_remote_plaintext_sources_fail_closed() {
    let mut entry = entry("../secret", b"x");
    let source = CatalogArtifactSource::new(&["https://api.circuits.siros.org".into()]).unwrap();
    assert!(source
        .read(&entry)
        .unwrap_err()
        .to_string()
        .contains("invalid circuit catalog id"));
    entry.id = "safe".into();
    assert!(CatalogArtifactSource::new(&["http://catalog.example".into()]).is_err());
}

#[test]
fn startup_prefetch_needs_no_catalog_at_verification_time() {
    let plain = b"prefetched circuit";
    let served = zstd::encode_all(Cursor::new(plain), 1).unwrap();
    let entry = entry("circuit", plain);
    let (descriptor_path, artifact_path) = paths(&entry, &served);
    let mirror = Mirror::new(
        vec![
            (
                descriptor_path,
                Reply::json(descriptor(&entry, &served, "zstd", plain)),
            ),
            (artifact_path, Reply::ok(served)),
        ],
        2,
    );
    let allow = Allowlist::new(&CircuitsConfig {
        sources: vec![mirror.url()],
        allow: vec![CircuitConfig {
            system_id: entry.system_id.clone(),
            config: entry.config.clone(),
            hash_circuit_id: entry.hash_circuit_id.clone(),
            sig_circuit_id: entry.sig_circuit_id.clone(),
            block_enc_hash: entry.block_enc_hash,
            block_enc_sig: entry.block_enc_sig,
            artifact_path: String::new(),
            artifact_id: entry.id.clone(),
            artifact_sha256: entry.sha256.clone(),
            artifact_bytes: entry.bytes,
        }],
    })
    .unwrap();
    let source = CatalogArtifactSource::new(&[mirror.url()])
        .unwrap()
        .prefetch(&allow)
        .unwrap();
    mirror.finish();
    assert_eq!(source.read(allow.entries().next().unwrap()).unwrap(), plain);
}

#[test]
fn local_files_still_bypass_the_catalog() {
    let (file, config) = support::artifact(b"local circuit");
    let entry = Entry {
        system_id: config.system_id,
        config: config.config,
        hash_circuit_id: config.hash_circuit_id,
        sig_circuit_id: config.sig_circuit_id,
        block_enc_hash: config.block_enc_hash,
        block_enc_sig: config.block_enc_sig,
        path: config.artifact_path,
        id: String::new(),
        sha256: config.artifact_sha256,
        bytes: config.artifact_bytes,
    };
    let source = CatalogArtifactSource::new(&[]).unwrap();
    assert_eq!(source.read(&entry).unwrap(), b"local circuit");
    drop(file);
}

#[test]
#[ignore = "live SIROS catalog integration"]
fn the_live_siros_nymauth_circuit_matches_the_native_test_vector() {
    let mut entry = Entry {
        system_id: SYSTEM_LONGFELLOW.into(),
        config: CONFIG_KNOWN_OFFENDER_MATCHING_SSC.into(),
        hash_circuit_id: "5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729".into(),
        sig_circuit_id: "00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb".into(),
        block_enc_hash: 6983,
        block_enc_sig: 4679,
        path: String::new(),
        id: "nymauth-longfellow-mdoc-v1".into(),
        sha256: "92dd42fdf99673249eec33c7d07850bd9da66fbdab01ef26391e04c8341c1b7f".into(),
        bytes: 1_062_842,
    };
    let source = CatalogArtifactSource::new(&["https://api.circuits.siros.org".into()]).unwrap();
    for id in ["nymauth-longfellow-mdoc-v1", SYSTEM_LONGFELLOW] {
        entry.id = id.into();
        let bytes = source.read(&entry).unwrap();
        assert_eq!(bytes.len(), 1_062_842);
        assert_eq!(sha(&bytes), entry.sha256);
    }
}
