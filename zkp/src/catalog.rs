//! SIROS circuit-catalog artifacts (`/v1/circuits/{id}.json` and
//! `/v1/artifacts/sha256/{hex}`).
//!
//! Catalog mirrors supply bytes, never policy. The descriptor must agree with
//! the operator's allowlist entry, and the returned decompressed artifact is
//! checked against that entry again by the verifier before a backend loads it.

use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

use crate::circuits::{check_artifact, Allowlist, ArtifactSource, Entry, FsArtifactSource};
use crate::nym_auth::SYSTEM_LONGFELLOW;
use crate::refusal::{ZkpError, ZkpResult};

const MAX_DESCRIPTOR_BYTES: u64 = 1024 * 1024;
const MAX_COMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_REDIRECTS: usize = 3;
const RESOLUTION_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Deserialize)]
struct Descriptor {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    system: String,
    published: bool,
    status: String,
    params: BTreeMap<String, Value>,
    artifact: Option<Artifact>,
}

#[derive(Debug, Deserialize)]
struct Artifact {
    #[serde(default)]
    url: String,
    hash: String,
    size: u64,
    compression: String,
    uncompressed: Option<Uncompressed>,
}

#[derive(Debug, Deserialize)]
struct Uncompressed {
    hash: String,
    size: u64,
}

/// A filesystem and SIROS catalog source. Local paths never use the network;
/// catalog IDs try the configured mirrors in order.
pub struct CatalogArtifactSource {
    sources: Vec<Url>,
    agent: ureq::Agent,
}

impl CatalogArtifactSource {
    pub fn new(sources: &[String]) -> ZkpResult<Self> {
        let mut parsed = Vec::with_capacity(sources.len());
        for source in sources {
            let mut url = Url::parse(source)
                .map_err(|e| fault(format!("invalid circuit catalog source {source:?}: {e}")))?;
            check_transport(&url)
                .map_err(|e| fault(format!("invalid circuit catalog source: {e}")))?;
            if !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(fault("a circuit catalog source must be a plain base URL"));
            }
            if !url.path().ends_with('/') {
                let path = format!("{}/", url.path());
                url.set_path(&path);
            }
            parsed.push(url);
        }
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .max_redirects(0)
            .build();
        Ok(Self {
            sources: parsed,
            agent: config.into(),
        })
    }

    fn allowed_url(&self, url: &Url) -> Result<(), String> {
        check_transport(url)?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("catalog URLs must not contain credentials, a query, or a fragment".into());
        }
        if self.sources.iter().any(|source| same_origin(source, url)) {
            Ok(())
        } else {
            Err(format!(
                "catalog URL {} is not on a configured source origin",
                url.origin().ascii_serialization()
            ))
        }
    }

    fn fetch(&self, initial: Url, limit: u64, deadline: Instant) -> Result<Vec<u8>, String> {
        let mut url = initial;
        for redirects in 0..=MAX_REDIRECTS {
            self.allowed_url(&url)?;
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| "circuit catalog resolution deadline exceeded".to_owned())?;
            let mut response = self
                .agent
                .get(url.as_str())
                .config()
                .timeout_global(Some(remaining.min(Duration::from_secs(30))))
                .build()
                .call()
                .map_err(|e| format!("GET {}: {e}", url.as_str()))?;
            let status = response.status().as_u16();
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                if redirects == MAX_REDIRECTS {
                    return Err(format!("GET {}: too many redirects", url.as_str()));
                }
                let location = response
                    .headers()
                    .get("location")
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| format!("GET {}: redirect without Location", url.as_str()))?
                    .to_owned();
                url = url
                    .join(&location)
                    .map_err(|e| format!("invalid catalog redirect {location:?}: {e}"))?;
                continue;
            }
            if status != 200 {
                return Err(format!("GET {}: HTTP {status}", url.as_str()));
            }
            let mut bytes = Vec::new();
            response
                .body_mut()
                .as_reader()
                .take(limit.saturating_add(1))
                .read_to_end(&mut bytes)
                .map_err(|e| format!("reading {}: {e}", url.as_str()))?;
            if bytes.len() as u64 > limit {
                return Err(format!(
                    "response from {} exceeds {limit} bytes",
                    url.as_str()
                ));
            }
            return Ok(bytes);
        }
        unreachable!("the redirect limit always returns")
    }

    fn read_from(&self, source: &Url, entry: &Entry, deadline: Instant) -> Result<Vec<u8>, String> {
        if !valid_id(&entry.id) {
            return Err(format!("invalid circuit catalog id {:?}", entry.id));
        }
        let descriptor_url = source
            .join(&format!("v1/circuits/{}.json", entry.id))
            .map_err(|e| e.to_string())?;
        let bytes = self.fetch(descriptor_url, MAX_DESCRIPTOR_BYTES, deadline)?;
        let descriptor: Descriptor = serde_json::from_slice(&bytes)
            .map_err(|e| format!("invalid circuit descriptor: {e}"))?;
        self.check_descriptor(&descriptor, entry)?;
        let artifact = descriptor
            .artifact
            .as_ref()
            .ok_or_else(|| "circuit descriptor has no artifact".to_owned())?;
        let served_hash = artifact_hash(&artifact.hash)?;
        if artifact.size == 0 || artifact.size > MAX_COMPRESSED_BYTES {
            return Err(format!(
                "invalid compressed artifact size {}",
                artifact.size
            ));
        }
        let expected_path = format!("v1/artifacts/sha256/{served_hash}");
        if !artifact.url.is_empty()
            && artifact.url.strip_prefix('/').unwrap_or(&artifact.url) != expected_path
        {
            return Err(
                "artifact URL is not the content-addressed path for its declared SHA-256; absolute and off-catalog URLs are refused"
                    .into(),
            );
        }
        let artifact_url = source.join(&expected_path).map_err(|e| e.to_string())?;
        let served = self.fetch(artifact_url, artifact.size, deadline)?;
        if served.len() as u64 != artifact.size {
            return Err(format!(
                "compressed artifact is {} bytes; the descriptor says {}",
                served.len(),
                artifact.size
            ));
        }
        let actual_served_hash = sha256(&served);
        if actual_served_hash != served_hash {
            return Err(format!(
                "compressed artifact hashes to {actual_served_hash}; the descriptor says {served_hash}"
            ));
        }

        let decompressed = match artifact.compression.as_str() {
            "none" => served,
            "zstd" => {
                let decoder = zstd::stream::read::Decoder::new(Cursor::new(served))
                    .map_err(|e| format!("initializing zstd decoder: {e}"))?;
                let mut out = Vec::new();
                decoder
                    .take(entry.bytes + 1)
                    .read_to_end(&mut out)
                    .map_err(|e| format!("decompressing circuit artifact: {e}"))?;
                out
            }
            other => return Err(format!("unsupported artifact compression {other:?}")),
        };
        if let Some(expected) = &artifact.uncompressed {
            let expected_hash = artifact_hash(&expected.hash)?;
            if decompressed.len() as u64 != expected.size || sha256(&decompressed) != expected_hash
            {
                return Err("decompressed artifact does not match the descriptor's uncompressed hash and size".into());
            }
        }
        check_artifact(entry, &decompressed).map_err(|e| e.to_string())?;
        Ok(decompressed)
    }

    /// Resolve every catalog-backed entry before the service starts handling
    /// requests. The returned source performs no network I/O.
    pub fn prefetch(self, allowlist: &Allowlist) -> ZkpResult<PrefetchedArtifactSource> {
        let mut artifacts = BTreeMap::new();
        for entry in allowlist.entries().filter(|entry| entry.path.is_empty()) {
            let bytes = self.read(entry)?;
            artifacts.insert((entry.system_id.clone(), entry.config.clone()), bytes);
        }
        Ok(PrefetchedArtifactSource { artifacts })
    }

    fn check_descriptor(&self, descriptor: &Descriptor, entry: &Entry) -> Result<(), String> {
        if descriptor.id != entry.id && !descriptor.aliases.contains(&entry.id) {
            return Err(format!(
                "catalog returned circuit {:?} for requested id {:?}",
                descriptor.id, entry.id
            ));
        }
        if !descriptor.published || !matches!(descriptor.status.as_str(), "active" | "deprecated") {
            return Err("circuit is not published in a usable state".into());
        }
        let expected_system = if entry.system_id == SYSTEM_LONGFELLOW {
            "longfellow-nymauth"
        } else {
            "vega-nymauth"
        };
        if descriptor.system != expected_system {
            return Err(format!(
                "catalog circuit system {:?} does not match the allowlist system {:?}",
                descriptor.system, entry.system_id
            ));
        }
        let required = [
            ("configuration", entry.config.clone()),
            ("hash_circuit_id", entry.hash_circuit_id.clone()),
            ("sig_circuit_id", entry.sig_circuit_id.clone()),
            ("block_enc_hash", entry.block_enc_hash.to_string()),
            ("block_enc_sig", entry.block_enc_sig.to_string()),
        ];
        for (name, expected) in required {
            if expected.is_empty() || (name.starts_with("block_enc") && expected == "0") {
                continue;
            }
            let actual = descriptor
                .params
                .get(name)
                .and_then(scalar)
                .ok_or_else(|| format!("catalog parameter {name:?} is missing or not scalar"))?;
            let matches = if name.ends_with("_circuit_id") {
                actual.eq_ignore_ascii_case(&expected)
            } else {
                actual == expected
            };
            if !matches {
                return Err(format!(
                    "catalog parameter {name} is {actual:?}; the allowlist says {expected:?}"
                ));
            }
        }
        Ok(())
    }
}

impl ArtifactSource for CatalogArtifactSource {
    fn read(&self, entry: &Entry) -> ZkpResult<Vec<u8>> {
        if !entry.path.is_empty() {
            return FsArtifactSource.read(entry);
        }
        if entry.bytes == 0 || entry.bytes > MAX_DECOMPRESSED_BYTES {
            return Err(fault(format!(
                "circuit artifact size {} exceeds the catalog safety limit",
                entry.bytes
            )));
        }
        if self.sources.is_empty() {
            return Err(fault("no circuit catalog sources are configured"));
        }
        let deadline = Instant::now() + RESOLUTION_TIMEOUT;
        let mut last = String::new();
        for source in &self.sources {
            match self.read_from(source, entry, deadline) {
                Ok(bytes) => return Ok(bytes),
                Err(error) => last = format!("{}: {error}", source.as_str()),
            }
        }
        Err(fault(format!(
            "no circuit catalog source yielded the allowed artifact {:?}: {last}",
            entry.id
        )))
    }
}

/// Verified artifacts loaded at startup. Catalog failures after construction
/// are impossible because this source has no HTTP client.
pub struct PrefetchedArtifactSource {
    artifacts: BTreeMap<(String, String), Vec<u8>>,
}

impl ArtifactSource for PrefetchedArtifactSource {
    fn read(&self, entry: &Entry) -> ZkpResult<Vec<u8>> {
        if !entry.path.is_empty() {
            return FsArtifactSource.read(entry);
        }
        self.artifacts
            .get(&(entry.system_id.clone(), entry.config.clone()))
            .cloned()
            .ok_or_else(|| {
                fault(format!(
                    "catalog artifact {:?} was not prefetched",
                    entry.id
                ))
            })
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(_) | Value::Bool(_) => Some(value.to_string()),
        _ => None,
    }
}

fn artifact_hash(value: &str) -> Result<String, String> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or_else(|| "artifact hash must use sha256:".to_owned())?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("artifact hash is not a 64-character SHA-256".into());
    }
    Ok(hex.to_ascii_lowercase())
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn check_transport(url: &Url) -> Result<(), String> {
    match url.scheme() {
        "https" if url.host_str().is_some() => Ok(()),
        "http" if url.host_str().is_some_and(loopback) => Ok(()),
        "http" => Err("plaintext catalog HTTP is allowed only on loopback".into()),
        _ => Err("catalog URL must be HTTPS with a host".into()),
    }
}

fn loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || matches!(host, "::1" | "[::1]")
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

fn fault(message: impl Into<String>) -> ZkpError {
    ZkpError::fault(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_expired_resolution_deadline_prevents_network_io() {
        let source =
            CatalogArtifactSource::new(&["https://api.circuits.siros.org".into()]).unwrap();
        let url = source.sources[0].join("v1/circuits/circuit.json").unwrap();
        let error = source
            .fetch(url, 1, Instant::now() - Duration::from_secs(1))
            .unwrap_err();
        assert!(error.contains("deadline"), "{error}");
    }
}
