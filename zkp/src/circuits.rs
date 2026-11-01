//! Which nym_auth circuit builds a verifier may load.
//!
//! Decides WHICH artifact, checks that the artifact is the one the operator allowed, and hands over the bytes.
//! Loading them into a verifier is a proof backend's job. The ways to get this wrong (an entry naming the wrong system
//! or configuration, an artifact that is not the allowed one, two entries claiming one of each) are all decidable
//! without a circuit, so this module needs neither a circuit nor a native library to test.

use std::collections::BTreeMap;
use std::io::Read;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::nym_auth::{
    check_system_id, CONFIG_KNOWN_OFFENDER_MATCHING_PSC, CONFIG_KNOWN_OFFENDER_MATCHING_SSC,
    SYSTEM_LONGFELLOW, SYSTEM_VEGA,
};
use crate::refusal::{ZkpError, ZkpResult};

/// One allowlist entry as configured.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitConfig {
    pub system_id: String,
    pub config: String,
    /// Longfellow parameters. Required for Longfellow, refused for Vega.
    #[serde(default)]
    pub hash_circuit_id: String,
    #[serde(default)]
    pub sig_circuit_id: String,
    #[serde(default)]
    pub block_enc_hash: u32,
    #[serde(default)]
    pub block_enc_sig: u32,
    /// Exactly one of the next two.
    #[serde(default)]
    pub artifact_path: String,
    #[serde(default)]
    pub artifact_id: String,
    pub artifact_sha256: String,
    pub artifact_bytes: u64,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitsConfig {
    /// Catalog URLs an `artifact_id` is fetched from.
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub allow: Vec<CircuitConfig>,
}

/// A resolved entry: an allowed build and how to get its bytes.
#[derive(Clone)]
pub struct Entry {
    pub system_id: String,
    pub config: String,
    pub hash_circuit_id: String,
    pub sig_circuit_id: String,
    pub block_enc_hash: u32,
    pub block_enc_sig: u32,
    pub path: String,
    pub id: String,
    pub sha256: String,
    pub bytes: u64,
}

type Key = (String, String);

/// The set of builds a verifier may load, by proof system and configuration.
#[derive(Debug)]
pub struct Allowlist {
    by_key: BTreeMap<Key, Entry>,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("system_id", &self.system_id)
            .field("config", &self.config)
            .field("sha256", &self.sha256)
            .finish()
    }
}

fn bad(where_: &str, msg: impl std::fmt::Display) -> ZkpError {
    ZkpError::fault(format!("{where_}: {msg}"))
}

impl Allowlist {
    /// Check a configured allowlist and resolve it. At construction, so a deployment whose allowlist cannot be
    /// honoured fails at startup, not at the first presentation where an operator would see a refused proof and no
    /// reason to suspect the configuration.
    pub fn new(cfg: &CircuitsConfig) -> ZkpResult<Self> {
        for (i, source) in cfg.sources.iter().enumerate() {
            let where_ = format!("circuits.sources[{i}]");
            let rest = source
                .strip_prefix("https://")
                .or_else(|| source.strip_prefix("http://"))
                .ok_or_else(|| bad(&where_, format!("{source:?} is not an http(s) URL")))?;
            if rest.is_empty() || rest.starts_with('/') {
                return Err(bad(&where_, format!("{source:?} has no host")));
            }
        }
        let mut by_key = BTreeMap::new();
        for (i, e) in cfg.allow.iter().enumerate() {
            let where_ = format!("circuits.allow[{i}]");
            check_system_id(&e.system_id).map_err(|err| bad(&where_, err))?;
            if !matches!(
                e.config.as_str(),
                CONFIG_KNOWN_OFFENDER_MATCHING_SSC | CONFIG_KNOWN_OFFENDER_MATCHING_PSC
            ) {
                // The configuration decides the pseudonym's domain separator: an unrecognised one is a build this
                // code cannot reason about at all.
                return Err(bad(
                    &where_,
                    format!(
                        "{:?} is not a known-offender-matching configuration",
                        e.config
                    ),
                ));
            }
            let key = (e.system_id.clone(), e.config.clone());
            if by_key.contains_key(&key) {
                // Two builds for one system and configuration: refused, not resolved by order. Two entries that
                // differ only in system_id are NOT a clash: that is a verifier offering both proof systems.
                return Err(bad(
                    &where_,
                    format!(
                        "a second circuit is allowed for system {:?} and configuration {:?}",
                        e.system_id, e.config
                    ),
                ));
            }
            check_params(e, &where_)?;
            if e.artifact_sha256.len() != 64
                || !e.artifact_sha256.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(bad(
                    &where_,
                    "artifact_sha256 is not a 64-character hex SHA-256",
                ));
            }
            if e.artifact_bytes == 0 {
                return Err(bad(&where_, "artifact_bytes must be positive"));
            }
            if e.artifact_path.is_empty() == e.artifact_id.is_empty() {
                return Err(bad(
                    &where_,
                    "name exactly one of artifact_path and artifact_id",
                ));
            }
            if !e.artifact_id.is_empty() && cfg.sources.is_empty() {
                return Err(bad(
                    &where_,
                    format!(
                        "names artifact_id {:?} but no circuits.sources are configured",
                        e.artifact_id
                    ),
                ));
            }
            by_key.insert(
                key,
                Entry {
                    system_id: e.system_id.clone(),
                    config: e.config.clone(),
                    hash_circuit_id: e.hash_circuit_id.clone(),
                    sig_circuit_id: e.sig_circuit_id.clone(),
                    block_enc_hash: e.block_enc_hash,
                    block_enc_sig: e.block_enc_sig,
                    path: e.artifact_path.clone(),
                    id: e.artifact_id.clone(),
                    sha256: e.artifact_sha256.to_ascii_lowercase(),
                    bytes: e.artifact_bytes,
                },
            );
        }
        Ok(Self { by_key })
    }

    /// The allowed build for a proof system and configuration.
    pub fn entry(&self, system_id: &str, config: &str) -> ZkpResult<&Entry> {
        self.by_key
            .get(&(system_id.to_owned(), config.to_owned()))
            .ok_or_else(|| {
                ZkpError::fault(format!(
                    "no allowed circuit implements proof system {system_id:?} and pseudonym configuration {config:?}"
                ))
            })
    }

    /// Every allowed entry, sorted by system and configuration.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.by_key.values()
    }

    /// Every allowed build as `<system_id> <config>`, sorted so a startup log reads the same way twice.
    pub fn allowed(&self) -> Vec<String> {
        self.by_key
            .keys()
            .map(|(s, c)| format!("{s} {c}"))
            .collect()
    }
}

/// The four circuit parameters are LONGFELLOW'S. Required for one system and refused for the other: a Vega entry
/// carrying them is a Longfellow entry someone copied and edited, and ignoring them would let it start while naming
/// parameters nothing will ever check.
fn check_params(e: &CircuitConfig, where_: &str) -> ZkpResult<()> {
    match e.system_id.as_str() {
        SYSTEM_LONGFELLOW => {
            for (v, what) in [
                (&e.hash_circuit_id, "hash_circuit_id"),
                (&e.sig_circuit_id, "sig_circuit_id"),
            ] {
                if v.is_empty() {
                    return Err(bad(where_, format!("{what} is empty")));
                }
                if !v.bytes().all(|b| b.is_ascii_hexdigit()) || v.len() % 2 != 0 {
                    return Err(bad(where_, format!("{what} is not hex")));
                }
            }
            if e.hash_circuit_id == e.sig_circuit_id {
                return Err(bad(
                    where_,
                    "the hash and signature circuit ids are the same, which no real build has",
                ));
            }
            if e.block_enc_hash == 0 {
                return Err(bad(where_, "block_enc_hash is zero; it is the hash circuit's Ligero parameter and the loader checks it"));
            }
            if e.block_enc_sig == 0 {
                return Err(bad(where_, "block_enc_sig is zero; it is the signature circuit's Ligero parameter and the loader checks it"));
            }
            Ok(())
        }
        SYSTEM_VEGA => {
            for (what, set) in [
                ("hash_circuit_id", !e.hash_circuit_id.is_empty()),
                ("sig_circuit_id", !e.sig_circuit_id.is_empty()),
                ("block_enc_hash", e.block_enc_hash != 0),
                ("block_enc_sig", e.block_enc_sig != 0),
            ] {
                if set {
                    return Err(bad(
                        where_,
                        format!(
                            "{what} is a Longfellow parameter and this entry is {}; a Vega circuit is identified by \
                             its shapes digest alone, so nothing would ever check it",
                            e.system_id
                        ),
                    ));
                }
            }
            Ok(())
        }
        other => Err(bad(
            where_,
            format!("no circuit-parameter rule for system {other:?}"),
        )),
    }
}

/// Check artifact bytes against the entry's own statement: exact length, then SHA-256. Re-made here rather than left
/// to a native loader, which refuses with a status code an operator cannot tell a corrupt download, a wrong digest
/// and a stale path apart by.
pub fn check_artifact(entry: &Entry, bytes: &[u8]) -> ZkpResult<()> {
    if bytes.len() as u64 != entry.bytes {
        return Err(ZkpError::fault(format!(
            "the circuit artifact for {} {} is {} bytes; the allowlist says {}",
            entry.system_id,
            entry.config,
            bytes.len(),
            entry.bytes
        )));
    }
    let got: String = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if got != entry.sha256 {
        return Err(ZkpError::fault(format!(
            "the circuit artifact for {} {} hashes to {got}; the allowlist says {}",
            entry.system_id, entry.config, entry.sha256
        )));
    }
    Ok(())
}

/// Where artifact bytes come from. Filesystem and catalog implementations sit
/// behind this seam; the verifier applies the same allowlist check to both.
pub trait ArtifactSource: Send + Sync {
    /// The artifact's bytes, unchecked. At most `entry.bytes + 1` bytes may be returned, so an artifact that is too
    /// LONG is detected rather than silently truncated to the expected size and then hashed.
    fn read(&self, entry: &Entry) -> ZkpResult<Vec<u8>>;
}

/// Local files (`artifact_path`) only. Use
/// [`crate::catalog::CatalogArtifactSource`] to resolve catalog IDs as well.
pub struct FsArtifactSource;

impl ArtifactSource for FsArtifactSource {
    fn read(&self, entry: &Entry) -> ZkpResult<Vec<u8>> {
        if entry.path.is_empty() {
            return Err(ZkpError::fault(format!(
                "circuit {} {} is configured as catalog id {:?}, which this build cannot resolve yet; use artifact_path",
                entry.system_id, entry.config, entry.id
            )));
        }
        let file = std::fs::File::open(&entry.path).map_err(|e| {
            ZkpError::fault(format!(
                "circuit artifact for {} {}: {e}",
                entry.system_id, entry.config
            ))
        })?;
        let mut out = Vec::new();
        file.take(entry.bytes + 1)
            .read_to_end(&mut out)
            .map_err(|e| {
                ZkpError::fault(format!(
                    "circuit artifact for {} {}: {e}",
                    entry.system_id, entry.config
                ))
            })?;
        Ok(out)
    }
}
