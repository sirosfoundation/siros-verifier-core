use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;
pub use siros_verifier_core::config::SecretProvider;
use siros_verifier_core::config::SecretSource;
use siros_verifier_core::issuer_set::IssuerSetPolicy;
use siros_verifier_core::Error as CoreError;
use siros_verifier_core_tunnelbana::{VpBackendConfig, ZkpBackendConfig};
use siros_verifier_zkp::circuits::CircuitsConfig;
use siros_verifier_zkp::verify::Tolerance;

// ---- secret providers: the operational implementations of the core trait ---------

/// The env-var [`SecretProvider`] — the platform-native secret channel.
/// A k8s Secret reaches the process as an env var through
/// `secretKeyRef`; the provider just reads it. This is the default.
pub struct EnvVarSecretProvider;

impl SecretProvider for EnvVarSecretProvider {
    fn resolve(&self, source: &SecretSource) -> siros_verifier_core::Result<String> {
        match source {
            SecretSource::Env(name) => match std::env::var(name) {
                Ok(value) if !value.is_empty() => Ok(value),
                Ok(_) => Err(CoreError::Policy(format!(
                    "secret provider: env var {name} is set to the empty string"
                ))),
                Err(_) => Err(CoreError::Policy(format!(
                    "secret provider: env var {name} is not set"
                ))),
            },
            SecretSource::File(path) => Err(CoreError::Policy(format!(
                "secret provider: this provider resolves env vars only, not the secret file {path}"
            ))),
        }
    }
}

/// The file [`SecretProvider`] — the k8s Secret volume-mount model. A
/// mounted Secret materializes its keys as files under one directory;
/// [`FileSecretProvider`] resolves a relative source against that base
/// directory (absolute paths resolve as-given). An empty file is an
/// error (a mounted key that was never filled in) and a missing file an
/// error (the mount is not what the config believes) — matching the
/// env provider's fail-fast contract.
pub struct FileSecretProvider {
    /// The mount point: a mounted Secret's directory, or the config
    /// directory for sibling secret files.
    base: PathBuf,
}

impl FileSecretProvider {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    fn path(&self, source: &str) -> PathBuf {
        let p = Path::new(source);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.base.join(p)
        }
    }
}

impl SecretProvider for FileSecretProvider {
    fn resolve(&self, source: &SecretSource) -> siros_verifier_core::Result<String> {
        match source {
            SecretSource::File(name) => {
                let path = self.path(name);
                let value = std::fs::read_to_string(&path).map_err(|e| {
                    CoreError::Policy(format!(
                        "secret provider: reading {} for {name}: {e}",
                        path.display()
                    ))
                })?;
                if value.is_empty() {
                    return Err(CoreError::Policy(format!(
                        "secret provider: secret file {} for {name} is empty",
                        path.display()
                    )));
                }
                Ok(value)
            }
            SecretSource::Env(name) => Err(CoreError::Policy(format!(
                "secret provider: this provider resolves secret files only, not env var {name}"
            ))),
        }
    }
}

/// Both platform channels in one [`SecretProvider`]: `_env` references
/// resolve through the environment, `_file` references against a base
/// directory (the config directory, so a relative file sits beside the
/// config the way sibling paths resolve). Serves a config that mixes the
/// two reference styles — a k8s deployment with some Secrets as
/// `secretKeyRef` env vars and some as volume mounts.
pub struct PlatformSecretProvider {
    env: EnvVarSecretProvider,
    files: FileSecretProvider,
}

impl PlatformSecretProvider {
    /// `file_base` is the directory relative `_file` references resolve
    /// against — the config file's directory in the boot.
    pub fn new(file_base: impl Into<PathBuf>) -> Self {
        Self {
            env: EnvVarSecretProvider,
            files: FileSecretProvider::new(file_base),
        }
    }
}

impl SecretProvider for PlatformSecretProvider {
    fn resolve(&self, source: &SecretSource) -> siros_verifier_core::Result<String> {
        match source {
            SecretSource::Env(_) => self.env.resolve(source),
            SecretSource::File(_) => self.files.resolve(source),
        }
    }
}

// ---- the client roster: the config+secret default of the core trait ---------------

/// The default client roster (the config+secret implementation of the
/// core's [`siros_verifier_core::config::ClientRegistrationProvider`]):
/// the `[[frontend.config.clients]]` block plus a secret provider.
///
/// Each entry may carry its id and its credential as inline values, as
/// `client_id_env`/`client_secret_env` references (the #935 model: both
/// halves of the pair from one mechanism), or the credential may be
/// absent altogether (a `none`/`private_key_jwt` client). Each `_env`
/// reference is resolved through the secret provider at boot and
/// stripped from the entry before it reaches the consumer's parser —
/// the downstream client model never learns about `_env` fields. An
/// inline value AND an `_env` reference for the same member is refused,
/// as is a duplicate `client_id` across the roster (the consumer's
/// store keys by id and would silently keep only the last).
#[derive(Clone)]
pub struct ConfigClientRegistration {
    entries: Vec<Value>,
    secrets: std::sync::Arc<dyn SecretProvider>,
}

impl ConfigClientRegistration {
    /// Build from the raw config block (the `[[frontend.config.clients]]`
    /// array as the config system handed it to the boot).
    pub fn new(entries: Vec<Value>, secrets: std::sync::Arc<dyn SecretProvider>) -> Self {
        Self { entries, secrets }
    }

    /// Resolve one entry: validate the secret source combination, resolve
    /// the credential, strip the `_env` field.
    fn resolve_entry(&self, entry: Value) -> siros_verifier_core::Result<Value> {
        let id = entry
            .get("client_id")
            .and_then(Value::as_str)
            .unwrap_or("<missing client_id>")
            .to_string();
        let object = match entry {
            Value::Object(map) => map,
            _ => {
                return Err(CoreError::Policy(format!(
                    "client {id}: the roster entry is not a JSON object"
                )))
            }
        };
        let mut object = object;
        // The #935 model: BOTH halves of the credential pair may name
        // their env var — one mechanism manages the whole pair. Each
        // `_env` reference resolves through the secret provider and is
        // stripped before the entry reaches the consumer's parser.
        for (member, reference) in [
            ("client_id", "client_id_env"),
            ("client_secret", "client_secret_env"),
        ] {
            let inline = object.get(member).cloned();
            let env = object.get(reference).cloned();
            match (inline, env) {
                (Some(_), Some(_)) => {
                    return Err(CoreError::Policy(format!(
                        "client {id}: both {member} and {reference} are set — two sources for one value"
                    )))
                }
                (None, Some(env)) => {
                    let name = env.as_str().ok_or_else(|| {
                        CoreError::Policy(format!("client {id}: {reference} is not a string"))
                    })?;
                    let value = self
                        .secrets
                        .resolve(&SecretSource::Env(name.to_string()))
                        .map_err(|e| CoreError::Policy(format!("client {id}: {e}")))?;
                    if value.is_empty() {
                        return Err(CoreError::Policy(format!(
                            "client {id}: {reference} {name} is set to the empty string"
                        )));
                    }
                    object.insert(member.into(), Value::String(value));
                }
                _ => {}
            }
            object.remove(reference);
        }
        Ok(Value::Object(object))
    }

    /// The resolved roster: `_env` references already resolved to inline
    /// values (the same surface as the core's [`ClientRegistrationProvider`],
    /// which this type implements).
    pub fn clients(&self) -> siros_verifier_core::Result<Vec<Value>> {
        let mut resolved = Vec::with_capacity(self.entries.len());
        let mut seen: HashSet<String> = HashSet::with_capacity(self.entries.len());
        for entry in self.entries.clone() {
            let value = self.resolve_entry(entry)?;
            let id = value
                .get("client_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CoreError::Policy("client roster entry has no string client_id".into())
                })?
                .to_string();
            if !seen.insert(id.clone()) {
                return Err(CoreError::Policy(format!(
                    "duplicate client_id '{id}' across the client roster: the consumer's store keys by id and would silently keep only the last"
                )));
            }
            resolved.push(value);
        }
        Ok(resolved)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkpDeploymentConfig {
    #[serde(flatten)]
    pub backend: ZkpBackendConfig,
    pub circuits: CircuitsConfig,
    #[serde(default = "default_issuer_set_policy")]
    pub issuer_set: IssuerSetPolicy,
    #[serde(default)]
    pub tolerance: Tolerance,
}

fn default_issuer_set_policy() -> IssuerSetPolicy {
    IssuerSetPolicy::AllTrusted
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowStorageConfig {
    /// `memory` for an explicitly single-process deployment, or `mongodb`.
    pub backend: String,
    #[serde(default)]
    pub uri: Option<String>,
    /// The env var the MongoDB URI comes from (a k8s Secret's
    /// `secretKeyRef`, a Fly secret). Mutually exclusive with `uri` and
    /// `uri_file` — two sources named for one value is two different
    /// beliefs about where it comes from.
    #[serde(default)]
    pub uri_env: Option<String>,
    /// A file the MongoDB URI comes from (a Secret volume mount).
    /// Mutually exclusive with `uri` and `uri_env`.
    #[serde(default)]
    pub uri_file: Option<String>,
    #[serde(default)]
    pub database: Option<String>,
    #[serde(default)]
    pub collection: Option<String>,
}

/// Deployment-only settings wrapped around the backend's closed protocol config.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentConfig {
    pub request_signing_key_path: String,
    pub storage: FlowStorageConfig,
    pub request_certificate_chain_path: String,
    pub pdp_endpoint: String,
    #[serde(default)]
    pub pdp_bearer_token: Option<String>,
    /// The env var the PDP bearer token comes from (a k8s Secret's
    /// `secretKeyRef`, a Fly secret). Mutually exclusive with
    /// `pdp_bearer_token` and `pdp_bearer_token_file`.
    #[serde(default)]
    pub pdp_bearer_token_env: Option<String>,
    /// A file the PDP bearer token comes from (a Secret volume mount).
    /// Mutually exclusive with `pdp_bearer_token` and
    /// `pdp_bearer_token_env`.
    #[serde(default)]
    pub pdp_bearer_token_file: Option<String>,
    /// The prior request-signing key, retained for one rotation window:
    /// in-flight flows are re-signed (`request_uri_method = "post"`) by
    /// the pair they were created under. New flows always use the
    /// current key. Both this and its chain must be set together.
    #[serde(default)]
    pub previous_request_signing_key_path: Option<String>,
    /// The prior request certificate chain, paired with the previous key.
    #[serde(default)]
    pub previous_request_certificate_chain_path: Option<String>,
    #[serde(default)]
    pub pdp_id: Option<String>,
    /// Explicitly permit plain HTTP to a non-loopback PDP on a trusted local
    /// development network. Leave false in production.
    #[serde(default)]
    pub allow_insecure_http: bool,
    /// Local test-only escape hatch for a self-signed status-list endpoint.
    #[serde(default)]
    pub allow_invalid_status_list_certificates: bool,
    #[serde(default)]
    pub receipt_key_id: Option<String>,
    #[serde(default)]
    pub receipt_issuer: Option<String>,
    #[serde(default)]
    pub receipt_audience: Option<String>,
    #[serde(default)]
    pub max_receipt_ttl_secs: Option<i64>,
    #[serde(default)]
    pub zkp: Option<ZkpDeploymentConfig>,
    /// The serialized WRPRC (`rc-wrp+jwt` per ETSI TS 119 475 §5.2) of the
    /// FRONTED relying party — the deployment is an intermediary's. Read at
    /// startup, validated (shape + signature consistency), and carried on
    /// every armed request per ETSI TS 119 472-2 §6.3.2.2's `registration_cert`
    /// element. Absent for a non-intermediary deployment — the request stays
    /// the pre-EAAP shape.
    #[serde(default)]
    pub wrprc_path: Option<String>,
    /// The 472-2 §6.3.2.2 registrar dataset JSON (the B.2 members:
    /// identifier/srvDescription/registryURI/intendedUseIdentifier/purpose/
    /// policyURI, optional credential) — the RP Registrar-provided data the
    /// wallet renders. Absent when the deployment runs without the EAAP
    /// members.
    #[serde(default)]
    pub verifier_info_path: Option<String>,
    /// The WMP surface: absent — the whole [wmp] block — the service
    /// has no WMP surface at all.
    #[serde(default)]
    pub wmp: Option<crate::wmp::WmpConfig>,
    #[serde(flatten)]
    pub vp: VpBackendConfig,
}

impl DeploymentConfig {
    pub fn pdp_id(&self) -> &str {
        self.pdp_id.as_deref().unwrap_or(&self.pdp_endpoint)
    }
    pub fn receipt_key_id(&self) -> &str {
        self.receipt_key_id.as_deref().unwrap_or("receipt-dev")
    }
    pub fn receipt_issuer(&self) -> &str {
        self.receipt_issuer
            .as_deref()
            .unwrap_or("siros-verifier-core")
    }
    pub fn receipt_audience(&self) -> &str {
        self.receipt_audience.as_deref().unwrap_or("vp")
    }
    pub fn max_receipt_ttl_secs(&self) -> i64 {
        self.max_receipt_ttl_secs.unwrap_or(300)
    }
}

impl siros_verifier_core::config::ClientRegistrationProvider for ConfigClientRegistration {
    fn clients(&self) -> siros_verifier_core::Result<Vec<Value>> {
        // The inherent method: the same surface, reachable through the
        // core trait.
        ConfigClientRegistration::clients(self)
    }
}
