use serde::Deserialize;
use siros_verifier_core::issuer_set::IssuerSetPolicy;
use siros_verifier_core_tunnelbana::{VpBackendConfig, ZkpBackendConfig};
use siros_verifier_zkp::circuits::CircuitsConfig;
use siros_verifier_zkp::verify::Tolerance;

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
