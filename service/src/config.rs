use serde::Deserialize;
use siros_verifier_core_tunnelbana::VpBackendConfig;

/// Deployment-only settings wrapped around the backend's closed protocol config.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentConfig {
    pub request_signing_key_path: String,
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
    #[serde(default)]
    pub receipt_key_id: Option<String>,
    #[serde(default)]
    pub receipt_issuer: Option<String>,
    #[serde(default)]
    pub receipt_audience: Option<String>,
    #[serde(default)]
    pub max_receipt_ttl_secs: Option<i64>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_deployment_fields_are_refused() {
        let value = serde_json::json!({
            "request_signing_key_path": "/k",
            "request_certificate_chain_path": "/c",
            "pdp_endpoint": "https://pdp.example/evaluation",
            "dcql": {"credentials": []},
            "attribute_map": {},
            "subject_pointer": "/sub",
            "role": "pid-provider",
            "unexpected": true
        });
        assert!(serde_json::from_value::<DeploymentConfig>(value).is_err());
    }
}
