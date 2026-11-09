//! The deployment configuration refuses unknown fields: a typo in the
//! configuration file is a startup error, never a silently ignored setting.

use serde_json::json;
use siros_verifier_service::config::DeploymentConfig;

#[test]
fn unknown_deployment_fields_are_refused() {
    let valid = json!({
        "request_signing_key_path": "/k",
        "request_certificate_chain_path": "/c",
        "pdp_endpoint": "https://pdp.example/evaluation",
        "storage": {"backend": "memory"},
        "dcql": {"credentials": []},
        "attribute_map": {},
        "subject_pointer": "/sub",
        "role": "pid-provider",
    });
    // Positive control: the document without the extra field is a valid
    // deployment configuration, so the refusal below is because of the
    // unknown field and nothing else.
    serde_json::from_value::<DeploymentConfig>(valid.clone())
        .expect("the fixture without the unknown field is valid");
    let mut refused = valid;
    refused["unexpected"] = json!(true);
    let error = serde_json::from_value::<DeploymentConfig>(refused)
        .expect_err("an unknown field is a startup error");
    assert!(
        error.to_string().contains("unexpected"),
        "{error}: the refusal must name the unknown field"
    );
}
