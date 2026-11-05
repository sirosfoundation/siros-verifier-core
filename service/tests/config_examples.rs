use tunnelbana_core::config::ProxyConfig;

#[test]
fn integrator_examples_load_through_the_real_config_parser() {
    // The examples deliberately use environment placeholders rather than secrets.
    unsafe {
        std::env::set_var(
            "SIROS_VERIFIER_STATE_KEY",
            "test-only-state-key-with-32-plus-bytes",
        );
        std::env::set_var("SIROS_VERIFIER_MONGODB_URI", "mongodb://127.0.0.1:27017");
        std::env::set_var("SIROS_PDP_BEARER_TOKEN", "test-only-token");
    }
    for name in ["quickstart", "mdoc-only", "replicas", "production"] {
        let path = format!("{}/../examples/{name}.toml", env!("CARGO_MANIFEST_DIR"));
        ProxyConfig::load(&path).unwrap_or_else(|error| panic!("{name}.toml: {error}"));
    }
    unsafe {
        std::env::remove_var("SIROS_VERIFIER_STATE_KEY");
        std::env::remove_var("SIROS_VERIFIER_MONGODB_URI");
        std::env::remove_var("SIROS_PDP_BEARER_TOKEN");
    }
}
