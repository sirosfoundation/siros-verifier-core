//! The SIROS verifier gateway binary: an actix HTTP server around a real
//! tunnelbana OIDC frontend and the OpenID4VP backend from
//! `siros-verifier-core-tunnelbana`, assembled from the library modules in
//! this package (`siros_verifier_service`).

use std::sync::Arc;

use actix_web::{web, App, HttpServer};
use anyhow::{anyhow, bail, Context as _};
use grindvakt::provider::TokenUseStore;
use siros_verifier_core::oid4vp;
use siros_verifier_core::session_seal::SessionSealer;
use siros_verifier_core_tunnelbana::{
    system_clock, ui::UiFrontend, FlowStore, HttpPdp, MemoryFlowStore, PdpClient,
    ReqwestStatusListClient, TrustGate, VpBackend,
};
use siros_verifier_service::config::{DeploymentConfig, FlowStorageConfig, ZkpDeploymentConfig};
use siros_verifier_service::http::{self, ReqwestClient};
use siros_verifier_service::mongo_store::{MongoFlowStore, MongoTokenUseStore};
use siros_verifier_zkp::backend::{BackendRegistry, ProofBackend, SystemProfile};
use siros_verifier_zkp::catalog::CatalogArtifactSource;
use siros_verifier_zkp::circuits::Allowlist;
use siros_verifier_zkp::functions::FunctionRegistry;
use siros_verifier_zkp::longfellow::LongfellowBackend;
use siros_verifier_zkp::nym_auth::{SYSTEM_LONGFELLOW, SYSTEM_VEGA};
use siros_verifier_zkp::vega::VegaBackend;
use siros_verifier_zkp::verify::{VerifierPolicy, ZkpVerifier};
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::config::ProxyConfig;
use tunnelbana_core::http::HttpClient;
use tunnelbana_core::plugin::{BuildContext, Registry};
use tunnelbana_core::proxy::Proxy;
use tunnelbana_core::state::StateSealer;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/siros-verifier/proxy.toml".to_string());
    let cfg = ProxyConfig::load(&config_path).unwrap_or_else(|e| {
        eprintln!("failed to load config {config_path}: {e}");
        std::process::exit(1);
    });
    init_tracing(&cfg.logging);
    if cfg.tls.is_some() {
        eprintln!(
            "inbound TLS is not implemented in siros-verifier-service yet; terminate TLS upstream"
        );
        std::process::exit(1);
    }

    let proxy = build_proxy(cfg.clone(), &config_path)
        .await
        .unwrap_or_else(|e| {
            eprintln!("failed to assemble verifier proxy: {e:#}");
            std::process::exit(1);
        });
    let proxy = web::Data::new(Arc::new(proxy));
    let bind = std::env::var("TUNNELBANA_BIND").unwrap_or_else(|_| "127.0.0.1:9001".to_string());
    tracing::info!(%bind, base_url = %cfg.base_url, "starting siros-verifier-service");
    HttpServer::new(move || {
        App::new()
            .app_data(proxy.clone())
            .app_data(web::PayloadConfig::new(http::MAX_HTTP_BODY_BYTES))
            .route("/health", web::get().to(http::health))
            .default_service(web::to(http::handle))
    })
    .bind(&bind)?
    .run()
    .await
}

fn init_tracing(logging: &tunnelbana_core::config::LoggingConfig) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_new(&logging.level).unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if logging.format == "json" {
        builder.json().init();
    } else {
        builder.init();
    }
}

/// Assemble the real OIDC frontend and our custom OpenID4VP backend. The
/// frontend is configured through the ordinary tunnelbana registry; the custom
/// backend is constructed explicitly because it owns key material and a PDP.
async fn build_proxy(cfg: ProxyConfig, config_path: &str) -> anyhow::Result<Proxy> {
    let mut registry = Registry::new();
    tunnelbana_plugins::register_all(&mut registry);
    registry.register_frontend("ui", UiFrontend::build);

    let mapper = match &cfg.attributes {
        Some(path) => {
            let path = resolve_sibling(config_path, path);
            // A startup-only read, kept off the async runtime's worker threads.
            let read_path = path.clone();
            let toml_str =
                actix_web::rt::task::spawn_blocking(move || std::fs::read_to_string(read_path))
                    .await
                    .with_context(|| "joining the attribute-map read task")?
                    .with_context(|| format!("reading attribute map {}", path.display()))?;
            AttributeMapper::from_toml(&toml_str)?
        }
        None => AttributeMapper::default(),
    };
    let mapper = Arc::new(mapper);
    let http: Arc<dyn HttpClient> = Arc::new(ReqwestClient::with_limits(
        cfg.http_connect_timeout_seconds,
        cfg.http_read_timeout_seconds,
        cfg.http_request_timeout_seconds,
        cfg.http_max_response_bytes,
    ));
    let make_ctx = |name: &str, config: serde_json::Value| BuildContext {
        name: name.to_string(),
        base_url: cfg.base_url.clone(),
        config,
        attribute_mapper: mapper.clone(),
        http_client: http.clone(),
        secret: cfg.state_encryption_key.clone(),
        previous_secrets: cfg.previous_state_encryption_keys.clone(),
    };

    let token_use_store = build_token_use_store(&cfg).await?;
    let mut frontends = Vec::new();
    for p in &cfg.frontends {
        let bx = make_ctx(&p.name, p.config_json());
        if p.kind == "oidc" {
            if let Some(store) = &token_use_store {
                frontends.push(
                    tunnelbana_plugins::oidc_frontend::OidcFrontend::build_with_token_use_store(
                        &bx,
                        store.clone(),
                    )?,
                );
            } else {
                frontends.push(registry.build_frontend(&p.kind, &bx)?);
            }
        } else {
            frontends.push(registry.build_frontend(&p.kind, &bx)?);
        }
        tracing::info!(name = %p.name, kind = %p.kind, "loaded frontend");
    }
    if cfg.backends.len() != 1 || cfg.backends[0].kind != "openid4vp" {
        bail!("exactly one backend of type openid4vp is required");
    }
    let plugin = &cfg.backends[0];
    let backend = build_openid4vp_backend(&cfg, plugin, config_path).await?;
    let backends = vec![backend];
    let mut microservices = Vec::new();
    for p in &cfg.microservices {
        let bx = make_ctx(&p.name, p.config_json());
        microservices.push(registry.build_microservice(&p.kind, &bx)?);
        tracing::info!(name = %p.name, kind = %p.kind, "loaded microservice");
    }

    let ttl = (cfg.state_cookie_max_age != 0).then_some(cfg.state_cookie_max_age);
    let sealer = StateSealer::new(&cfg.state_encryption_key, cfg.cookie_name.clone())
        .with_secure(cfg.cookie_secure)
        .with_same_site(cfg.cookie_same_site.clone())
        .with_ttl_seconds(ttl)
        .with_previous_secrets(&cfg.previous_state_encryption_keys);
    Ok(Proxy::new(frontends, backends, microservices, sealer))
}

async fn build_token_use_store(
    cfg: &ProxyConfig,
) -> anyhow::Result<Option<Arc<dyn TokenUseStore>>> {
    if cfg.backends.len() != 1 || cfg.backends[0].kind != "openid4vp" {
        bail!("exactly one backend of type openid4vp is required");
    }
    let deployment: DeploymentConfig = serde_json::from_value(cfg.backends[0].config_json())?;
    match deployment.storage.backend.as_str() {
        "memory" => Ok(None),
        "mongodb" => {
            let uri = deployment
                .storage
                .uri
                .as_deref()
                .ok_or_else(|| anyhow!("MongoDB storage requires uri"))?;
            let database = deployment
                .storage
                .database
                .as_deref()
                .ok_or_else(|| anyhow!("MongoDB storage requires database"))?;
            Ok(Some(Arc::new(
                MongoTokenUseStore::connect(uri, database, "oidc_token_use")
                    .await
                    .map_err(|e| anyhow!(e))?,
            )))
        }
        other => bail!("unsupported flow storage backend {other:?}"),
    }
}

async fn build_flow_store(config: &FlowStorageConfig) -> anyhow::Result<Arc<dyn FlowStore>> {
    match config.backend.as_str() {
        "memory" => {
            if config.uri.is_some() || config.database.is_some() || config.collection.is_some() {
                bail!("memory storage does not accept MongoDB settings");
            }
            Ok(Arc::new(MemoryFlowStore::default()))
        }
        "mongodb" => {
            let uri = config
                .uri
                .as_deref()
                .ok_or_else(|| anyhow!("MongoDB storage requires uri"))?;
            let database = config
                .database
                .as_deref()
                .ok_or_else(|| anyhow!("MongoDB storage requires database"))?;
            let collection = config.collection.as_deref().unwrap_or("presentation_flows");
            for (name, value) in [("database", database), ("collection", collection)] {
                if value.is_empty()
                    || value.len() > 63
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                {
                    bail!("MongoDB {name} must be 1..=63 ASCII letters, digits, '_' or '-'");
                }
            }
            Ok(Arc::new(
                MongoFlowStore::connect(uri, database, collection)
                    .await
                    .map_err(|e| anyhow!(e))?,
            ))
        }
        other => bail!("unsupported flow storage backend {other:?}"),
    }
}

fn build_zkp_verifier(config: &ZkpDeploymentConfig) -> anyhow::Result<ZkpVerifier> {
    let allowlist = Allowlist::new(&config.circuits).map_err(|e| anyhow!(e))?;
    let mut backends = BackendRegistry::new();
    for allowed in allowlist.allowed() {
        let system = allowed.split(' ').next().unwrap_or_default();
        backends
            .register(
                system,
                SystemProfile::single_issuer_age_check(),
                |entry, bytes| {
                    if entry.system_id == SYSTEM_LONGFELLOW {
                        LongfellowBackend::from_entry(entry, bytes)
                            .map(|backend| Box::new(backend) as Box<dyn ProofBackend>)
                    } else if entry.system_id == SYSTEM_VEGA {
                        VegaBackend::from_entry(entry, bytes)
                            .map(|backend| Box::new(backend) as Box<dyn ProofBackend>)
                    } else {
                        Err(siros_verifier_zkp::refusal::ZkpError::fault(format!(
                            "proof system {:?} has no registered native backend in this build",
                            entry.system_id
                        )))
                    }
                },
            )
            .map_err(|e| anyhow!(e))?;
    }
    let artifacts = CatalogArtifactSource::new(&config.circuits.sources)?.prefetch(&allowlist)?;
    let verifier = ZkpVerifier::new(
        allowlist,
        Box::new(artifacts),
        FunctionRegistry::with_builtins(),
        backends,
        VerifierPolicy {
            role: config.backend.role.clone(),
            issuer_set: config.issuer_set,
            tolerance: config.tolerance,
        },
    )?;
    // Validate local paths/hashes and initialize every allowlisted native backend before serving a
    // presentation. Embedded users keep lazy loading; the service pays this cost once at startup.
    verifier.prewarm().map_err(|e| anyhow!(e))?;
    Ok(verifier)
}

async fn build_openid4vp_backend(
    cfg: &ProxyConfig,
    plugin: &tunnelbana_core::config::PluginConfig,
    config_path: &str,
) -> anyhow::Result<Box<dyn tunnelbana_core::plugin::Backend>> {
    let mut deployment: DeploymentConfig = serde_json::from_value(plugin.config_json())?;
    let key_path = resolve_sibling(config_path, &deployment.request_signing_key_path);
    // Startup-only reads, kept off the async runtime's worker threads.
    let key_read_path = key_path.clone();
    let key_pem =
        actix_web::rt::task::spawn_blocking(move || std::fs::read_to_string(key_read_path))
            .await
            .with_context(|| "joining the request signing key read task")?
            .with_context(|| format!("reading request signing key {}", key_path.display()))?;
    let mut request_jwk = jose_rs::jwk::jwk_from_pkcs8_pem(&key_pem)?;
    request_jwk.alg = Some("ES256".into());
    let private_scalar = request_jwk
        .d
        .as_deref()
        .ok_or_else(|| anyhow!("request signing JWK has no private scalar"))?;
    let receipt_key = p256::ecdsa::SigningKey::from_slice(
        &jose_rs::base64url::decode(private_scalar).context("decoding receipt signing scalar")?,
    )?;
    let request_signer = oid4vp::software_signer(&request_jwk)?;

    let chain_path = resolve_sibling(config_path, &deployment.request_certificate_chain_path);
    let chain_read_path = chain_path.clone();
    let chain_pem =
        actix_web::rt::task::spawn_blocking(move || std::fs::read_to_string(chain_read_path))
            .await
            .with_context(|| "joining the request certificate chain read task")?
            .with_context(|| {
                format!("reading request certificate chain {}", chain_path.display())
            })?;
    let chain_der: Vec<Vec<u8>> = pem::parse_many(chain_pem)?
        .into_iter()
        .filter(|block| block.tag() == "CERTIFICATE")
        .map(|block| block.into_contents())
        .collect();
    if chain_der.is_empty() {
        bail!("request certificate chain is empty");
    }

    // Increment 2 (#39): the intermediary deployment's EAAP members. The
    // WRPRC is the FRONTED relying party's registration certificate; the
    // request-signing key + chain above are the INTERMEDIARY's WRPAC (the
    // X.509 access certificate per ETSI TS 119 411-8) — the operator points
    // those config paths at the intermediary's own credentials. The WRPRC
    // is loaded once and validated at startup (fail-fast on a malformed
    // file); the arm re-validates freshness per-request.
    let wrprc = match &deployment.wrprc_path {
        Some(path) => {
            let path = resolve_sibling(config_path, path);
            let read_path = path.clone();
            let token =
                actix_web::rt::task::spawn_blocking(move || std::fs::read_to_string(read_path))
                    .await
                    .with_context(|| "joining the WRPRC read task")?
                    .with_context(|| format!("reading WRPRC {}", path.display()))?;
            // Validate at startup: the shape, the signature consistency
            // under the presented chain, and the freshness right now. A
            // malformed or stale file fails the boot, not the first
            // request.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            siros_verifier_core::wrprc::parse_wrprc(token.trim(), now)
                .with_context(|| format!("validating WRPRC {}", path.display()))?;
            tracing::info!(name = %plugin.name, "loaded WRPRC (the fronted RP's registration certificate)");
            Some(token.trim().to_owned())
        }
        None => None,
    };
    let verifier_info = match &deployment.verifier_info_path {
        Some(path) => {
            let path = resolve_sibling(config_path, path);
            let read_path = path.clone();
            let dataset =
                actix_web::rt::task::spawn_blocking(move || std::fs::read_to_string(read_path))
                    .await
                    .with_context(|| "joining the verifier_info read task")?
                    .with_context(|| format!("reading registrar dataset {}", path.display()))?;
            let dataset: serde_json::Value = serde_json::from_str(&dataset)
                .with_context(|| format!("parsing registrar dataset {}", path.display()))?;
            // Validate the B.2 members at startup — the same validation the
            // arm applies, caught before the boot completes.
            siros_verifier_core::wrprc::build_verifier_info(Some(&dataset), None)
                .with_context(|| format!("validating registrar dataset {}", path.display()))?;
            tracing::info!(name = %plugin.name, "loaded registrar dataset (the verifier_info element)");
            Some(dataset)
        }
        None => None,
    };
    let mut vp_config = deployment.vp.clone();
    vp_config.wrprc = wrprc;
    vp_config.verifier_info = verifier_info;

    let pdp: Arc<dyn PdpClient> = if deployment.allow_insecure_http {
        Arc::new(
            HttpPdp::new_allow_http(
                &deployment.pdp_endpoint,
                deployment.pdp_bearer_token.clone(),
                std::time::Duration::from_secs(10),
            )
            .map_err(|e| anyhow!(e))?,
        )
    } else {
        Arc::new(
            HttpPdp::new(
                &deployment.pdp_endpoint,
                deployment.pdp_bearer_token.clone(),
                std::time::Duration::from_secs(10),
            )
            .map_err(|e| anyhow!(e))?,
        )
    };
    let gate = TrustGate::new(
        pdp,
        receipt_key,
        deployment.receipt_key_id(),
        deployment.receipt_issuer(),
        deployment.receipt_audience(),
        deployment.pdp_id(),
        deployment.max_receipt_ttl_secs(),
    )
    .with_no_freshness_ttl(deployment.max_receipt_ttl_secs());
    let previous_masters: Vec<&[u8]> = cfg
        .previous_state_encryption_keys
        .iter()
        .map(|secret| secret.as_bytes())
        .collect();
    let sealer = SessionSealer::from_master(cfg.state_encryption_key.as_bytes(), &plugin.name)?
        .with_previous_masters(&previous_masters, &plugin.name)?;
    let module_base = format!("{}/{}", cfg.base_url.trim_end_matches('/'), plugin.name);
    let store = build_flow_store(&deployment.storage).await?;
    let backend = if let Some(zkp) = deployment.zkp.take() {
        let verifier = build_zkp_verifier(&zkp)?;
        VpBackend::new_with_zkp(
            &plugin.name,
            &module_base,
            vp_config,
            zkp.backend,
            gate,
            request_signer,
            chain_der,
            verifier,
            system_clock(),
        )?
    } else {
        VpBackend::new(
            &plugin.name,
            &module_base,
            vp_config,
            gate,
            request_signer,
            chain_der,
            system_clock(),
        )?
    };
    let status_list_client = if deployment.allow_invalid_status_list_certificates {
        ReqwestStatusListClient::new_allow_invalid_certificates_for_testing(
            std::time::Duration::from_secs(5),
        )
    } else {
        ReqwestStatusListClient::new(std::time::Duration::from_secs(5))
    }
    .map_err(|e| anyhow!(e))?;
    let backend = backend
        .with_flow_store(store)
        .with_session_sealer(sealer)
        .with_status_list_client(Arc::new(status_list_client));
    tracing::info!(name = %plugin.name, pdp = %deployment.pdp_endpoint, storage = %deployment.storage.backend, "loaded OpenID4VP backend");
    Ok(Box::new(backend))
}

fn resolve_sibling(config_path: &str, rel: &str) -> std::path::PathBuf {
    let p = std::path::Path::new(rel);
    if p.is_absolute() {
        return p.to_path_buf();
    }
    std::path::Path::new(config_path)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(p)
}
