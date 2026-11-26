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
use siros_verifier_service::config::{
    ConfigClientRegistration, DeploymentConfig, FlowStorageConfig, PlatformSecretProvider,
    SecretProvider, ZkpDeploymentConfig,
};
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
    // The WMP surface (the [wmp] block of the backend config): built
    // fail-fast — a malformed identity chain aborts the boot. The
    // Arc-shared surface serves both the boot evaluation task and the
    // POST /wmp/joins delivery endpoint. Absent — no surface, no route.
    let wmp_state: Option<web::Data<siros_verifier_service::wmp_http::WmpEndpointState>> =
        match wmp_config(&cfg) {
            Some(config) => {
                let surface = match siros_verifier_service::wmp::WmpSurface::new(
                    config,
                    &config_dir(&config_path),
                ) {
                    Ok(surface) => surface,
                    Err(e) => {
                        eprintln!("the WMP surface refused the boot: {e:#}");
                        std::process::exit(1);
                    }
                };
                let surface = std::sync::Arc::new(surface);
                tracing::info!(
                    identity = surface.identity(),
                    invites = surface.config_invites().len(),
                    groups = surface.config_groups_len(),
                    "the WMP surface is configured"
                );
                // The config invites' and groups' decisions, evaluated
                // in the background (fail-closed at the PDP; a stalled
                // PDP never delays the bind).
                let task_surface = surface.clone();
                actix_web::rt::spawn(async move {
                    for (invite, decision) in task_surface.evaluate_config_invites().await {
                        tracing::info!(
                            group = %invite.provider,
                            sender = %invite.sender,
                            allowed = decision == siros_verifier_service::wmp::Decision::Allow,
                            "the config invite's join decision"
                        );
                    }
                    for (group, decision) in task_surface.evaluate_config_groups().await {
                        tracing::info!(
                            group = %group.id,
                            via = %group.via,
                            allowed = decision == siros_verifier_service::wmp::Decision::Allow,
                            "the config group's join decision"
                        );
                    }
                });
                Some(web::Data::new(
                    siros_verifier_service::wmp_http::WmpEndpointState { surface },
                ))
            }
            None => None,
        };
    let bind = std::env::var("TUNNELBANA_BIND").unwrap_or_else(|_| "127.0.0.1:9001".to_string());
    tracing::info!(%bind, base_url = %cfg.base_url, "starting siros-verifier-service");
    HttpServer::new(move || {
        let mut app = App::new()
            .app_data(proxy.clone())
            .app_data(web::PayloadConfig::new(http::MAX_HTTP_BODY_BYTES))
            .route("/health", web::get().to(http::health));
        if let Some(state) = &wmp_state {
            // The orchestrator's delivery channel — served only when
            // the [wmp] block is present.
            app = app.app_data(state.clone()).route(
                "/wmp/joins",
                web::post().to(siros_verifier_service::wmp_http::post_join),
            );
        }
        app.default_service(web::to(http::handle))
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

    // The platform secret provider — the boot's one selection point. The
    // service constructs the default (both platform channels: env vars
    // and files under the config directory); an alternative provider
    // (a k8s API watch, a Vault client) replaces this construction and
    // everything downstream resolves through the trait unchanged.
    let secrets: Arc<dyn SecretProvider> =
        Arc::new(PlatformSecretProvider::new(config_dir(config_path)));

    // The one deployment config parse and secret resolution, shared by
    // both stores: the flow store and the token-use store consume the
    // same resolved storage settings, so a `uri_env`/`uri_file`
    // reference reaches both, never just one (which would boot the
    // other on the unresolved raw config and refuse a present secret).
    // Validate the shape first: tunnelbana's parser defaults an omitted
    // `[[backend]]` to an empty vector, and indexing it would panic —
    // refuse with the operator-facing message instead.
    if cfg.backends.len() != 1 || cfg.backends[0].kind != "openid4vp" {
        bail!("exactly one backend of type openid4vp is required");
    }
    let mut deployment: DeploymentConfig = serde_json::from_value(cfg.backends[0].config_json())?;
    resolve_deployment_secrets(&mut deployment, secrets.as_ref())?;
    let token_use_store = build_token_use_store(&deployment.storage).await?;
    let mut frontends = Vec::new();
    for p in &cfg.frontends {
        let mut config = p.config_json();
        if p.kind == "oidc" {
            // Resolve the client roster's `_env` credential references
            // through the platform secret provider (the SUNET/vc #935
            // pattern): each entry names the env var its credential comes
            // from, the provider resolves it at boot (fail-fast on a
            // missing, empty or doubly-sourced value), and the strict
            // downstream parser never sees the `_env` field — only the
            // resolved `client_secret`. A k8s deployment backs the
            // variable with a Secret's `secretKeyRef`.
            if let Some(clients) = config.get_mut("clients").cloned() {
                let raw = clients.as_array().cloned().ok_or_else(|| {
                    anyhow!("frontend {}: clients must be a list of tables", p.name)
                })?;
                let resolved = ConfigClientRegistration::new(raw, secrets.clone())
                    .clients()
                    .map_err(|e| anyhow!("frontend {}: {} [{}]", p.name, e, e.code()))?;
                config["clients"] = serde_json::Value::Array(resolved);
            }
        }
        let bx = make_ctx(&p.name, config);
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
    let backend = build_openid4vp_backend(&cfg, plugin, config_path, deployment).await?;
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
    storage: &FlowStorageConfig,
) -> anyhow::Result<Option<Arc<dyn TokenUseStore>>> {
    match storage.backend.as_str() {
        "memory" => Ok(None),
        "mongodb" => {
            let uri = storage
                .uri
                .as_deref()
                .ok_or_else(|| anyhow!("MongoDB storage requires uri"))?;
            let database = storage
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

/// Resolve the deployment config's secret references at boot, through
/// the platform secret provider: `_env` references through the
/// environment (a k8s Secret's `secretKeyRef`, a Fly secret), `_file`
/// references against the config file's directory (a Secret volume
/// mount, materialized beside the config). Fail fast: a missing or
/// empty source, or two sources named for one value, is a boot error
/// naming the field and the source.
///
/// Mutates the config in place: the resolved value replaces the
/// reference fields, which are cleared afterwards so a later reader
/// cannot mistake a reference for a value.
fn resolve_deployment_secrets(
    deployment: &mut DeploymentConfig,
    secrets: &dyn SecretProvider,
) -> anyhow::Result<()> {
    let resolve = |field: &str,
                   inline: Option<&str>,
                   env: Option<&str>,
                   file: Option<&str>|
     -> anyhow::Result<Option<String>> {
        siros_verifier_core::config::resolve_secret_field(field, inline, env, file, secrets)
            .map_err(|e| anyhow!("resolving {field}: {} [{}]", e, e.code()))
    };
    deployment.pdp_bearer_token = resolve(
        "pdp_bearer_token",
        deployment.pdp_bearer_token.as_deref(),
        deployment.pdp_bearer_token_env.as_deref(),
        deployment.pdp_bearer_token_file.as_deref(),
    )?;
    deployment.pdp_bearer_token_env = None;
    deployment.pdp_bearer_token_file = None;
    deployment.storage.uri = resolve(
        "storage.uri",
        deployment.storage.uri.as_deref(),
        deployment.storage.uri_env.as_deref(),
        deployment.storage.uri_file.as_deref(),
    )?;
    deployment.storage.uri_env = None;
    deployment.storage.uri_file = None;
    Ok(())
}

/// Load a request-signing key/chain pair from the configured paths: the
/// PKCS#8 PEM, the DER certificate chain (leaf first), and the JWK (the
/// current pair also derives the receipt key from the JWK's private
/// scalar).
async fn load_request_signing_pair(
    config_path: &str,
    key_path: &str,
    chain_path: &str,
) -> anyhow::Result<(kryptering::SoftwareSigner, Vec<Vec<u8>>, jose_rs::jwk::Jwk)> {
    let key_full = resolve_sibling(config_path, key_path);
    let key_read_path = key_full.clone();
    let key_pem =
        actix_web::rt::task::spawn_blocking(move || std::fs::read_to_string(key_read_path))
            .await
            .with_context(|| "joining the request signing key read task")?
            .with_context(|| format!("reading request signing key {}", key_full.display()))?;
    let mut jwk = jose_rs::jwk::jwk_from_pkcs8_pem(&key_pem)?;
    jwk.alg = Some("ES256".into());
    let signer = oid4vp::software_signer(&jwk)?;
    let chain_full = resolve_sibling(config_path, chain_path);
    let chain_read_path = chain_full.clone();
    let chain_pem =
        actix_web::rt::task::spawn_blocking(move || std::fs::read_to_string(chain_read_path))
            .await
            .with_context(|| "joining the certificate chain read task")?
            .with_context(|| format!("reading certificate chain {}", chain_full.display()))?;
    let chain_der: Vec<Vec<u8>> = pem::parse_many(chain_pem)?
        .into_iter()
        .filter(|block| block.tag() == "CERTIFICATE")
        .map(|block| block.into_contents())
        .collect();
    if chain_der.is_empty() {
        bail!("certificate chain {chain_path} is empty");
    }
    // The key must be the chain leaf's key: a mismatched pair would pass
    // every later init step and only surface as signatures no wallet can
    // verify. Refuse it here, naming both paths — the same fail-fast
    // posture the WRPRC validation has. The thumbprint covers the public
    // members only, so the private JWK and the leaf's public JWK
    // thumbprint identically when (and only when) they are the same key.
    let key_thumbprint = jose_rs::jwk::thumbprint::thumbprint_sha256(&jwk)
        .with_context(|| "thumbprinting the request signing key")?;
    let leaf_jwk = siros_verifier_core::sdjwt::jwk_from_cert_der(&chain_der[0])
        .with_context(|| "extracting the chain leaf's public key")?;
    let leaf_thumbprint = jose_rs::jwk::thumbprint::thumbprint_sha256(&leaf_jwk)
        .with_context(|| "thumbprinting the chain leaf")?;
    if key_thumbprint != leaf_thumbprint {
        bail!(
            "the request signing key {key_path} does not match the certificate chain leaf in {chain_path} — a mismatched pair signs requests no wallet can verify"
        );
    }
    Ok((signer, chain_der, jwk))
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
    mut deployment: DeploymentConfig,
) -> anyhow::Result<Box<dyn tunnelbana_core::plugin::Backend>> {
    // Startup-only reads, kept off the async runtime's worker threads.
    let (request_signer, chain_der, request_jwk) = load_request_signing_pair(
        config_path,
        &deployment.request_signing_key_path,
        &deployment.request_certificate_chain_path,
    )
    .await?;
    let private_scalar = request_jwk
        .d
        .as_deref()
        .ok_or_else(|| anyhow!("request signing JWK has no private scalar"))?;
    let receipt_key = p256::ecdsa::SigningKey::from_slice(
        &jose_rs::base64url::decode(private_scalar).context("decoding receipt signing scalar")?,
    )?;

    // The rotation window: a previous request-signing key/chain pair is
    // retained so in-flight flows (created under the old key, re-signed
    // when `request_uri_method = "post"` echoes a wallet_nonce) complete
    // under the generation they started with. New flows always use the
    // current pair. Both paths must be set together; the retention
    // window is bounded by `request_ttl_secs`, so the pair is dropped
    // from the config once every pre-rotation flow has expired.
    let previous_pair = match (
        &deployment.previous_request_signing_key_path,
        &deployment.previous_request_certificate_chain_path,
    ) {
        (Some(key), Some(chain)) => {
            let (signer, chain_der, _) =
                load_request_signing_pair(config_path, key, chain).await?;
            tracing::info!(name = %plugin.name, "retained a previous request-signing key for the rotation window");
            Some((signer, chain_der))
        }
        (None, None) => None,
        _ => bail!(
            "previous_request_signing_key_path and previous_request_certificate_chain_path must be set together"
        ),
    };

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
            // The strict parse: duplicate members are ambiguous to
            // different parsers — the same check every other attacker-
            // controlled JSON input gets.
            let dataset: serde_json::Value =
                siros_verifier_core::json_strict::from_str(&dataset)
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
    // The deployment surface is PATH-ONLY: the DeploymentConfig flattens
    // VpBackendConfig, so an inline `wrprc` or `verifier_info` member in
    // the config file would be accepted by the deserializer and then
    // silently discarded here (both overwritten from the file paths). Fail
    // loudly instead — the operator meant to configure the intermediary.
    if deployment.vp.wrprc.is_some() {
        bail!("inline `wrprc` is not supported on the deployment config; use `wrprc_path`");
    }
    if deployment.vp.verifier_info.is_some() {
        bail!("inline `verifier_info` is not supported on the deployment config; use `verifier_info_path`");
    }
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
    // The rotation window's retained pair, validated (distinct leaves)
    // by the builder.
    let backend = match previous_pair {
        Some(previous) => backend.with_previous_request_signers(vec![previous])?,
        None => backend,
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

/// The [wmp] block from the backend config, when present. The one
/// backend's own config parse stays build_proxy's; this extracts only
/// the surface's member.
fn wmp_config(cfg: &ProxyConfig) -> Option<siros_verifier_service::wmp::WmpConfig> {
    if cfg.backends.len() != 1 || cfg.backends[0].kind != "openid4vp" {
        return None;
    }
    let deployment: siros_verifier_service::config::DeploymentConfig =
        serde_json::from_value(cfg.backends[0].config_json())
            .expect("the backend config parses (build_proxy enforces the same)");
    deployment.wmp
}

/// The config file's directory: the base sibling paths (and relative
/// `_file` secret references) resolve against.
fn config_dir(config_path: &str) -> std::path::PathBuf {
    std::path::Path::new(config_path)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."))
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
