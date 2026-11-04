//! The SIROS verifier gateway: an actix HTTP server, a real tunnelbana OIDC
//! frontend, and the OpenID4VP backend from `siros-verifier-core-tunnelbana`.

mod config;
mod http;
mod mongo_store;

use std::collections::BTreeMap;
use std::sync::Arc;

use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};
use anyhow::{anyhow, bail, Context as _};
use config::{DeploymentConfig, FlowStorageConfig, ZkpDeploymentConfig};
use grindvakt::provider::TokenUseStore;
use http::ReqwestClient;
use mongo_store::{MongoFlowStore, MongoTokenUseStore};
use siros_verifier_core::oid4vp;
use siros_verifier_core::session_seal::SessionSealer;
use siros_verifier_core_tunnelbana::{
    system_clock, ui::UiFrontend, FlowStore, HttpPdp, MemoryFlowStore, PdpClient,
    ReqwestStatusListClient, TrustGate, VpBackend,
};
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
use tunnelbana_core::http::{HttpClient, HttpRequestData, Response};
use tunnelbana_core::plugin::{BuildContext, Registry};
use tunnelbana_core::proxy::Proxy;
use tunnelbana_core::state::StateSealer;

// A real Longfellow nym_auth proof is about 344 KiB before CBOR and JWE
// base64 expansion. Keep a hard limit, but allow those genuine presentations.
const MAX_HTTP_BODY_BYTES: usize = 2 * 1024 * 1024;

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
            .app_data(web::PayloadConfig::new(MAX_HTTP_BODY_BYTES))
            .route("/health", web::get().to(health))
            .default_service(web::to(handle))
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
            let toml_str = std::fs::read_to_string(&path)
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
    let key_pem = std::fs::read_to_string(&key_path)
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
    let chain_pem = std::fs::read_to_string(&chain_path)
        .with_context(|| format!("reading request certificate chain {}", chain_path.display()))?;
    let chain_der: Vec<Vec<u8>> = pem::parse_many(chain_pem)?
        .into_iter()
        .filter(|block| block.tag() == "CERTIFICATE")
        .map(|block| block.into_contents())
        .collect();
    if chain_der.is_empty() {
        bail!("request certificate chain is empty");
    }

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
    let mut backend = VpBackend::new(
        &plugin.name,
        &module_base,
        deployment.vp,
        gate,
        request_signer,
        chain_der,
        system_clock(),
    )?;
    if let Some(zkp) = deployment.zkp.take() {
        let verifier = build_zkp_verifier(&zkp)?;
        backend = backend.with_zkp(zkp.backend, verifier)?;
    }
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

async fn health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({ "status": "ok" }))
}

async fn handle(req: HttpRequest, body: web::Bytes, proxy: web::Data<Arc<Proxy>>) -> HttpResponse {
    let request = build_request_data(&req, &body);
    let response = proxy.run(request).await;
    to_actix(response)
}

fn build_request_data(req: &HttpRequest, body: &web::Bytes) -> HttpRequestData {
    let path = req.path().trim_start_matches('/').to_string();
    let method = req.method().as_str().to_uppercase();
    let query_pairs = form_urlencoded::parse(req.query_string().as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect::<Vec<_>>();
    let query = query_pairs.iter().cloned().collect();

    let mut headers = BTreeMap::new();
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            headers.insert(name.as_str().to_lowercase(), v.to_string());
        }
    }
    let is_form = headers
        .get("content-type")
        .map(|c| c.starts_with("application/x-www-form-urlencoded"))
        .unwrap_or(false);
    let form_pairs = if is_form {
        form_urlencoded::parse(std::str::from_utf8(body).unwrap_or("").as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let form = form_pairs.iter().cloned().collect();
    let cookies = parse_cookies(headers.get("cookie").map(|s| s.as_str()).unwrap_or(""));
    let uri = format!(
        "{}://{}{}",
        req.connection_info().scheme(),
        req.connection_info().host(),
        req.uri()
    );

    HttpRequestData {
        path,
        method,
        uri,
        query_pairs,
        query,
        form_pairs,
        form,
        body: body.to_vec(),
        headers,
        cookies,
    }
}

fn parse_cookies(header: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for part in header.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    map
}

fn to_actix(resp: Response) -> HttpResponse {
    let status = actix_web::http::StatusCode::from_u16(resp.status)
        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = HttpResponse::build(status);
    for (k, v) in &resp.headers {
        builder.append_header((k.clone(), v.clone()));
    }
    builder.body(resp.body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::StatusCode, test};

    #[actix_web::test]
    async fn health_returns_status_ok() {
        let app = test::init_service(App::new().route("/health", web::get().to(health))).await;
        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body, serde_json::json!({ "status": "ok" }));
    }

    #[actix_web::test]
    async fn genuine_longfellow_response_size_fits_the_http_body_limit() {
        let app = test::init_service(
            App::new()
                .app_data(web::PayloadConfig::new(MAX_HTTP_BODY_BYTES))
                .default_service(web::to(|_body: web::Bytes| async {
                    HttpResponse::Ok().finish()
                })),
        )
        .await;
        // Measured from a genuine Pixel Longfellow direct_post.jwt response.
        let req = test::TestRequest::post()
            .uri("/vp/response/id")
            .set_payload(vec![0u8; 1_102_937])
            .to_request();
        let response = test::call_service(&app, req).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn request_adapter_preserves_duplicate_protocol_parameters() {
        let request = test::TestRequest::post()
            .uri("/vp/response/id?resource=first&resource=second&state=one&state=two")
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .to_http_request();
        let body = web::Bytes::from_static(b"response=first&response=second");
        let data = build_request_data(&request, &body);
        assert_eq!(data.query_pairs.len(), 4);
        assert_eq!(data.form_pairs.len(), 2);
        assert_eq!(data.query.get("state").map(String::as_str), Some("two"));
        assert_eq!(
            data.form.get("response").map(String::as_str),
            Some("second")
        );
    }

    #[actix_web::test]
    async fn builds_the_real_oidc_frontend_and_custom_backend() {
        let dir = std::env::temp_dir().join(format!(
            "siros-verifier-service-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["verifier.example".to_string()])
            .unwrap()
            .self_signed(&kp)
            .unwrap();
        std::fs::write(dir.join("key.pem"), kp.serialize_pem()).unwrap();
        std::fs::write(dir.join("chain.pem"), cert.pem()).unwrap();
        let cfg = ProxyConfig::from_str(&format!(
            r#"
            base_url = "https://verifier.example"
            state_encryption_key = "a-32-byte-or-longer-test-secret!!"
            cookie_secure = false

            [[frontend]]
            type = "ui"
            name = "ui"

            [[frontend]]
            type = "oidc"
            name = "OIDC"
              [frontend.config]
              signing_key_path = "{key}"
              signing_algorithm = "ES256"

            [[backend]]
            type = "openid4vp"
            name = "vp"
              [backend.config]
              request_signing_key_path = "{key}"
              request_certificate_chain_path = "{chain}"
              pdp_endpoint = "http://go-trust-allow:6001/evaluation"
              allow_insecure_http = true
              role = "pid-provider"
              dcql = {{ credentials = [] }}
              attribute_map = {{}}
              subject_pointer = "/sub"

              [backend.config.storage]
              backend = "memory"

              [backend.config.zkp]
              query = {{ id = "nym_attestation", format = "zkp_req",
                meta = {{ source_format = "mso_mdoc", doctype_value = "eu.europa.ec.eudi.nym_auth.1" }},
                _req = [
                  {{ fn_id = "pseudonym", return = "nym-1", params = {{
                    config = "known-offender-matching-ssc", ver = 1, prf = "sha-256" }} }},
                  {{ fn_id = "age_check", return = "age-1", params = {{
                    ge = "2008-10-10", le = "2013-10-09" }} }},
                ] }}
              system_id_values = ["urn:circuits:longfellow:nym_auth:v1"]
              proof_system_values = ["longfellow-libzk-v1"]
              role = "mdoc-issuer"
              verifier_id = "x509_san_dns:verifier.example"
              subject_handle = "nym-1"
              attribute_map = {{ pseudonym = "nym-1", ageOver = "age-1" }}
              auth_class_ref = "urn:eudi:loa:high"

              [backend.config.zkp.circuits]
              sources = []

              [[backend.config.zkp.circuits.allow]]
              system_id = "urn:circuits:longfellow:nym_auth:v1"
              config = "known-offender-matching-ssc"
              hash_circuit_id = "5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729"
              sig_circuit_id = "00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb"
              block_enc_hash = 6983
              block_enc_sig = 4679
              artifact_path = "{dir}/nymauth.bin"
              artifact_sha256 = "92dd42fdf99673249eec33c7d07850bd9da66fbdab01ef26391e04c8341c1b7f"
              artifact_bytes = 1062842
        "#,
            dir = dir.display(),
            key = dir.join("key.pem").display(),
            chain = dir.join("chain.pem").display()
        ))
        .unwrap();
        let artifact =
            zstd::decode_all(&include_bytes!("../../zkp/testdata/nymauth/mdoc-circuits.zst")[..])
                .expect("decode the genuine Longfellow circuit used by the startup prewarm test");
        assert_eq!(artifact.len(), 1_062_842);
        std::fs::write(dir.join("nymauth.bin"), artifact).unwrap();
        build_proxy(cfg, dir.join("proxy.toml").to_str().unwrap())
            .await
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
