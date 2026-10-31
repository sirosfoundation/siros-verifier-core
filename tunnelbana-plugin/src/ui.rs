//! Browser UI frontend for direct verifier testing.
//!
//! It deliberately uses the ordinary tunnelbana request/response pipeline: the
//! UI starts the same OpenID4VP backend as an OIDC relying party and renders
//! the verified internal attributes when the backend completes.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use siros_verifier_core::oid4vp;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::http::Response;
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{BuildContext, Frontend, FrontendAction, Route};

pub const QR_REQUESTER: &str = "siros-verifier-ui:qr";
pub const DC_API_REQUESTER: &str = "siros-verifier-ui:dc-api";
/// Request-local attributes used only to hand the user's launch profile from
/// the UI frontend to the backend; they are never emitted as verified claims.
pub const DCQL_ATTRIBUTE: &str = "_siros_dcql";
pub const SCHEME_ATTRIBUTE: &str = "_siros_scheme";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    pub id: String,
    pub label: String,
    pub dcql: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UiConfig {
    #[serde(default = "default_presets")]
    presets: Vec<Preset>,
    #[serde(default = "default_invocations")]
    invocations: Vec<String>,
    #[serde(default = "default_scheme")]
    schemes: Vec<String>,
    #[serde(default)]
    registry_url: Option<String>,
    #[serde(default)]
    registry_allowed_hosts: Option<Vec<String>>,
    #[serde(default)]
    registry_cache_seconds: Option<i64>,
}

fn default_presets() -> Vec<Preset> {
    vec![Preset {
        id: "eudi_pid".into(),
        label: "EUDI PID (ARF 1.8)".into(),
        dcql: serde_json::json!({"credentials": [{
            "id": "eudi_pid", "format": "dc+sd-jwt",
            "meta": {"vct_values": ["urn:eudi:pid:arf-1.8:1"]},
            "claims": [
                {"path": ["given_name"]},
                {"path": ["family_name"]},
                {"path": ["birthdate"]},
                {"path": ["nationalities"]},
                {"path": ["personal_administrative_number"]},
            ]
        }]}),
    }]
}

fn default_invocations() -> Vec<String> {
    vec!["qr".into(), "dc-api".into(), "link".into()]
}

fn default_scheme() -> Vec<String> {
    vec!["openid4vp".into()]
}

pub struct UiFrontend {
    name: String,
    presets: Vec<Preset>,
    invocations: Vec<String>,
    schemes: Vec<String>,
    registry: Option<std::sync::Arc<crate::ts11::Ts11Registry>>,
}

impl UiFrontend {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn Frontend>> {
        let cfg: UiConfig = bx.parse_config()?;
        if cfg.presets.is_empty() {
            return Err(Error::Config("at least one UI preset is required".into()));
        }
        for preset in &cfg.presets {
            if preset.id.is_empty() || preset.label.is_empty() {
                return Err(Error::Config(
                    "UI presets need non-empty id and label".into(),
                ));
            }
            oid4vp::validate_dcql_query(&preset.dcql)
                .map_err(|e| Error::Config(format!("preset {}: {e}", preset.id)))?;
        }
        validate_choices(&cfg.invocations, &["qr", "dc-api", "link"], "invocation")?;
        validate_choices(
            &cfg.schemes,
            &["openid4vp", "haip", "haip-vp", "mdoc-openid4vp"],
            "scheme",
        )?;
        let registry = match cfg.registry_url {
            Some(url) => Some(std::sync::Arc::new(
                crate::ts11::Ts11Registry::new(
                    &url,
                    cfg.registry_allowed_hosts
                        .unwrap_or_else(|| vec!["registry.siros.org".into()]),
                    cfg.registry_cache_seconds.unwrap_or(600),
                )
                .map_err(Error::Config)?,
            )),
            None => {
                if cfg.registry_allowed_hosts.is_some() || cfg.registry_cache_seconds.is_some() {
                    return Err(Error::Config(
                        "registry_url is required when registry cache options are set".into(),
                    ));
                }
                None
            }
        };
        Ok(Box::new(Self {
            name: bx.name.clone(),
            presets: cfg.presets,
            invocations: cfg.invocations,
            schemes: cfg.schemes,
            registry,
        }))
    }

    async fn catalog(&self) -> (Vec<Preset>, Option<String>) {
        let Some(registry) = &self.registry else {
            return (self.presets.clone(), None);
        };
        match registry.catalog().await {
            Ok(catalog) => {
                let mut presets = self.presets.clone();
                let mut ids: std::collections::BTreeSet<String> =
                    presets.iter().map(|preset| preset.id.clone()).collect();
                for value in catalog.presets() {
                    let Some(id) = value.get("id").and_then(Value::as_str) else {
                        continue;
                    };
                    if ids.contains(id) {
                        continue;
                    }
                    let label = value
                        .get("label")
                        .and_then(Value::as_str)
                        .unwrap_or(id)
                        .to_owned();
                    let dcql = value.get("dcql").cloned().unwrap_or(Value::Null);
                    if oid4vp::validate_dcql_query(&dcql).is_err() {
                        continue;
                    }
                    ids.insert(id.to_owned());
                    presets.push(Preset {
                        id: id.to_owned(),
                        label,
                        dcql,
                    });
                }
                (presets, None)
            }
            Err(error) => {
                tracing::warn!(%error, "TS11 registry refresh failed");
                (
                    self.presets.clone(),
                    Some("Credential registry unavailable; showing configured presets.".into()),
                )
            }
        }
    }
}

fn validate_choices(values: &[String], allowed: &[&str], what: &str) -> Result<()> {
    let mut unique = std::collections::BTreeSet::new();
    if values.is_empty()
        || values
            .iter()
            .any(|value| !allowed.contains(&value.as_str()) || !unique.insert(value))
    {
        return Err(Error::Config(format!(
            "invalid or duplicate {what} option; allowed: {}",
            allowed.join(", ")
        )));
    }
    Ok(())
}

#[async_trait]
impl Frontend for UiFrontend {
    fn name(&self) -> &str {
        &self.name
    }

    fn register_endpoints(&self, _backend_names: &[String]) -> Vec<Route> {
        vec![
            Route::exact("", "index"),
            Route::exact(
                format!("{}/assets/presentation-flow.js", self.name),
                "flow_js",
            ),
            Route::exact(format!("{}/assets/demo.js", self.name), "demo_js"),
            Route::exact(format!("{}/start/qr", self.name), "start_qr"),
            Route::exact(format!("{}/start/dc-api", self.name), "start_dc_api"),
        ]
    }

    async fn handle_endpoint(&self, ctx: &mut Context, route_id: &str) -> Result<FrontendAction> {
        match route_id {
            "index" if ctx.request.method == "GET" => {
                let (presets, notice) = self.catalog().await;
                Ok(FrontendAction::Respond(Response::html(index_page(
                    &self.name,
                    &presets,
                    &self.invocations,
                    &self.schemes,
                    notice.as_deref(),
                )?)))
            }
            "flow_js" if ctx.request.method == "GET" => Ok(FrontendAction::Respond(javascript(
                include_str!("assets/presentation-flow.js"),
            ))),
            "demo_js" if ctx.request.method == "GET" => Ok(FrontendAction::Respond(javascript(
                include_str!("assets/demo.js"),
            ))),
            "start_qr" if ctx.request.method == "POST" => Ok(FrontendAction::StartAuth {
                request: launch_request(ctx, QR_REQUESTER),
                target_backend: None,
            }),
            "start_dc_api" if ctx.request.method == "POST" => Ok(FrontendAction::StartAuth {
                request: launch_request(ctx, DC_API_REQUESTER),
                target_backend: None,
            }),
            "index" | "flow_js" | "demo_js" | "start_qr" | "start_dc_api" => Ok(
                FrontendAction::Respond(Response::text(405, "method not allowed")),
            ),
            other => Err(Error::NoBoundEndpoint(other.to_string())),
        }
    }

    async fn handle_authn_response(
        &self,
        _ctx: &mut Context,
        response: InternalData,
    ) -> Result<Response> {
        Ok(Response::html(result_page(&response)))
    }

    async fn handle_backend_error(&self, _ctx: &mut Context, error: &Error) -> Result<Response> {
        Ok(error_page(error.status_hint()))
    }
}

pub(crate) fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · SIROS verifier</title>
<style>
:root {{ color-scheme: light dark; font-family: system-ui,sans-serif; }}
body {{ margin:0; min-height:100vh; display:grid; place-items:center; background:#f3f5f8; color:#172033; }}
main {{ box-sizing:border-box; width:min(92vw,680px); margin:32px 0; padding:32px; border-radius:16px; background:#fff; box-shadow:0 8px 32px #17203318; }}
h1 {{ margin-top:0; font-size:1.7rem; }} p {{ line-height:1.5; }}
.choices {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:16px; margin-top:28px; }}
a.choice {{ display:block; padding:20px; border:1px solid #d8dee9; border-radius:12px; color:inherit; text-decoration:none; }}
a.choice:hover,a.choice:focus {{ border-color:#3167d5; outline:none; }}
.choice strong {{ display:block; color:#214faa; margin-bottom:8px; }}
.presentation-flow > label {{ display:block; margin:18px 0 8px; font-weight:600; }}
.presentation-flow select,.presentation-flow textarea {{ box-sizing:border-box; width:100%; margin-top:6px; padding:10px; border:1px solid #aab5c5; border-radius:8px; background:inherit; color:inherit; font:inherit; }}
.presentation-flow textarea {{ min-height:260px; font-family:ui-monospace,monospace; font-size:.88rem; }}
.claim-options {{ border:0; padding:0; margin:16px 0; }} .claim-option {{ display:block; font-weight:400; margin:5px 0; }}
.flow-actions {{ display:flex; flex-wrap:wrap; gap:12px; margin-top:20px; }}
.flow-actions button {{ padding:11px 18px; border:1px solid #3167d5; border-radius:8px; background:#3167d5; color:white; cursor:pointer; }}
.flow-actions button:nth-child(n+2) {{ background:transparent; color:#3167d5; }}
.wallet-launch {{ margin-top:24px; }} .wallet-launch a {{ color:#214faa; overflow-wrap:anywhere; }}
.qr-code {{ display:grid; place-items:center; background:white; padding:16px; border-radius:12px; margin:16px 0; }}
.siros-spinner {{ display:flex; gap:5px; align-items:center; justify-content:center; margin:20px 0; font-weight:800; letter-spacing:.2em; color:#3167d5; }}
.siros-spinner span {{ animation:siros-pulse 1.2s infinite ease-in-out; }} .siros-spinner span:nth-child(2) {{ animation-delay:.1s; }} .siros-spinner span:nth-child(3) {{ animation-delay:.2s; }} .siros-spinner span:nth-child(4) {{ animation-delay:.3s; }} .siros-spinner span:nth-child(5) {{ animation-delay:.4s; }}
@keyframes siros-pulse {{ 0%,100% {{ opacity:.25; transform:translateY(0); }} 50% {{ opacity:1; transform:translateY(-4px); }} }}
dl {{ display:grid; grid-template-columns:minmax(0,1fr) minmax(0,2fr); gap:10px 16px; }}
dt {{ font-weight:650; overflow-wrap:anywhere; }} dd {{ margin:0; overflow-wrap:anywhere; }}
a.back {{ display:inline-block; margin-top:24px; color:#214faa; }}
@media (prefers-color-scheme:dark) {{ body {{ background:#111722; color:#e7ebf3; }} main {{ background:#1b2432; }} a.choice {{ border-color:#3a4658; }} .choice strong,a.back {{ color:#8eb2ff; }} }}
</style></head><body><main>{body}</main></body></html>"#
    )
}

fn index_page(
    name: &str,
    presets: &[Preset],
    invocations: &[String],
    schemes: &[String],
    notice: Option<&str>,
) -> Result<String> {
    let catalog = serde_json::to_string(&serde_json::json!({
        "presets": presets,
        "invocations": invocations,
        "schemes": schemes,
        "startPath": format!("/{name}/start"),
    }))?
    .replace('&', "\\u0026")
    .replace('<', "\\u003c")
    .replace('>', "\\u003e");
    let notice_html = notice
        .map(|text| format!("<p role=\"status\"><em>{}</em></p>", html_escape(text)))
        .unwrap_or_default();
    Ok(page(
        "Verify a credential",
        &format!(
            r#"<h1>Verify a credential</h1>
<p>Select a registry-backed request or edit the DCQL, then choose how to invoke your wallet.</p>
{notice_html}
<div id="presentation-app"></div>
<script id="presentation-catalog" type="application/json">{catalog}</script>
<script type="module" src="/{name}/assets/demo.js"></script>"#,
        ),
    ))
}

fn launch_request(ctx: &Context, requester: &str) -> InternalData {
    let mut request = InternalData::request(requester);
    if let Some(dcql) = ctx.request.form.get("dcql") {
        request.set_attr(DCQL_ATTRIBUTE, dcql);
    }
    if let Some(scheme) = ctx.request.form.get("scheme") {
        request.set_attr(SCHEME_ATTRIBUTE, scheme);
    }
    request
}

fn javascript(source: &'static str) -> Response {
    Response::new(200)
        .with_header("content-type", "application/javascript; charset=utf-8")
        .with_header("cache-control", "no-store")
        .with_body(source.as_bytes().to_vec())
}

fn result_page(response: &InternalData) -> String {
    let mut rows = String::new();
    for (name, values) in &response.attributes {
        rows.push_str(&format!(
            "<dt>{}</dt><dd>{}</dd>",
            html_escape(name),
            html_escape(&values.join(", "))
        ));
    }
    let issuer = response.auth_info.issuer.as_deref().unwrap_or("unknown");
    page(
        "Credential verified",
        &format!(
            r#"<h1>Credential verified</h1><p>The issuer signature, holder binding, presentation, and issuer trust were accepted.</p>
<dl><dt>Issuer</dt><dd>{}</dd>{rows}</dl><a class="back" href="/">Verify another credential</a>"#,
            html_escape(issuer)
        ),
    )
}

fn error_page(status: u16) -> Response {
    let body = format!(
        r#"<h1>Presentation failed</h1><p>The credential presentation could not be completed (HTTP {status}). No verified attributes were released.</p><a class="back" href="/">Try again</a>"#
    );
    Response::new(status)
        .with_header("content-type", "text/html; charset=utf-8")
        .with_body(page("Presentation failed", &body).into_bytes())
}

pub(crate) fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn landing_offers_qr_and_dc_api() {
        let html = index_page(
            "ui",
            &default_presets(),
            &default_invocations(),
            &default_scheme(),
            None,
        )
        .unwrap();
        assert!(html.contains("/ui/assets/demo.js"));
        assert!(html.contains("presentation-catalog"));
        assert!(html.contains("dc-api"));
        assert!(!html.contains("haip-vp"));
        assert!(!html.contains("navigator.credentials"));
    }

    #[test]
    fn result_escapes_verified_attribute_text() {
        let mut data = InternalData::default();
        data.auth_info.issuer = Some("https://issuer.example/<unsafe>".into());
        data.set_attr("givenname", "<script>alert('x')</script>");
        let html = result_page(&data);
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("https://issuer.example/&lt;unsafe&gt;"));
        assert!(html.contains("dt { font-weight:650; overflow-wrap:anywhere; }"));
        assert!(html.contains("grid-template-columns:minmax(0,1fr) minmax(0,2fr)"));
    }
}
