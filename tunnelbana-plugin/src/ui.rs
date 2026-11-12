//! Browser UI frontend for direct verifier testing.
//!
//! It deliberately uses the ordinary tunnelbana request/response pipeline: the
//! UI starts the same OpenID4VP backend as an OIDC relying party and renders
//! the verified internal attributes when the backend completes.

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
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

/// True when the flow was launched directly by the browser through this UI
/// frontend (the `siros-verifier-ui:*` requester namespace). UI-launched
/// flows render a refusal's reason on the failure page; RP-initiated flows —
/// whose requester is the relying party's client id — must instead surface
/// the protocol error, so the frontend returns the authorization error and
/// the original state to the waiting RP.
pub fn is_ui_requester(requester: Option<&str>) -> bool {
    requester.is_some_and(|r| r.starts_with("siros-verifier-ui:"))
}
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
    /// Full registry claim catalog used for selection; `dcql` remains the
    /// requested subset sent to the wallet. Optional for existing integrations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available_dcql: Option<Value>,
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
        available_dcql: None,
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
                    let label = value
                        .get("label")
                        .and_then(Value::as_str)
                        .unwrap_or(id)
                        .to_owned();
                    let dcql = value.get("dcql").cloned().unwrap_or(Value::Null);
                    if oid4vp::validate_dcql_query(&dcql).is_err() {
                        continue;
                    }
                    merge_available_claims(&mut presets, &dcql);
                    if ids.contains(id) {
                        continue;
                    }
                    ids.insert(id.to_owned());
                    presets.push(Preset {
                        id: id.to_owned(),
                        label,
                        dcql,
                        available_dcql: None,
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

fn same_credential_profile(left: &Value, right: &Value) -> bool {
    let (Some(left), Some(right)) = (
        left.get("credentials").and_then(Value::as_array),
        right.get("credentials").and_then(Value::as_array),
    ) else {
        return false;
    };
    !left.is_empty()
        && left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.get("format") == right.get("format") && left.get("meta") == right.get("meta")
        })
}

fn merge_available_claims(presets: &mut [Preset], registry_dcql: &Value) {
    for preset in presets
        .iter_mut()
        .filter(|preset| same_credential_profile(&preset.dcql, registry_dcql))
    {
        preset.available_dcql = Some(registry_dcql.clone());
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
    let logo = BASE64.encode(include_bytes!("assets/siros-logo.png"));
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · SIROS verifier</title>
<style>
:root {{ color-scheme: light dark; font-family:'Helvetica Neue',Arial,system-ui,sans-serif; }}
body {{ margin:0; min-height:100vh; background:#f3f5f8; color:#172033; }}
.navbar {{ background:#fff; border-bottom:1px solid #e0e0e0; }}
.navbar-inner {{ box-sizing:border-box; width:min(92vw,680px); margin:0 auto; padding:10px 0; display:flex; align-items:center; }}
.navbar-brand {{ display:flex; align-items:center; gap:12px; color:#1C4587; text-decoration:none; font-weight:600; font-size:1.1rem; }}
.navbar-brand img {{ display:block; height:40px; width:auto; }}
main {{ box-sizing:border-box; width:min(92vw,680px); margin:32px auto; padding:32px; border-radius:16px; background:#fff; box-shadow:0 8px 32px #17203318; }}
h1 {{ margin-top:0; color:#1C4587; font-size:1.7rem; }} h2 {{ color:#1C4587; }} p {{ line-height:1.5; }}
.choices {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:16px; margin-top:28px; }}
a.choice {{ display:block; padding:20px; border:1px solid #d8dee9; border-radius:12px; color:inherit; text-decoration:none; }}
a.choice:hover,a.choice:focus {{ border-color:#1C4587; outline:none; }}
.choice strong {{ display:block; color:#1C4587; margin-bottom:8px; }}
.presentation-flow > label {{ display:block; margin:18px 0 8px; font-weight:600; }}
.presentation-flow select,.presentation-flow textarea {{ box-sizing:border-box; width:100%; margin-top:6px; padding:10px; border:1px solid #aab5c5; border-radius:8px; background:inherit; color:inherit; font:inherit; }}
.presentation-flow textarea {{ min-height:260px; font-family:ui-monospace,monospace; font-size:.88rem; }}
.claim-options {{ display:block; margin:16px 0; }}
.claim-options option::before {{ content:"☐ "; }} .claim-options option:checked::before {{ content:"☑ "; }}
.flow-actions {{ display:flex; flex-wrap:wrap; gap:12px; margin-top:20px; }}
.flow-actions button {{ padding:11px 18px; border:1px solid #1C4587; border-radius:8px; background:#1C4587; color:white; cursor:pointer; }}
.flow-actions button:nth-child(n+2) {{ background:transparent; color:#1C4587; }}
.wallet-launch {{ margin-top:24px; }} .wallet-launch a {{ color:#1C4587; overflow-wrap:anywhere; }}
.wallet-launch-dialog {{ max-width:min(92vw,560px); border:0; border-radius:16px; }}
.wallet-launch-dialog::backdrop {{ background:#17203380; }}
.qr-code {{ display:grid; place-items:center; background:white; padding:16px; border-radius:12px; margin:16px 0; }}
.siros-spinner {{ box-sizing:border-box; width:28px; height:28px; margin:20px auto; border:3px solid #1C458733; border-top-color:#1C4587; border-radius:50%; animation:siros-spin .8s linear infinite; }}
@keyframes siros-spin {{ to {{ transform:rotate(360deg); }} }}
dl {{ display:grid; grid-template-columns:minmax(0,1fr) minmax(0,2fr); gap:10px 16px; }}
dt {{ font-weight:650; overflow-wrap:anywhere; }} dd {{ margin:0; overflow-wrap:anywhere; }}
a.back {{ display:inline-block; margin-top:24px; color:#1C4587; }}
@media (prefers-color-scheme:dark) {{ body {{ background:#111722; color:#e7ebf3; }} main,.wallet-launch-dialog {{ background:#1b2432; }} h1,h2,.choice strong,a.back {{ color:#8eb2ff; }} a.choice {{ border-color:#3a4658; }} }}
</style></head><body><header class="navbar"><div class="navbar-inner"><a class="navbar-brand" href="/"><img src="data:image/png;base64,{logo}" alt="SIROS Foundation"><span>Verifier</span></a></div></header><main>{body}</main></body></html>"#
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
        assert!(html.contains("navbar-brand"));
        assert!(html.contains("data:image/png;base64,"));
        assert!(html.contains("alt=\"SIROS Foundation\""));
        assert!(!html.contains("<footer"));
        assert!(html.contains(".claim-options option::before"));
        assert!(html.contains(".claim-options option:checked::before"));
        assert!(!html.contains("haip-vp"));
        assert!(!html.contains("navigator.credentials"));
    }

    #[test]
    fn registry_claims_expand_selection_without_expanding_the_requested_subset() {
        let mut presets = default_presets();
        let registry = serde_json::json!({"credentials": [{
            "id": "registry-uuid", "format": "dc+sd-jwt",
            "meta": {"vct_values": ["urn:eudi:pid:arf-1.8:1"]},
            "claims": [
                {"path": ["given_name"]},
                {"path": ["family_name"]},
                {"path": ["personal_administrative_number"]},
                {"path": ["age_over_18"]},
            ]
        }]});
        merge_available_claims(&mut presets, &registry);
        assert_eq!(
            presets[0].dcql["credentials"][0]["claims"]
                .as_array()
                .unwrap()
                .len(),
            5
        );
        assert_eq!(
            presets[0].available_dcql.as_ref().unwrap()["credentials"][0]["claims"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        let html = index_page(
            "ui",
            &presets,
            &default_invocations(),
            &default_scheme(),
            None,
        )
        .unwrap();
        assert!(html.contains("available_dcql"));
        assert!(html.contains("age_over_18"));
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
