//! The HTTP adapters: a bounded reqwest-backed implementation of tunnelbana's
//! outbound HTTP trait (adapted from SUNET/tunnelbana's `reqwest_client.rs`,
//! BSD-2-Clause), and the inbound actix glue — request translation, response
//! translation, and the health endpoint — used by the binary's server setup.

use std::collections::BTreeMap;
use std::sync::Arc;

use actix_web::{web, HttpRequest, HttpResponse};
use async_trait::async_trait;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::http::{HttpClient, HttpFetchResponse, HttpRequestData, Response};
use tunnelbana_core::proxy::Proxy;

/// A real Longfellow nym_auth proof is about 344 KiB before CBOR and JWE
/// base64 expansion. Keep a hard limit, but allow those genuine presentations.
pub const MAX_HTTP_BODY_BYTES: usize = 2 * 1024 * 1024;

pub struct ReqwestClient {
    inner: reqwest::Client,
    max_response_bytes: usize,
}

impl ReqwestClient {
    pub fn with_limits(
        connect_timeout_seconds: u64,
        read_timeout_seconds: u64,
        request_timeout_seconds: u64,
        max_response_bytes: usize,
    ) -> Self {
        let inner = reqwest::Client::builder()
            .user_agent(concat!(
                "siros-verifier-service/",
                env!("CARGO_PKG_VERSION")
            ))
            .connect_timeout(std::time::Duration::from_secs(connect_timeout_seconds))
            .read_timeout(std::time::Duration::from_secs(read_timeout_seconds))
            .timeout(std::time::Duration::from_secs(request_timeout_seconds))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build reqwest client");
        Self {
            inner,
            max_response_bytes,
        }
    }
}

#[async_trait]
impl HttpClient for ReqwestClient {
    async fn get(&self, url: &str) -> Result<HttpFetchResponse> {
        let resp = self
            .inner
            .get(url)
            .send()
            .await
            .map_err(|e| Error::Internal(format!("GET {url}: {e}")))?;
        into_fetch(resp, self.max_response_bytes).await
    }

    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        headers: &[(String, String)],
    ) -> Result<HttpFetchResponse> {
        let mut req = self.inner.post(url).form(form);
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| Error::Internal(format!("POST {url}: {e}")))?;
        into_fetch(resp, self.max_response_bytes).await
    }
}

async fn into_fetch(
    mut resp: reqwest::Response,
    max_response_bytes: usize,
) -> Result<HttpFetchResponse> {
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    if resp
        .content_length()
        .is_some_and(|length| length > max_response_bytes as u64)
    {
        return Err(Error::Internal(format!(
            "outbound response exceeds {max_response_bytes} byte limit"
        )));
    }

    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| Error::Internal(format!("reading body: {e}")))?
    {
        body.len()
            .checked_add(chunk.len())
            .filter(|length| *length <= max_response_bytes)
            .ok_or_else(|| {
                Error::Internal(format!(
                    "outbound response exceeds {max_response_bytes} byte limit"
                ))
            })?;
        body.extend_from_slice(&chunk);
    }
    Ok(HttpFetchResponse {
        status,
        body,
        content_type,
    })
}

// ---- the inbound actix adapter -------------------------------------------------

pub async fn health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({ "status": "ok" }))
}

pub async fn handle(
    req: HttpRequest,
    body: web::Bytes,
    proxy: web::Data<Arc<Proxy>>,
) -> HttpResponse {
    let request = build_request_data(&req, &body);
    let response = proxy.run(request).await;
    to_actix(response)
}

/// Translate an actix request into tunnelbana's transport-independent form,
/// preserving every query and form pair — including duplicates, which the
/// verifiers read by position — and lowercasing header names.
pub fn build_request_data(req: &HttpRequest, body: &web::Bytes) -> HttpRequestData {
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

/// Translate tunnelbana's transport-independent response into an actix one.
/// An unmappable status is never silently rewritten: it falls back to 500.
pub fn to_actix(resp: Response) -> HttpResponse {
    let status = actix_web::http::StatusCode::from_u16(resp.status)
        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = HttpResponse::build(status);
    for (k, v) in &resp.headers {
        builder.append_header((k.clone(), v.clone()));
    }
    builder.body(resp.body)
}
