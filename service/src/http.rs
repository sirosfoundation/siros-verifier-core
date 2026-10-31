//! A bounded reqwest-backed implementation of tunnelbana's outbound HTTP trait.
//! Adapted from SUNET/tunnelbana's `reqwest_client.rs` (BSD-2-Clause).

use async_trait::async_trait;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::http::{HttpClient, HttpFetchResponse};

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
