//! Bounded HTTP adapter for the sans-I/O TS11 catalog client.

use siros_verifier_core::ts11::{
    self, Catalog, RegistryDocument, MAX_CATALOGUE_BYTES, MAX_DOCUMENT_BYTES,
};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

const MAX_PAGES: usize = 64;
const MAX_DOCUMENTS: usize = 2048;
const MAX_AGGREGATE_BYTES: usize = 32 * 1024 * 1024;

pub struct Ts11Registry {
    client: reqwest::Client,
    list_url: String,
    allowed_hosts: BTreeSet<String>,
    freshness_secs: i64,
    stale_ceiling_secs: i64,
    allow_http: bool,
    cache: Mutex<Option<CachedCatalog>>,
    refresh: tokio::sync::Mutex<()>,
}

struct CachedCatalog {
    catalog: Arc<Catalog>,
    fetched_at: i64,
}

impl Ts11Registry {
    pub fn new(
        list_url: &str,
        allowed_hosts: Vec<String>,
        freshness_secs: i64,
    ) -> std::result::Result<Self, String> {
        Self::build(list_url, allowed_hosts, freshness_secs, false)
    }

    #[cfg(test)]
    fn new_for_test(
        list_url: &str,
        allowed_hosts: Vec<String>,
        freshness_secs: i64,
    ) -> std::result::Result<Self, String> {
        Self::build(list_url, allowed_hosts, freshness_secs, true)
    }

    fn build(
        list_url: &str,
        allowed_hosts: Vec<String>,
        freshness_secs: i64,
        allow_http: bool,
    ) -> std::result::Result<Self, String> {
        let list = if allow_http {
            url::Url::parse(list_url).map_err(|e| e.to_string())?
        } else {
            ts11::https_url(list_url).map_err(|e| e.to_string())?
        };
        if list.path() != "/api/v1/schemas.json"
            || list.query().is_some()
            || list.fragment().is_some()
        {
            return Err("registry_url must be the exact /api/v1/schemas.json endpoint".into());
        }
        if allowed_hosts.is_empty() {
            return Err("at least one registry host is required".into());
        }
        let allowed_hosts: BTreeSet<String> = allowed_hosts.into_iter().collect();
        if !allowed_hosts.contains(list.host_str().unwrap_or_default()) {
            return Err("registry_url host is not in registry_allowed_hosts".into());
        }
        let client = reqwest::Client::builder()
            .user_agent(concat!("siros-verifier-core/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            client,
            list_url: list_url.into(),
            allowed_hosts,
            freshness_secs: freshness_secs.clamp(30, 3600),
            stale_ceiling_secs: 3600,
            allow_http,
            cache: Mutex::new(None),
            refresh: tokio::sync::Mutex::new(()),
        })
    }

    pub async fn catalog(&self) -> std::result::Result<Arc<Catalog>, String> {
        let _refresh = self.refresh.lock().await;
        let now = now();
        if let Some(cached) = self.cache.lock().expect("TS11 cache").as_ref() {
            if now - cached.fetched_at < self.freshness_secs {
                return Ok(cached.catalog.clone());
            }
        }
        match self.fetch().await {
            Ok(catalog) => {
                let catalog = Arc::new(catalog);
                *self.cache.lock().expect("TS11 cache") = Some(CachedCatalog {
                    catalog: catalog.clone(),
                    fetched_at: now,
                });
                Ok(catalog)
            }
            Err(error) => {
                if let Some(cached) = self.cache.lock().expect("TS11 cache").as_ref() {
                    if now - cached.fetched_at <= self.stale_ceiling_secs {
                        return Ok(cached.catalog.clone());
                    }
                }
                Err(error)
            }
        }
    }

    async fn fetch(&self) -> std::result::Result<Catalog, String> {
        let mut schemas = Vec::new();
        let mut offset = 0usize;
        let mut seen_ids = BTreeSet::new();
        for _ in 0..MAX_PAGES {
            let url = if offset == 0 {
                self.list_url.clone()
            } else {
                format!("{}?limit=100&offset={offset}", self.list_url)
            };
            let page = self.get_json(&url, MAX_CATALOGUE_BYTES).await?;
            let page = ts11::parse_schema_page(&page).map_err(|e| e.to_string())?;
            let count = page.schemas.len();
            for schema in page.schemas {
                if !seen_ids.insert(schema.id.clone()) {
                    return Err("registry repeated a schema while paginating".into());
                }
                schemas.push(schema);
            }
            if schemas.len() >= page.total || count == 0 {
                if schemas.len() != page.total {
                    return Err("registry page count does not match total".into());
                }
                break;
            }
            offset = offset
                .checked_add(count)
                .ok_or_else(|| "registry pagination overflow".to_string())?;
        }
        if schemas.len() > MAX_DOCUMENTS {
            return Err("registry document limit exceeded".into());
        }

        let mut documents = Vec::new();
        let mut aggregate = 0usize;
        for schema in schemas {
            for link in &schema.schema_uris {
                self.check_document_url(&link.uri)?;
                if documents.len() >= MAX_DOCUMENTS {
                    return Err("registry document limit exceeded".into());
                }
                let body = self.get_json(&link.uri, MAX_DOCUMENT_BYTES).await?;
                aggregate = aggregate
                    .checked_add(body.len())
                    .filter(|total| *total <= MAX_AGGREGATE_BYTES)
                    .ok_or_else(|| "registry aggregate byte limit exceeded".to_string())?;
                documents.push(RegistryDocument {
                    schema: schema.clone(),
                    format: link.format_identifier.clone(),
                    uri: link.uri.clone(),
                    body,
                });
            }
        }
        Catalog::from_documents(documents).map_err(|e| e.to_string())
    }

    fn check_document_url(&self, uri: &str) -> std::result::Result<(), String> {
        let url = if self.allow_http {
            reqwest::Url::parse(uri).map_err(|e| e.to_string())?
        } else {
            ts11::https_url(uri).map_err(|e| e.to_string())?
        };
        if !self
            .allowed_hosts
            .contains(url.host_str().unwrap_or_default())
        {
            return Err("schema URI host is not allowed".into());
        }
        Ok(())
    }

    async fn get_json(&self, url: &str, limit: usize) -> std::result::Result<Vec<u8>, String> {
        self.check_document_url(url)?;
        let mut response = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| format!("registry request failed: {}", e.without_url()))?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(format!(
                "registry returned HTTP {}",
                response.status().as_u16()
            ));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !content_type.starts_with("application/json") {
            return Err("registry response is not application/json".into());
        }
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            return Err("registry response exceeds byte limit".into());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| format!("registry response read failed: {}", e.without_url()))?
        {
            body.len()
                .checked_add(chunk.len())
                .filter(|length| *length <= limit)
                .ok_or_else(|| "registry response exceeds byte limit".to_string())?;
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn schema_page(address: std::net::SocketAddr) -> String {
        format!(
            r#"{{"data":[{{
                "id":"pid","version":"1.5","rulebookURI":"https://registry.example/rulebook",
                "attestationLoS":"iso_18045_high","bindingType":"key",
                "supportedFormats":["dc+sd-jwt"],
                "schemaURIs":[{{"formatIdentifier":"dc+sd-jwt","uri":"http://{address}/pid.json"}}]
            }}],"total":1,"limit":1,"offset":0}}"#
        )
    }

    fn answer(
        mut stream: std::net::TcpStream,
        _path: &str,
        content_type: &str,
        status: &str,
        body: &str,
    ) {
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    #[tokio::test]
    async fn fetches_once_and_uses_the_fresh_cache() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 2048];
                let mut stream = stream;
                let n = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..n]);
                if request.starts_with("GET /api/v1/schemas.json") {
                    answer(
                        stream,
                        "json",
                        "application/json; charset=utf-8",
                        "200 OK",
                        &schema_page(address),
                    );
                } else {
                    answer(
                        stream,
                        "json",
                        "application/json",
                        "200 OK",
                        r#"{"vct":"urn:pid","claims":[]}"#,
                    );
                }
            }
        });
        let registry = Ts11Registry::new_for_test(
            &format!("http://{address}/api/v1/schemas.json"),
            vec!["127.0.0.1".into()],
            600,
        )
        .unwrap();
        let first = registry.catalog().await.unwrap();
        let second = registry.catalog().await.unwrap();
        assert_eq!(first.presets().len(), 1);
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[tokio::test]
    async fn rejects_non_json_and_redirect_responses() {
        for (status, content_type) in [("200 OK", "text/plain"), ("302 Found", "application/json")]
        {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let page = schema_page(address);
            std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                answer(stream, "json", content_type, status, &page);
            });
            let registry = Ts11Registry::new_for_test(
                &format!("http://{address}/api/v1/schemas.json"),
                vec!["127.0.0.1".into()],
                600,
            )
            .unwrap();
            assert!(registry.catalog().await.is_err());
        }
    }
}
