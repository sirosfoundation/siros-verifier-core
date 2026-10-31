//! ETSI TS 119 602 (TS11) credential-schema metadata.
//!
//! The core is sans-I/O: it parses catalogue pages and documents supplied by a
//! bounded transport adapter, validates their identities and integrity, and
//! builds DCQL presets. It never follows URLs, performs HTTP, or trusts JWS.

use crate::error::{integrity, malformed, policy};
use crate::Result;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_CATALOGUE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_DOCUMENT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaMeta {
    pub id: String,
    pub version: String,
    #[serde(rename = "rulebookURI")]
    pub rulebook_uri: String,
    #[serde(rename = "attestationLoS")]
    pub attestation_los: String,
    pub binding_type: String,
    pub supported_formats: Vec<String>,
    #[serde(rename = "schemaURIs")]
    pub schema_uris: Vec<SchemaUri>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaUri {
    pub format_identifier: String,
    pub uri: String,
}

#[derive(Debug)]
pub struct SchemaPage {
    pub schemas: Vec<SchemaMeta>,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
}

pub fn parse_schema_page(body: &[u8]) -> Result<SchemaPage> {
    if body.len() > MAX_CATALOGUE_BYTES {
        return Err(policy("TS11 catalogue response too large"));
    }
    let value: Value = crate::json_strict::from_slice(body)
        .map_err(|e| malformed(format!("invalid TS11 catalogue JSON: {e}")))?;
    let page: SchemaPageWire = serde_json::from_value(value)
        .map_err(|e| malformed(format!("invalid TS11 catalogue page: {e}")))?;
    if page.data.len() > page.total
        || page.limit > page.total
        || page.offset > page.total
        || (page.total > 0 && page.limit == 0)
    {
        return Err(malformed("inconsistent TS11 pagination"));
    }
    let mut ids = BTreeSet::new();
    for schema in &page.data {
        validate_schema(schema)?;
        if !ids.insert(schema.id.clone()) {
            return Err(policy(format!("duplicate schema id {}", schema.id)));
        }
    }
    Ok(SchemaPage {
        schemas: page.data,
        total: page.total,
        limit: page.limit,
        offset: page.offset,
    })
}

#[derive(Deserialize)]
struct SchemaPageWire {
    data: Vec<SchemaMeta>,
    total: usize,
    limit: usize,
    offset: usize,
}

fn validate_schema(schema: &SchemaMeta) -> Result<()> {
    if schema.id.is_empty() || schema.version.is_empty() || schema.rulebook_uri.is_empty() {
        return Err(malformed("schema id, version and rulebookURI are required"));
    }
    if !matches!(
        schema.attestation_los.as_str(),
        "iso_18045_high" | "iso_18045_moderate" | "iso_18045_enhanced-basic" | "iso_18045_basic"
    ) {
        return Err(policy("unsupported attestationLoS"));
    }
    if !matches!(
        schema.binding_type.as_str(),
        "claim" | "key" | "biometric" | "none"
    ) {
        return Err(policy("unsupported bindingType"));
    }
    if schema.supported_formats.is_empty() || schema.schema_uris.is_empty() {
        return Err(malformed("schema needs formats and schemaURIs"));
    }
    for format in &schema.supported_formats {
        validate_format(format)?;
    }
    for link in &schema.schema_uris {
        validate_format(&link.format_identifier)?;
        if !schema.supported_formats.contains(&link.format_identifier) {
            return Err(malformed("schemaURI format is not in supportedFormats"));
        }
        https_url(&link.uri)?;
    }
    https_url(&schema.rulebook_uri)?;
    Ok(())
}

fn validate_format(format: &str) -> Result<()> {
    if matches!(
        format,
        "dc+sd-jwt" | "mso_mdoc" | "jwt_vc_json" | "jwt_vc_json-ld" | "ldp_vc"
    ) {
        Ok(())
    } else {
        Err(policy(format!("unsupported schema format {format}")))
    }
}

pub fn https_url(value: &str) -> Result<url::Url> {
    let url =
        url::Url::parse(value).map_err(|e| malformed(format!("invalid registry URL: {e}")))?;
    let loopback_http = url.scheme() == "http"
        && matches!(
            url.host_str(),
            Some("127.0.0.1") | Some("localhost") | Some("[::1]") | Some("::1")
        );
    if (url.scheme() != "https" && !loopback_http)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(policy(
            "registry URLs must be HTTPS (HTTP loopback only) without userinfo",
        ));
    }
    Ok(url)
}

pub fn source_uri(uri: &str) -> Result<String> {
    let mut url = https_url(uri)?;
    url.set_fragment(None);
    Ok(url.into())
}

pub fn verify_sri(uri: &str, body: &[u8]) -> Result<()> {
    let url = https_url(uri)?;
    let Some(fragment) = url.fragment() else {
        return Ok(());
    };
    let encoded = fragment
        .strip_prefix("sha256-")
        .ok_or_else(|| policy("only sha256 SRI is supported"))?;
    let expected = B64
        .decode(encoded)
        .map_err(|_| malformed("invalid sha256 SRI"))?;
    if expected.len() != 32 || Sha256::digest(body).as_slice() != expected {
        return Err(integrity("TS11 document SRI mismatch"));
    }
    Ok(())
}

#[derive(Debug)]
pub struct RegistryDocument {
    pub schema: SchemaMeta,
    pub format: String,
    pub uri: String,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClaimMetadata {
    pub path: Vec<Option<String>>,
    pub label: String,
    pub mandatory: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialType {
    pub schema_id: String,
    pub version: String,
    pub format: String,
    pub identifier: String,
    pub label: String,
    pub claims: Vec<ClaimMetadata>,
    pub dcql: Value,
    /// Whether this format has a complete OpenID4VP verification path.
    pub supported: bool,
    pub raw: Value,
}

#[derive(Debug, Default)]
pub struct Catalog {
    pub credentials: Vec<CredentialType>,
    by_vct: BTreeMap<String, Vec<usize>>,
    by_doctype: BTreeMap<String, Vec<usize>>,
}

impl Catalog {
    pub fn from_documents(documents: Vec<RegistryDocument>) -> Result<Self> {
        let mut catalog = Catalog::default();
        for document in documents {
            if document.body.len() > MAX_DOCUMENT_BYTES {
                return Err(policy("TS11 metadata document too large"));
            }
            validate_schema(&document.schema)?;
            if document.format != "dc+sd-jwt" && document.format != "mso_mdoc" {
                continue; // Preserve catalogue compatibility; only these formats are indexed.
            }
            if !document.schema.supported_formats.contains(&document.format) {
                return Err(malformed("document format is not advertised by its schema"));
            }
            if !document.schema.schema_uris.iter().any(|link| {
                link.format_identifier == document.format
                    && source_uri(&link.uri).ok().as_deref()
                        == source_uri(&document.uri).ok().as_deref()
            }) {
                return Err(policy("document URI is not declared by its schema"));
            }
            verify_sri(&document.uri, &document.body)?;
            let raw: Value = crate::json_strict::from_slice(&document.body)
                .map_err(|e| malformed(format!("invalid TS11 metadata JSON: {e}")))?;
            if document.format == "mso_mdoc" && mdoc_identifier(&raw).is_none() {
                // A fetch URI is not a doctype. Keep such documents out of the
                // presentation catalog rather than inventing an identifier.
                continue;
            }
            let credential = match document.format.as_str() {
                "dc+sd-jwt" => sdjwt_credential(&document, raw)?,
                "mso_mdoc" => mdoc_credential(&document, raw)?,
                _ => unreachable!(),
            };
            let index = catalog.credentials.len();
            if credential.format == "dc+sd-jwt" {
                catalog
                    .by_vct
                    .entry(credential.identifier.clone())
                    .or_default()
                    .push(index);
            } else {
                catalog
                    .by_doctype
                    .entry(credential.identifier.clone())
                    .or_default()
                    .push(index);
            }
            catalog.credentials.push(credential);
        }
        catalog
            .credentials
            .sort_by(|a, b| a.label.cmp(&b.label).then(a.schema_id.cmp(&b.schema_id)));
        Ok(catalog)
    }

    /// Resolve only an unambiguous identifier. Multiple schemas may legitimately
    /// share a VCT; callers that need one answer get none instead of a random pick.
    pub fn resolve_vct(&self, vct: &str) -> Option<&CredentialType> {
        self.by_vct
            .get(vct)
            .and_then(|matches| (matches.len() == 1).then(|| &self.credentials[matches[0]]))
    }

    pub fn resolve_doctype(&self, doctype: &str) -> Option<&CredentialType> {
        self.by_doctype
            .get(doctype)
            .and_then(|matches| (matches.len() == 1).then(|| &self.credentials[matches[0]]))
    }

    pub fn presets(&self) -> Vec<Value> {
        self.credentials
            .iter()
            .filter(|credential| credential.supported)
            .map(|credential| {
                serde_json::json!({
                    "id": credential.schema_id,
                    "label": credential.label,
                    "dcql": credential.dcql,
                    "format": credential.format,
                    "identifier": credential.identifier,
                })
            })
            .collect()
    }
}

fn sdjwt_credential(document: &RegistryDocument, raw: Value) -> Result<CredentialType> {
    let vct = raw
        .get("vct")
        .and_then(Value::as_str)
        .filter(|vct| !vct.is_empty())
        .ok_or_else(|| malformed("VCTM without vct"))?
        .to_owned();
    let label = display_label(raw.get("display"), "name")
        .or_else(|| raw.get("name").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_else(|| vct.clone());
    let mut claims = Vec::new();
    for claim in raw
        .get("claims")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let path = string_path(claim.get("path"))?;
        claims.push(ClaimMetadata {
            label: display_label(claim.get("display"), "label")
                .or_else(|| display_label(claim.get("display"), "name"))
                .unwrap_or_else(|| {
                    path.iter()
                        .rev()
                        .find_map(|segment| segment.clone())
                        .unwrap_or_default()
                }),
            path,
            mandatory: claim
                .get("mandatory")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        });
    }
    let dcql = serde_json::json!({"credentials": [{
        "id": document.schema.id,
        "format": "dc+sd-jwt",
        "meta": {"vct_values": [vct.clone()]},
        "claims": claims.iter().map(|claim| serde_json::json!({"path": claim.path})).collect::<Vec<_>>(),
    }]});
    Ok(CredentialType {
        schema_id: document.schema.id.clone(),
        version: document.schema.version.clone(),
        format: document.format.clone(),
        identifier: vct,
        label,
        claims,
        dcql,
        supported: true,
        raw,
    })
}

fn mdoc_identifier(raw: &Value) -> Option<&str> {
    raw.get("doctype")
        .and_then(Value::as_str)
        .or_else(|| {
            raw.pointer("/properties/docType/const")
                .and_then(Value::as_str)
        })
        .filter(|doctype| !doctype.is_empty())
}

fn mdoc_credential(document: &RegistryDocument, raw: Value) -> Result<CredentialType> {
    let doctype = mdoc_identifier(&raw)
        .ok_or_else(|| malformed("mdoc metadata without a doctype"))?
        .to_owned();
    let label = display_label(raw.get("display"), "name")
        .or_else(|| raw.get("name").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_else(|| doctype.clone());
    let mut claims = Vec::new();
    if let Some(namespaces) = raw.get("claims").and_then(Value::as_object) {
        for (namespace, elements) in namespaces {
            if let Some(elements) = elements.as_object() {
                for (name, metadata) in elements {
                    claims.push(ClaimMetadata {
                        path: vec![Some(namespace.clone()), Some(name.clone())],
                        label: display_label(metadata.get("display"), "name")
                            .or_else(|| display_label(metadata.get("display"), "label"))
                            .unwrap_or_else(|| name.clone()),
                        mandatory: metadata
                            .get("mandatory")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                    });
                }
            }
        }
    }
    claims.sort_by(|a, b| a.path.cmp(&b.path));
    let dcql = serde_json::json!({"credentials": [{
        "id": document.schema.id,
        "format": "mso_mdoc",
        "meta": {"doctype_value": doctype.clone()},
        "claims": claims.iter().map(|claim| serde_json::json!({"path": claim.path})).collect::<Vec<_>>(),
    }]});
    Ok(CredentialType {
        schema_id: document.schema.id.clone(),
        version: document.schema.version.clone(),
        format: document.format.clone(),
        identifier: doctype,
        label,
        claims,
        dcql,
        supported: true,
        raw,
    })
}

fn string_path(value: Option<&Value>) -> Result<Vec<Option<String>>> {
    let path = value
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("claim path must be an array"))?;
    if path.is_empty() {
        return Err(malformed("claim path must not be empty"));
    }
    path.iter()
        .enumerate()
        .map(|(index, segment)| {
            if segment.is_null() && index + 1 == path.len() {
                Ok(None)
            } else {
                segment
                    .as_str()
                    .filter(|segment| !segment.is_empty())
                    .map(|segment| Some(segment.to_owned()))
                    .ok_or_else(|| {
                        malformed("claim path segments must be strings or a trailing null")
                    })
            }
        })
        .collect()
}

fn display_label(display: Option<&Value>, key: &str) -> Option<String> {
    display
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let locale = entry.get("locale").and_then(Value::as_str).unwrap_or("");
            let value = entry.get(key).and_then(Value::as_str)?;
            (!value.is_empty()).then(|| (locale == "en-US", value.to_owned()))
        })
        .fold(None, |best, (preferred, value)| {
            if preferred || best.is_none() {
                Some(value)
            } else {
                best
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn schema(id: &str, formats: &[&str]) -> SchemaMeta {
        SchemaMeta {
            id: id.into(),
            version: "1.5".into(),
            rulebook_uri: "https://registry.example/rulebook".into(),
            attestation_los: "iso_18045_high".into(),
            binding_type: "key".into(),
            supported_formats: formats.iter().map(|f| f.to_string()).collect(),
            schema_uris: formats
                .iter()
                .map(|format| SchemaUri {
                    format_identifier: format.to_string(),
                    uri: format!("https://registry.example/{id}/{}", format.replace('+', "-")),
                })
                .collect(),
        }
    }

    pub(crate) fn document(schema: SchemaMeta, format: &str, body: Value) -> RegistryDocument {
        let uri = schema
            .schema_uris
            .iter()
            .find(|link| link.format_identifier == format)
            .unwrap()
            .uri
            .clone();
        RegistryDocument {
            schema,
            format: format.into(),
            uri,
            body: serde_json::to_vec(&body).unwrap(),
        }
    }

    #[test]
    fn builds_sd_jwt_and_mdoc_indexes_and_presets() {
        let sd = document(
            schema("pid", &["dc+sd-jwt"]),
            "dc+sd-jwt",
            serde_json::json!({
                "vct": "urn:eudi:pid:1",
                "display": [{"locale": "en-US", "name": "PID"}],
                "claims": [{"path": ["birthdate"], "mandatory": true, "display": [{"locale": "en-US", "label": "Birthdate"}]}]
            }),
        );
        let mdoc = document(
            schema("pid", &["mso_mdoc"]),
            "mso_mdoc",
            serde_json::json!({
                "doctype": "org.iso.18013.5.1.mDL",
                "claims": {"org.iso.18013.5.1": {"family_name": {"mandatory": true}}}
            }),
        );
        let catalog = Catalog::from_documents(vec![sd, mdoc]).unwrap();
        assert_eq!(catalog.resolve_vct("urn:eudi:pid:1").unwrap().label, "PID");
        assert_eq!(
            catalog
                .resolve_doctype("org.iso.18013.5.1.mDL")
                .unwrap()
                .claims[0]
                .path,
            [Some("org.iso.18013.5.1".into()), Some("family_name".into())]
        );
        let presets = catalog.presets();
        assert_eq!(presets.len(), 2, "both supported formats are offered");
        assert_eq!(
            presets[0]["dcql"]["credentials"][0]["meta"]["vct_values"][0],
            "urn:eudi:pid:1"
        );
        assert!(presets[0]["dcql"]["credentials"][0]["claims"][0]["mandatory"].is_null());
    }

    #[test]
    fn keeps_multi_schema_identifiers_unambiguous() {
        let one = document(
            schema("one", &["dc+sd-jwt"]),
            "dc+sd-jwt",
            serde_json::json!({"vct": "urn:duplicate"}),
        );
        let two = document(
            schema("two", &["dc+sd-jwt"]),
            "dc+sd-jwt",
            serde_json::json!({"vct": "urn:duplicate"}),
        );
        let catalog = Catalog::from_documents(vec![one, two]).unwrap();
        assert_eq!(catalog.credentials.len(), 2);
        assert!(catalog.resolve_vct("urn:duplicate").is_none());
        let schema_doc = document(
            schema("pid-mdoc", &["mso_mdoc"]),
            "mso_mdoc",
            serde_json::json!({"properties": {"docType": {"const": "eu.europa.ec.eudi.pid.1"}}}),
        );
        let catalog = Catalog::from_documents(vec![schema_doc]).unwrap();
        assert_eq!(
            catalog
                .resolve_doctype("eu.europa.ec.eudi.pid.1")
                .unwrap()
                .identifier,
            "eu.europa.ec.eudi.pid.1"
        );
    }

    #[test]
    fn validates_sri_exactly() {
        let body = br#"{"vct":"urn:test"}"#;
        let digest = B64.encode(Sha256::digest(body));
        let uri = format!("https://registry.example/doc.json#sha256-{digest}");
        assert!(verify_sri(&uri, body).is_ok());
        assert!(verify_sri(&uri, b"changed").is_err());
    }
}
