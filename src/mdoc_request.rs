//! ISO/IEC 18013-5 DeviceRequest and ReaderAuth construction, sans-I/O.
//!
//! The reader's long-term signing key stays behind `kryptering::Signer`; the
//! ephemeral session key remains in `ReaderSession`. Trust in the reader
//! certificate is evaluated by the wallet, not by this builder.

use std::collections::BTreeSet;

use ciborium::Value;
use kryptering::{EcCurve, HashAlgorithm, SignatureAlgorithm, Signer};

use crate::error::policy;
use crate::mdoc::{enc, leaf_key, parse, sig_structure, tag24, verify_es256};
use crate::{Error, Result};

const ES256_PROTECTED: &[u8] = &[0xa1, 0x01, 0x26];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestedElement {
    pub identifier: String,
    pub intent_to_retain: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestedNamespace {
    pub namespace: String,
    pub elements: Vec<RequestedElement>,
}

pub struct ReaderAuthParams<'a> {
    pub signer: &'a dyn Signer,
    /// DER certificates, leaf first. This is evidence for the wallet, not a
    /// verifier-side trust decision.
    pub x5c_der: &'a [Vec<u8>],
}

pub struct RequestedDocument<'a> {
    pub doc_type: String,
    pub namespaces: Vec<RequestedNamespace>,
    /// Optional ISO 18013-5 v1.0 requestInfo entries, in encoding order.
    pub request_info: Vec<(String, Value)>,
    pub reader_auth: Option<ReaderAuthParams<'a>>,
}

fn duplicate<T: Ord>(values: impl IntoIterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().any(|value| !seen.insert(value))
}

fn items_request(document: &RequestedDocument<'_>) -> Result<Vec<u8>> {
    if document.doc_type.is_empty() {
        return Err(policy("mdoc_request_empty_doc_type"));
    }
    if document.namespaces.is_empty() {
        return Err(policy("mdoc_request_empty_namespaces"));
    }
    if duplicate(document.namespaces.iter().map(|ns| ns.namespace.as_str())) {
        return Err(policy("mdoc_request_duplicate_namespace"));
    }
    if duplicate(document.request_info.iter().map(|(key, _)| key.as_str())) {
        return Err(policy("mdoc_request_duplicate_request_info"));
    }
    if document.request_info.iter().any(|(key, _)| key.is_empty()) {
        return Err(policy("mdoc_request_empty_request_info_key"));
    }

    let mut namespaces = Vec::with_capacity(document.namespaces.len());
    for namespace in &document.namespaces {
        if namespace.namespace.is_empty() {
            return Err(policy("mdoc_request_empty_namespace"));
        }
        if namespace.elements.is_empty() {
            return Err(policy("mdoc_request_empty_elements"));
        }
        if duplicate(
            namespace
                .elements
                .iter()
                .map(|element| element.identifier.as_str()),
        ) {
            return Err(policy("mdoc_request_duplicate_element"));
        }
        let mut elements = Vec::with_capacity(namespace.elements.len());
        for element in &namespace.elements {
            if element.identifier.is_empty() {
                return Err(policy("mdoc_request_empty_element"));
            }
            elements.push((
                Value::Text(element.identifier.clone()),
                Value::Bool(element.intent_to_retain),
            ));
        }
        namespaces.push((
            Value::Text(namespace.namespace.clone()),
            Value::Map(elements),
        ));
    }

    let mut request = vec![
        (
            Value::Text("docType".into()),
            Value::Text(document.doc_type.clone()),
        ),
        (Value::Text("nameSpaces".into()), Value::Map(namespaces)),
    ];
    if !document.request_info.is_empty() {
        request.push((
            Value::Text("requestInfo".into()),
            Value::Map(
                document
                    .request_info
                    .iter()
                    .map(|(key, value)| (Value::Text(key.clone()), value.clone()))
                    .collect(),
            ),
        ));
    }
    Ok(enc(&Value::Map(request)))
}

fn reader_auth(
    session_transcript_bytes: &[u8],
    items_request_bytes: &[u8],
    params: &ReaderAuthParams<'_>,
) -> Result<Value> {
    if params.signer.algorithm()
        != (SignatureAlgorithm::Ecdsa(EcCurve::P256, HashAlgorithm::Sha256))
    {
        return Err(policy("reader_auth_algorithm"));
    }
    let Some((leaf, _)) = params.x5c_der.split_first() else {
        return Err(policy("reader_auth_empty_chain"));
    };

    // SessionTranscriptBytes wraps the bare transcript used in
    // ReaderAuthentication. ItemsRequestBytes is already in its exact emitted
    // form; do not re-encode only one side of the signature/request pair.
    let transcript = parse(session_transcript_bytes)?;
    let transcript = tag24(&transcript)?;
    let mut authentication = vec![0x83];
    authentication.extend(enc(&Value::Text("ReaderAuthentication".into())));
    authentication.extend_from_slice(transcript);
    authentication.extend_from_slice(items_request_bytes);
    let authentication_bytes = enc(&Value::Tag(24, Box::new(Value::Bytes(authentication))));
    let signing_input = sig_structure("Signature1", ES256_PROTECTED, &authentication_bytes);
    let signature = params
        .signer
        .sign(&signing_input)
        .map_err(|error| Error::Crypto(format!("reader_auth_signer: {error}")))?;

    // Catch a mismatched key and certificate without making a trust decision.
    verify_es256(&leaf_key(leaf)?, &signing_input, &signature)?;

    let chain = if params.x5c_der.len() == 1 {
        Value::Bytes(leaf.clone())
    } else {
        Value::Array(
            params
                .x5c_der
                .iter()
                .map(|der| Value::Bytes(der.clone()))
                .collect(),
        )
    };
    Ok(Value::Array(vec![
        Value::Bytes(ES256_PROTECTED.to_vec()),
        Value::Map(vec![(Value::Integer(33.into()), chain)]),
        Value::Null,
        Value::Bytes(signature),
    ]))
}

/// Build a complete ISO 18013-5 v1.0 DeviceRequest.
///
/// `session_transcript_bytes` is the tag-24-wrapped transcript from the
/// session. The returned bytes can be passed directly to
/// `ReaderSession::establishment_message` or `data_message`.
pub fn build_device_request(
    session_transcript_bytes: &[u8],
    documents: &[RequestedDocument<'_>],
) -> Result<Vec<u8>> {
    if documents.is_empty() {
        return Err(policy("mdoc_request_empty_documents"));
    }
    let mut requests = Vec::with_capacity(documents.len());
    for document in documents {
        let inner = items_request(document)?;
        let items_request_value = Value::Tag(24, Box::new(Value::Bytes(inner)));
        let items_request_bytes = enc(&items_request_value);
        let mut request = vec![(Value::Text("itemsRequest".into()), items_request_value)];
        if let Some(params) = &document.reader_auth {
            request.push((
                Value::Text("readerAuth".into()),
                reader_auth(session_transcript_bytes, &items_request_bytes, params)?,
            ));
        }
        requests.push(Value::Map(request));
    }
    Ok(enc(&Value::Map(vec![
        (Value::Text("version".into()), Value::Text("1.0".into())),
        (Value::Text("docRequests".into()), Value::Array(requests)),
    ])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_detection_is_not_encoding_based() {
        assert!(duplicate(["same", "other", "same"]));
        assert!(!duplicate(["one", "two"]));
    }
}
