use siros_verifier_core::ts11::*;

fn page(id: &str, total: usize, limit: usize, offset: usize) -> String {
    format!(
        r#"{{
      "data": [{{
        "id": "{id}", "version": "1.5", "rulebookURI": "https://registry.example/rulebook",
        "attestationLoS": "iso_18045_high", "bindingType": "key",
        "supportedFormats": ["dc+sd-jwt"],
        "schemaURIs": [{{"formatIdentifier": "dc+sd-jwt", "uri": "https://registry.example/pid.json"}}]
      }}],
      "total": {total}, "limit": {limit}, "offset": {offset}
    }}"#
    )
}

#[test]
fn parses_current_static_page_shape_and_non_semver_versions() {
    let page = parse_schema_page(page("pid", 32, 32, 0).as_bytes()).unwrap();
    assert_eq!(page.total, 32);
    assert_eq!(page.schemas[0].version, "1.5");
    assert_eq!(
        page.schemas[0].schema_uris[0].format_identifier,
        "dc+sd-jwt"
    );
}

#[test]
fn catalogue_validation_fails_closed() {
    assert!(parse_schema_page(br#"{"data":[],"total":1,"limit":0,"offset":0}"#).is_err());
    assert!(parse_schema_page(page("pid", 0, 1, 0).as_bytes()).is_err());
    assert!(parse_schema_page(
        page("pid", 1, 1, 0)
            .replace("iso_18045_high", "bogus")
            .as_bytes()
    )
    .is_err());
    assert!(parse_schema_page(
        page("pid", 1, 1, 0)
            .replace(
                "https://registry.example/pid.json",
                "http://registry.example/pid.json"
            )
            .as_bytes()
    )
    .is_err());
    assert!(parse_schema_page(
        page("pid", 1, 1, 0)
            .replace("\"dc+sd-jwt\"", "\"not-a-format\"")
            .as_bytes()
    )
    .is_err());
}

#[test]
fn source_urls_drop_only_the_sri_fragment() {
    assert_eq!(
        source_uri("https://registry.example/pid.json#sha256-abc").unwrap(),
        "https://registry.example/pid.json"
    );
    assert!(source_uri("https://user@registry.example/pid.json").is_err());
}

fn registry_schema(id: &str, format: &str) -> SchemaMeta {
    SchemaMeta {
        id: id.into(),
        version: "1".into(),
        rulebook_uri: "https://registry.example/rulebook".into(),
        attestation_los: "iso_18045_high".into(),
        binding_type: "key".into(),
        supported_formats: vec![format.into()],
        schema_uris: vec![SchemaUri {
            format_identifier: format.into(),
            uri: format!("https://registry.example/{id}.json"),
        }],
    }
}

fn registry_document(id: &str, format: &str, body: serde_json::Value) -> RegistryDocument {
    let schema = registry_schema(id, format);
    let uri = schema.schema_uris[0].uri.clone();
    RegistryDocument {
        schema,
        format: format.into(),
        uri,
        body: serde_json::to_vec(&body).unwrap(),
    }
}

#[test]
fn catalog_indexes_follow_the_sorted_credentials() {
    let catalog = Catalog::from_documents(vec![
        registry_document(
            "sd-z",
            "dc+sd-jwt",
            serde_json::json!({"vct": "urn:a:1", "name": "Zulu"}),
        ),
        registry_document(
            "sd-y",
            "dc+sd-jwt",
            serde_json::json!({"vct": "urn:b:1", "name": "Yankee"}),
        ),
        registry_document(
            "mdoc-z",
            "mso_mdoc",
            serde_json::json!({"doctype": "org.example.z", "name": "Alpha"}),
        ),
        registry_document(
            "mdoc-y",
            "mso_mdoc",
            serde_json::json!({"doctype": "org.example.a", "name": "Beta"}),
        ),
    ])
    .unwrap();

    let labels: Vec<&str> = catalog
        .credentials
        .iter()
        .map(|credential| credential.label.as_str())
        .collect();
    assert_eq!(labels, ["Alpha", "Beta", "Yankee", "Zulu"]);
    for vct in ["urn:a:1", "urn:b:1"] {
        assert_eq!(catalog.resolve_vct(vct).unwrap().identifier, vct);
    }
    for doctype in ["org.example.z", "org.example.a"] {
        assert_eq!(
            catalog.resolve_doctype(doctype).unwrap().identifier,
            doctype
        );
    }
}
