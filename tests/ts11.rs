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
