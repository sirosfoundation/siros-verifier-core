# Verifier documentation

This directory is for users and integrators.

## Start here

- [Integration guide](INTEGRATORS.md): choose the gateway, Rust core, JS library, or native FFI, and see deployment prerequisites.
- [User guide](USERS.md): supported presentation flows, consent, disclosure, errors, and current limits.
- [Configuration reference](CONFIGURATION.md): complete service configuration, trust, storage, retrieval, ZK, and circuit settings.
- [Examples index](../examples/README.md): explained TOML configurations for common setups and native-reader snippets.
- [Release guide](RELEASING.md): versioned Docker images, native artifacts, SBOM, provenance, and post-release verification.
- [Release record](../CHANGELOG.md): published testing and production releases, validation evidence, deployment notes, and rollback history.
- [OIDF conformance](oidf-conformance.md): the OpenID Foundation OID4VP verifier plan in CI — what runs, the pinned suite, skips and evidence, and when reports publish.

Additional integration-specific guides:

- [Browser presentation library](../tunnelbana-plugin/src/assets/README.md)
- [Native Android/iOS FFI](../ffi/README.md)

`docs/design/` contains historical findings, design notes, and developer tools. It is not integrator documentation and is not a compatibility contract.
