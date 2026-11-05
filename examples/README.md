# Integrator examples

These files show common service configurations and small native integration snippets. They are not production secret stores. Replace every `/replace/me` path, relying-party URI, hostname, and credential before use. Supply secrets through the documented `${VARIABLE}` environment placeholders rather than editing real secrets into these files.

## Configuration examples

“Frontend” and “backend” are plugin roles, not two separate applications. The `ui` frontend is the thin browser initiation surface; the `oidc` frontend is the relying-party protocol endpoint; the single `openid4vp` backend verifies the wallet presentation for either entry surface. See [Plugin roles](../docs/CONFIGURATION.md#plugin-roles-frontend-and-backend).

| File | Intended setup | External dependencies |
| --- | --- | --- |
| `quickstart.toml` | One local process with SD-JWT and nym_auth, in-memory flow storage, and an offline Longfellow artifact. | Request signing key/certificate, a loopback go-trust fixture, and the exact circuit artifact at the path you configure. |
| `mdoc-only.toml` | One local mdoc-over-OpenID4VP process with no `zkp_req` backend. | Request signing key/certificate and a loopback go-trust fixture. |
| `replicas.toml` | Multiple processes sharing replay and result state, with catalog-backed Longfellow. | MongoDB, HTTPS go-trust, and the circuit catalog. Use a replica set or managed HA MongoDB for database failover. |
| `production.toml` | HTTPS deployment with shared MongoDB and both Longfellow and Vega. | MongoDB HA, HTTPS go-trust, the circuit catalog, and TLS termination upstream. |

The files are valid TOML templates for `siros-verifier-service`. Read [Configuration](../docs/CONFIGURATION.md) before changing query profiles, roles, storage, or artifact fields.

## Run one

Copy the chosen file to a private directory, edit it, then run:

```sh
TUNNELBANA_BIND=127.0.0.1:9001 siros-verifier-service /private/config/quickstart.toml
```

For a container, use `TUNNELBANA_BIND=0.0.0.0:9001` and mount the configuration, key material, and any offline circuit artifact read-only. For a native host, first place the exact Longfellow artifact at the path in `quickstart.toml` (or change that path), then start the service. The Docker image already contains the Longfellow artifact at `/etc/siros-verifier/circuits/nymauth-mdoc.bin`; Vega must come from an exact configured artifact or the catalog.

Plain HTTP is allowed by default only for an exact loopback PDP, so `allow_insecure_http` stays `false` in every example. Setting it to `true` additionally permits plaintext HTTP to a non-loopback PDP on a trusted development network; do not enable it for a remote production PDP. `replicas.toml` and `production.toml` require HTTPS for the PDP and secure cookies.

## Secret injection

`ProxyConfig` expands `${VARIABLE}` placeholders at load time. Inject these values from your secret manager rather than committing them:

```sh
export SIROS_VERIFIER_STATE_KEY='replace-with-at-least-32-random-bytes'
export SIROS_VERIFIER_MONGODB_URI='mongodb://verifier-user:change-me@mongo.internal:27017'
export SIROS_PDP_BEARER_TOKEN='replace-with-the-pdp-token'
```

The MongoDB URI and PDP bearer token are needed only for deployments that use them. The quickstart uses in-memory storage and no PDP bearer token. Request signing keys and certificate chains stay in protected files referenced by the configuration, not in these TOML files.

## Native reader snippets

`native-reader/` contains small Kotlin and Swift examples of:

- starting a reader with a verifier-owned role;
- building an ordered, ReaderAuth-signed request;
- exchanging session messages through a host-provided transport;
- verifying a response;
- withholding every element until the host's PDP explicitly permits it.

They are deliberately not full applications and do not implement QR/NFC handover, transport, key storage, consent UI, or go-trust itself. See [the FFI guide](../ffi/README.md) for packaging and [the native-reader README](native-reader/README.md) for the API contract.

## Design and developer material

Historical findings and Rust developer tools are under [`docs/design/`](../docs/design/README.md), not here. That material is not integrator documentation or a supported configuration interface.
