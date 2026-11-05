# Verifier configuration

Runnable local and Fly examples are maintained in `sirosid-dev` under [`fixtures/siros-verifier/`](https://github.com/sirosfoundation/sirosid-dev/tree/main/fixtures/siros-verifier). Run the service with:

```sh
siros-verifier-service /etc/siros-verifier/proxy.toml
```

Set `TUNNELBANA_BIND=0.0.0.0:9001` when the service is behind a public proxy. Keep request signing keys, the state-sealing master, MongoDB credentials, and any PDP bearer token in a secret manager, not in the TOML file.

## Trust boundary

**All issuer and verifier trust decisions belong to go-trust, including status-list signer trust.** Configure `pdp_endpoint`, `pdp_id`, and issuer/verifier policies there, including the `status-list-signer` action when credentials carry status references. The circuit catalog and the local circuit allowlist are integrity controls, not a trust registry. Do not add a second issuer/verifier trust path in this service.

The signing certificate chain is configured separately from the issuer's keys. Use a dedicated verifier key. `zkp_req` normally uses `x509_san_dns:<host>` as `client_id`; other formats retain `x509_hash`. Put the public host in the certificate SAN and authorize both subject forms, plus the test CA when SAN chain validation is required, in go-trust.

## HTTP, sessions, and storage

```toml
base_url = "https://verifier.example"
state_encryption_key = "replace-with-at-least-32-random-bytes"
previous_state_encryption_keys = ["previous-master-during-rotation"]
cookie_secure = true
cookie_same_site = "None"
state_cookie_max_age = 900
```

Use `mongodb` for every deployment with more than one process:

```toml
[backend.config.storage]
backend = "mongodb"
uri = "mongodb://verifier-user:password@mongo.internal:27017"
database = "siros_verifier"
collection = "presentation_flows"
```

Flow claims, replay protection, OIDC token consumption, and result collection must share one database. Use a least-privilege user with `readWrite` only on `siros_verifier`. A standalone MongoDB is shared storage, not database-level HA; use a replica set or managed HA service when required. `memory` is for explicitly single-process tests only.

The current hard limits are 2 MiB for an HTTP body and compact JWE, and 1 MiB for decrypted response plaintext. Genuine Longfellow and Vega responses fit these bounds.

SD-JWT `status.status_list` references are fetched over HTTPS with a 5-second timeout, no redirects or ambient proxies, a streaming 64 KiB token limit, and a 1 MiB decompressed-list limit. Userinfo is refused. Only public IP addresses are allowed: literal private addresses are refused before dialing and DNS results are filtered at connection time, including IPv4-mapped IPv6 addresses. Tokens must be `statuslist+jwt` with a valid ES256 signature and time window and a subject matching the reference. The signer is evaluated through go-trust with the `status-list-signer` action. Fetch/parse failures, untrusted signers, and nonzero status values fail closed.

`allow_invalid_status_list_certificates = true` disables TLS certificate validation and the public-address restriction for local conformance fixtures with self-signed servers. Never enable it in a real deployment. PDP responses have a streaming 1 MiB limit and also ignore ambient proxy settings.

## Request object retrieval

The default is `request_uri_method = "get"`. Set `request_uri_method = "post"` for wallets that require POST retrieval. The wallet supplies `wallet_nonce` in its form POST; the service echoes it in a re-signed request object and requires exactly one valid field. Missing, duplicate, unknown, or malformed fields are refused. GET retrieval remains unchanged and is always available alongside POST retrieval.

## UI presets

`frontend.config.presets` is an array of tables with `id`, `label`, and `dcql`. Registry-derived presets are merged by credential format and type; the registry's full claim list remains available for editing. Configure the requested claim subset for your deployment and include a subject claim—the first claim becomes the subject when no custom pointer is configured.

Only the QR display is modal, and its contents are replaced on every request. The complete page shows a neutral spinner while pending and then renders the decoded verified response or an error.

## `zkp_req`

The supported nym_auth profile is pseudonym plus optional `age_check`, with Longfellow and Vega native verification. Vega and Longfellow artifacts are independent allowlist entries. BBS and predicate-only requests fail closed.

Shared backend settings:

```toml
[backend.config.zkp]
system_id_values = ["urn:circuits:longfellow:nym_auth:v1", "urn:circuits:vega:nym_auth:v1"]
proof_system_values = ["longfellow-libzk-v1", "vega-v1"]
role = "mdoc-issuer"
verifier_id = "x509_san_dns:verifier.example"
auth_class_ref = "urn:eudi:loa:high"
```

Configure each UI/backend pair independently. Query ID, result handles, age bounds, subject handle, and attribute map must agree:

```toml
[[backend.config.zkp.profiles]]
query = { id = "nym_auth", format = "zkp_req",
  meta = { source_format = "mso_mdoc", doctype_value = "eu.europa.ec.eudi.nym_auth.1" },
  _req = [
    { fn_id = "pseudonym", return = "nym", params = {
      config = "known-offender-matching-ssc", ver = 1, prf = "sha-256" } },
  ] }
subject_handle = "nym"
attribute_map = { pseudonym = "nym" }

[[backend.config.zkp.profiles]]
query = { id = "nym_auth", format = "zkp_req",
  meta = { source_format = "mso_mdoc", doctype_value = "eu.europa.ec.eudi.nym_auth.1" },
  _req = [
    { fn_id = "pseudonym", return = "nym", params = {
      config = "known-offender-matching-ssc", ver = 1, prf = "sha-256" } },
    { fn_id = "age_check", return = "age", params = {
      ge = "1980-01-01", le = "2000-12-31" } },
  ] }
subject_handle = "nym"
attribute_map = { pseudonym = "nym", age = "age" }
```

The UI uses the same two objects with IDs `nym_auth_pseudonym` and `nym_auth_pseudonym_age`. Multiple profiles may share a query ID because their function lists differ; two byte-equivalent queries are rejected at startup. The legacy single `query`/`subject_handle`/`attribute_map` form remains supported for compatibility.

Age windows are inclusive and must span at least 365 days. Use a range satisfied by the intended holder; gdc's 1980–2000 range matches its 1990 test credential.

## Circuit catalog and allowlist

```toml
[backend.config.zkp.circuits]
sources = ["https://api.circuits.siros.org"]

[[backend.config.zkp.circuits.allow]]
system_id = "urn:circuits:longfellow:nym_auth:v1"
config = "known-offender-matching-ssc"
hash_circuit_id = "5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729"
sig_circuit_id = "00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb"
block_enc_hash = 6983
block_enc_sig = 4679
artifact_id = "nymauth-longfellow-mdoc-v1"
artifact_sha256 = "92dd42fdf99673249eec33c7d07850bd9da66fbdab01ef26391e04c8341c1b7f"
artifact_bytes = 1062842

[[backend.config.zkp.circuits.allow]]
system_id = "urn:circuits:vega:nym_auth:v1"
config = "known-offender-matching-ssc"
artifact_id = "nymauth-vega-mdoc-v1"
artifact_sha256 = "4da5e73afb9be2682e70be793c9956a73304e21f31246aa10da0d3e95c926425"
artifact_bytes = 12205144
```

`api.circuits.siros.org` serves descriptors and immutable artifacts; `circuits.siros.org` is the human-facing site. Sources are ordered mirrors, each subject to the same operator pin. Startup prefetches and verifies catalog artifacts; wallet responses never fetch them. The service then prewarms every allowlisted native backend, validating local files and initializing Longfellow/Vega before the first presentation. If startup cannot obtain, verify, or initialize the exact allowed artifact, the service fails closed. Embedded library users may instead keep lazy backend loading by not calling `ZkpVerifier::prewarm`.

`artifact_sha256` and `artifact_bytes` always describe the **decompressed** bytes. Use exactly one of `artifact_id` and `artifact_path` per entry. `artifact_path` is the explicit offline alternative and bypasses catalog access. Do not put Longfellow parameters on a Vega entry.
