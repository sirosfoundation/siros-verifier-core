# The OIDF conformance run: the verifier against the certification suite

The OpenID Foundation's OID4VP **verifier** plan certifies the relying-party
side: the suite acts as the wallet, initiates the authorization request
through our service, and judges the request objects, response handling, and
error behavior our verifier produces. This repository's run is the
conformance repo's `VERIFIER_IMPL=core` mode
(`specs/conformance/oid4vp-verifier.spec.ts` in
[siros-conformance](https://github.com/sirosfoundation/siros-conformance)):
no wallet of ours, no phone — the suite's own wallet answers our traffic.

## What the run does

`Conformance (verifier)` (`.github/workflows/conformance.yml`) builds the
`siros-verifier-core` image **from the PR's own source** (never a registry
tag), checks out the conformance repo at a pinned ref, and brings up the
core stack from that repo's compose files:

| Service | Role |
| --- | --- |
| `conformance-suite` (server + nginx) | The OIDF suite itself; drives the plan from `https://localhost.emobix.co.uk:8443` |
| `go-trust-allow` | The suite's local allow-all go-trust stand-in (conformance fixtures only; never a real trust decision) |
| `siros-verifier-core` | This repository's verifier, built from the PR's source, on MongoDB, behind the suite-facing nginx at `https://conformance.example.com:9443` |

The suite version is **pinned** in `conformance/suite-version` (never
`latest`): an invisible upstream bump would change the verdict without a
change here. Adopt a new release deliberately, in one PR with its release
notes.

The variant exercised is the one this verifier documents and supports:
`sd_jwt_vc / x509_hash / direct_post.jwt / request_uri_signed / plain_vp`.

## Skips and evidence

`conformance/blacklist.json` maps module names to skip reasons — a
blacklisted module is absent from the run, not run-and-ignored, and the
summary records the skip with its reason. Remove entries as the work they
track lands.

Some modules ask for evidence the suite cannot generate itself (a
screenshot, a policy statement); the spec uploads the suite's placeholder
evidence for those and they complete as REVIEW rather than PASS. The
verdict to read is "every applicable module PASSED or REVIEW with its
refusal verified".

## When reports publish

- **Pull requests**: the results ride the run's artifacts (the Checks tab),
  never the site — a PR is a conversation, not a release.
- **Release tags (`v*`)**: the run dispatches the conformance repo's own
  publish workflow (`repository_dispatch: conformance-verifier`), which owns
  the gh-pages push to **conformance.siros.org** — one report set per
  release, addressable from the release notes and diffable against the
  previous release. The dispatch token is documented in
  [conformance-dispatch-token.md](conformance-dispatch-token.md).
- **Manual**: `workflow_dispatch` runs the same path against any conformance
  repo ref.

## Running locally

The conformance repo owns the stack; from its checkout:

```sh
docker build -t siros-verifier-core:local /path/to/siros-verifier-core
npm ci && npx playwright install chromium --with-deps
echo '127.0.0.1 localhost.emobix.co.uk conformance.example.com' | sudo tee -a /etc/hosts
CONFORMANCE_SUITE_TAG=release-v5.3.4 SIROS_VERIFIER_CORE_IMAGE=siros-verifier-core:local \
  docker compose -f compose/siros-verifier-core.yml -f compose/go-trust.yml \
    -f compose/conformance-suite.yml up -d --remove-orphans
VERIFIER_IMPL=core NODE_TLS_REJECT_UNAUTHORIZED=0 \
  npx playwright test specs/conformance/oid4vp-verifier.spec.ts
```

The suite's first boot is slow (its Mongo seed and Spring context); the
nginx 302 on the suite URL is the readiness signal.
