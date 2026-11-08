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

The verdict is judged against a **fully pinned reference** — three pins,
each bumped deliberately in its own PR, never left to drift:

| Pin | File | What it fixes |
| --- | --- | --- |
| The OIDF suite release | `conformance/suite-version` | The suite's server + nginx images (never `latest`) |
| The harness revision | `conformance/conformance-ref` | The conformance repo's exact commit — its specs, compose fixtures, and assertions define what "conformant" means here |
| The runner image | `runs-on` in the workflow | `ubuntu-24.04`, the newest host platform the pinned Playwright (1.60) ships browser builds for; unpinned when that bumps |

An invisible change to any of the three would change the verdict when the
same verifier commit is rerun. Adopt a new suite release or harness
revision in one PR that reads the diff and the release notes.

## Readiness is a hard gate

The spec self-skips every module when either the suite or the verifier is
unavailable — a stack that never comes up would otherwise finish green
having verified nothing. The workflow therefore **fails the job** when
either readiness wait expires (the suite's nginx 302; the verifier's
`/health` with a success status), leaving the stack's logs and the run's
artifacts as the diagnosis. A green `OIDF verifier conformance` check means
modules actually executed.

## Skips and evidence

`conformance/blacklist.json` is the intended skip interface (module name →
reason), seeded empty. **It is inert today**: the pinned verifier harness
does not read `CONFORMANCE_BLACKLIST` — only the conformance repo's wallet
specs do — so an entry cannot skip a module until the harness grows that
support and the `conformance-ref` pin bumps to the revision that has it.
When that lands, a blacklisted module is absent from the run, not
run-and-ignored, and the summary records the skip with its reason. Until
then: do not add entries expecting them to work.

Some modules ask for evidence the suite cannot generate itself (a
screenshot, a policy statement); the spec uploads the suite's placeholder
evidence for those and they complete as REVIEW rather than PASS. The
verdict to read is "every applicable module PASSED or REVIEW with its
refusal verified".

## When reports publish

- **Pull requests**: the results ride the run's artifacts (the Checks tab),
  never the site — a PR is a conversation, not a release.
- **Release tags (`v*`)**: the run hands the report set to the conformance
  repo via a `repository_dispatch` (`event_type: conformance-verifier`)
  carrying the tag and the run URL, authenticated by the token in
  [conformance-dispatch-token.md](conformance-dispatch-token.md).
  **PENDING on the conformance repo's side**: its verifier workflow accepts
  the dispatch but does not yet honor `verifier-impl=core`, and it has no
  gh-pages publish for verifier reports yet — so a release's reports reach
  **conformance.siros.org** only after that repo lands its core-mode
  publish chain (one report set per release, addressable from the release
  notes and diffable against the previous release, is the target design).
  Until then the tag's results live in the tag run's artifacts.
- **Manual**: `workflow_dispatch` runs the same path, optionally overriding
  the harness pin with its `conformance-ref` input (a branch or commit on
  the conformance repo — the override never persists into PR or tag runs).

## Running locally

The conformance repo owns the stack; from its checkout:

```sh
docker build -t siros-verifier-core:local /path/to/siros-verifier-core
npm ci --ignore-scripts && node_modules/.bin/playwright install chrome --with-deps
echo '127.0.0.1 localhost.emobix.co.uk conformance.example.com' | sudo tee -a /etc/hosts
CONFORMANCE_SUITE_TAG=release-v5.3.4 SIROS_VERIFIER_CORE_IMAGE=siros-verifier-core:local \
  docker compose -f compose/siros-verifier-core.yml -f compose/go-trust.yml \
    -f compose/conformance-suite.yml up -d --remove-orphans
VERIFIER_IMPL=core NODE_TLS_REJECT_UNAUTHORIZED=0 \
  node_modules/.bin/playwright test specs/conformance/oid4vp-verifier.spec.ts
```

The suite's first boot is slow (its Mongo seed and Spring context); the
nginx 302 on the suite URL is the readiness signal.
