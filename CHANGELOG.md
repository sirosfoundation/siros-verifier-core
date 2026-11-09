# Release record

This file records published testing and production releases. The release
process itself is documented in [`docs/RELEASING.md`](docs/RELEASING.md).

Every published release must receive an entry immediately after its artifacts
are published and verified. Entries include source and artifact identities,
validation evidence, deployment/rollback instructions, known limitations, and
the corresponding documentation updates. Do not add speculative entries for
unreleased work.

## Published releases

### 0.1.0-testing — 2026-11-09

- **Source:** commit [`a6bd169`](https://github.com/sirosfoundation/siros-verifier-core/commit/a6bd1698a8d00f1fc9d6893bac6e56ff7c4dc963) (merge of #29 into `main`; every reviewed PR #17–#29 behind it), built from the locked dependency graph: pinned Git dependencies, no crates.io or Maven Central prerequisites. No signed tag yet — `v0.1.0` follows the tag workflow with explicit approval.
- **Verifier image:** `siros-verifier-core:0.1.0-testing`, image ID `sha256:650c3c7acf29e5006c34117aa66ac06948a35ba5499b3a26582b38d218fb83da`, built locally from the merged source with the repository `Dockerfile`. Not published to GHCR: GHCR publication, signed SBOMs, and provenance attestations are tag-workflow outputs, so this testing image's immutable identity is its image ID digest.
- **Native artifacts:** none in this testing release; the Android AAR and iOS XCFramework are tag-workflow outputs and stay on the same shared workspace version.
- **Summary:** first versioned testing image of the Phase 0 verifier — the HA presentation lifecycle (processing leases, crash recovery, bounded HTTP, replay protection, sealed one-time results), strict status-list checking, native Longfellow ZKP verification on the blocking pool, the thin JS initiation/status surface, and the recorded HA/overload and native soak evidence in `docs/design/SOAK.md`.
- **Validation:**
  - Full CI green on the release head ([PR #29](https://github.com/sirosfoundation/siros-verifier-core/pull/29), all checks: workspace tests with real MongoDB, clippy, fmt, the advisories/bans/licenses/sources gate, the mutation gate, parser fuzz smoke, the OIDF verifier conformance profile, iOS packaging, and the PR-level SonarCloud checks). After the merge, the eight standard CI jobs re-ran green on `main` — Test, Clippy, Format, Advisories, Mutation, Parser fuzz, Presentation flow package, and the iOS Reader build; the OIDF conformance suite is PR-scheduled and did not re-run on `main` (the tag path covers it), and the SonarCloud main-branch gate carries the pre-existing condition triaged under Known limitations.
  - Image startup through the Compose profile: verifier and least-privilege MongoDB healthy in ~10 s, `/health` OK.
  - Live presentations through the image: 13,471 genuine SD-JWT presentations in 30 s (~449/s on one replica), every accepted flow terminal, 0 abandoned, 0 duplicates across 1,345 performed exactly-once samples.
  - Explicit PDP denial: with every trust evaluation denied, every presentation is refused fail-closed with a terminal 403 at the response POST — 4,859 refused, 0 completed, 0 abandoned.
  - Image internals: service binary SHA-256 `c07da1e3ce8f45e18be018e02e8dfe55e80f4a9717784a27d453683dd3ca0be9`; the packaged Longfellow artifact matches the configuration-pinned `artifact_sha256` exactly; the binary links only `libc`, `libgcc_s`, and `libm` (no system zlib).
  - SBOM (CycloneDX), vulnerability report, SHA256SUMS (over the binary, circuit artifact, SBOM, scan, and smoke logs), and both smoke logs are published as the durable evidence bundle for this release: https://gist.github.com/leifj/8b3671da05183bd12bc73ea0a4e4869b.
- **Deployment:** the loopback-HTTP Compose profile from `docs/INTEGRATORS.md` — set `SIROS_VERIFIER_IMAGE` (by digest in the published form) and `docker compose up --no-build -d`, so a missing image fails instead of silently building an unverified substitute. No configuration migration; `examples/compose.toml` is unchanged. (The recorded validation ran the pre-built `0.1.0-testing` image; its container identity matches the image ID above.)
- **Rollback:** first testing image; there is no previous image. Roll back with `docker compose down` and removing the image tag, or rebuild from the prior `main` commit.
- **Documentation:** this entry; the local testing-image procedure added to `docs/RELEASING.md`; the soak evidence recorded with #29 in `docs/design/SOAK.md`.
- **Known limitations:** the image is local until the tag workflow publishes by GHCR digest. The vulnerability scan reports 324 findings — 1 CRITICAL, 45 HIGH, 126 MEDIUM, 152 LOW — all in the `debian:bookworm-slim` runtime base's system packages (`zlib1g`, `util-linux`, `perl-base`, `tar`, `ncurses`, `login`); the Rust dependency tree is clean per the workspace advisory gate, and the flagged system libraries are reached only by base-image utilities (the container healthcheck's `curl`), not by the verifier binary. A base-image refresh is a follow-up for the tagged release. The Compose profile remains loopback HTTP with a single MongoDB — not a production TLS/HA profile. Separately, the SonarCloud main-branch quality gate has failed on every `main` commit since well before this release: under SonarCloud autoanalysis the main-branch "new code" spans the whole repository, headed by a false positive (the genuine Longfellow proof fixture `zkp/testdata/nymauth/pseudonym.json` flagged as a hard-coded secret), plus wildcard-import and cognitive-complexity code smells in pre-existing code and blocking-file-operation flags in `service/src/main.rs`. PR-level analysis of every merged change passed on every PR. Recommended follow-ups: configure the SonarCloud analysis scope to exclude `**/testdata/**` and define versions so new code is measured against a previous release — both org-level settings — and consider an in-repo cleanup of the flagged spots; none affect this release head's gates.

## Entry template

Copy this template into the section above after a verified release:

```markdown
### <version> — <YYYY-MM-DD>

- **Source:** <signed tag and commit URL>
- **Verifier image:** <GHCR image and immutable digest>
- **Native artifacts:** <Android/iOS package versions, checksums, and links>
- **Summary:** <user-visible changes and affected integration boundaries>
- **Validation:** <CI, live presentation, device, and acceptance evidence>
- **Deployment:** <configuration changes, migration requirements, and staging evidence>
- **Rollback:** <previous known-good image/config and rollback verification>
- **Documentation:** <updated guides, examples, and release notes>
- **Known limitations:** <remaining issues and unsupported behavior>
```
