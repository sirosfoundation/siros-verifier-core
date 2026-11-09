# Releasing

The tag workflow is [`.github/workflows/release.yml`](../.github/workflows/release.yml). It validates the tagged source, builds the GHCR image through the organization workflow, builds the native Android and iOS artifacts, generates signed source/image SBOMs and vulnerability results, and attaches native artifacts, the image digest, checksums, and provenance attestations to the GitHub release.

Every release job builds from the tagged source and lockfiles. No release track publishes to crates.io or requires an external crates.io publication, trusted-publisher configuration, or namespace negotiation. Pinned Git dependencies, including tunnelbana and the native ZK backends, remain source dependencies for reproducible builds. Native SDK releases also remain independent of Maven Central publication.

The native Reader jobs build from the same tag. `native-android` publishes the AAR and POM to this repository's GitHub Packages Maven repository and attaches them to the release. `native-ios` attaches `SirosVerifierCore.xcframework.zip`, the Swift Package Manager checksum, and the generated Swift bindings. Ordinary GitHub CI also builds and uploads the iOS package on `macos-latest` for pushes to `main` and all pull requests, so packaging is exercised before a tag. The Kotlin and Swift SDKs must select these artifacts from one shared version rather than generating bindings from different core revisions. Local build inputs and outputs are documented in [`ffi/README.md`](../ffi/README.md).

## Shared prerequisites

1. Keep every workspace package version equal to the intended tag. The workflow rejects a mismatch.
2. Merge the release changes and require the complete CI run to pass. Complete live Longfellow and Vega presentations against the candidate gateway before tagging.

## Release artifacts

After the shared prerequisites pass, create the signed release tag through the normal reviewed release process. The workflow produces:

- the GHCR image and its immutable digest;
- the Android AAR/POM in GitHub Packages and on the release;
- the iOS XCFramework, Swift bindings, and SPM checksum;
- signed source/image SBOMs and vulnerability results;
- `image-digest.txt`, `SHA256SUMS`, and their provenance attestations.

The workflow does not create or upload `.crate` packages. GitHub's immutable source archives and the release artifacts above are the supported release outputs; crates.io publication is neither a prerequisite nor a release step.

For the initial full release the tag is `v0.1.0`; do not create it locally as part of feature development or create that full-release tag until every release track is ready.

After the workflow succeeds, verify the GHCR digest, native artifacts, release checksums and attestations, SBOM artifacts, and vulnerability results. Deploy the image by digest and repeat the live Longfellow and Vega smoke tests before updating production provenance.

## Testing images

Between tagged releases, a versioned testing image can be built and validated locally from merged `main`:

1. Build from the merged source and lockfiles (the build sandbox needs `--network host` for package and Git-dependency fetches):

   ```sh
   docker build --network host -t siros-verifier-core:<version>-testing .
   ```

2. Validate before recording: startup through the Compose profile (`SIROS_VERIFIER_IMAGE=<tag> docker compose up --no-build -d`, so a missing image fails instead of silently building an unverified substitute; then `curl --fail http://localhost:9001/health`); one complete presentation and one explicit PDP denial through the `docs/design/SOAK.md` driver tools; an SBOM and vulnerability scan (for example trivy CycloneDX); and SHA-256 checksums of the binary and the packaged circuit artifact, with the artifact checked against the pinned `artifact_sha256`.
3. Record the testing release in [`CHANGELOG.md`](../CHANGELOG.md) with the image ID digest as its immutable identity, noting that GHCR publication and signed provenance follow at the tag. Testing images stay local; the GHCR image and its digest are tag-workflow outputs.

Immediately after every testing or production release, add its publication and verification details to [`CHANGELOG.md`](../CHANGELOG.md), including source/artifact identities, deployment and rollback evidence, known limitations, and the corresponding documentation updates.
