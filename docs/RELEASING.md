# Releasing

The tag workflow is [`.github/workflows/release.yml`](../.github/workflows/release.yml). It validates the tagged source, builds the GHCR image through the organization workflow, generates signed source/image SBOMs and vulnerability results, publishes the public Rust crates with OIDC trusted publishing, and attaches `.crate` files, checksums, the image digest, and provenance attestations to the GitHub release.

The GHCR image and native Android/iOS artifacts are built from the tagged source and lockfiles, not from crates.io or Maven publications. The registry preflight runs only in the crates job, so Docker and native SDK publication can proceed while external Rust dependencies are unpublished or a Maven-native artifact has not been released. Docker does not depend on a successful crates.io or Maven release.

The native Reader jobs build from the same tag. `native-android` publishes the AAR and POM to this repository's GitHub Packages Maven repository and attaches them to the release. `native-ios` attaches `SirosVerifierCore.xcframework.zip`, the Swift Package Manager checksum, and the generated Swift bindings. The Kotlin and Swift SDKs must select these artifacts from one shared version rather than generating bindings from different core revisions. Local build inputs and outputs are documented in [`ffi/README.md`](../ffi/README.md).

## Prerequisites

1. Publish the exact external registry dependencies used by the public crates. For this release those are `siros-dc-matcher-core` 0.12.0, `zk-cred-longfellow` 0.1.2, `zk-cred-vega` 0.0.7, and `tunnelbana-core` 0.6.0. Git revisions remain pinned for development; crates.io packages resolve the corresponding registry versions.
2. Configure each of `siros-verifier-core`, `siros-verifier-zkp`, `siros-verifier-core-ffi`, and `siros-verifier-core-tunnelbana` for crates.io trusted publishing from this repository's `release.yml` workflow and the `crates-io` environment.
3. Keep every workspace package version equal to the intended tag. The workflow rejects a mismatch.
4. Merge the release changes and require the complete CI run to pass. Complete live Longfellow and Vega presentations against the candidate gateway before tagging.

`cargo package --list` checks package contents but is not package verification. `cargo publish` performs the full package/build check against registry dependencies before each upload, so missing dependency versions fail the release rather than producing an unusable crate.

## Tag and verify

Only after the prerequisites and live verification pass, create the signed release tag through the normal reviewed release process. For the initial release the tag is `v0.1.0`; do not create it locally as part of feature development.

The crates job publishes in dependency order:

1. `siros-verifier-core`
2. `siros-verifier-zkp`
3. `siros-verifier-core-ffi`
4. `siros-verifier-core-tunnelbana`

Crates.io versions are immutable. A rerun skips a version that already exists, but a tag must never be moved to replace source associated with a published version.

After the workflow succeeds, verify the GHCR digest, release checksums and attestations, crates.io pages, SBOM artifacts, and vulnerability results. Deploy the image by digest and repeat the live Longfellow and Vega smoke tests before updating production provenance.
