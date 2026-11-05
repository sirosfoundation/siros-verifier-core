# Release record

This file records published testing and production releases. The release
process itself is documented in [`docs/RELEASING.md`](docs/RELEASING.md).

Every published release must receive an entry immediately after its artifacts
are published and verified. Entries include source and artifact identities,
validation evidence, deployment/rollback instructions, known limitations, and
the corresponding documentation updates. Do not add speculative entries for
unreleased work.

## Published releases

No testing or production releases have been published.

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
