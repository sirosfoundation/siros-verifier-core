# CONFORMANCE_DISPATCH_TOKEN — creation and setup

The verifier's conformance workflow (`.github/workflows/conformance.yml`)
publishes release-tag conformance reports to **conformance.siros.org** by
dispatching the conformance repo's own publish workflow
(`repository_dispatch`, event `conformance-verifier`). The dispatch needs a
token — this one. (The same pattern and token policy as siros-wallet-core's
`docs/conformance-dispatch-token.md`.)

## What it is

A **GitHub fine-grained personal access token (PAT)** with exactly one
permission: **Actions: write** (the repository-dispatch right) on
**`sirosfoundation/siros-conformance`** — nothing else. It cannot read code,
cannot merge, cannot touch anything outside that one repo's dispatch
endpoint. (A classic PAT with the full `repo` scope would also work but
grants far more than the job needs; the fine-grained form is the least
privilege.)

## Creating it

1. Sign in to GitHub as yourself (or the service account the org uses for
   automation), then:

   **Settings → Developer settings → Personal access tokens → Fine-grained
   tokens → Generate new token**

2. Fill in:

   | Field | Value |
   |---|---|
   | **Token name** | `conformance-dispatch-verifier` |
   | **Expiration** | 90 days (GitHub's cap for fine-grained tokens; set a calendar reminder to rotate — the workflow starts failing with 401/403 when it expires, which is the rotation signal) |
   | **Resource owner** | `sirosfoundation` |
   | **Repository access** | Only select repositories → `sirosfoundation/siros-conformance` |
   | **Permissions → Repository permissions → Actions** | **Read and write** |

   Everything else stays **No access**.

3. Generate and copy the token (it is shown once).

## Installing it

Add it as a repository secret of **this** repository:

**Settings → Secrets and variables → Actions → New repository secret**

| Field | Value |
|---|---|
| **Name** | `CONFORMANCE_DISPATCH_TOKEN` |
| **Secret** | the token value |

The workflow reads it as `secrets.CONFORMANCE_DISPATCH_TOKEN` only in the
release-tag dispatch step; PR runs never touch it.

## Rotating it

Repeat the creation steps and update the secret. The failure mode of an
expired token is a 401/403 on the dispatch step of a release-tag run — the
rest of the run is unaffected, and the report set can be re-published by
re-running the workflow after rotation.
