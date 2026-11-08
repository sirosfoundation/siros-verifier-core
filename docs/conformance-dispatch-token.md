# CONFORMANCE_DISPATCH_TOKEN — creation and setup

The verifier's conformance workflow (`.github/workflows/conformance.yml`)
hands release-tag results to the conformance repo by dispatching its
verifier workflow (`repository_dispatch`, event `conformance-verifier`). The
dispatch needs a token — this one.

## What it is

A **GitHub fine-grained personal access token (PAT)** with exactly one
repository permission: **Contents — Read and write** on
**`sirosfoundation/siros-conformance`** — nothing else.

Why Contents and not Actions: GitHub's fine-grained token permission table
puts the repository-dispatch endpoint (`POST /repos/{owner}/{repo}/dispatches`)
under **Contents: write** — "Actions: write" covers the *workflow* dispatch
endpoint instead. A token with only Actions: write is rejected with 403 on
this call.

Be clear-eyed about what this grant is: Contents: write on that repository
can read and modify its code. That is broader than the single dispatch the
job performs, and it is the narrowest credential GitHub offers for this
endpoint — a classic PAT with the `repo` scope is strictly wider, and a
GitHub App installation token with the same Contents permission is heavier
machinery for the same right. The compensating controls:

- **Scope**: the token is restricted to `sirosfoundation/siros-conformance`
  alone — it cannot touch any other repository.
- **Lifetime**: 90 days (GitHub's cap for fine-grained tokens), with a
  calendar reminder to rotate.
- **Use**: the workflow reads it only in the release-tag dispatch step; PR
  and manual runs never touch it.

## Creating it

1. Sign in to GitHub as yourself (or the service account the org uses for
   automation), then:

   **Settings → Developer settings → Personal access tokens → Fine-grained
   tokens → Generate new token**

2. Fill in:

   | Field | Value |
   |---|---|
   | **Token name** | `conformance-dispatch-verifier` |
   | **Expiration** | 90 days |
   | **Resource owner** | `sirosfoundation` |
   | **Repository access** | Only select repositories → `sirosfoundation/siros-conformance` |
   | **Permissions → Repository permissions → Contents** | **Read and write** |

   Everything else stays **No access** — including Actions, which is *not*
   needed for this dispatch.

3. Generate and copy the token (it is shown once).

## Installing it

Add it as a repository secret of **this** repository:

**Settings → Secrets and variables → Actions → New repository secret**

| Field | Value |
|---|---|
| **Name** | `CONFORMANCE_DISPATCH_TOKEN` |
| **Secret** | the token value |

The workflow reads it as `secrets.CONFORMANCE_DISPATCH_TOKEN` only in the
release-tag dispatch step.

## Rotating it

Repeat the creation steps and update the secret. The failure mode of an
expired or wrong-scoped token is a 403 on the dispatch step of a
release-tag run — the rest of the run is unaffected, and the dispatch can
be retried after rotation.

## Verifying it before the first release tag

From any machine with `gh` (not just CI):

```sh
GH_TOKEN=<the token> gh api -X POST \
  /repos/sirosfoundation/siros-conformance/dispatches \
  -f event_type=conformance-verifier \
  -f 'client_payload[probe]=token-check'
```

Expect HTTP 204 (no content) and a run of the conformance repo's verifier
workflow. A 403 means the token's permission or repository scope is wrong;
401 means it expired or was revoked.
