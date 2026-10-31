# @sirosfoundation/presentation-flow

Framework-free ES module for a DCQL-driven OpenID4VP presentation UI. The demo
page only supplies a catalog and backend binding; request signing, issuer trust,
and verification remain in the verifier backend. This package is intended to be
published independently to npm after its API stabilizes.

## Host integration

```js
import { PresentationFlow } from "@sirosfoundation/presentation-flow";

const flow = new PresentationFlow({
  root: document.querySelector("#app"),
  presets: registryBackedPresets,
  invocations: ["qr", "dc-api", "link"],
  schemes: ["openid4vp", "haip", "haip-vp", "mdoc-openid4vp"],
  startPath: "/ui/start",
  tenant: "example-tenant",
  onResult: (result) => showVerifiedResult(result),
  onError: (error) => showError(error),
});

// start() also resolves/rejects directly:
const result = await flow.start("dc-api");
```

The invocation list controls which buttons appear. Scheme selection affects QR
and direct links only; it never changes DCQL or the DC API request. The demo
shows a SIROS spinner while a start is pending.

## Backend contract and tenancy

`startPath` binds the library to one verifier backend. Start calls are form POSTs
containing `dcql`, `scheme`, and, when configured, `tenant`. Backend-provided
response, status, and completion URLs must be same-origin (or listed explicitly
in `backendOrigins`), which prevents one tenant's start response redirecting the
browser to another origin. The backend remains authoritative for tenant policy,
DCQL validation, request signing, trust, and result collection.

- `POST <startPath>/qr` → `{authorization_request, qr_code, status_uri}`
- `POST <startPath>/dc-api` → `{request, response_uri, status_uri, complete_uri}`
- `GET <status_uri>` → `{status, complete_uri}` where status is `pending`, `done`,
  `failed`, `expired`, or `unknown`.

`start()` resolves with `{status: "done", complete_uri}` or throws an error. A
host may use `onResult`/`onError` or handle the promise itself. Authentication of
verifier initiation is deliberately out of scope for this iteration.

## DC API adapters and shim support

The default adapter is the native `navigator.credentials.get`. A host can inject
an adapter (including the existing SIROS DC API shim) for other platforms:

```js
new PresentationFlow({
  ...options,
  dcApiAdapter: (request) => shimGetCredential(request),
});
```

Adapters receive the standard `{digital: {requests: [...]}}` argument and must
return a credential whose `data.response` contains the compact JWE.

## Registry-backed presets

A preset is `{id, label, dcql}`. The Rust TS11 adapter produces this shape from
`registry.siros.org/api/v1/schemas.json` and its referenced metadata. Other hosts
can generate the same shape from another TS11 deployment or static configuration;
the JS package has no registry-specific logic.
