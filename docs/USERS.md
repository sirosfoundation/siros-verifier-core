# Using the verifier

## Supported presentation flows

- **SD-JWT VC over OpenID4VP:** signed requests, QR/direct-link/DC API delivery, encrypted responses, issuer and key-binding verification, verified claims, and Token Status List checks.
- **ISO/IEC 18013-5 mdoc:** OpenID4VP and proximity engagement, issuer and device authentication, and ordered DocumentRequests with optional P-256 ReaderAuth.
- **`zkp_req` nym_auth:** pseudonym and optional age verification with native Longfellow and Vega backends and verifier-scoped pseudonyms.

BBS and predicate-only ZK requests are outside the supported profile and fail closed.

## What happens during a presentation

1. The verifier creates a request from its own DCQL, nonce, client identity, and signing key.
2. The wallet presents that request to the user, including the requested credential and claims.
3. The user explicitly consents before the wallet answers.
4. The verifier checks response shape, encryption, session/transcript binding, credential signatures, disclosures, and request policy.
5. The verifier asks go-trust for an explicit permit for each document.
6. Only then are verified elements returned. A signature alone does not authorize disclosure.

The browser library initiates the presentation and asynchronously waits for the result. It does not decide trust or verification policy.

## Errors and privacy

- Expired, replayed, malformed, or unpermitted presentations are refused without releasing claims.
- `intentToRetain=false` means the request does not ask to retain those elements.
- A status-list signer must also be authorized by go-trust. Fetch or signature failures do not silently become valid status.
- Transport, consent UI, and credential storage are application responsibilities in native integrations. The verifier core does not receive a wallet PIN or the long-term device key.

See [Configuration](CONFIGURATION.md) for request TTLs, response limits, status-list limits, and storage behavior, or [Examples](../examples/README.md) for working configurations.

## Current limits

- Protocol and algorithm profiles are intentionally allowlisted. Unsupported response modes, client-ID schemes, proof systems, and query features fail closed.
- The native mobile FFI is for proximity mdoc reading; it is not a complete wallet, OpenID4VP client, or NFC transport implementation.
- A new verifier image or circuit catalog does not create a new trust decision. Trust policy belongs to go-trust.
- Stock consumer devices must not require bootloader unlocking, factory wipes, or developer-only modes for installation or acceptance testing.
