# Native reader FFI snippets

These snippets show how to embed the proximity-reader FFI without turning them into a complete application. They intentionally leave these host responsibilities as interfaces:

- QR/NFC handover and BLE/NFC transport
- Long-term ReaderAuth key storage and signing
- The go-trust/AuthZEN PDP call and its explicit permit decision
- Consent UI, credential storage, and time

`deviceEngagement` is the raw CBOR DeviceEngagement value, not an NDEF message. For QR handover, `handover` is CBOR `null`—the single byte `0xf6`, not an empty array. For NFC, use `nfcHandoverCbor(select, request)` with the raw CBOR Handover Select and optional Handover Request to produce the required handover bytes; do not pass an NDEF record.

Use `Reader.startWithRole` for an explicit issuer role, or `Reader.start` for the compatibility-default `pid-provider` role. `establishmentMessageFromDocuments` builds and encrypts the request and retains its response policy. `openResponse` verifies the response but **does not authorize disclosure**: submit each document's `authzenRequestJson` to the PDP and return elements only when that document is permitted.

The `ReaderAuthSigner` callback must use the verifier's long-term P-256 ReaderAuth key and return raw `r || s`, not a DER signature and never the ephemeral session key. Keep the callback and `ReaderAuth` object alive for the whole native call. The native session lock is released before that callback runs.

Files:

- `ReaderExample.kt` — generated Kotlin/UniFFI API
- `ReaderExample.swift` — generated Swift/UniFFI API

The examples use `org.iso.18013.5.1.mDL` and request `given_name` and `family_name` with `intentToRetain=false`. Replace the placeholder transport and PDP methods with your own implementation, and handle typed `FfiException`/`FfiError` values rather than treating every failure as a transport error.
