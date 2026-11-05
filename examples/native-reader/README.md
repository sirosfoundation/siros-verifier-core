# Native reader FFI snippets

These snippets show how to embed the proximity-reader FFI without turning them into a complete application. They intentionally leave these host responsibilities as interfaces:

- QR/NFC handover and BLE/NFC transport
- Long-term ReaderAuth key storage and signing
- The go-trust/AuthZEN PDP call and its explicit permit decision
- Consent UI, credential storage, and time

`deviceEngagement` is the raw CBOR DeviceEngagement value, not an NDEF message. For QR handover, `handover` is CBOR `null`—the single byte `0xf6`, not an empty array. For NFC, call `nfcHandoverCbor(select, request)` with the complete, unmodified Handover Select NDEF message and optional Handover Request NDEF message. Use the helper's CBOR output as `Reader.startWithRole`'s `handover`; do not pass either NDEF message directly as that `handover` value.

Use `Reader.startWithRole` for an explicit issuer role, or `Reader.start` for the compatibility-default `pid-provider` role. `establishmentMessageFromDocuments` builds and encrypts the request and retains its response policy. `openResponse` verifies the response but **does not authorize disclosure**: submit each document's `authzenRequestJson` to the PDP and return elements only when that document is permitted.

The `ReaderAuthSigner` callback must use the verifier's long-term P-256 ReaderAuth key and return raw `r || s`, not a DER signature and never the ephemeral session key. Keep the callback and `ReaderAuth` object alive for the whole native call. The native session lock is released before that callback runs.

The `clock` callback is sampled only after `transport.exchange` returns, immediately before `openResponse`. Do not capture a timestamp before holder consent or transport: an mdoc must be valid at the time its response is verified, not at the earlier request time.

Files:

- `ReaderExample.kt` — generated Kotlin/UniFFI API
- `ReaderExample.swift` — generated Swift/UniFFI API

The examples use `org.iso.18013.5.1.mDL` and request `given_name` and `family_name` with `intentToRetain=false`. Replace the placeholder transport and PDP methods with your own implementation, and handle typed `FfiException`/`FfiError` values rather than treating every failure as a transport error.
