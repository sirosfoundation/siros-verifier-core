//! The session transcript and challenge a nym_auth proof is bound to.
//!
//! Both handovers the circuits define (nym-auth-circuits SPEC section 3; OpenID4VP 1.0 appendix B.2.6.1):
//!
//! ```text
//! DC API    SessionTranscript = [null, null, ["OpenID4VPDCAPIHandover", bstr(SHA-256(cbor([origin, nonce, thumbprint|null])))]]
//! redirect  SessionTranscript = [null, null, ["OpenID4VPHandover",      bstr(SHA-256(cbor([client_id, nonce, thumbprint, response_uri])))]]
//! ```
//!
//! and the challenge `e2 = SHA-256(cbor(["Signature1", h'A10126', h'', DeviceAuthenticationBytes]))`.
//!
//! Every input is the verifier's own: the origin or client id it published, the nonce it issued, the response URI it
//! listens on, the thumbprint of the encryption key it generated. A transcript built from anything the response
//! carries would be a proof of whatever the holder chose. The two handovers are different structures and a wallet
//! built only one of them, so they are separate entry points and a wrong choice is a legible error, not an opaque
//! proof failure. Agreement with the shared vectors is tested byte for byte (`tests/challenge_vectors.rs`).

use ciborium::Value;
use sha2::{Digest, Sha256};
use siros_verifier_core::{Error, Result};

/// The shortest request nonce the challenge accepts (characters). The nonce is what makes a proof this session's,
/// so its length is the entropy of that binding.
pub const MIN_NONCE_CHARS: usize = 16;

const THUMBPRINT_BYTES: usize = 32;
const SESSION_TRANSCRIPT_ITEMS: usize = 3;

fn policy(m: &str) -> Error {
    Error::Policy(m.to_owned())
}

fn enc(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("in-memory cbor write");
    out
}

fn check_nonce(nonce: &str) -> Result<()> {
    if nonce.is_empty() {
        return Err(policy(
            "the challenge needs the request nonce, which is what makes it this session's proof",
        ));
    }
    let n = nonce.chars().count();
    if n < MIN_NONCE_CHARS {
        return Err(Error::Policy(format!(
            "the request nonce is {n} characters; the shared vectors require at least {MIN_NONCE_CHARS}"
        )));
    }
    Ok(())
}

fn transcript(handover_name: &str, info: &Value) -> Vec<u8> {
    let hash = Sha256::digest(enc(info));
    enc(&Value::Array(vec![
        Value::Null,
        Value::Null,
        Value::Array(vec![
            Value::Text(handover_name.to_owned()),
            Value::Bytes(hash.to_vec()),
        ]),
    ]))
}

/// SessionTranscript for a presentation returned through the Digital Credentials API. `thumbprint` is the JWK
/// thumbprint of the response-encryption key, or `None` when the response is not encrypted (it never crosses a
/// network on this channel).
pub fn session_transcript_dcapi(
    origin: &str,
    nonce: &str,
    thumbprint: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if origin.is_empty() {
        return Err(policy(
            "the challenge needs the calling origin, which binds the proof to the page that asked for it",
        ));
    }
    check_nonce(nonce)?;
    if let Some(t) = thumbprint {
        if t.len() != THUMBPRINT_BYTES {
            return Err(Error::Policy(format!(
                "the reader key thumbprint is {} bytes; a SHA-256 thumbprint is {THUMBPRINT_BYTES}",
                t.len()
            )));
        }
    }
    let info = Value::Array(vec![
        Value::Text(origin.to_owned()),
        Value::Text(nonce.to_owned()),
        thumbprint.map_or(Value::Null, |t| Value::Bytes(t.to_vec())),
    ]);
    Ok(transcript("OpenID4VPDCAPIHandover", &info))
}

/// SessionTranscript for a presentation delivered by redirect (a link or QR; the wallet POSTs to `response_uri`).
///
/// The thumbprint is required, and exactly 32 bytes: over a redirect the response must be encrypted
/// (`direct_post.jwt`), so there is always a key and a thumbprint of it. A missing one would mean an unencrypted
/// response, which this flow does not allow.
pub fn session_transcript_redirect(
    client_id: &str,
    nonce: &str,
    response_uri: &str,
    thumbprint: &[u8],
) -> Result<Vec<u8>> {
    if client_id.is_empty() {
        return Err(policy(
            "the challenge needs the request's client_id, which binds the proof to the verifier that asked",
        ));
    }
    check_nonce(nonce)?;
    if response_uri.is_empty() {
        return Err(policy(
            "the challenge needs the response_uri, which binds the proof to where this verifier is listening",
        ));
    }
    if thumbprint.len() != THUMBPRINT_BYTES {
        return Err(Error::Policy(format!(
            "the reader key thumbprint is {} bytes; a redirect presentation is always encrypted, so it is a \
             {THUMBPRINT_BYTES}-byte SHA-256 thumbprint",
            thumbprint.len()
        )));
    }
    let info = Value::Array(vec![
        Value::Text(client_id.to_owned()),
        Value::Text(nonce.to_owned()),
        Value::Bytes(thumbprint.to_vec()),
        Value::Text(response_uri.to_owned()),
    ]);
    Ok(transcript("OpenID4VPHandover", &info))
}

/// The handover info of the redirect transcript (what is hashed), for diagnostics and the vectors.
pub fn handover_info_redirect(
    client_id: &str,
    nonce: &str,
    response_uri: &str,
    thumbprint: &[u8],
) -> Vec<u8> {
    enc(&Value::Array(vec![
        Value::Text(client_id.to_owned()),
        Value::Text(nonce.to_owned()),
        Value::Bytes(thumbprint.to_vec()),
        Value::Text(response_uri.to_owned()),
    ]))
}

/// Refuse a transcript that is not exactly one well-formed three-item CBOR array.
///
/// Each failure here would otherwise hash cleanly into a challenge no prover reproduces, and the mismatch would be
/// reported as a bad proof: empty input, a different item, trailing bytes, truncation, invalid UTF-8 in a text
/// string, and non-canonical simple values.
fn check_session_transcript(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        return Err(policy("the challenge needs a session transcript"));
    }
    let mut cur = bytes;
    let v: Value = ciborium::from_reader(&mut cur).map_err(|e| {
        Error::Malformed(format!(
            "the session transcript is not well-formed CBOR: {e}"
        ))
    })?;
    if !cur.is_empty() {
        return Err(Error::Malformed(
            "the session transcript has bytes after its single CBOR item".into(),
        ));
    }
    match v {
        Value::Array(a) if a.len() == SESSION_TRANSCRIPT_ITEMS => Ok(()),
        Value::Array(a) => Err(Error::Malformed(format!(
            "the session transcript has {} items; ISO 18013-5 fixes it at {SESSION_TRANSCRIPT_ITEMS}",
            a.len()
        ))),
        _ => Err(Error::Malformed(
            "the session transcript is not a CBOR array".into(),
        )),
    }
}

/// The message an mdoc device signature is computed over, for a SessionTranscript the caller holds:
/// `cbor(["Signature1", h'A10126', h'', DeviceAuthenticationBytes])`.
pub fn challenge(session_transcript: &[u8], doc_type: &str) -> Result<Vec<u8>> {
    check_session_transcript(session_transcript)?;
    if doc_type.is_empty() {
        return Err(policy(
            "the challenge needs the docType, which binds the proof to this credential type",
        ));
    }
    // DeviceAuthenticationBytes = #6.24(bstr(cbor(["DeviceAuthentication", SessionTranscript, docType, #6.24(bstr(h'A0'))])))
    // The transcript is spliced in as raw bytes so it is not re-encoded.
    let mut inner = vec![0x84];
    inner.extend(enc(&Value::Text("DeviceAuthentication".into())));
    inner.extend_from_slice(session_transcript);
    inner.extend(enc(&Value::Text(doc_type.to_owned())));
    inner.extend(enc(&Value::Tag(24, Box::new(Value::Bytes(vec![0xa0])))));
    let device_auth_bytes = enc(&Value::Tag(24, Box::new(Value::Bytes(inner))));
    Ok(enc(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(vec![0xa1, 0x01, 0x26]),
        Value::Bytes(vec![]),
        Value::Bytes(device_auth_bytes),
    ])))
}

/// SHA-256 of [`challenge`]: the circuits' `e2`.
pub fn challenge_digest(session_transcript: &[u8], doc_type: &str) -> Result<[u8; 32]> {
    Ok(Sha256::digest(challenge(session_transcript, doc_type)?).into())
}
