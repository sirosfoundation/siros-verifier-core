//! SD-JWT VC verification and OpenID4VP request/response handling,
//! built on `jose-rs` and `kryptering`.
//!
//! Layering mirrors the design page ("Layered Verifier Core"):
//!
//! - [`sdjwt`]: format layer. Verifies a presentation given an issuer key
//!   resolver; never evaluates trust.
//! - [`oid4vp`]: protocol layer. Builds a signed request object and handles
//!   an encrypted `direct_post.jwt` response.
//! - [`trust`]: the AuthZEN evaluation request the trust layer would send.
//! - `testutil`: issuer and wallet simulators used by tests.
//!
//! Everything is sans-IO: callers pass `now` and key material explicitly.

pub mod error;
pub mod issuer_set;
pub mod json_strict;
pub mod mdoc;
pub mod mdoc_request;
pub mod mdoc_session;
pub mod oid4vp;
pub mod receipt;
pub mod sdjwt;
pub mod session_seal;
pub mod status_list;
#[cfg(feature = "testutil")]
pub mod testutil;
pub mod trust;
pub mod ts11;
pub mod wrprc;

pub use error::{Error, Result};

pub(crate) fn b64u(data: &[u8]) -> String {
    jose_rs::base64url::encode(data)
}

pub(crate) fn b64u_decode(s: &str) -> Result<Vec<u8>> {
    // jose-rs rejects padding and non-alphabet characters.
    Ok(jose_rs::base64url::decode(s)?)
}
