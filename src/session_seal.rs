//! Sealing of OpenID4VP request sessions for storage.
//!
//! A [`Session`] holds the ephemeral private key the wallet's response is encrypted to. Any store that outlives the
//! process (a shared cache, a database) must therefore never see it in the clear. Sessions are sealed with
//! AES-256-GCM under a key derived per tenant from a master secret, and the flow id is bound in as associated data,
//! so a record cannot be moved to another flow or another tenant.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::oid4vp::Session;
use crate::{b64u, b64u_decode, Error, Result};

const VERSION: &str = "v1";
const MIN_MASTER: usize = 32;
const MAX_SEALED: usize = 1024 * 1024;

pub struct SessionSealer {
    key: Zeroizing<[u8; 32]>,
}

impl SessionSealer {
    /// Derive the sealing key for one tenant. The master secret must be at least 32 bytes of high-entropy
    /// material; nothing weaker is accepted, because a guessable master would make the sealing decorative.
    pub fn from_master(master: &[u8], tenant: &str) -> Result<Self> {
        if master.len() < MIN_MASTER {
            return Err(Error::Crypto(
                "session sealing master secret must be at least 32 bytes".into(),
            ));
        }
        let hk = Hkdf::<Sha256>::new(None, master);
        let mut key = Zeroizing::new([0u8; 32]);
        hk.expand(
            format!("siros-verifier session seal v1:{tenant}").as_bytes(),
            &mut *key,
        )
        .map_err(|_| Error::Crypto("hkdf expand".into()))?;
        Ok(Self { key })
    }

    /// Seal `session` for the flow named by `aad` (the flow id).
    pub fn seal(&self, session: &Session, aad: &[u8]) -> Result<String> {
        self.seal_json(session, aad)
    }

    /// Seal a serializable stored value. Callers use distinct associated-data
    /// domains for sessions and verified results.
    pub fn seal_json<T: Serialize>(&self, value: &T, aad: &[u8]) -> Result<String> {
        let plain = Zeroizing::new(
            serde_json::to_vec(value).map_err(|_| Error::Crypto("session encode".into()))?,
        );
        let cipher =
            Aes256Gcm::new_from_slice(&*self.key).map_err(|_| Error::Crypto("key".into()))?;
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).expect("OS randomness");
        let ct = cipher
            .encrypt(&Nonce::from(nonce), Payload { msg: &plain, aad })
            .map_err(|_| Error::Crypto("seal".into()))?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(format!("{VERSION}.{}", b64u(&out)))
    }

    /// Open a sealed session. Fails if the token was altered, sealed under another key, or sealed for another flow.
    pub fn unseal(&self, token: &str, aad: &[u8]) -> Result<Session> {
        self.unseal_json(token, aad)
    }

    /// Open an authenticated stored value with strict duplicate-member JSON checks.
    pub fn unseal_json<T: DeserializeOwned>(&self, token: &str, aad: &[u8]) -> Result<T> {
        if token.len() > MAX_SEALED {
            return Err(Error::Policy("sealed session too large".into()));
        }
        let body = token
            .strip_prefix(VERSION)
            .and_then(|r| r.strip_prefix('.'))
            .ok_or_else(|| Error::Malformed("sealed session version".into()))?;
        let raw = b64u_decode(body)?;
        if raw.len() < 12 + 16 {
            return Err(Error::Malformed("sealed session too short".into()));
        }
        let (nonce, ct) = raw.split_at(12);
        let nonce =
            Nonce::try_from(nonce).map_err(|_| Error::Malformed("sealed session nonce".into()))?;
        let cipher =
            Aes256Gcm::new_from_slice(&*self.key).map_err(|_| Error::Crypto("key".into()))?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(&nonce, Payload { msg: ct, aad })
                .map_err(|_| Error::Integrity("sealed session did not authenticate".into()))?,
        );
        crate::json_strict::from_slice(&plain).and_then(|v| {
            serde_json::from_value(v).map_err(|_| Error::Malformed("sealed session content".into()))
        })
    }
}
