//! Error type with stable machine-readable codes.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The input is not well-formed (syntax, structure, encoding).
    #[error("malformed input: {0}")]
    Malformed(String),
    /// A signature, hash binding or AEAD tag did not verify.
    #[error("integrity check failed: {0}")]
    Integrity(String),
    /// Well-formed and authentic, but rejected by a verification rule.
    #[error("rejected: {0}")]
    Policy(String),
    /// Key or primitive failure.
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error(transparent)]
    Jose(#[from] jose_rs::JoseError),
}

impl Error {
    /// Stable code for APIs, logs and agents. Never changes meaning.
    pub fn code(&self) -> &'static str {
        match self {
            Error::Malformed(_) => "malformed",
            Error::Integrity(_) => "integrity",
            Error::Policy(_) => "policy",
            Error::Crypto(_) => "crypto",
            Error::Jose(_) => "jose",
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn malformed(s: impl Into<String>) -> Error {
    Error::Malformed(s.into())
}
pub(crate) fn integrity(s: impl Into<String>) -> Error {
    Error::Integrity(s.into())
}
pub(crate) fn policy(s: impl Into<String>) -> Error {
    Error::Policy(s.into())
}
