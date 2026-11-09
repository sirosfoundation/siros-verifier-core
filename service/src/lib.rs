//! The SIROS verifier gateway as a library: deployment configuration, the
//! inbound and outbound HTTP adapters, and the MongoDB flow store, assembled
//! into a binary by `main.rs`.
//!
//! The library is the importable surface — integration tests and any other
//! embedding use it; the binary is a thin assembly (config load, tracing,
//! backend assembly, server startup) over these modules.

pub mod config;
pub mod http;
pub mod mongo_store;
