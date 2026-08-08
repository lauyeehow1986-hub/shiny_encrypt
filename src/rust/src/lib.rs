//! shinyEncrypt native backend (scaffold — Phase 4+).
//!
//! When built via rextendr, this exposes real Argon2id, hybrid HPKE (X25519 +
//! ML-KEM-768), ML-DSA/SLH-DSA/FN-DSA signatures, CP-ABE, FF1, PRE, Shamir,
//! time-lock, and (size-guarded) TFHE / ZK to R. Until then it is intentionally
//! empty so the pure-R Core AEAD path carries the app.
//!
//! Example (Phase 4) signature to be filled in:
//! ```ignore
//! use extendr_api::prelude::*;
//! #[extendr]
//! fn native_argon2id(secret: &[u8], salt: &[u8], size: i32) -> Vec<u8> { /* ... */ }
//! extendr_module! { mod shinyencrypt_native; fn native_argon2id; }
//! ```
