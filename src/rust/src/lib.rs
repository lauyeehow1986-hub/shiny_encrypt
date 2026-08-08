//! shinyEncrypt native backend.
//!
//! Real, first-class crypto primitives exposed to R via extendr. Built as a
//! staticlib and linked into `shinyencrypt_native.dll` by `tools/build_native.R`;
//! `R/backend.R` dyn.loads it and advertises the capabilities it provides. When
//! the lib is absent the app runs entirely on the pure-R Core AEAD path.
//!
//! Every function returns `Result<_, String>` so failures surface as clean R
//! errors (extendr converts `Err(String)` into an R condition) instead of aborting.

use extendr_api::prelude::*;
use argon2::{Algorithm, Argon2, Params, Version};

/// Argon2id raw key derivation (OWASP-tunable). Returns `size` raw bytes.
///
/// * `secret`   password / passphrase bytes
/// * `salt`     >= 8 bytes (caller supplies a random salt, recorded in the envelope)
/// * `mem_kib`  memory cost in KiB (e.g. 19456 = 19 MiB, OWASP 2024 baseline)
/// * `iters`    time cost / passes (e.g. 2)
/// * `lanes`    parallelism (e.g. 1)
/// * `size`     output length in bytes (e.g. 32)
///
/// This is the real Argon2id this machine's libsodium cannot provide.
#[extendr]
fn native_argon2id(
    secret: &[u8],
    salt: &[u8],
    mem_kib: i32,
    iters: i32,
    lanes: i32,
    size: i32,
) -> std::result::Result<Vec<u8>, String> {
    if salt.len() < 8 {
        return Err(format!("argon2id: salt must be >= 8 bytes (got {})", salt.len()));
    }
    if size < 4 || size > 1024 {
        return Err(format!("argon2id: size must be in 4..=1024 (got {size})"));
    }
    let params = Params::new(mem_kib as u32, iters as u32, lanes as u32, Some(size as usize))
        .map_err(|e| format!("argon2id: bad params: {e}"))?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; size as usize];
    a.hash_password_into(secret, salt, &mut out)
        .map_err(|e| format!("argon2id: {e}"))?;
    Ok(out)
}

/// Report the crate version so R can confirm which native build is loaded.
#[extendr]
fn native_backend_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

extendr_module! {
    mod shinyencrypt_native;
    fn native_argon2id;
    fn native_backend_version;
}
