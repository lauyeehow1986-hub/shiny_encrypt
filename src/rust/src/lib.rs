//! shinyEncrypt native backend.
//!
//! Real, first-class crypto primitives exposed to R via extendr. Built as a
//! staticlib and linked into `shinyencrypt_native.dll` by `tools/build_native.R`;
//! `R/backend.R` dyn.loads it and advertises the capabilities it provides. When
//! the lib is absent the app runs entirely on the pure-R Core AEAD path.
//!
//! Every function returns `Result<_, String>` (or a plain value) so failures
//! surface as clean R errors instead of aborting the R process.
//!
//! FFI convention: byte blobs cross as R `raw` (<-> Rust `&[u8]` / `Vec<u8>`) with
//! fixed, documented layouts so R can split them without any struct marshalling.

use extendr_api::prelude::*;

use argon2::{Algorithm, Argon2, Params, Version};

use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen as KemKeyGen, SerDes as KemSerDes};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes as SigSerDes, Signer, Verifier};

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use rand_core::OsRng;

use sharks::{Share, Sharks};

// ---- fixed lengths (bytes) --------------------------------------------------
const X_SK: usize = 32;   // X25519 secret
const X_PK: usize = 32;   // X25519 public
const K_EK: usize = 1184; // ML-KEM-768 encapsulation (public) key
const K_DK: usize = 2400; // ML-KEM-768 decapsulation (secret) key
const K_CT: usize = 1088; // ML-KEM-768 ciphertext
const SS: usize = 32;     // shared secret / derived key
const D_PK: usize = 1952; // ML-DSA-65 public key
const D_SK: usize = 4032; // ML-DSA-65 secret key
const D_SIG: usize = 3309;// ML-DSA-65 signature

fn take<const N: usize>(buf: &[u8], off: usize) -> std::result::Result<[u8; N], String> {
    buf.get(off..off + N)
        .ok_or_else(|| format!("input too short: need {} bytes at offset {}", N, off))?
        .try_into()
        .map_err(|_| "slice/array length mismatch".to_string())
}

// ============================================================================
// Argon2id KDF (also fixes this machine's broken libsodium Argon2).
// ============================================================================

/// Argon2id raw key derivation (OWASP-tunable). Returns `size` raw bytes.
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
    if !(4..=1024).contains(&size) {
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

// ============================================================================
// Hybrid KEM: X25519 + ML-KEM-768 (post-quantum key-wrap).
//
// Secure if EITHER primitive is unbroken. The derived key binds the full
// ephemeral transcript (dh | mlkem_ss | epk | ct) via HKDF-SHA256.
// ============================================================================

fn hybrid_kdf(dh: &[u8], mlkem_ss: &[u8], epk: &[u8], ct: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let mut ikm = Vec::with_capacity(SS + SS + X_PK + K_CT);
    ikm.extend_from_slice(dh);
    ikm.extend_from_slice(mlkem_ss);
    ikm.extend_from_slice(epk);
    ikm.extend_from_slice(ct);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = vec![0u8; SS];
    hk.expand(b"shinyEncrypt-hybrid-kem-v1", &mut okm)
        .map_err(|_| "hkdf expand failed".to_string())?;
    Ok(okm)
}

/// Generate a recipient hybrid keypair.
/// Returns: sk_x(32) || dk_m(2400) || pk_x(32) || ek_m(1184)  [secret first].
/// R splits secret_bundle = first 2432 bytes, public_bundle = last 1216 bytes.
#[extendr]
fn native_hybrid_keygen() -> std::result::Result<Vec<u8>, String> {
    let x_sk = StaticSecret::random_from_rng(OsRng);
    let x_pk = PublicKey::from(&x_sk);
    let (ek, dk) = ml_kem_768::KG::try_keygen().map_err(|e| format!("ml-kem keygen: {e}"))?;

    let mut out = Vec::with_capacity(X_SK + K_DK + X_PK + K_EK);
    out.extend_from_slice(&x_sk.to_bytes());
    out.extend_from_slice(&dk.into_bytes());
    out.extend_from_slice(&x_pk.to_bytes());
    out.extend_from_slice(&ek.into_bytes());
    Ok(out)
}

/// Encapsulate to a recipient public bundle (pk_x || ek_m, 1216 bytes).
/// Returns: encapsulation(epk(32) || ct(1088) = 1120) || shared_key(32) = 1152.
/// R stores the 1120-byte encapsulation in the envelope and uses the 32-byte key.
#[extendr]
fn native_hybrid_encaps(public_bundle: &[u8]) -> std::result::Result<Vec<u8>, String> {
    if public_bundle.len() != X_PK + K_EK {
        return Err(format!("public bundle must be {} bytes", X_PK + K_EK));
    }
    let pk_x = PublicKey::from(take::<X_PK>(public_bundle, 0)?);
    let ek = ml_kem_768::EncapsKey::try_from_bytes(take::<K_EK>(public_bundle, X_PK)?)
        .map_err(|e| format!("bad ml-kem ek: {e}"))?;

    let e_sk = EphemeralSecret::random_from_rng(OsRng);
    let epk = PublicKey::from(&e_sk);
    let dh = e_sk.diffie_hellman(&pk_x);
    let (ssk, ct) = ek.try_encaps().map_err(|e| format!("ml-kem encaps: {e}"))?;

    let epk_b = epk.to_bytes();
    let ct_b = ct.into_bytes();
    let key = hybrid_kdf(dh.as_bytes(), &ssk.into_bytes(), &epk_b, &ct_b)?;

    let mut out = Vec::with_capacity(X_PK + K_CT + SS);
    out.extend_from_slice(&epk_b);
    out.extend_from_slice(&ct_b);
    out.extend_from_slice(&key);
    Ok(out)
}

/// Decapsulate with the recipient secret bundle (sk_x || dk_m, 2432 bytes) and
/// the 1120-byte encapsulation. Returns the 32-byte shared key.
#[extendr]
fn native_hybrid_decaps(secret_bundle: &[u8], encapsulation: &[u8]) -> std::result::Result<Vec<u8>, String> {
    if secret_bundle.len() != X_SK + K_DK {
        return Err(format!("secret bundle must be {} bytes", X_SK + K_DK));
    }
    if encapsulation.len() != X_PK + K_CT {
        return Err(format!("encapsulation must be {} bytes", X_PK + K_CT));
    }
    let x_sk = StaticSecret::from(take::<X_SK>(secret_bundle, 0)?);
    let dk = ml_kem_768::DecapsKey::try_from_bytes(take::<K_DK>(secret_bundle, X_SK)?)
        .map_err(|e| format!("bad ml-kem dk: {e}"))?;

    let epk = PublicKey::from(take::<X_PK>(encapsulation, 0)?);
    let ct = ml_kem_768::CipherText::try_from_bytes(take::<K_CT>(encapsulation, X_PK)?)
        .map_err(|e| format!("bad ml-kem ct: {e}"))?;

    let dh = x_sk.diffie_hellman(&epk);
    let ssk = dk.try_decaps(&ct).map_err(|e| format!("ml-kem decaps: {e}"))?;
    hybrid_kdf(dh.as_bytes(), &ssk.into_bytes(), epk.as_bytes(), &ct.into_bytes())
}

// ============================================================================
// ML-DSA-65 signatures (FIPS 204) over the envelope.
// ============================================================================

/// Generate an ML-DSA-65 signing keypair. Returns sk(4032) || pk(1952).
#[extendr]
fn native_mldsa_keygen() -> std::result::Result<Vec<u8>, String> {
    let (pk, sk) = ml_dsa_65::try_keygen().map_err(|e| format!("ml-dsa keygen: {e}"))?;
    let mut out = Vec::with_capacity(D_SK + D_PK);
    out.extend_from_slice(&sk.into_bytes());
    out.extend_from_slice(&pk.into_bytes());
    Ok(out)
}

/// Sign `msg` with an ML-DSA-65 secret key (4032 bytes). Returns a 3309-byte signature.
#[extendr]
fn native_mldsa_sign(sk_bytes: &[u8], msg: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let sk = ml_dsa_65::PrivateKey::try_from_bytes(take::<D_SK>(sk_bytes, 0)?)
        .map_err(|e| format!("bad ml-dsa sk: {e}"))?;
    let sig = sk.try_sign(msg, &[]).map_err(|e| format!("ml-dsa sign: {e}"))?;
    Ok(sig.to_vec())
}

/// Verify an ML-DSA-65 signature. Returns 1 if valid, 0 otherwise.
#[extendr]
fn native_mldsa_verify(pk_bytes: &[u8], msg: &[u8], sig: &[u8]) -> std::result::Result<i32, String> {
    let pk = ml_dsa_65::PublicKey::try_from_bytes(take::<D_PK>(pk_bytes, 0)?)
        .map_err(|e| format!("bad ml-dsa pk: {e}"))?;
    let sig_arr: [u8; D_SIG] = sig.try_into().map_err(|_| format!("signature must be {D_SIG} bytes"))?;
    Ok(if pk.verify(msg, &sig_arr, &[]) { 1 } else { 0 })
}

// ============================================================================
// Shamir secret sharing (t-of-n) over GF(256). Splits the data key across
// custodians: any t shares reconstruct it, any t-1 reveal nothing.
// ============================================================================

/// Split `secret` into `n` shares, any `t` of which reconstruct it. Every share
/// serializes to (1 + secret.len()) bytes: [x_index, y_bytes...], and each x is
/// distinct (1..=n), so shares can be recombined in any order. Returns all n
/// shares concatenated; R slices them into equal-length chunks.
#[extendr]
fn native_shamir_split(secret: &[u8], t: i32, n: i32) -> std::result::Result<Vec<u8>, String> {
    if secret.is_empty() {
        return Err("shamir: secret must be non-empty".to_string());
    }
    if !(1..=255).contains(&t) || !(1..=255).contains(&n) || t > n {
        return Err(format!("shamir: need 1 <= t <= n <= 255 (got t={t}, n={n})"));
    }
    let sharks = Sharks(t as u8);
    let dealer = sharks.dealer(secret);
    let share_len = 1 + secret.len();
    let mut out = Vec::with_capacity(n as usize * share_len);
    for s in dealer.take(n as usize) {
        let bytes = Vec::from(&s);
        if bytes.len() != share_len {
            return Err("shamir: unexpected share length".to_string());
        }
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

/// Reconstruct the secret from `shares_concat` (each `share_len` bytes). Shamir
/// interpolation silently yields the wrong secret if fewer than the original
/// threshold are supplied, so the caller must pass at least `t` shares; a wrong
/// key is then caught by the AEAD tag on decrypt. Returns the recovered secret.
#[extendr]
fn native_shamir_combine(shares_concat: &[u8], share_len: i32) -> std::result::Result<Vec<u8>, String> {
    let sl = share_len as usize;
    if sl < 2 || shares_concat.is_empty() || shares_concat.len() % sl != 0 {
        return Err(format!("shamir: shares not a whole multiple of share_len={sl}"));
    }
    let shares: Vec<Share> = shares_concat
        .chunks(sl)
        .map(|c| Share::try_from(c).map_err(|e| format!("shamir: bad share: {e}")))
        .collect::<std::result::Result<_, _>>()?;
    // The real threshold is not encoded in shares; recover interpolates whatever
    // it is given, so set the modulus to the count provided (never over-rejects).
    let sharks = Sharks(shares.len() as u8);
    sharks
        .recover(shares.as_slice())
        .map_err(|e| format!("shamir: recover failed: {e}"))
}

// ============================================================================

/// Report the crate version so R can confirm which native build is loaded.
#[extendr]
fn native_backend_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

extendr_module! {
    mod shinyencrypt_native;
    fn native_argon2id;
    fn native_hybrid_keygen;
    fn native_hybrid_encaps;
    fn native_hybrid_decaps;
    fn native_mldsa_keygen;
    fn native_mldsa_sign;
    fn native_mldsa_verify;
    fn native_shamir_split;
    fn native_shamir_combine;
    fn native_backend_version;
}
