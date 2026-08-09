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
use sha2::{Digest, Sha512};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use rand_core::{OsRng, RngCore};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

use sharks::{Share, Sharks};

use aes::Aes256;
use fpe::ff1::{FlexibleNumeralString, FF1};

use num_bigint_dig::{BigUint, RandPrime};

use rabe::schemes::bsw;
use rabe::utils::policy::pest::PolicyLanguage;

use ibe::kem::kiltz_vahlis_one::{
    CipherText as IbeCipherText, PublicKey as IbePublicKey, SecretKey as IbeSecretKey,
    UserSecretKey as IbeUserSecretKey, CT_BYTES as IBE_CT, PK_BYTES as IBE_PK, SK_BYTES as IBE_SK,
    USK_BYTES as IBE_USK, KV1,
};
use ibe::kem::IBKEM;
use ibe::{Compress, Derive};

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
// Format-preserving encryption (FF1, NIST SP 800-38G) over an arbitrary radix.
//
// A thin, fixed-layout primitive over a sequence of numerals (one per byte, each
// < radix). R owns the character<->numeral mapping, the passthrough of
// non-alphabet characters, and the per-value domain rule, so all of that stays
// testable in pure R. AES-256 (32-byte key). Deterministic per (key, tweak,
// input): equal inputs map to equal outputs, preserving referential integrity.
// ============================================================================

fn ff1_apply(
    key: &[u8],
    tweak: &[u8],
    radix: i32,
    numerals: &[u8],
    encrypt: bool,
) -> std::result::Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!("ff1: key must be 32 bytes for AES-256 (got {})", key.len()));
    }
    if !(2..=256).contains(&radix) {
        return Err(format!("ff1: radix must be in 2..=256 (got {radix})"));
    }
    let radix = radix as u32;
    let n = numerals.len();
    if n < 2 {
        return Err("ff1: need at least 2 numerals".to_string());
    }
    for &d in numerals {
        if (d as u32) >= radix {
            return Err(format!("ff1: numeral {d} out of range for radix {radix}"));
        }
    }
    // FF1 domain rule (SP 800-38G): radix^len must be >= 1_000_000.
    if (radix as f64).powi(n as i32) < 1_000_000.0 {
        return Err(format!(
            "ff1: domain too small (radix^len < 1e6 for radix={radix}, len={n})"
        ));
    }
    let ff1 = FF1::<Aes256>::new(key, radix).map_err(|e| format!("ff1: bad key/radix: {e:?}"))?;
    let ns = FlexibleNumeralString::from(numerals.iter().map(|&b| b as u16).collect::<Vec<u16>>());
    let out = if encrypt {
        ff1.encrypt(tweak, &ns)
    } else {
        ff1.decrypt(tweak, &ns)
    }
    .map_err(|e| format!("ff1: {e:?}"))?;
    let out_v: Vec<u16> = out.into();
    Ok(out_v.into_iter().map(|x| x as u8).collect())
}

/// FF1-encrypt a sequence of numerals (one per byte, each < radix). 32-byte key.
#[extendr]
fn native_ff1_encrypt(
    key: &[u8],
    tweak: &[u8],
    radix: i32,
    numerals: &[u8],
) -> std::result::Result<Vec<u8>, String> {
    ff1_apply(key, tweak, radix, numerals, true)
}

/// FF1-decrypt a sequence of numerals (one per byte, each < radix). 32-byte key.
#[extendr]
fn native_ff1_decrypt(
    key: &[u8],
    tweak: &[u8],
    radix: i32,
    numerals: &[u8],
) -> std::result::Result<Vec<u8>, String> {
    ff1_apply(key, tweak, radix, numerals, false)
}

// ============================================================================
// Time-lock encryption (RSW sequential-squaring puzzle, Rivest-Shamir-Wagner).
//
// Seal (trapdoor fast-path): pick an RSA modulus N = p*q, base a = 2, and a
// squaring count T. Knowing phi(N), the solution b = a^(2^T) mod N is computed
// instantly via e = 2^T mod phi(N), b = a^e mod N. The caller derives a mask
// from b, XOR-wraps the data key, then DISCARDS p, q, phi (and b too, unless it
// keeps a creator master) — so no shortcut survives.
//
// Solve (no trapdoor): recompute b by T sequential modular squarings. Each
// squaring depends on the last, so the work cannot be parallelised; wall-clock
// is bounded by the solver's single-core speed. Security rests on factoring N
// being hard AND on there being no squaring shortcut without phi(N).
//
// FFI: N and b cross as fixed |N| = bits/8 big-endian byte blobs. The solve is
// exposed in chunks so R can drive a progress bar over a deliberately-slow run.
// ============================================================================

fn tl_pad_be(v: Vec<u8>, len: usize) -> Vec<u8> {
    if v.len() >= len {
        return v;
    }
    let mut out = vec![0u8; len - v.len()];
    out.extend_from_slice(&v);
    out
}

/// Generate a time-lock puzzle for `t` squarings at an `bits`-bit modulus.
/// Returns N || b, each bits/8 bytes (big-endian). `b` is the trapdoor-computed
/// solution; discard it unless keeping a creator master key.
#[extendr]
fn native_timelock_generate(bits: i32, t: f64) -> std::result::Result<Vec<u8>, String> {
    if !(1024..=4096).contains(&bits) || bits % 8 != 0 {
        return Err(format!(
            "timelock: bits must be in 1024..=4096 and a multiple of 8 (got {bits})"
        ));
    }
    if !t.is_finite() || t < 1.0 || t > 9.0e15 {
        return Err(format!(
            "timelock: t (squarings) must be a positive integer below 9e15 (got {t})"
        ));
    }
    let bits = bits as usize;
    let t_u = t as u64;
    let mut rng = rand::thread_rng();
    let half = bits / 2;
    let p = rng.gen_prime(half);
    let mut q = rng.gen_prime(half);
    while q == p {
        q = rng.gen_prime(half);
    }
    let n = &p * &q;
    let one = BigUint::from(1u32);
    let phi = (&p - &one) * (&q - &one);
    let two = BigUint::from(2u32);
    // e = 2^T mod phi(N); then b = 2^e mod N == 2^(2^T) mod N (trapdoor path).
    let e = two.modpow(&BigUint::from(t_u), &phi);
    let b = two.modpow(&e, &n);
    let l = bits / 8;
    let mut out = tl_pad_be(n.to_bytes_be(), l);
    out.extend_from_slice(&tl_pad_be(b.to_bytes_be(), l));
    Ok(out)
}

/// One chunk of the sequential solve: returns x^(2^steps) mod N as |N| bytes.
/// R starts from x = 2 and loops this until `steps` sum to T, carrying x across.
#[extendr]
fn native_timelock_solve_steps(x: &[u8], n: &[u8], steps: i32) -> std::result::Result<Vec<u8>, String> {
    if steps < 1 {
        return Err(format!("timelock: steps must be >= 1 (got {steps})"));
    }
    if n.is_empty() {
        return Err("timelock: empty modulus".to_string());
    }
    let modulus = BigUint::from_bytes_be(n);
    if modulus < BigUint::from(2u32) {
        return Err("timelock: modulus too small".to_string());
    }
    let mut cur = BigUint::from_bytes_be(x) % &modulus;
    for _ in 0..steps {
        cur = (&cur * &cur) % &modulus;
    }
    Ok(tl_pad_be(cur.to_bytes_be(), n.len()))
}

/// Estimate this machine's sequential-squaring rate (squarings/second) at the
/// given modulus size, so R can translate a target delay into a count T.
#[extendr]
fn native_timelock_calibrate(bits: i32, millis: i32) -> std::result::Result<f64, String> {
    if !(512..=8192).contains(&bits) {
        return Err(format!("timelock: calibrate bits out of range (got {bits})"));
    }
    let millis = millis.clamp(20, 5000) as u128;
    let bits = bits as usize;
    let mut rng = rand::thread_rng();
    let half = bits / 2;
    let n = &rng.gen_prime(half) * &rng.gen_prime(half);
    let mut cur = BigUint::from(2u32);
    let batch = 256u64;
    let mut count: u64 = 0;
    let start = std::time::Instant::now();
    loop {
        for _ in 0..batch {
            cur = (&cur * &cur) % &n;
        }
        count += batch;
        if start.elapsed().as_millis() >= millis {
            break;
        }
    }
    let secs = start.elapsed().as_secs_f64().max(1e-6);
    Ok(count as f64 / secs)
}

// ============================================================================
// Attribute-Based Encryption (CP-ABE, BSW ciphertext-policy scheme).
//
// A dataset key is sealed under a boolean POLICY over attributes (e.g.
// `"cardiology" and ("senior" or "admin")`). An authority holds (PK, MK); it
// issues per-recipient ATTRIBUTE keys from MK. A ciphertext opens only for a key
// whose attribute set satisfies the policy — role-based access without a
// per-recipient key exchange. Decryption of a non-satisfying key errors (fails
// closed), and the sealed bytes are additionally AEAD-protected inside rabe.
//
// FFI: keys and ciphertexts cross as serde_json byte blobs (opaque to R). setup
// returns [u32_be pk_len] || pk_json || mk_json so R can split the public part
// (shareable) from the master (secret).
// ============================================================================

fn cpabe_prefix(pk: &[u8], mk: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + pk.len() + mk.len());
    out.extend_from_slice(&(pk.len() as u32).to_be_bytes());
    out.extend_from_slice(pk);
    out.extend_from_slice(mk);
    out
}

/// CP-ABE (BSW) authority setup. Returns [u32_be pk_len] || pk_json || mk_json:
/// the public key (encrypts under a policy) and the master key (issues attribute
/// keys — SECRET). R splits on pk_len.
#[extendr]
fn native_cpabe_setup() -> std::result::Result<Vec<u8>, String> {
    let (pk, mk) = bsw::setup();
    let pk_b = serde_json::to_vec(&pk).map_err(|e| format!("cpabe: serialize pk: {e}"))?;
    let mk_b = serde_json::to_vec(&mk).map_err(|e| format!("cpabe: serialize mk: {e}"))?;
    Ok(cpabe_prefix(&pk_b, &mk_b))
}

/// Issue an attribute secret key for `attrs` from the authority (pk_json, mk_json).
/// Returns the key as a serde_json blob (SECRET — give it to one recipient).
#[extendr]
fn native_cpabe_keygen(
    pk: &[u8],
    mk: &[u8],
    attrs: Vec<String>,
) -> std::result::Result<Vec<u8>, String> {
    if attrs.is_empty() {
        return Err("cpabe: attribute set must be non-empty".to_string());
    }
    let pk: bsw::CpAbePublicKey =
        serde_json::from_slice(pk).map_err(|e| format!("cpabe: parse public key: {e}"))?;
    let mk: bsw::CpAbeMasterKey =
        serde_json::from_slice(mk).map_err(|e| format!("cpabe: parse master key: {e}"))?;
    let refs: Vec<&str> = attrs.iter().map(|s| s.as_str()).collect();
    let sk = bsw::keygen(&pk, &mk, &refs)
        .ok_or_else(|| "cpabe: keygen failed (empty/invalid attribute set)".to_string())?;
    serde_json::to_vec(&sk).map_err(|e| format!("cpabe: serialize attribute key: {e}"))
}

/// Seal `plaintext` (a data key) under a boolean `policy` in human syntax
/// (e.g. `"a" and ("b" or "c")`). Returns the ciphertext as a serde_json blob.
#[extendr]
fn native_cpabe_encrypt(
    pk: &[u8],
    policy: &str,
    plaintext: &[u8],
) -> std::result::Result<Vec<u8>, String> {
    let pk: bsw::CpAbePublicKey =
        serde_json::from_slice(pk).map_err(|e| format!("cpabe: parse public key: {e}"))?;
    let ct = bsw::encrypt(&pk, policy, PolicyLanguage::HumanPolicy, plaintext)
        .map_err(|e| format!("cpabe: encrypt failed (check policy syntax): {e:?}"))?;
    serde_json::to_vec(&ct).map_err(|e| format!("cpabe: serialize ciphertext: {e}"))
}

/// Recover the sealed bytes if the attribute key `sk` satisfies the ciphertext's
/// policy; errors (fails closed) otherwise. `sk` and `ct` are serde_json blobs.
#[extendr]
fn native_cpabe_decrypt(sk: &[u8], ct: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let sk: bsw::CpAbeSecretKey =
        serde_json::from_slice(sk).map_err(|e| format!("cpabe: parse attribute key: {e}"))?;
    let ct: bsw::CpAbeCiphertext =
        serde_json::from_slice(ct).map_err(|e| format!("cpabe: parse ciphertext: {e}"))?;
    bsw::decrypt(&sk, &ct)
        .map_err(|e| format!("cpabe: attributes do not satisfy the policy: {e:?}"))
}

// ============================================================================
// Identity-Based Encryption (Kiltz-Vahlis IBE1, IND-CCA2 IBKEM).
//
// A dataset key is sealed straight to an IDENTITY STRING (an email, a role name,
// a study id) with no certificate and no prior key exchange: anyone holding the
// authority public key can encapsulate to `alice@hospital`. A trusted authority
// (the Private Key Generator) holds (PK, master SK) and EXTRACTS a per-identity
// user key from it; only that key decapsulates. As with CP-ABE the master is an
// escrow root — it can mint any identity's key — and there is no revocation:
// rotate the authority to cut identities off.
//
// FFI: keys and ciphertext cross as the crate's fixed-size compressed byte arrays
// (opaque to R). setup returns [u32_be pk_len] || pk || msk so R splits the public
// key (shareable) from the master (secret). encaps returns
// [u32_be ct_len] || ct || shared_key(32): R stores ct in the envelope and uses
// the 32-byte shared secret as the AEAD data key. decaps recovers that same key.
// ============================================================================

type IbeId = <KV1 as IBKEM>::Id;

fn ibe_id(identity: &str) -> std::result::Result<IbeId, String> {
    let id = identity.trim();
    if id.is_empty() {
        return Err("ibe: identity must be a non-empty string".to_string());
    }
    Ok(<IbeId as Derive>::derive_str(id))
}

fn ibe_pk_from(b: &[u8]) -> std::result::Result<IbePublicKey, String> {
    let arr: [u8; IBE_PK] = b
        .try_into()
        .map_err(|_| format!("ibe: public key must be {IBE_PK} bytes"))?;
    IbePublicKey::from_bytes(&arr)
        .into_option()
        .ok_or_else(|| "ibe: invalid public key bytes".to_string())
}

fn ibe_sk_from(b: &[u8]) -> std::result::Result<IbeSecretKey, String> {
    let arr: [u8; IBE_SK] = b
        .try_into()
        .map_err(|_| format!("ibe: master key must be {IBE_SK} bytes"))?;
    IbeSecretKey::from_bytes(&arr)
        .into_option()
        .ok_or_else(|| "ibe: invalid master key bytes".to_string())
}

fn ibe_usk_from(b: &[u8]) -> std::result::Result<IbeUserSecretKey, String> {
    let arr: [u8; IBE_USK] = b
        .try_into()
        .map_err(|_| format!("ibe: user key must be {IBE_USK} bytes"))?;
    IbeUserSecretKey::from_bytes(&arr)
        .into_option()
        .ok_or_else(|| "ibe: invalid user key bytes".to_string())
}

fn ibe_ct_from(b: &[u8]) -> std::result::Result<IbeCipherText, String> {
    let arr: [u8; IBE_CT] = b
        .try_into()
        .map_err(|_| format!("ibe: ciphertext must be {IBE_CT} bytes"))?;
    IbeCipherText::from_bytes(&arr)
        .into_option()
        .ok_or_else(|| "ibe: invalid ciphertext bytes".to_string())
}

/// IBE (Kiltz-Vahlis) authority setup. Returns [u32_be pk_len] || pk || msk: the
/// public key (encrypts to any identity) and the master key (extracts identity
/// keys — SECRET). R splits on pk_len.
#[extendr]
fn native_ibe_setup() -> std::result::Result<Vec<u8>, String> {
    let mut rng = OsRng;
    let (pk, sk) = KV1::setup(&mut rng);
    let pk_b = pk.to_bytes();
    let sk_b = sk.to_bytes();
    let pk_s: &[u8] = pk_b.as_ref();
    let sk_s: &[u8] = sk_b.as_ref();
    let mut out = Vec::with_capacity(4 + pk_s.len() + sk_s.len());
    out.extend_from_slice(&(pk_s.len() as u32).to_be_bytes());
    out.extend_from_slice(pk_s);
    out.extend_from_slice(sk_s);
    Ok(out)
}

/// Extract the user secret key for `identity` from the authority (pk, msk).
/// Returns the fixed-size key bytes (SECRET — give it to that one identity holder).
#[extendr]
fn native_ibe_extract(pk: &[u8], sk: &[u8], identity: &str) -> std::result::Result<Vec<u8>, String> {
    let id = ibe_id(identity)?;
    let pk = ibe_pk_from(pk)?;
    let sk = ibe_sk_from(sk)?;
    let mut rng = OsRng;
    let usk = KV1::extract_usk(Some(&pk), &sk, &id, &mut rng);
    let usk_b = usk.to_bytes();
    let usk_s: &[u8] = usk_b.as_ref();
    Ok(usk_s.to_vec())
}

/// Seal to `identity`: encapsulate a fresh 32-byte data key to the identity under
/// the authority public key. Returns [u32_be ct_len] || ct || shared_key(32); R
/// stores ct in the envelope and uses the 32-byte key as the AEAD data key.
#[extendr]
fn native_ibe_encaps(pk: &[u8], identity: &str) -> std::result::Result<Vec<u8>, String> {
    let id = ibe_id(identity)?;
    let pk = ibe_pk_from(pk)?;
    let mut rng = OsRng;
    let (ct, ss) = KV1::encaps(&pk, &id, &mut rng);
    let ct_b = ct.to_bytes();
    let ct_s: &[u8] = ct_b.as_ref();
    let mut out = Vec::with_capacity(4 + ct_s.len() + SS);
    out.extend_from_slice(&(ct_s.len() as u32).to_be_bytes());
    out.extend_from_slice(ct_s);
    out.extend_from_slice(&ss.0);
    Ok(out)
}

/// Recover the 32-byte data key: decapsulate `ct` with the identity's user key.
/// Fails closed (errors) if the key was issued for a different identity.
#[extendr]
fn native_ibe_decaps(usk: &[u8], ct: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let usk = ibe_usk_from(usk)?;
    let ct = ibe_ct_from(ct)?;
    let ss = KV1::decaps(None, &usk, &ct)
        .map_err(|e| format!("ibe: decapsulation failed (wrong identity key?): {e:?}"))?;
    Ok(ss.0.to_vec())
}

// ---- OPRF (verifiable oblivious PRF, ristretto255 + SHA-512) ---------------
// A VOPRF lets a client compute F_k(input) with the key holder's key k WITHOUT
// revealing `input` to the key holder, and WITHOUT learning k — the output is a
// pseudorandom function of (input, k) that neither party could compute alone.
// This is the ristretto255 group; the DLEQ proof makes it *verifiable* (the
// client checks the key holder used the committed key). Not wire-compatible with
// other RFC 9497 suites (self-consistent DSTs), which is fine for single-machine
// use: the app plays both client and server, and decrypt reproduces the key
// because the random blind cancels out.

const OPRF_DST_GROUP: &[u8] = b"shinyEncrypt-OPRF-ristretto255-v1-HashToGroup";
const OPRF_DST_SCALAR: &[u8] = b"shinyEncrypt-OPRF-ristretto255-v1-Challenge";
const OPRF_DST_FINAL: &[u8] = b"shinyEncrypt-OPRF-ristretto255-v1-Finalize";

fn oprf_rand_scalar() -> Scalar {
    let mut b = [0u8; 64];
    OsRng.fill_bytes(&mut b);
    Scalar::from_bytes_mod_order_wide(&b)
}

// Map an arbitrary input to a group element (random oracle): 64 uniform SHA-512
// bytes through ristretto's one-way map.
fn oprf_hash_to_group(input: &[u8]) -> RistrettoPoint {
    let mut h = Sha512::new();
    h.update(OPRF_DST_GROUP);
    h.update((input.len() as u64).to_be_bytes());
    h.update(input);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(h.finalize().as_slice());
    RistrettoPoint::from_uniform_bytes(&wide)
}

fn oprf_hash_to_scalar(parts: &[&[u8]]) -> Scalar {
    let mut h = Sha512::new();
    h.update(OPRF_DST_SCALAR);
    for p in parts {
        h.update(p);
    }
    let mut wide = [0u8; 64];
    wide.copy_from_slice(h.finalize().as_slice());
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn oprf_scalar_from(bytes: &[u8], what: &str) -> std::result::Result<Scalar, String> {
    if bytes.len() != 32 {
        return Err(format!("oprf: {what} must be 32 bytes"));
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(bytes);
    Ok(Scalar::from_bytes_mod_order(b))
}

fn oprf_key_scalar(key: &[u8]) -> std::result::Result<Scalar, String> {
    let k = oprf_scalar_from(key, "key")?;
    if k == Scalar::ZERO {
        return Err("oprf: invalid (zero) key".into());
    }
    Ok(k)
}

fn oprf_point_from(bytes: &[u8], what: &str) -> std::result::Result<RistrettoPoint, String> {
    if bytes.len() != 32 {
        return Err(format!("oprf: {what} must be 32 bytes"));
    }
    CompressedRistretto::from_slice(bytes)
        .map_err(|_| format!("oprf: {what} is not a valid point encoding"))?
        .decompress()
        .ok_or_else(|| format!("oprf: {what} is not a valid ristretto point"))
}

/// Generate a 32-byte OPRF secret key (a ristretto255 scalar).
#[extendr]
fn native_oprf_keygen() -> Vec<u8> {
    oprf_rand_scalar().to_bytes().to_vec()
}

/// Public (verification) key for a VOPRF secret key: k*G, 32 compressed bytes.
/// Shareable — lets the client verify the DLEQ proof without learning k.
#[extendr]
fn native_oprf_public_key(key: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let k = oprf_key_scalar(key)?;
    Ok((RISTRETTO_BASEPOINT_POINT * k).compress().to_bytes().to_vec())
}

/// Client blind: returns blind_scalar(32) || blinded_element(32). The blinded
/// element hides `input` from the OPRF key holder (it is input*r on the curve).
#[extendr]
fn native_oprf_blind(input: &[u8]) -> Vec<u8> {
    let r = oprf_rand_scalar();
    let b = r * oprf_hash_to_group(input);
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&r.to_bytes());
    out.extend_from_slice(&b.compress().to_bytes());
    out
}

/// Server evaluate: E = k*B, plus a Chaum-Pedersen DLEQ proof that the same k
/// underlies the public key k*G. Returns evaluated(32) || dleq_c(32) || dleq_z(32).
/// The key holder sees only the blinded element, never the client's input.
#[extendr]
fn native_oprf_evaluate(key: &[u8], blinded: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let k = oprf_key_scalar(key)?;
    let b = oprf_point_from(blinded, "blinded element")?;
    let e = k * b;
    let pk = RISTRETTO_BASEPOINT_POINT * k;
    // DLEQ: prove log_G(pk) == log_B(e) == k without revealing k.
    let t = oprf_rand_scalar();
    let k1 = RISTRETTO_BASEPOINT_POINT * t;
    let k2 = b * t;
    let c = oprf_hash_to_scalar(&[
        &pk.compress().to_bytes(),
        &b.compress().to_bytes(),
        &e.compress().to_bytes(),
        &k1.compress().to_bytes(),
        &k2.compress().to_bytes(),
    ]);
    let z = t + c * k;
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(&e.compress().to_bytes());
    out.extend_from_slice(&c.to_bytes());
    out.extend_from_slice(&z.to_bytes());
    Ok(out)
}

/// Client finalize: verify the DLEQ proof (fails closed), unblind, and hash to a
/// 64-byte PRF output. `blind_bundle` = blind(32)||blinded(32) from oprf_blind;
/// `evaluated` = evaluated(32)||c(32)||z(32) from oprf_evaluate; `pubkey` = 32.
/// The output depends only on (input, k), so re-running with a fresh blind gives
/// the same value — that is what makes it usable as a key-derivation function.
#[extendr]
fn native_oprf_finalize(
    input: &[u8],
    blind_bundle: &[u8],
    evaluated: &[u8],
    pubkey: &[u8],
) -> std::result::Result<Vec<u8>, String> {
    if blind_bundle.len() != 64 {
        return Err("oprf: blind bundle must be 64 bytes".into());
    }
    if evaluated.len() != 96 {
        return Err("oprf: evaluated bundle must be 96 bytes".into());
    }
    let r = oprf_scalar_from(&blind_bundle[0..32], "blind scalar")?;
    let b = oprf_point_from(&blind_bundle[32..64], "blinded element")?;
    let e = oprf_point_from(&evaluated[0..32], "evaluated element")?;
    let c = oprf_scalar_from(&evaluated[32..64], "dleq c")?;
    let z = oprf_scalar_from(&evaluated[64..96], "dleq z")?;
    let pk = oprf_point_from(pubkey, "public key")?;
    // Recompute the proof commitments from (c, z) and reject if the challenge
    // disagrees: guarantees the response used the key behind `pubkey`.
    let k1 = RISTRETTO_BASEPOINT_POINT * z - pk * c;
    let k2 = b * z - e * c;
    let c_check = oprf_hash_to_scalar(&[
        &pk.compress().to_bytes(),
        &b.compress().to_bytes(),
        &e.compress().to_bytes(),
        &k1.compress().to_bytes(),
        &k2.compress().to_bytes(),
    ]);
    if c_check != c {
        return Err(
            "oprf: DLEQ verification failed (wrong OPRF key or tampered response)".into(),
        );
    }
    // Unblind: r^-1 * (k*r*P) = k*P, then hash to the final output.
    let n = r.invert() * e;
    let mut h = Sha512::new();
    h.update(OPRF_DST_FINAL);
    h.update((input.len() as u64).to_be_bytes());
    h.update(input);
    h.update(n.compress().to_bytes());
    Ok(h.finalize().to_vec())
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
    fn native_ff1_encrypt;
    fn native_ff1_decrypt;
    fn native_timelock_generate;
    fn native_timelock_solve_steps;
    fn native_timelock_calibrate;
    fn native_cpabe_setup;
    fn native_cpabe_keygen;
    fn native_cpabe_encrypt;
    fn native_cpabe_decrypt;
    fn native_ibe_setup;
    fn native_ibe_extract;
    fn native_ibe_encaps;
    fn native_ibe_decaps;
    fn native_oprf_keygen;
    fn native_oprf_public_key;
    fn native_oprf_blind;
    fn native_oprf_evaluate;
    fn native_oprf_finalize;
    fn native_backend_version;
}
