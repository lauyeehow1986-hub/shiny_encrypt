# Full scheme catalogue registration.
#
# The Core AEAD schemes are fully implemented (crypto_aead.R). Every other tier
# is registered here so the UI shows the complete, honest catalogue with correct
# availability. Non-core schemes are gated on the native backend (Phase 4+); a
# [Stub] states the mathematical/ecosystem reason no secure implementation
# exists (a bigger GPU would not change it). Placeholders fail loudly if invoked.

.placeholder <- function(id, needs) {
  function(...) stop(sprintf(
    "Scheme '%s' needs %s, which is not built in this environment. The Core AEAD schemes are available now.",
    id, needs))
}

.register_scheme_placeholder <- function(id, tier, label, needs, note,
                                         available = function() FALSE) {
  register_scheme(id, tier, label,
                  encrypt = .placeholder(id, needs),
                  decrypt = .placeholder(id, needs),
                  available = available, note = note)
}

register_all_schemes <- function() {
  # Activate the native backend if it was built (enables argon2id etc.).
  load_native_backend(quiet = TRUE)

  # Core (real, now)
  .register_core_aead()

  cap <- function(name) function() crypto_backend_available(name)

  # Privacy layer (real, pure-R, available now \u2014 a separate tab, not an envelope scheme)
  .register_scheme_placeholder("dp", "Core",
    "Differential privacy (noisy aggregates)", "the Private stats (DP) tab",
    "Release counts, sums, and means with calibrated Laplace/Gaussian noise and a tracked epsilon budget \u2014 use the 'Private stats (DP)' tab. This protects query *results*, not the file itself: no single row measurably changes the output.",
    function() TRUE)

  # Native (real once the Rust/C++ crate is built)
  .register_scheme_placeholder("hpke-hybrid", "Native",
    "Hybrid HPKE: X25519 + ML-KEM-768 key-wrap", "the native PQC crate",
    "Post-quantum hybrid KEM \u2014 offered as the 'Recipient public key (PQC hybrid)' KEY SOURCE on the Encrypt tab when the native backend is built.",
    cap("hpke-hybrid"))
  .register_scheme_placeholder("ml-dsa", "Native",
    "ML-DSA (Dilithium) signature over the envelope", "the native PQC crate",
    "FIPS 204 signatures \u2014 enable 'Sign this envelope (ML-DSA-65)' on the Encrypt tab; the Decrypt tab verifies and shows the signer fingerprint.",
    cap("ml-dsa"))
  .register_scheme_placeholder("cp-abe", "Native",
    "Attribute-Based Encryption (CP-ABE, BSW)", "the native rabe crate",
    "Policy-based access control \u2014 offered as the 'Attribute policy (CP-ABE)' KEY SOURCE on the Encrypt tab; seal a key under a boolean policy, issue attribute keys from the authority master, and any key whose attributes satisfy the policy decrypts.",
    cap("cp-abe"))
  .register_scheme_placeholder("ibe", "Native",
    "Identity-Based Encryption (Kiltz-Vahlis IBE1)", "the native ibe crate",
    "Encrypt straight to an identity string \u2014 offered as the 'Recipient identity (IBE)' KEY SOURCE on the Encrypt tab; seal a key to an identity under the authority public key, extract that identity's key from the master, and only that key decrypts. No certificate or prior key exchange.",
    cap("ibe"))
  .register_scheme_placeholder("fpe-ff1", "Native",
    "Format-Preserving Encryption (FF1)", "the native fpe crate",
    "Column-level de-identification that keeps each field's length and character class \u2014 use the 'De-identify (FPE)' tab to tokenise ID columns and reverse them with the .fpekit.",
    cap("fpe-ff1"))
  .register_scheme_placeholder("oprf", "Native",
    "Oblivious PRF (verifiable, ristretto255)", "the native curve25519-dalek OPRF",
    "Harden a low-entropy input into a key with a SEPARATELY-held OPRF key \u2014 offered as the 'OPRF-hardened input' KEY SOURCE on the Encrypt tab. The key holder never sees the input, and the derived key needs BOTH the input and the OPRF key, so a weak input resists offline guessing while the OPRF key stays apart. A DLEQ proof makes the evaluation verifiable (fails closed on a wrong key).",
    cap("oprf"))
  .register_scheme_placeholder("pre", "Native",
    "Proxy Re-Encryption (Umbral)", "the optional GPL companion package shinyEncryptPRE",
    "Grant a receiver access to a file without decrypting it: the delegator seals to their own key and an untrusted proxy re-encrypts the ciphertext for the receiver. Ships as a SEPARATE GPL-3 package (umbral-pre is GPL-3.0) so the MIT core stays MIT; install it to get the 'Re-encrypt (PRE)' tab.",
    function() isTRUE(tryCatch(pre_companion_available(), error = function(e) FALSE)))
  .register_scheme_placeholder("tlock", "Native",
    "Time-Lock Encryption (RSW sequential-squaring puzzle)", "the native time-lock crate",
    "Decrypt only after a delay \u2014 offered as the 'Time-lock' KEY SOURCE on the Encrypt tab; the Decrypt tab solves the puzzle (or takes the creator's master key).",
    cap("tlock"))
  .register_scheme_placeholder("shamir", "Native",
    "Shamir secret sharing of the data key (t-of-n)", "the native sharks crate",
    "Split the key across custodians \u2014 offered as the 'Random key, split into Shamir shares' KEY SOURCE on the Encrypt tab; upload any t shares to decrypt.",
    cap("shamir"))

  # Heavy (real, but compute/memory-bound; size-guarded)
  .register_scheme_placeholder("tfhe", "Heavy",
    "Fully Homomorphic Encryption (TFHE, compute-on-ciphertext)", "the native Zama tfhe-rs backend",
    "Compute on data while it stays encrypted \u2014 use the 'Compute on ciphertext (FHE)' tab. A client encrypts numbers under a secret client key; an untrusted server holding only the evaluation (server) key homomorphically ADDS the ciphertexts without ever decrypting or seeing the values; the client decrypts the single result and it equals the plaintext sum. The server key cannot decrypt \u2014 there is no such operation. Heavy tier: keys and ciphertexts are large and every add is a bootstrapped circuit, so the demo is size-guarded and capped to a small number of values. CPU backend (no GPU required).",
    cap("tfhe"))
  .register_scheme_placeholder("zk-range", "Heavy",
    "Zero-Knowledge range proof (Pedersen + bit-OR, ristretto255)", "the native curve25519-dalek ZK backend",
    "Prove a hidden number lies in a public range [min, max] without revealing it \u2014 use the 'Zero-knowledge proof (ZK)' tab. A Pedersen commitment C = v\u00B7G + r\u00B7H hides the value; a per-bit Chaum-Pedersen OR proof (Fiat-Shamir, non-interactive) shows it decomposes into bits inside the range, and a matching proof on (max \u2212 v) pins it from above, together proving min \u2264 v \u2264 max. Transparent (no trusted setup), verifiable by anyone from the proof file alone; a false statement cannot be proved and a tampered proof fails closed. Reuses the OPRF group (no new dependency).",
    cap("zk-range"))

  # Interactive (multi-party; single-machine two-party simulation once built)
  .register_scheme_placeholder("psi", "Interactive",
    "Private Set Intersection (ECDH / DH-PSI)", "the native curve25519-dalek PSI",
    "Find which identifiers two parties share without revealing the rest \u2014 use the 'Set intersection (PSI)' tab. ECDH-PSI on ristretto255 (reuses the OPRF group): each party masks its set with a secret scalar, only masked (random-looking) points cross the wire, and equal double-masked points mark the overlap. Shipped as a single-machine two-party simulation with an exportable transcript.",
    cap("psi"))
  .register_scheme_placeholder("frost", "Interactive",
    "FROST threshold signatures (t-of-n)", "the native curve25519-dalek FROST",
    "Split one signing key across n custodians so any t of them can jointly produce a single ordinary Schnorr signature \u2014 use the 'Threshold signature (FROST)' tab. A trusted dealer shares the key via a degree-(t-1) polynomial; signing runs two rounds (nonce commitments, then partial signatures bound to the whole commitment set) and the coordinator sums the partials into one (R, z) that verifies under the single group public key. No custodian ever holds the whole key, and a sub-threshold quorum fails closed. FROST on ristretto255 (reuses the OPRF group), shipped as a single-machine simulation with an exportable transcript.",
    cap("frost"))
  .register_scheme_placeholder("opaque", "Interactive",
    "PAKE / OPAQUE (asymmetric PAKE)", "the native curve25519-dalek OPAQUE",
    "Log in by password where the server never sees the password and stores no password-equivalent \u2014 use the 'Password login (OPAQUE)' tab. OPAQUE-3DH on ristretto255 (reuses the OPRF group): registration hides the password behind an oblivious PRF and a per-user key; login runs the OPRF plus a 3-message Diffie-Hellman so both sides derive the same session key (and the client a stable export key). A stolen server record still forces a per-user offline dictionary attack, slowed by Argon2. Shipped as a single-machine two-party simulation with an exportable KE1/KE2/KE3 transcript.",
    cap("opaque"))

  # Stub (no secure production implementation exists anywhere)
  stub <- function(id, label, why)
    .register_scheme_placeholder(id, "Stub", label, "no secure implementation (theory limit)", why,
                                 available = function() FALSE)
  stub("fe",  "Functional Encryption",
       "Only inner-product / limited-class research libs exist; no general FE.")
  stub("we",  "Witness Encryption",
       "No secure practical construction exists anywhere.")
  stub("io",  "Indistinguishability Obfuscation",
       "Candidate schemes are astronomically inefficient \u2014 infeasible on any hardware.")
  stub("mpc", "General Multi-Party Computation",
       "Needs live networked parties; PSI/threshold are the runnable slices.")
  stub("rbe", "Registration-Based Encryption",
       "Libraries too immature for production.")
  stub("ue",  "Updatable Encryption",
       "Libraries too immature for production.")

  invisible(TRUE)
}
