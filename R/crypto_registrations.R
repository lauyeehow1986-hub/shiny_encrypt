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

  # Native (real once the Rust/C++ crate is built)
  .register_scheme_placeholder("hpke-hybrid", "Native",
    "Hybrid HPKE: X25519 + ML-KEM-768 key-wrap", "the native PQC crate",
    "Post-quantum hybrid KEM — offered as the 'Recipient public key (PQC hybrid)' KEY SOURCE on the Encrypt tab when the native backend is built.",
    cap("hpke-hybrid"))
  .register_scheme_placeholder("ml-dsa", "Native",
    "ML-DSA (Dilithium) signature over the envelope", "the native PQC crate",
    "FIPS 204 signatures — enable 'Sign this envelope (ML-DSA-65)' on the Encrypt tab; the Decrypt tab verifies and shows the signer fingerprint.",
    cap("ml-dsa"))
  .register_scheme_placeholder("cp-abe", "Native",
    "Attribute-Based Encryption (CP-ABE)", "the native rabe crate",
    "Policy-based access control. Build the native package to enable.", cap("cp-abe"))
  .register_scheme_placeholder("ibe", "Native",
    "Identity-Based Encryption", "the native pairing crate",
    "Encrypt to an identity string. Build the native package to enable.", cap("ibe"))
  .register_scheme_placeholder("fpe-ff1", "Native",
    "Format-Preserving Encryption (FF1)", "the native fpe crate",
    "Column-level de-identification that keeps each field's length and character class — use the 'De-identify (FPE)' tab to tokenise ID columns and reverse them with the .fpekit.",
    cap("fpe-ff1"))
  .register_scheme_placeholder("pre", "Native",
    "Proxy Re-Encryption", "the native recrypt crate",
    "Re-share ciphertext to another key. Build the native package to enable.", cap("pre"))
  .register_scheme_placeholder("tlock", "Native",
    "Time-Lock Encryption (VDF / drand tlock)", "the native time-lock crate",
    "Decrypt only after time T. Build the native package to enable.", cap("tlock"))
  .register_scheme_placeholder("shamir", "Native",
    "Shamir secret sharing of the data key (t-of-n)", "the native sharks crate",
    "Split the key across custodians — offered as the 'Random key, split into Shamir shares' KEY SOURCE on the Encrypt tab; upload any t shares to decrypt.",
    cap("shamir"))

  # Heavy (real, but compute/memory-bound; size-guarded)
  .register_scheme_placeholder("tfhe", "Heavy",
    "Fully Homomorphic Encryption (TFHE, compute-on-ciphertext)", "the native TFHE crate + CUDA",
    "Mean/sum/linreg on ciphertext. Build the native package to enable.", cap("tfhe"))
  .register_scheme_placeholder("zk-stark", "Heavy",
    "Zero-Knowledge proof (zk-STARK / Bulletproofs)", "the native ZK crate",
    "Prove a property without revealing data. Build the native package to enable.", cap("zk-stark"))

  # Interactive (multi-party; single-machine two-party simulation once built)
  .register_scheme_placeholder("psi", "Interactive",
    "Private Set Intersection", "the native PSI crate",
    "Two-party set overlap (simulated). Build the native package to enable.", cap("psi"))
  .register_scheme_placeholder("frost", "Interactive",
    "FROST threshold signatures (t-of-n)", "the native FROST crate",
    "Shared authorization (simulated). Build the native package to enable.", cap("frost"))
  .register_scheme_placeholder("opaque", "Interactive",
    "PAKE / OPAQUE", "the native OPAQUE crate",
    "Password-authenticated key exchange (simulated). Build to enable.", cap("opaque"))

  # Stub (no secure production implementation exists anywhere)
  stub <- function(id, label, why)
    .register_scheme_placeholder(id, "Stub", label, "no secure implementation (theory limit)", why,
                                 available = function() FALSE)
  stub("fe",  "Functional Encryption",
       "Only inner-product / limited-class research libs exist; no general FE.")
  stub("we",  "Witness Encryption",
       "No secure practical construction exists anywhere.")
  stub("io",  "Indistinguishability Obfuscation",
       "Candidate schemes are astronomically inefficient — infeasible on any hardware.")
  stub("mpc", "General Multi-Party Computation",
       "Needs live networked parties; PSI/threshold are the runnable slices.")
  stub("rbe", "Registration-Based Encryption",
       "Libraries too immature for production.")
  stub("ue",  "Updatable Encryption",
       "Libraries too immature for production.")

  invisible(TRUE)
}
