# Oblivious-PRF-hardened key derivation (verifiable OPRF, ristretto255 + SHA-512).
#
# A VOPRF turns a (possibly low-entropy) input into a pseudorandom 32-byte key
# using a SEPARATELY-held OPRF key, run through the oblivious protocol so the key
# holder never sees the input. The derived key needs BOTH the input and the OPRF
# key: an attacker with the ciphertext who guesses the input still cannot derive
# the key without the OPRF key, so a weak input is protected against offline
# brute force as long as the OPRF key stays secret (ideally held by a different
# custodian or device). Decryption reproduces the same key because the random
# blind cancels out — the output is deterministic in (input, key). The app plays
# both client and server locally; the DLEQ proof makes the evaluation verifiable
# and the derivation fails closed on a wrong or tampered response.

# Coerce a text/raw input to the exact raw bytes fed to the OPRF.
.oprf_input_raw <- function(x) {
  if (is.raw(x)) return(x)
  if (is.character(x)) return(charToRaw(paste(x, collapse = "")))
  as_raw(x)
}

# A fresh random OPRF key (32 bytes), generated in-app.
oprf_new_key <- function() native_oprf_keygen()

# Run the full local VOPRF and return the derived 32-byte key plus a small
# transcript (the public key and the blinded element the key holder would see).
oprf_derive_key <- function(input, oprf_key) {
  inp <- .oprf_input_raw(input)
  if (length(inp) == 0L)
    stop("OPRF: enter a non-empty input to harden (a passphrase, id, or secret).")
  key <- as_raw(oprf_key)
  if (length(key) != 32L)
    stop("OPRF: the OPRF key must be exactly 32 bytes.")
  pub   <- native_oprf_public_key(key)              # k*G (shareable, for verification)
  blind <- native_oprf_blind(inp)                   # blind(32) || blinded(32)
  eval  <- native_oprf_evaluate(key, blind[33:64])  # E(32) || dleq_c(32) || dleq_z(32)
  out   <- native_oprf_finalize(inp, blind, eval, pub)   # 64-byte PRF output
  list(key = out[1:32], public_key = pub, blinded = blind[33:64])
}
