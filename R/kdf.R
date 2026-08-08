# Key-derivation functions.
#
# NOTE (this machine): the bundled libsodium's Argon2 (`sodium::argon2`) fails at
# runtime ("pwhash failed"), so the default here is scrypt (memory-hard, working).
# Argon2id is wired in through the native Rust backend when it is available
# (see backend.R / crypto_pqc). scrypt requires a 32-byte salt in this build.

KDF_ALGOS <- c("scrypt", "bcrypt_pbkdf", "blake3", "sha256", "argon2id")

available_kdfs <- function() {
  a <- c("scrypt", "bcrypt_pbkdf", "blake3", "sha256")
  if (isTRUE(crypto_backend_available("argon2id"))) a <- c("argon2id", a)
  a
}

# Salt-length requirements differ per KDF; produce a suitable random salt.
kdf_salt <- function(algo) {
  n <- switch(algo, "scrypt" = 32L, "bcrypt_pbkdf" = 16L, 16L)
  sodium::random(n)
}

# Derive a `size`-byte key from `secret` (raw/char) and `salt`.
# Returns list(key, salt, algo, params).
kdf_derive <- function(secret, salt = NULL, algo = "scrypt", size = 32L,
                       params = list()) {
  algo   <- match.arg(algo, KDF_ALGOS)
  secret <- as_raw(secret)
  if (is.null(salt)) salt <- kdf_salt(algo) else salt <- as_raw(salt)

  key <- switch(algo,
    "scrypt" = {
      if (length(salt) != 32L) salt <- sodium::sha256(salt)          # force 32 bytes
      sodium::scrypt(secret, salt, size = size)
    },
    "bcrypt_pbkdf" = {
      rounds <- as.integer(params$rounds %||% 16L)
      openssl::bcrypt_pbkdf(rawToChar(secret), salt = salt,
                            rounds = rounds, size = size)
    },
    "blake3" = {
      # fast (NOT memory-hard) — hash secret||salt. Kept for interop/demo.
      coerce_key(hash_bytes(c(secret, salt), "blake3"), size)
    },
    "sha256" = {
      coerce_key(sodium::sha256(c(secret, salt)), size)
    },
    "argon2id" = {
      if (!isTRUE(crypto_backend_available("argon2id")))
        stop("Argon2id needs the native backend (not built). Use scrypt.")
      native_argon2id(secret, salt, size, params)   # provided by backend when present
    }
  )
  list(key = as.raw(key), salt = as.raw(salt), algo = algo, params = params)
}
