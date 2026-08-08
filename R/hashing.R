# Hashing / digest utility.
#
# Exposes a unified set of digests over raw bytes: MD5, SHA-1, SHA-256, SHA-512,
# SHA-3 (256/512), BLAKE2b and BLAKE3. Used both as a standalone fingerprint
# tool and as a key-source ("free-text -> hash -> key material").

HASH_ALGOS <- c(
  "md5", "sha1", "sha256", "sha512",
  "sha3-256", "sha3-512", "blake2b", "blake3"
)

available_hashes <- function() HASH_ALGOS

# Return the digest of `x` (raw or character) as a raw vector.
hash_bytes <- function(x, algo = "sha256") {
  algo <- match.arg(algo, HASH_ALGOS)
  raw <- as_raw(x)
  switch(algo,
    "md5"      = digest::digest(raw, algo = "md5",    serialize = FALSE, raw = TRUE),
    "sha1"     = digest::digest(raw, algo = "sha1",   serialize = FALSE, raw = TRUE),
    "sha256"   = digest::digest(raw, algo = "sha256", serialize = FALSE, raw = TRUE),
    "sha512"   = digest::digest(raw, algo = "sha512", serialize = FALSE, raw = TRUE),
    "blake3"   = digest::digest(raw, algo = "blake3", serialize = FALSE, raw = TRUE),
    "sha3-256" = as.raw(openssl::sha3(raw, size = 256)),
    "sha3-512" = as.raw(openssl::sha3(raw, size = 512)),
    "blake2b"  = sodium::hash(raw, size = 32L)
  )
}

# Hex-encoded digest.
hash_hex <- function(x, algo = "sha256") sodium::bin2hex(hash_bytes(x, algo))
