# Key sources: where the symmetric key comes from.
#
# Encryption side: resolve_key(spec) -> list(key, salt, source_meta, key_export).
#   `source_meta` (stored in the envelope) never contains the secret.
#   `key_export`  is non-NULL only when the key MUST be downloaded to be
#                 recoverable later (the random-key source).
# Decryption side: resolve_key_for_decrypt(source_meta, salt_hex, secret).

KEY_SOURCES <- c("random", "passphrase", "freetext_hash", "keyfile")

resolve_key <- function(spec) {
  type <- match.arg(spec$type %||% "random", KEY_SOURCES)
  switch(type,
    "random" = {
      key <- spec$key %||% sodium::random(32L)
      list(key = as.raw(key), salt = NULL,
           source_meta = list(type = "random"),
           key_export = as.raw(key))
    },
    "passphrase" = {
      kd <- kdf_derive(spec$passphrase, salt = spec$salt,
                       algo = spec$kdf %||% "scrypt", size = 32L,
                       params = spec$kdf_params %||% list())
      list(key = kd$key, salt = kd$salt,
           source_meta = list(type = "passphrase", kdf = kd$algo),
           key_export = NULL)
    },
    "freetext_hash" = {
      halgo  <- spec$hash_algo %||% "blake3"
      digest <- hash_bytes(spec$text, halgo)
      if (isTRUE(spec$harden)) {
        kd <- kdf_derive(digest, salt = spec$salt, algo = "scrypt", size = 32L)
        list(key = kd$key, salt = kd$salt,
             source_meta = list(type = "freetext_hash", hash_algo = halgo,
                                harden = TRUE, kdf = "scrypt"),
             key_export = NULL)
      } else {
        list(key = coerce_key(digest, 32L), salt = NULL,
             source_meta = list(type = "freetext_hash", hash_algo = halgo,
                                harden = FALSE),
             key_export = NULL)
      }
    },
    "keyfile" = {
      list(key = coerce_key(spec$bytes, 32L), salt = NULL,
           source_meta = list(type = "keyfile"),
           key_export = NULL)
    }
  )
}

resolve_key_for_decrypt <- function(source_meta, salt_hex, secret) {
  type <- source_meta$type %||% "random"
  salt <- if (!is.null(salt_hex)) sodium::hex2bin(salt_hex) else NULL
  key <- switch(type,
    "random"    = coerce_key(secret, 32L),
    "keyfile"   = coerce_key(secret, 32L),
    "passphrase" = kdf_derive(secret, salt = salt,
                              algo = source_meta$kdf %||% "scrypt", size = 32L)$key,
    "freetext_hash" = {
      digest <- hash_bytes(secret, source_meta$hash_algo %||% "blake3")
      if (isTRUE(source_meta$harden))
        kdf_derive(digest, salt = salt, algo = "scrypt", size = 32L)$key
      else coerce_key(digest, 32L)
    },
    stop(sprintf("Unknown key source: %s", type))
  )
  list(key = key)
}
