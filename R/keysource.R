# Key sources: where the symmetric key comes from.
#
# Encryption side: resolve_key(spec) -> list(key, salt, source_meta, key_export).
#   `source_meta` (stored in the envelope) never contains the secret.
#   `key_export`  is non-NULL only when the key MUST be downloaded to be
#                 recoverable later (the random-key source).
# Decryption side: resolve_key_for_decrypt(source_meta, salt_hex, secret).

KEY_SOURCES <- c("random", "passphrase", "freetext_hash", "keyfile", "hybrid_pqc",
                 "shamir", "timelock", "cpabe", "ibe", "oprf")

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
           source_meta = list(type = "passphrase", kdf = kd$algo,
                              kdf_params = kd$params),
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
    },
    "hybrid_pqc" = {
      pub <- as_raw(spec$public_bundle %||%
                      stop("Generate or upload a recipient public key first."))
      enc <- native_hybrid_encaps(pub)   # X25519 + ML-KEM-768 encapsulation
      list(key = enc$key, salt = NULL,
           source_meta = list(type = "hybrid_pqc", kem = "x25519-mlkem768",
                              encapsulation = raw_to_base64(enc$encapsulation)),
           key_export = NULL)   # recipient decrypts with their downloaded secret bundle
    },
    "shamir" = {
      key <- as.raw(spec$key %||% sodium::random(32L))
      t <- as.integer(spec$t %||% 2L); n <- as.integer(spec$n %||% 3L)
      if (t > n) stop("Shamir: threshold t must not exceed the number of shares n.")
      shares <- native_shamir_split(key, t, n)   # list of n raw shares
      list(key = key, salt = NULL,
           source_meta = list(type = "shamir", t = t, n = n,
                              share_len = length(shares[[1]])),
           key_export = NULL,          # the key itself is never stored \u2014 only shares
           shares = shares)            # downloaded as t-of-n custodian files
    },
    "timelock" = {
      key  <- as.raw(spec$key %||% sodium::random(32L))
      bits <- as.integer(spec$bits %||% 2048L)
      t    <- as.numeric(spec$t_squarings %||%
                stop("Time-lock: internal error \u2014 missing squaring count."))
      puz  <- native_timelock_generate(bits, t)   # list(N, b); b is the solution
      masked <- .tl_xor(key, timelock_mask(puz$b))
      list(key = key, salt = NULL,
           source_meta = list(type = "timelock", alg = "rsw-puzzle-v1",
                              a = TIMELOCK_BASE, bits = bits, t_squarings = t,
                              modulus = raw_to_base64(puz$N),
                              masked_key = raw_to_base64(masked),
                              rate_est = spec$rate_est %||% NA,
                              target_seconds = spec$target_seconds %||% NA),
           key_export = NULL,          # no key file \u2014 solving the puzzle IS the key
           # trapdoor destroyed here; keep b only if the creator wants an instant unlock
           timelock_master = if (isTRUE(spec$keep_master)) puz$b else NULL)
    },
    "cpabe" = {
      key    <- as.raw(spec$key %||% sodium::random(32L))
      pk     <- as_raw(spec$pk %||%
                  stop("CP-ABE: generate or upload an authority public key first."))
      policy <- spec$policy %||% ""
      if (!nzchar(trimws(policy)))
        stop("CP-ABE: enter an access policy, e.g. \"cardiology\" and \"senior\".")
      ct <- native_cpabe_encrypt(pk, policy, key)   # seals the data key under the policy
      list(key = key, salt = NULL,
           source_meta = list(type = "cpabe", alg = "bsw-cpabe",
                              policy = policy, ct = raw_to_base64(ct)),
           key_export = NULL)   # recipients decrypt with an attribute key, not a key file
    },
    "ibe" = {
      pk <- as_raw(spec$pk %||%
              stop("IBE: generate or upload an authority public key first."))
      identity <- spec$identity %||% ""
      if (!nzchar(trimws(identity)))
        stop("IBE: enter a recipient identity, e.g. alice@hospital.org.")
      enc <- native_ibe_encaps(pk, identity)   # KEM: seals a fresh data key to the identity
      list(key = enc$key, salt = NULL,         # the encapsulated 32-byte secret IS the key
           source_meta = list(type = "ibe", alg = "kv1-ibkem",
                              identity = trimws(identity),
                              ct = raw_to_base64(enc$ct)),
           key_export = NULL)   # recipient decrypts with their extracted identity key
    },
    "oprf" = {
      text <- spec$text %||% ""
      if (!nzchar(text))
        stop("OPRF: enter an input to harden (a passphrase, id, or secret).")
      okey <- as_raw(spec$oprf_key %||%
                       stop("OPRF: generate or upload a 32-byte OPRF key first."))
      der <- oprf_derive_key(text, okey)   # key = VOPRF_k(input); needs the OPRF key too
      list(key = der$key, salt = NULL,
           source_meta = list(type = "oprf", alg = "voprf-ristretto255-sha512",
                              public_key = sodium::bin2hex(der$public_key)),
           key_export = NULL,          # the input is user-remembered, never stored
           oprf_key = okey)            # offered for download as the .oprfkey (SECRET)
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
                              algo = source_meta$kdf %||% "scrypt", size = 32L,
                              params = as.list(source_meta$kdf_params %||% list()))$key,
    "freetext_hash" = {
      digest <- hash_bytes(secret, source_meta$hash_algo %||% "blake3")
      if (isTRUE(source_meta$harden))
        kdf_derive(digest, salt = salt, algo = "scrypt", size = 32L)$key
      else coerce_key(digest, 32L)
    },
    "hybrid_pqc" = {
      encap <- base64_to_raw(source_meta$encapsulation %||%
                               stop("Artifact is missing its KEM encapsulation."))
      native_hybrid_decaps(as_raw(secret), encap)   # secret = recipient secret bundle
    },
    "shamir" = {
      sl <- as.integer(source_meta$share_len %||%
                         stop("Artifact is missing its Shamir share length."))
      native_shamir_combine(as_raw(secret), sl)      # secret = concatenated shares
    },
    "timelock" = {
      # `secret` is the solved puzzle answer b (from timelock_solve) or the
      # creator's uploaded master. The slow squaring happens in the server layer.
      masked <- base64_to_raw(source_meta$masked_key %||%
                               stop("Artifact is missing its time-lock masked key."))
      .tl_xor(masked, timelock_mask(as_raw(secret)))
    },
    "cpabe" = {
      # `secret` is a CP-ABE attribute key; native decrypt returns the data key
      # only if its attributes satisfy the policy, else errors (fails closed).
      ct <- base64_to_raw(source_meta$ct %||%
                            stop("Artifact is missing its CP-ABE ciphertext."))
      native_cpabe_decrypt(as_raw(secret), ct)
    },
    "ibe" = {
      # `secret` is the recipient's extracted identity key; native decaps returns
      # the data key only if the key matches the sealed identity, else errors.
      ct <- base64_to_raw(source_meta$ct %||%
                            stop("Artifact is missing its IBE ciphertext."))
      native_ibe_decaps(as_raw(secret), ct)
    },
    "oprf" = {
      # `secret` is list(text, oprf_key): both the exact input and the OPRF key
      # are required to reproduce the derived key.
      if (!is.list(secret) || is.null(secret$text) || is.null(secret$oprf_key))
        stop("OPRF: decryption needs both the input text and the OPRF key file.")
      der  <- oprf_derive_key(secret$text, secret$oprf_key)
      want <- source_meta$public_key
      if (!is.null(want) &&
          !identical(tolower(want), tolower(sodium::bin2hex(der$public_key))))
        stop("OPRF: that OPRF key does not match the one this file was hardened with.")
      der$key   # wrong input still fails closed on the AEAD tag
    },
    stop(sprintf("Unknown key source: %s", type))
  )
  list(key = key)
}
