# ML-DSA-65 envelope signatures (FIPS 204, native backend).
#
# A signature lets whoever holds the signing SECRET key vouch for a ciphertext
# and its metadata. Verification needs only the PUBLIC key, which travels inside
# the envelope, so any recipient can check it — but that only proves the envelope
# was not altered after this particular key signed it. Trust still requires the
# recipient to confirm the signer's public-key fingerprint out-of-band (the
# Decrypt tab shows it for exactly that comparison).

SIGN_ALG <- "ml-dsa-65"

# Deterministic digest over the envelope's meaning-bearing fields, EXCLUDING the
# `signature` block. Every field is reduced to a string or a JSON form that
# survives the Base64(JSON) round-trip, so a signature made at encrypt time still
# verifies after the artifact is parsed back on decrypt.
.envelope_signing_digest <- function(env) {
  jj <- function(x) as.character(jsonlite::toJSON(x %||% list(), auto_unbox = TRUE))
  parts <- c(
    "shinyEncrypt-envelope-sig-v1",
    as.character(env$v %||% ""),
    as.character(env$scheme %||% ""),
    as.character(env$pt_algo %||% ""),
    as.character(env$pt_digest %||% ""),
    as.character(env$orig_kind %||% ""),
    as.character(env$orig_name %||% ""),
    as.character(isTRUE(env$compressed)),
    as.character(env$encoding %||% ""),
    as.character(env$salt %||% ""),
    jj(env$params),
    jj(env$key_source),
    as.character(env$ciphertext_b64 %||% "")
  )
  as_raw(sodium::sha256(charToRaw(paste(parts, collapse = "\x1f"))))
}

# Short, human-comparable fingerprint of a public key (first 8 bytes of its
# SHA-256, grouped). Recipients compare this against the signer's known key.
sign_fingerprint <- function(public_key) {
  h <- sodium::bin2hex(as_raw(sodium::sha256(as_raw(public_key)))[seq_len(8)])
  paste(regmatches(h, gregexpr(".{1,4}", h))[[1]], collapse = " ")
}

# Attach an ML-DSA signature block to an envelope. `secret_key`/`public_key` are
# the raw ML-DSA-65 keypair. Returns the envelope with `$signature` set.
envelope_sign <- function(env, secret_key, public_key) {
  digest <- .envelope_signing_digest(env)
  sig <- native_mldsa_sign(as_raw(secret_key), digest)
  env$signature <- list(
    alg        = SIGN_ALG,
    public_key = sodium::bin2hex(as_raw(public_key)),
    sig        = raw_to_base64(sig)
  )
  env
}

# Verify an envelope's signature (if any). Returns a list describing the outcome:
#   status = "unsigned" | "valid" | "invalid"
#   alg, public_key (hex), fingerprint  (present when a signature block exists)
#   expected_match = NA (no pin) | TRUE | FALSE
#
# A valid signature only proves the envelope was not altered since *whoever holds
# the embedded public key* signed it. Pass `expected_public` (the sender's
# out-of-band .signpub, raw or hex) to also assert the signer is that specific
# party: expected_match is TRUE only when the embedded key equals the pinned one.
envelope_verify <- function(env, expected_public = NULL) {
  s <- env$signature
  if (is.null(s) || is.null(s$sig) || is.null(s$public_key))
    return(list(status = "unsigned", expected_match = NA))
  pub <- tryCatch(sodium::hex2bin(s$public_key), error = function(e) NULL)
  ok <- tryCatch(
    !is.null(pub) &&
      native_mldsa_verify(pub, .envelope_signing_digest(env), base64_to_raw(s$sig)),
    error = function(e) FALSE)
  expected_match <- NA
  if (!is.null(expected_public)) {
    eh <- tryCatch(
      if (is.character(expected_public)) gsub("[[:space:]]", "", expected_public)
      else sodium::bin2hex(as_raw(expected_public)),
      error = function(e) NA_character_)
    expected_match <- !is.na(eh) && identical(tolower(eh), tolower(s$public_key))
  }
  list(status = if (isTRUE(ok)) "valid" else "invalid",
       alg = s$alg %||% SIGN_ALG, public_key = s$public_key,
       fingerprint = if (!is.null(pub)) sign_fingerprint(pub) else "(unreadable key)",
       expected_match = expected_match)
}
