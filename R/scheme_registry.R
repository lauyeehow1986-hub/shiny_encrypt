# Plugin registry for cryptographic schemes.
#
# Each scheme is a small record with a common interface so the UI can list and
# drive them uniformly:
#   id         unique string id
#   tier       "Core" | "Native" | "Heavy" | "Interactive" | "Stub"
#   label      human name
#   params     list of parameter specs (for the UI): name, type, default, label
#   encrypt(pt_raw, key, params) -> list(ciphertext=raw, params=list)   (updated params, e.g. nonce)
#   decrypt(ct_raw, key, params) -> raw
#   available()-> logical (default TRUE)

.scheme_registry <- new.env(parent = emptyenv())

register_scheme <- function(id, tier, label, params = list(),
                            encrypt = NULL, decrypt = NULL,
                            available = function() TRUE,
                            note = "") {
  .scheme_registry[[id]] <- list(
    id = id, tier = tier, label = label, params = params,
    encrypt = encrypt, decrypt = decrypt, available = available, note = note
  )
  invisible(id)
}

get_scheme <- function(id) {
  sc <- .scheme_registry[[id]]
  if (is.null(sc)) stop(sprintf("Unknown scheme: %s", id))
  sc
}

list_schemes <- function(tier = NULL) {
  ids <- ls(.scheme_registry)
  out <- lapply(ids, function(i) {
    s <- .scheme_registry[[i]]
    data.frame(id = s$id, tier = s$tier, label = s$label,
               available = isTRUE(tryCatch(s$available(), error = function(e) FALSE)),
               note = s$note, stringsAsFactors = FALSE)
  })
  df <- do.call(rbind, out)
  if (!is.null(tier)) df <- df[df$tier %in% tier, , drop = FALSE]
  df[order(match(df$tier, c("Core","Native","Heavy","Interactive","Stub")), df$label), ]
}

# ---- High-level encrypt/decrypt operating on the envelope ----

# keyres = resolve_key() output: list(key, salt, source_meta)
se_encrypt <- function(plaintext_raw, scheme_id, keyres, params = list(),
                       pt_algo = "sha256", meta = list()) {
  sc <- get_scheme(scheme_id)
  if (!isTRUE(sc$available()))
    stop(sprintf("Scheme '%s' is not available in this environment (%s).",
                 scheme_id, sc$note))
  res <- sc$encrypt(plaintext_raw, keyres$key, params)
  env <- envelope_build(
    scheme     = scheme_id,
    params     = res$params,
    salt       = keyres$salt,
    key_source = keyres$source_meta,
    ciphertext = res$ciphertext,
    pt_raw     = plaintext_raw,
    pt_algo    = pt_algo,
    meta       = meta
  )
  env
}

# secret: user-supplied secret material (passphrase/text/keyfile bytes) or, for a
# random-key source, the raw key bytes themselves.
se_decrypt <- function(env, secret) {
  sc <- get_scheme(env$scheme)
  keyres <- resolve_key_for_decrypt(env$key_source, env$salt, secret)
  ct <- base64_to_raw(env$ciphertext_b64)
  pt <- sc$decrypt(ct, keyres$key, env$params)
  # Integrity check against the stored plaintext digest.
  if (!is.null(env$pt_digest)) {
    got <- hash_hex(pt, env$pt_algo %||% "sha256")
    if (!identical(got, env$pt_digest))
      stop("Integrity check failed: recovered data does not match stored digest.")
  }
  pt
}
