# Self-describing ciphertext envelope.
#
# The envelope carries everything needed to decrypt later *except* the secret:
# scheme id + version, scheme params (nonce/iv...), KDF salt, the (non-secret)
# key-source description, the plaintext integrity digest, and the Base64
# ciphertext. It is serialized as Base64(JSON) between BEGIN/END markers, so the
# exact same block can live in a `.txt` file or be embedded verbatim inside an
# exported `.R` script. Parsing never executes anything.

ENVELOPE_VERSION <- 1L
ENV_BEGIN <- "-----BEGIN SHINY-ENCRYPT ENVELOPE-----"
ENV_END   <- "-----END SHINY-ENCRYPT ENVELOPE-----"

hexornull <- function(x) if (is.null(x)) NULL else sodium::bin2hex(as_raw(x))

envelope_build <- function(scheme, params, salt, key_source, ciphertext,
                           pt_raw, pt_algo = "sha256", meta = list()) {
  list(
    v            = ENVELOPE_VERSION,
    app          = "shinyEncrypt",
    scheme       = scheme,
    created       = now_utc(),
    params       = params %||% list(),
    salt         = hexornull(salt),
    key_source   = key_source %||% list(type = "raw"),
    pt_algo      = pt_algo,
    pt_digest    = hash_hex(pt_raw, pt_algo),
    orig_kind    = meta$orig_kind %||% "binary",
    orig_name    = meta$orig_name %||% "payload.bin",
    compressed   = isTRUE(meta$compressed),
    encoding     = meta$encoding %||% "base64",
    ciphertext_b64 = raw_to_base64(ciphertext)
  )
}

# Serialize envelope -> wrapped Base64(JSON) text block.
envelope_serialize <- function(env) {
  json <- jsonlite::toJSON(env, auto_unbox = TRUE, null = "null")
  b64  <- openssl::base64_encode(charToRaw(as.character(json)))
  # wrap Base64 to 76-char lines for readability
  lines <- regmatches(b64, gregexpr(".{1,76}", b64))[[1]]
  paste(c(ENV_BEGIN, lines, ENV_END), collapse = "\n")
}

# Parse a wrapped block back to the envelope list. Works whether the block sits
# in a .txt or is embedded in a .R file (surrounding text is ignored).
envelope_parse <- function(text) {
  lines <- strsplit(text, "\r?\n")[[1]]
  # Match lines that *contain* the markers, not equal them: inside an exported
  # .R the BEGIN marker shares its line with `envelope_text <- "` and END with a
  # trailing quote. The body lines in between are pure Base64 either way.
  b <- which(grepl(ENV_BEGIN, lines, fixed = TRUE))
  e <- which(grepl(ENV_END, lines, fixed = TRUE))
  if (length(b) < 1L || length(e) < 1L || e[1] <= b[1])
    stop("No valid SHINY-ENCRYPT envelope found in the uploaded artifact.")
  b <- b[1]; e <- e[1]
  body <- paste(trimws(lines[(b + 1L):(e - 1L)]), collapse = "")
  json <- rawToChar(openssl::base64_decode(body))
  env  <- jsonlite::fromJSON(json, simplifyVector = TRUE)
  # jsonlite may simplify params to non-list; keep as list
  if (!is.null(env$params) && !is.list(env$params)) env$params <- as.list(env$params)
  if (!is.null(env$key_source) && !is.list(env$key_source))
    env$key_source <- as.list(env$key_source)
  env
}
