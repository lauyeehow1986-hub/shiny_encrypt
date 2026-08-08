# Build the two export artifacts from an envelope:
#   * .txt : the wrapped envelope block plus a short human header.
#   * .R   : a self-contained, portable script that decrypts Core AEAD artifacts
#            with only {sodium, openssl} installed (no package needed). It
#            *parses* the embedded envelope as data and never executes anything
#            from the artifact.

build_txt_export <- function(env, scheme_label = env$scheme) {
  header <- paste0(
    "# shinyEncrypt ciphertext envelope\n",
    "# Scheme : ", scheme_label, " (", env$scheme, ")\n",
    "# Created: ", env$created, "\n",
    "# Original: ", env$orig_name, "  (kind: ", env$orig_kind, ")\n",
    "# NOT for diagnosis/clinical decisions. You are responsible for key custody.\n\n")
  paste0(header, envelope_serialize(env), "\n")
}

build_r_export <- function(env, scheme_label = env$scheme) {
  env_block <- envelope_serialize(env)
  core <- env$scheme %in% c("aead-secretbox", "aead-aesgcm")

  decrypt_body <- if (core) {
'
## ---- self-contained decrypt (Core AEAD; needs only sodium + openssl) ----
stopifnot(requireNamespace("sodium", quietly=TRUE),
          requireNamespace("openssl", quietly=TRUE))

.parse_env <- function(txt) {
  ls <- strsplit(txt, "\r?\n")[[1]]
  b <- which(trimws(ls)=="-----BEGIN SHINY-ENCRYPT ENVELOPE-----")
  e <- which(trimws(ls)=="-----END SHINY-ENCRYPT ENVELOPE-----")
  body <- paste(trimws(ls[(b+1):(e-1)]), collapse="")
  jsonlite::fromJSON(rawToChar(openssl::base64_decode(body)))
}
.coerce_key <- function(k,n=32L){ k<-if(is.character(k)) sodium::hex2bin(k) else k
  if(length(k)==n) k else sodium::sha256(k)[seq_len(n)] }
.derive <- function(src, salt_hex, secret){
  salt <- if(!is.null(salt_hex)) sodium::hex2bin(salt_hex) else NULL
  t <- src$type
  if(t %in% c("random","keyfile")) return(.coerce_key(secret))
  if(t=="passphrase") return(sodium::scrypt(if(is.character(secret)) charToRaw(secret) else secret,
                                            if(length(salt)!=32L) sodium::sha256(salt) else salt, size=32L))
  if(t=="freetext_hash"){
    dig <- switch(src$hash_algo,
      md5=digest::digest(charToRaw(secret),"md5",serialize=FALSE,raw=TRUE),
      sha256=sodium::sha256(charToRaw(secret)),
      blake3=digest::digest(charToRaw(secret),"blake3",serialize=FALSE,raw=TRUE),
      sodium::sha256(charToRaw(secret)))
    if(isTRUE(src$harden)) return(sodium::scrypt(dig, if(length(salt)!=32L) sodium::sha256(salt) else salt, size=32L))
    return(.coerce_key(dig))
  }
  stop("unknown key source")
}

env <- .parse_env(envelope_text)
key <- .derive(env$key_source, env$salt, secret)
ct  <- openssl::base64_decode(gsub("[[:space:]]","", env$ciphertext_b64))
pt  <- if(env$scheme=="aead-secretbox")
         sodium::data_decrypt(ct, key, sodium::hex2bin(env$params$nonce)) else
         openssl::aes_gcm_decrypt(ct, key=key, iv=sodium::hex2bin(env$params$iv))
outfile <- env$orig_name %||% "recovered.bin"
writeBin(as.vector(pt), outfile)
cat("Recovered", length(pt), "bytes to", outfile, "\\n")
'
  } else {
'
## ---- this scheme needs the shinyEncrypt package (native backend) ----
stopifnot(requireNamespace("shinyEncrypt", quietly=TRUE))
env <- shinyEncrypt::envelope_parse(envelope_text)
pt  <- shinyEncrypt::se_decrypt(env, secret)
writeBin(as.vector(pt), env$orig_name %||% "recovered.bin")
'
  }

  paste0(
'#!/usr/bin/env Rscript
## shinyEncrypt reproducible artifact  ---------------------------------------
## Scheme : ', scheme_label, ' (', env$scheme, ')
## Created: ', env$created, '
## Original: ', env$orig_name, '  (kind: ', env$orig_kind, ')
##
## HOW TO DECRYPT:
##   1) Set `secret` below to your passphrase/free-text (string) OR key hex.
##   2) Run:  Rscript this_file.R
##   The embedded envelope is parsed as DATA only; nothing from it is executed.
##
## DISCLAIMER: research/utility tool. NOT for diagnosis or clinical decisions.
## You are responsible for key custody. Never commit secrets or real data.
## ---------------------------------------------------------------------------

`%||%` <- function(a,b) if(is.null(a)||length(a)==0) b else a
secret <- NULL   # <== EDIT ME (passphrase / free-text / key hex)

envelope_text <- "', env_block, '"
', decrypt_body)
}
