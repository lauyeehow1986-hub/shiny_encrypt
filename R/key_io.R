# Key-material formatting for download, and reading secrets on decrypt.

# Build downloadable key files for a resolved key. Returns a named list of
# list(name, text). Only the random-key source yields a secret key file (it is
# the sole copy); passphrase/free-text sources are reconstructed from the secret
# the user already holds.
key_material_files <- function(keyres, scheme_id = "aead") {
  files <- list()
  if (!is.null(keyres$key_export)) {
    files[["secret_key"]] <- list(
      name = sprintf("%s.secret.key.txt", scheme_id),
      text = paste0(
        "# shinyEncrypt SECRET KEY - keep private, anyone with this can decrypt.\n",
        "# hex(32 bytes):\n",
        sodium::bin2hex(keyres$key_export), "\n")
    )
  }
  if (!is.null(keyres$salt)) {
    files[["salt"]] <- list(
      name = sprintf("%s.salt.txt", scheme_id),
      text = paste0("# KDF salt (not secret, but needed to rederive the key)\n",
                    sodium::bin2hex(keyres$salt), "\n")
    )
  }
  files
}

# Read a user-provided secret file to raw bytes (accepts a hex-in-text keyfile or
# a raw binary keyfile). Lines beginning with '#' are treated as comments.
read_secret_bytes <- function(path) {
  txt <- tryCatch(readLines(path, warn = FALSE), error = function(e) character())
  body <- paste(txt[!grepl("^\\s*#", txt)], collapse = "")
  body <- gsub("[[:space:]]", "", body)
  if (nzchar(body) && grepl("^[0-9a-fA-F]+$", body) && nchar(body) %% 2 == 0)
    return(sodium::hex2bin(body))
  readBin(path, "raw", n = file.info(path)$size)   # fall back to raw bytes
}
