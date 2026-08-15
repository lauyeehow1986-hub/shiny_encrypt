# Key-material formatting for download, and reading secrets on decrypt.

# Build downloadable key files for a resolved key. Returns a named list of
# list(name, text). Only the random-key source yields a secret key file (it is
# the sole copy). Passphrase/free-text sources are reconstructed from the secret
# the user already holds, and their KDF salt is already stored inside the
# envelope, so nothing needs downloading \u2014 returning no files keeps the
# "Download key material" button (and the temptation to re-upload the salt) away.
key_material_files <- function(keyres, scheme_id = "aead") {
  files <- list()
  if (!is.null(keyres$key_export)) {
    files[["secret_key"]] <- list(
      name = sprintf("%s.secret.key.txt", scheme_id),
      text = paste0(
        "# shinyEncrypt SECRET KEY - keep private, anyone with this can decrypt.\n",
        "# This is the ONLY copy. Upload this file to decrypt. hex(32 bytes):\n",
        sodium::bin2hex(keyres$key_export), "\n")
    )
  }
  # Shamir custody: one file per custodian; any t reconstruct the key.
  if (!is.null(keyres$shares)) {
    n <- length(keyres$shares)
    t <- keyres$source_meta$t %||% n
    for (i in seq_len(n)) {
      files[[sprintf("share_%d", i)]] <- list(
        name = sprintf("share_%d_of_%d.txt", i, n),
        text = paste0(
          sprintf("# shinyEncrypt Shamir share %d of %d (threshold t=%d).\n", i, n, t),
          sprintf("# Distribute to separate custodians. ANY %d of the %d shares\n", t, n),
          "# reconstruct the key on the Decrypt tab; fewer reveal nothing. hex:\n",
          sodium::bin2hex(keyres$shares[[i]]), "\n")
      )
    }
  }
  # OPRF hardening key: the separately-held secret that (with the input) derives
  # the data key. Ideally kept apart from the input, on another device/custodian.
  if (!is.null(keyres$oprf_key)) {
    files[["oprf_key"]] <- list(
      name = "oprf_key.oprfkey",
      text = paste0(
        "# shinyEncrypt OPRF KEY (SECRET) - hardens the input for this file.\n",
        "# Decrypting needs BOTH this key AND the exact input you typed.\n",
        "# Keep it apart from the input (different device/custodian). hex(32 bytes):\n",
        sodium::bin2hex(as_raw(keyres$oprf_key)), "\n")
    )
  }
  # Time-lock creator master: the puzzle solution, letting the owner skip the wait.
  if (!is.null(keyres$timelock_master)) {
    files[["timelock_master"]] <- list(
      name = "timelock_master.key.txt",
      text = paste0(
        "# shinyEncrypt TIME-LOCK MASTER key (the puzzle solution).\n",
        "# It lets YOU decrypt immediately, skipping the time-lock wait.\n",
        "# Keep it private: anyone with it bypasses the delay entirely. hex:\n",
        sodium::bin2hex(as_raw(keyres$timelock_master)), "\n")
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
