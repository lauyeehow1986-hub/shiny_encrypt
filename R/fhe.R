# Fully homomorphic encryption engine (native TFHE backend, Zama tfhe-rs).
#
# Compute on ciphertext: a client encrypts numbers under a secret client key; a
# "server" holding ONLY the evaluation (server) key adds the ciphertexts without
# ever seeing the plaintext or being able to decrypt; the client decrypts the
# single result. This drives the native primitives (native_tfhe_keygen /
# _encrypt / _sum / _decrypt); the tab in R/mod_fhe.R calls fhe_sum_demo().
#
# Heavy tier: TFHE ciphertexts and keys are large and every operation is a
# bootstrapped homomorphic circuit, so the tab is size-guarded (resource_guard)
# and hard-capped on the number of values before it runs.

.fhe_hex <- function(raw) paste(format(as.hexmode(as.integer(raw)), width = 2), collapse = "")

# Encode a non-negative whole number as 8-byte little-endian (u64) raw, matching
# zk_u64() in the Rust backend. Capped at 2^53 so the value survives R's double.
.fhe_u64le <- function(x, what = "value") {
  x <- suppressWarnings(as.numeric(x))
  if (length(x) != 1L || !is.finite(x))
    stop(sprintf("%s must be a single finite number.", what))
  if (x < 0)
    stop(sprintf("%s must be >= 0 \u2014 this FHE demo works on non-negative integers.", what))
  if (x != floor(x))
    stop(sprintf("%s must be a whole number.", what))
  if (x > 2^53)
    stop(sprintf("%s is too large (maximum 2^53).", what))
  b <- integer(8L); v <- x
  for (i in 1:8) { b[i] <- v %% 256; v <- floor(v / 256) }
  as.raw(b)
}

# Read an 8-byte little-endian u64 (a decrypt result) back into an R number.
.fhe_read_u64le <- function(raw) {
  b <- as.integer(raw[1:8]); v <- 0
  for (i in 8:1) v <- v * 256 + b[i]
  v
}

# Pack a vector of non-negative whole numbers into the values blob the native
# encrypt function expects (n contiguous 8-byte LE u64s).
.fhe_pack_values <- function(vals) {
  do.call(c, lapply(seq_along(vals), function(i) .fhe_u64le(vals[i], sprintf("value %d", i))))
}

# Hard cap on how many values we will homomorphically add, independent of the
# RAM guard \u2014 each add is a bootstrapped circuit, so compute time is the limit.
.fhe_max_values <- function() as.integer(getOption("shinyEncrypt.fhe.max", 128L))

.fhe_require <- function() {
  if (!isTRUE(crypto_backend_available("tfhe")))
    stop("Native TFHE backend not built \u2014 run tools/build_native.R and restart.")
}

# End-to-end demonstration for the tab. Encrypts `values` under a fresh client
# key, hands ONLY the server key + ciphertexts to the homomorphic sum, decrypts
# the single result with the client key, and checks it equals the plaintext sum.
# Returns sizes and a ciphertext sample so the UI can show that (a) the server
# never held the secret key and (b) the encrypted result decrypts correctly.
fhe_sum_demo <- function(values) {
  .fhe_require()
  vals <- suppressWarnings(as.numeric(values))
  vals <- vals[is.finite(vals)]
  if (!length(vals)) stop("Provide at least one number to encrypt.")
  vals <- round(vals)
  if (any(vals < 0)) stop("This FHE demo sums non-negative integers.")
  n <- length(vals)
  cap <- .fhe_max_values()
  if (n > cap)
    stop(sprintf("Too many values (%d). The homomorphic sum is capped at %d \u2014 subsample or aggregate first.",
                 n, cap))
  guard <- resource_guard(n, "tfhe")
  if (!isTRUE(guard$ok)) stop(guard$message)
  pt_sum <- sum(vals)
  if (pt_sum > 2^53)
    stop("The plaintext sum exceeds 2^53 \u2014 reduce the values so the check stays exact.")

  # 1. Client generates keys. keygen returns [u32_be ck_len][ck][sk...].
  kk <- native_tfhe_keygen()
  ck_len <- .fhe_u32be(kk[1:4])
  client_key <- kk[(4L + 1L):(4L + ck_len)]
  server_key <- kk[(4L + ck_len + 1L):length(kk)]

  # 2. Client encrypts each value under the client key.
  cts <- native_tfhe_encrypt(client_key, .fhe_pack_values(vals))

  # 3. Server adds the ciphertexts holding ONLY the server key (never client_key).
  enc_result <- native_tfhe_sum(server_key, cts)

  # 4. Client decrypts the single result.
  dec <- .fhe_read_u64le(native_tfhe_decrypt(client_key, enc_result))

  # A sample ciphertext (from the encrypt blob body) \u2014 looks like random bytes.
  ct_len <- .fhe_u32be(cts[5:8])
  sample_ct <- if (length(cts) >= 8L + min(ct_len, 24L))
    cts[(8L + 1L):(8L + min(ct_len, 24L))] else raw(0)

  list(
    success       = TRUE,
    n             = n,
    values_sample = utils::head(vals, 8L),
    fhe_result    = dec,
    plaintext_sum = pt_sum,
    correct       = isTRUE(dec == pt_sum),
    client_key_bytes = length(client_key),
    server_key_bytes = length(server_key),
    ct_each_bytes = ct_len,
    ct_total_bytes = length(cts),
    result_bytes  = length(enc_result),
    sample_ct_hex = .fhe_hex(sample_ct),
    enc_result    = enc_result,
    guard         = guard$message
  )
}

# Read a big-endian u32 from the first 4 bytes of a raw vector.
.fhe_u32be <- function(raw) {
  b <- as.integer(raw[1:4])
  b[1] * 16777216 + b[2] * 65536 + b[3] * 256 + b[4]
}
