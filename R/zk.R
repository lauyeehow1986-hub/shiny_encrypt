# Zero-knowledge range proof engine (native curve25519-dalek backend).
#
# Prove that a hidden value lies in a public range [min, max] without revealing
# it. A Pedersen commitment hides the value; a per-bit Chaum-Pedersen OR proof
# (made non-interactive with Fiat-Shamir) shows it decomposes into bits inside
# the range. Self-contained on ristretto255 \u2014 no trusted setup. The proof blob
# does NOT contain the value: a verifier learns only that the statement holds.
#
# This drives the native primitives (native_zk_range_prove / _verify); the tab
# in R/mod_zk.R calls zk_demo() to prove, verify, and show that a tampered proof
# and a false statement both fail closed.

.zk_hex <- function(raw) paste(format(as.hexmode(as.integer(raw)), width = 2), collapse = "")

# Encode a non-negative whole number as 8-byte little-endian (u64) raw, matching
# zk_u64() in the Rust backend. Capped at 2^53 so the value survives R's double.
.zk_u64le <- function(x, what = "value") {
  x <- suppressWarnings(as.numeric(x))
  if (length(x) != 1L || !is.finite(x))
    stop(sprintf("%s must be a single finite number.", what))
  if (x < 0)
    stop(sprintf("%s must be >= 0 \u2014 this range proof works on non-negative integers.", what))
  if (x != floor(x))
    stop(sprintf("%s must be a whole number.", what))
  if (x > 2^53)
    stop(sprintf("%s is too large (maximum 2^53).", what))
  b <- integer(8L); v <- x
  for (i in 1:8) { b[i] <- v %% 256; v <- floor(v / 256) }
  as.raw(b)
}

# Number of bits the range (max - min) occupies \u2014 the proof's per-side bit width.
.zk_bits <- function(min, max) {
  r <- max - min
  if (r <= 0) 1L else as.integer(floor(log2(r)) + 1L)
}

.zk_require <- function() {
  if (!isTRUE(crypto_backend_available("zk-range")))
    stop("Native zero-knowledge backend not built \u2014 run tools/build_native.R and restart.")
}

# Produce a range proof that a hidden `value` lies in [min, max]. Returns the raw
# proof blob. Fails closed (errors) if value is outside the range \u2014 you cannot
# prove a false statement.
zk_range_prove <- function(value, min, max) {
  .zk_require()
  if (max < min) stop("max must be >= min.")
  native_zk_range_prove(.zk_u64le(value, "value"),
                        .zk_u64le(min, "min"),
                        .zk_u64le(max, "max"))
}

# Verify a range proof (the bounds are embedded in the blob). TRUE/FALSE.
zk_range_verify <- function(proof) {
  .zk_require()
  native_zk_range_verify(proof)
}

# End-to-end demonstration for the tab: prove the hidden value is in range, then
# show that (a) the proof verifies, (b) a single flipped byte makes it reject,
# and (c) a value outside the range cannot be proved at all. `value` is never
# returned or embedded \u2014 only the fact that it lies in [min, max].
zk_demo <- function(value, min, max) {
  .zk_require()
  if (!is.finite(suppressWarnings(as.numeric(value))))
    stop("Provide a numeric value to prove.")
  if (max < min) stop("max must be >= min.")
  bits <- .zk_bits(min, max)

  res <- tryCatch({
    proof <- zk_range_prove(value, min, max)
    verified <- zk_range_verify(proof)

    # Tamper demo: flip one byte inside the proof body (past the header) and
    # confirm the verifier rejects it. Verify may error on a malformed blob, so
    # treat any non-TRUE result as "rejected".
    tam <- proof
    idx <- min(length(tam), 51L)           # first byte of the bit-proof body
    tam[idx] <- as.raw(bitwXor(as.integer(tam[idx]), 1L))
    tamper_rejected <- !isTRUE(tryCatch(zk_range_verify(tam), error = function(e) FALSE))

    list(success = TRUE, proof = proof, verified = verified,
         tamper_rejected = tamper_rejected, min = min, max = max,
         bits = bits, size = length(proof), in_range = TRUE)
  }, error = function(e) {
    # The prover refused: value is outside [min, max] (or another failure). This
    # is the point \u2014 a false statement is unprovable.
    list(success = FALSE, error = conditionMessage(e), min = min, max = max,
         bits = bits, in_range = FALSE)
  })
  res
}
