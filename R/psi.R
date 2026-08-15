# Private Set Intersection (ECDH / DH-PSI) \u2014 a single-machine two-party
# simulation. Two parties each hold a set of identifiers and want to learn only
# which ones they share, revealing nothing about the rest.
#
# Protocol (both parties honest-but-curious):
#   A has secret scalar a and set X; B has secret scalar b and set Y.
#   1. A sends {a*H(x)}            (masked X \u2014 looks like random points)
#   2. B returns {b*a*H(x)} and sends {b*H(y)}
#   3. A computes {a*b*H(y)} from B's masked Y
#   Now A holds ab*H(x) for its own set and ab*H(y) for B's; equal points mark
#   shared elements, because the group is commutative (a*b == b*a). Only masked
#   points ever cross between the parties \u2014 never the raw identifiers.
#
# Native primitives live in R/backend.R (native_psi_*); this file packs elements,
# runs the exchange, and compares the doubly-masked points. It reuses the same
# ristretto255 group as the OPRF module.

# Pack a character vector into the length-prefixed blob the native layer expects:
# for each element, [u32 big-endian length][UTF-8 bytes]. Raw bytes (not R
# strings) keep arbitrary identifiers round-tripping exactly.
.psi_pack_elements <- function(x) {
  x <- enc2utf8(as.character(x))
  if (length(x) == 0L) return(raw(0))
  parts <- lapply(x, function(e) {
    b <- charToRaw(e)
    c(writeBin(length(b), raw(), size = 4L, endian = "big"), b)
  })
  do.call(c, parts)
}

# Split a concatenation of 32-byte points into one hex string per point, so set
# membership can be tested with %in%. Vectorised sprintf keeps this fast.
.psi_point_hex <- function(raw_pts) {
  n <- length(raw_pts) %/% 32L
  if (n == 0L) return(character(0))
  m  <- matrix(as.integer(raw_pts), nrow = 32L)      # 32 x n
  hx <- matrix(sprintf("%02x", m), nrow = 32L)
  apply(hx, 2L, paste0, collapse = "")
}

# Normalise a party's set: coerce to character, drop NA/empty, de-duplicate
# (PSI is a set operation, so duplicates would only distort the counts).
.psi_prep_set <- function(x) {
  x <- as.character(x)
  x <- x[!is.na(x) & nzchar(x)]
  unique(x)
}

# Run the two-party PSI on two character vectors. Returns the intersection (as
# seen by party A), the set sizes, the Jaccard index, and the wire transcript
# (the single-masked points each party would actually send).
psi_two_party <- function(a_elems, b_elems,
                          max_size = getOption("shinyEncrypt.psi.max", 200000L)) {
  if (!isTRUE(crypto_backend_available("psi")))
    stop("Native PSI backend not built \u2014 run tools/build_native.R and restart.")
  a <- .psi_prep_set(a_elems)
  b <- .psi_prep_set(b_elems)
  if (length(a) == 0L || length(b) == 0L)
    stop("Both sets must have at least one non-empty value.")
  if (length(a) > max_size || length(b) > max_size)
    stop(sprintf(
      "PSI set too large (A: %d, B: %d; cap is %d). Subsample or raise the guard.",
      length(a), length(b), max_size))

  ka <- native_psi_keygen()
  kb <- native_psi_keygen()

  # Party A masks its set, party B re-masks it (double-masked, aligned to a).
  a_masked <- native_psi_hash_mask(ka, .psi_pack_elements(a))
  a_double <- native_psi_mask_points(kb, a_masked)
  # Party B masks its set, party A re-masks it (double-masked, aligned to b).
  b_masked <- native_psi_hash_mask(kb, .psi_pack_elements(b))
  b_double <- native_psi_mask_points(ka, b_masked)

  a_hex <- .psi_point_hex(a_double)
  b_hex <- .psi_point_hex(b_double)
  inter <- a[a_hex %in% b_hex]

  union_n <- length(a) + length(b) - length(inter)
  list(
    intersection = inter,
    n_a = length(a), n_b = length(b), n_inter = length(inter),
    jaccard = if (union_n > 0L) length(inter) / union_n else 0,
    # The transcript is exactly what a real counterparty would receive: masked
    # points that are uniform-random without the other party's scalar.
    transcript = list(a_masked = .psi_point_hex(a_masked),
                      b_masked = .psi_point_hex(b_masked))
  )
}
