# FROST \u2014 t-of-n threshold Schnorr signatures over ristretto255 (RFC 9591 in
# shape), shipped as a single-machine simulation. A group of n custodians shares
# one signing key so that any t of them can jointly produce ONE ordinary Schnorr
# signature under a single group public key \u2014 and no custodian ever holds the
# whole key. Fewer than t cannot sign.
#
# The native layer (R/backend.R) does the crypto; this file plays the trusted
# dealer plus every participant and the coordinator, forwarding only the
# fixed-length message blobs:
#   Keygen   dealer -> group public key + one signing share per custodian.
#   Sign     round 1: each chosen signer commits to two nonces;
#            round 2: given the whole commitment set, each emits a share z_i;
#            the coordinator sums the shares into one signature (R, z) and
#            verifies it under the group public key.
#
# A quorum below the threshold fails closed: the shares no longer interpolate the
# group secret, so the aggregated signature does not verify and aggregation errors.

.frost_hex <- function(raw) paste(sprintf("%02x", as.integer(raw)), collapse = "")

.frost_u16be <- function(x) {
  x <- as.integer(x)
  as.raw(c(x %/% 256L, x %% 256L))
}

.frost_msg_raw <- function(message) {
  message <- as.character(message)
  if (length(message) != 1L || is.na(message) || !nzchar(message))
    stop("Enter a (non-empty) message to sign.")
  charToRaw(enc2utf8(message))
}

.frost_require <- function() {
  if (!isTRUE(crypto_backend_available("frost")))
    stop("Native FROST backend not built \u2014 run tools/build_native.R and restart.")
}

# Pack the round-1 commitments into the shared signing package the native signer
# and aggregator both consume: count(u16 be) || each(id u16 be || D(32) || E(32)).
.frost_pack_package <- function(entries) {
  parts <- lapply(entries, function(e) c(.frost_u16be(e$id), as.raw(e$commitment)))
  c(.frost_u16be(length(entries)), do.call(c, parts))
}

# Trusted-dealer keygen: deal a fresh t-of-n group. Returns the group public key,
# the per-custodian signing shares (each with its identifier), and t/n.
frost_keygen <- function(t, n) {
  .frost_require()
  t <- as.integer(t); n <- as.integer(n)
  if (is.na(t) || is.na(n) || t < 1L || n < 1L || t > n)
    stop("Require 1 <= threshold t <= number of participants n.")
  if (n > 255L) stop("Keep n <= 255 for this simulation.")
  blob <- native_frost_keygen(t, n)             # group_pk(32) || n*(id2||share32)
  group_pk <- blob[1:32]
  shares <- lapply(seq_len(n), function(i) {
    off <- 32L + (i - 1L) * 34L
    id <- as.integer(blob[off + 1L]) * 256L + as.integer(blob[off + 2L])
    list(id = id, share = blob[(off + 3L):(off + 34L)])
  })
  list(group_pk = group_pk, shares = shares, t = t, n = n)
}

# Sign `message` with the custodians named in `signer_ids`. Runs both rounds over
# the simulated boundary and aggregates. On a valid quorum returns the signature
# and a TRUE verification; a sub-threshold (or wrong) quorum returns success =
# FALSE with the fail-closed reason. `shares`/`package` are kept for the transcript.
frost_sign <- function(message, keys, signer_ids) {
  .frost_require()
  msg <- .frost_msg_raw(message)
  ids <- as.integer(signer_ids)
  ids <- ids[!is.na(ids)]
  if (!length(ids)) stop("Pick at least one participant to sign.")
  if (anyDuplicated(ids)) stop("Each participant can sign only once.")
  known <- vapply(keys$shares, function(s) s$id, integer(1))
  if (!all(ids %in% known)) stop("A selected participant is not in this group.")

  share_for <- function(id) keys$shares[[match(id, known)]]$share

  # Round 1 \u2014 every chosen signer commits to two fresh nonces.
  rounds <- lapply(ids, function(id) {
    cm <- native_frost_commit()                 # nonce(64) || commitment(64)
    list(id = id, nonce = cm[1:64], commitment = cm[65:128])
  })
  package <- .frost_pack_package(
    lapply(rounds, function(r) list(id = r$id, commitment = r$commitment)))

  # Round 2 \u2014 every signer emits a share bound to the whole commitment set.
  zs <- lapply(rounds, function(r)
    native_frost_sign(share_for(r$id), r$id, r$nonce, msg, package, keys$group_pk))
  shares_concat <- do.call(c, zs)

  fail <- function(e) list(
    success = FALSE, error = conditionMessage(e), signer_ids = ids,
    message = message, threshold = keys$t, n = keys$n,
    commitments = lapply(rounds, function(r) list(id = r$id, commitment = r$commitment)),
    package = package, shares = zs, signature = NULL, verified = FALSE)

  # Aggregate \u2014 sums the shares and verifies; errors if the quorum is too small
  # or a share is bad (the fail-closed path).
  agg <- tryCatch(native_frost_aggregate(package, msg, keys$group_pk, shares_concat),
                  error = function(e) e)
  if (inherits(agg, "error")) return(fail(agg))

  list(success = TRUE, signature = agg,
       verified = native_frost_verify(keys$group_pk, msg, agg),
       signer_ids = ids, message = message, threshold = keys$t, n = keys$n,
       commitments = lapply(rounds, function(r) list(id = r$id, commitment = r$commitment)),
       package = package, shares = zs)
}
