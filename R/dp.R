# Differential privacy — mechanisms for releasing noisy aggregate statistics.
#
# This is a *privacy layer*, not encryption: it lets you publish counts / sums /
# means over a table while provably bounding how much any single row can influence
# the result (the (epsilon, delta) guarantee). It powers the "Private stats (DP)"
# tab. Pure R; noise is drawn from a cryptographically secure source (openssl).
#
# Design choices for real, honest guarantees:
#  * Counts / histograms use the DISCRETE Laplace (two-sided geometric) mechanism,
#    which returns integers and side-steps the floating-point vulnerabilities that
#    can undermine a naive continuous Laplace sampler (Mironov 2012).
#  * Sums / means clamp every value into a caller-supplied [lower, upper] range so
#    the sensitivity is bounded, then add continuous Laplace or Gaussian noise. The
#    continuous samplers carry the standard FP caveat (documented in-app).
#  * Composition is sequential: releasing k queries spends the sum of their epsilon
#    (and delta). Disjoint histogram bins compose in PARALLEL — one epsilon covers
#    the whole histogram.

# ---- secure randomness -----------------------------------------------------

# A single uniform in the open interval (0, 1) from 48 secure bits (exactly
# representable in a double). Rejects the endpoints so log()/sign() are safe.
dp_secure_unit <- function() {
  repeat {
    b <- as.numeric(openssl::rand_bytes(6L))          # 6 bytes = 48 bits
    u <- sum(b * 256^(0:5)) / 2^48
    if (u > 0 && u < 1) return(u)
  }
}

# n independent secure uniforms in (0, 1).
dp_secure_units <- function(n = 1L) vapply(seq_len(n), function(i) dp_secure_unit(), numeric(1))

# ---- noise distributions ---------------------------------------------------

# Continuous Laplace(0, scale) via inverse-CDF on a secure uniform.
dp_laplace_noise <- function(scale, n = 1L) {
  u <- dp_secure_units(n) - 0.5                         # (-0.5, 0.5)
  -scale * sign(u) * log(1 - 2 * abs(u))
}

# Secure standard normals via Box-Muller (two secure uniforms per value).
dp_normal <- function(n = 1L) {
  u1 <- dp_secure_units(n); u2 <- dp_secure_units(n)
  sqrt(-2 * log(u1)) * cos(2 * pi * u2)
}

# Gaussian noise scale for the classical (epsilon, delta) mechanism. Valid for
# 0 < epsilon < 1; larger epsilon still gives a (looser but valid) guarantee.
dp_gaussian_sigma <- function(epsilon, delta, sensitivity) {
  if (epsilon <= 0 || delta <= 0 || delta >= 1) stop("epsilon > 0 and 0 < delta < 1 required.")
  sqrt(2 * log(1.25 / delta)) * sensitivity / epsilon
}
dp_gaussian_noise <- function(sigma, n = 1L) sigma * dp_normal(n)

# Geometric(number of failures) with P(G >= g) = ratio^g, via inverse-CDF.
dp_rgeom <- function(ratio, n = 1L) floor(log(dp_secure_units(n)) / log(ratio))

# Discrete Laplace (two-sided geometric): integer noise with P(k) proportional to
# exp(-epsilon |k| / sensitivity). FP-robust — the released value is an integer.
dp_discrete_laplace_noise <- function(epsilon, sensitivity = 1, n = 1L) {
  if (epsilon <= 0) stop("epsilon must be > 0.")
  ratio <- exp(-epsilon / sensitivity)
  dp_rgeom(ratio, n) - dp_rgeom(ratio, n)
}

# ---- clamping --------------------------------------------------------------

dp_clamp <- function(x, lower, upper) {
  if (upper < lower) stop("upper bound must be >= lower bound.")
  pmin(pmax(x, lower), upper)
}

# ---- query mechanisms ------------------------------------------------------

# Differentially private count of n rows (sensitivity 1). Post-processed to be a
# non-negative integer (post-processing preserves the DP guarantee).
dp_count <- function(n, epsilon) {
  val <- n + dp_discrete_laplace_noise(epsilon, 1, 1L)
  max(0L, as.integer(round(val)))
}

# DP histogram over disjoint groups: add independent discrete-Laplace noise to
# each bin. Bins are disjoint, so a single epsilon covers the whole histogram
# (parallel composition). Returns non-negative integer counts.
dp_histogram <- function(counts, epsilon) {
  counts <- as.numeric(counts)
  noise <- dp_discrete_laplace_noise(epsilon, 1, length(counts))
  pmax(0L, as.integer(round(counts + noise)))
}

# DP sum of a numeric column, clamped to [lower, upper]. Sensitivity = upper-lower.
dp_sum <- function(values, lower, upper, epsilon,
                   mechanism = c("laplace", "gaussian"), delta = 1e-6) {
  mechanism <- match.arg(mechanism)
  if (epsilon <= 0) stop("epsilon must be > 0.")
  x <- dp_clamp(values[is.finite(values)], lower, upper)
  sens <- abs(upper - lower)
  noise <- if (mechanism == "gaussian")
    dp_gaussian_noise(dp_gaussian_sigma(epsilon, delta, sens))
  else dp_laplace_noise(sens / epsilon)
  sum(x) + noise
}

# DP mean of a numeric column, clamped to [lower, upper]. The row count n is
# treated as public (it is the size of the uploaded file, not a sensitive query),
# so the mean's sensitivity is (upper-lower)/n.
dp_mean <- function(values, lower, upper, epsilon,
                    mechanism = c("laplace", "gaussian"), delta = 1e-6) {
  mechanism <- match.arg(mechanism)
  if (epsilon <= 0) stop("epsilon must be > 0.")
  x <- dp_clamp(values[is.finite(values)], lower, upper)
  n <- length(x)
  if (n == 0L) stop("no finite values to average.")
  sens <- abs(upper - lower) / n
  noise <- if (mechanism == "gaussian")
    dp_gaussian_noise(dp_gaussian_sigma(epsilon, delta, sens))
  else dp_laplace_noise(sens / epsilon)
  mean(x) + noise
}
