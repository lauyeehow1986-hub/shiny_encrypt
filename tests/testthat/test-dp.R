# Differential privacy mechanisms (R/dp.R). Pure R — no native backend needed.
# Assertions are chosen to be robust to the (secure) randomness: at epsilon = 50
# the discrete-Laplace noise is exactly 0 (the smallest 48-bit uniform still far
# exceeds exp(-50)), so counts are deterministic; continuous mechanisms use wide,
# never-fail tolerances.

test_that("secure uniforms land strictly inside (0, 1)", {
  u <- vapply(1:2000, function(i) dp_secure_unit(), numeric(1))
  expect_true(all(u > 0 & u < 1))
  expect_length(dp_secure_units(5L), 5L)
  expect_lt(abs(mean(u) - 0.5), 0.05)          # ~7 SE — effectively never fails
})

test_that("clamping bounds values and rejects a bad range", {
  expect_equal(dp_clamp(c(-5, 3, 20), 0, 10), c(0, 3, 10))
  expect_error(dp_clamp(1, 10, 0), "lower")
})

test_that("discrete Laplace noise is integer-valued and ~symmetric", {
  nz <- dp_discrete_laplace_noise(0.5, 1, 3000L)
  expect_true(all(nz == round(nz)))            # integers
  expect_lt(abs(mean(nz)), 0.5)                # mean near 0
  expect_error(dp_discrete_laplace_noise(0, 1, 1L), "epsilon")
})

test_that("count is a non-negative integer and exact at high epsilon", {
  expect_identical(dp_count(1000, 50), 1000L)  # noise is 0 at epsilon = 50
  expect_true(dp_count(0, 0.5) >= 0L)          # post-processed to be non-negative
  expect_true(dp_count(37, 50) == 37L)
})

test_that("histogram preserves length, stays non-negative integer, exact at high epsilon", {
  counts <- c(300L, 150L, 50L, 0L)
  h <- dp_histogram(counts, 50)
  expect_identical(h, counts)                  # exact at epsilon = 50
  expect_length(dp_histogram(counts, 0.5), length(counts))
  expect_true(all(dp_histogram(counts, 0.5) >= 0L))
})

test_that("sum clamps then adds bounded noise", {
  v <- c(1e9, -1e9, 5, 3, 2)                    # extreme values must be clamped
  r <- dp_sum(v, 0, 10, 50, "laplace")          # clamped true sum = 10 + 0 + 5 + 3 + 2 = 20
  expect_true(is.finite(r))
  expect_lt(abs(r - 20), 200)                   # Laplace(scale=0.2) — |noise| tiny
  expect_lt(r, 1000)                            # nowhere near the unclamped 1e9
  expect_error(dp_sum(1, 0, 10, 0), "epsilon")
})

test_that("mean is close to the clamped mean at high epsilon (both mechanisms)", {
  v <- seq(0, 100, length.out = 500)
  truth <- mean(v)
  expect_lt(abs(dp_mean(v, 0, 100, 50, "laplace") - truth), 1)
  expect_lt(abs(dp_mean(v, 0, 100, 50, "gaussian", 1e-6) - truth), 1)
  expect_error(dp_mean(numeric(0), 0, 1, 1), "no finite")
})

test_that("Gaussian sigma is positive and scales inversely with epsilon", {
  s1 <- dp_gaussian_sigma(1.0, 1e-6, 1)
  s2 <- dp_gaussian_sigma(0.5, 1e-6, 1)
  expect_true(s1 > 0 && s2 > s1)               # smaller epsilon -> more noise
  expect_error(dp_gaussian_sigma(1, 1.0, 1), "delta")
})

test_that("Laplace noise has roughly the right spread", {
  nz <- dp_laplace_noise(3, 5000L)             # Var = 2*scale^2 = 18, sd ~ 4.24
  expect_lt(abs(mean(nz)), 1)
  expect_true(sd(nz) > 2 && sd(nz) < 7)        # wide band — robust to randomness
})
