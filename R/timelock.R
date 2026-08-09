# Time-lock encryption (RSW sequential-squaring puzzle) — R-side orchestration.
#
# The native backend (R/backend.R) supplies three primitives:
#   native_timelock_generate(bits, t)        -> list(N, b)   [trapdoor fast-path]
#   native_timelock_solve_steps(x, N, steps)                 [one slow chunk]
#   native_timelock_calibrate(bits, millis)  -> rate          [squarings/second]
# This file owns the mask derivation, the delay<->squaring-count calibration, and
# the chunked solve loop, all in pure R so they stay testable without Shiny.
#
# A fresh random data key K is sealed by XOR-masking it with H(b), where b is the
# puzzle solution. Only b (and thus K) is recovered by paying the sequential
# compute; the trappor is destroyed at seal time, so nobody holds a shortcut.

TIMELOCK_BASE <- 2L                        # base a; the solve starts from x = 2
.TL_DOMAIN    <- "shinyEncrypt-timelock-v1"

# 32-byte mask derived from the puzzle solution b (domain-separated SHA-256).
timelock_mask <- function(b) {
  digest::digest(c(charToRaw(.TL_DOMAIN), as.raw(b)),
                 algo = "sha256", serialize = FALSE, raw = TRUE)
}

# XOR two equal-length raw vectors (used to mask/unmask the data key).
.tl_xor <- function(a, b) as.raw(bitwXor(as.integer(as.raw(a)), as.integer(as.raw(b))))

# Convert a target delay (seconds) + measured rate (squarings/s) into a squaring
# count T, floored to a sane minimum so the puzzle is never trivial.
timelock_squarings <- function(target_seconds, rate) {
  target_seconds <- max(as.numeric(target_seconds), 0)
  rate <- max(as.numeric(rate), 1)
  max(round(target_seconds * rate), 1e5)
}

# Solve the puzzle: T sequential squarings, done in chunks so the caller can show
# progress. `on_progress(done, total)` runs after each chunk. Returns b (raw).
timelock_solve <- function(N, t, chunk = NULL, on_progress = NULL) {
  t <- as.numeric(t); L <- length(N)
  if (is.null(chunk) || chunk < 1) chunk <- max(200000, ceiling(t / 200))
  x <- as.raw(c(rep(0L, L - 1L), TIMELOCK_BASE))   # x = 2 (big-endian, |N| bytes)
  done <- 0
  while (done < t) {
    step <- min(chunk, t - done)
    x <- native_timelock_solve_steps(x, N, step)
    done <- done + step
    if (is.function(on_progress)) on_progress(done, t)
  }
  x
}

# Cache the calibrated squaring rate per modulus size (machine-global; the rate
# does not vary by session). Calibrating blocks ~0.3s, so we do it once per size.
.tl_rate_cache <- new.env(parent = emptyenv())
tl_current_rate <- function(bits) {
  k <- as.character(as.integer(bits))
  if (is.null(.tl_rate_cache[[k]]))
    .tl_rate_cache[[k]] <- tryCatch(native_timelock_calibrate(as.integer(bits), 300L),
                                    error = function(e) NA_real_)
  .tl_rate_cache[[k]]
}

# Human-readable delay ("10 minutes", "1.5 hours") for hints and summaries.
.tl_human <- function(secs) {
  secs <- as.numeric(secs)
  if (!is.finite(secs)) return("an unknown delay")
  units <- c(86400, 3600, 60, 1); names(units) <- c("day", "hour", "minute", "second")
  for (i in seq_along(units)) {
    if (secs >= units[i]) {
      v <- round(secs / units[i], 1)
      return(sprintf("%s %s%s", format(v, trim = TRUE), names(units)[i],
                     if (v == 1) "" else "s"))
    }
  }
  sprintf("%.1f seconds", secs)
}
