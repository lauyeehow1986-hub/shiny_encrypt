# Native-backend capability checks + resource guard.
#
# The Rust (extendr) / C++ (cpp11) crypto crates are optional. Until they are
# built (see tools/setup_toolchain.R and src/rust), every native primitive
# reports unavailable and the pure-R schemes carry the app. Nothing here loads a
# native library yet; it is the single place that will, once compiled.

# Names of capabilities provided by the native package (Phase 4+).
NATIVE_CAPS <- c(
  "argon2id", "ml-kem", "ml-dsa", "slh-dsa", "fn-dsa", "hpke-hybrid",
  "cp-abe", "ibe", "fpe-ff1", "pre", "tlock", "shamir", "frost",
  "tfhe", "zk-stark", "psi", "oprf", "opaque", "sse-native"
)

# Is a native capability available in this session?
crypto_backend_available <- function(name) {
  # Placeholder: the native package is not built in this environment.
  # When built, this will test `requireNamespace("shinyEncryptNative")` and the
  # crate's own feature flags / CUDA probe.
  isTRUE(getOption("shinyEncrypt.native.enabled", FALSE)) &&
    name %in% getOption("shinyEncrypt.native.caps", character())
}

native_backends_status <- function() {
  data.frame(
    capability = NATIVE_CAPS,
    available  = vapply(NATIVE_CAPS, crypto_backend_available, logical(1)),
    row.names  = NULL
  )
}

# Rough pre-flight for [Heavy] schemes against the 24 GB RAM / 8 GB VRAM budget.
# `cells` = rows * cols (or number of encrypted values). Returns list(ok, message).
resource_guard <- function(cells, scheme = "tfhe",
                           ram_gb = 24, vram_gb = 8) {
  cells <- as.numeric(cells %||% 0)
  # Very rough per-value ciphertext/工作-set estimates (MB) for gating only.
  per_cell_mb <- switch(scheme,
    "tfhe"     = 0.05,     # TFHE ciphertext + bootstrap keys are large (working set)
    "zk-stark" = 0.02,
    "oram"     = 0.01,
    0.001
  )
  est_gb <- cells * per_cell_mb / 1024
  budget <- min(ram_gb, if (scheme == "tfhe") vram_gb * 3 else ram_gb)
  ok <- est_gb <= budget * 0.6
  list(
    ok = ok,
    est_gb = round(est_gb, 2),
    message = sprintf(
      "%s: ~%.2f GB working set for %d values (budget ~%.0f GB). %s",
      scheme, est_gb, as.integer(cells), budget,
      if (ok) "OK to run." else "Exceeds guard — reduce data size or subsample."
    )
  )
}
