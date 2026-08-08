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
  isTRUE(getOption("shinyEncrypt.native.enabled", FALSE)) &&
    name %in% getOption("shinyEncrypt.native.caps", character())
}

# Locate the built native dll (build artifact from tools/build_native.R).
native_lib_path <- function() {
  cand <- c(
    system.file("libs", "x64", "shinyencrypt_native.dll", package = "shinyEncrypt"),
    file.path(getwd(), "inst", "libs", "x64", "shinyencrypt_native.dll"),
    file.path(getOption("shinyEncrypt.root", getwd()), "inst", "libs", "x64",
              "shinyencrypt_native.dll")
  )
  cand <- cand[nzchar(cand) & file.exists(cand)]
  if (length(cand)) normalizePath(cand[1], winslash = "/") else ""
}

# dyn.load the native backend if it was built, and advertise its capabilities.
# Safe to call repeatedly; a missing/failed lib just leaves the pure-R path in
# place (options stay FALSE). Returns TRUE if the native backend is active.
load_native_backend <- function(quiet = TRUE) {
  if (isTRUE(getOption("shinyEncrypt.native.enabled", FALSE))) return(TRUE)
  path <- native_lib_path()
  if (!nzchar(path)) return(FALSE)
  # The dll imports R.dll; make sure R's bin dir is resolvable at load time.
  if (.Platform$OS.type == "windows") {
    rbin <- file.path(R.home(), "bin", "x64")
    if (dir.exists(rbin) && !grepl(rbin, Sys.getenv("PATH"), fixed = TRUE))
      Sys.setenv(PATH = paste(rbin, Sys.getenv("PATH"), sep = .Platform$path.sep))
  }
  ok <- tryCatch({
    if (!is.loaded("wrap__native_backend_version")) dyn.load(path)
    ver <- .Call("wrap__native_backend_version")
    caps <- c("argon2id")   # capabilities compiled into this build
    options(shinyEncrypt.native.enabled = TRUE,
            shinyEncrypt.native.caps = caps,
            shinyEncrypt.native.version = ver)
    if (!quiet) message("shinyEncrypt native backend v", ver,
                        " loaded (", paste(caps, collapse = ", "), ").")
    TRUE
  }, error = function(e) {
    if (!quiet) message("native backend not loaded: ", conditionMessage(e))
    FALSE
  })
  isTRUE(ok)
}

# ---- R wrappers over native primitives (only call when available) ----------

# Real Argon2id KDF. secret/salt are raw; returns `size` raw bytes.
native_argon2id <- function(secret, salt, mem_kib = 19456L, iters = 2L,
                            lanes = 1L, size = 32L) {
  if (!crypto_backend_available("argon2id"))
    stop("native argon2id not available (build it via tools/build_native.R).")
  .Call("wrap__native_argon2id", as_raw(secret), as_raw(salt),
        as.integer(mem_kib), as.integer(iters), as.integer(lanes), as.integer(size))
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
