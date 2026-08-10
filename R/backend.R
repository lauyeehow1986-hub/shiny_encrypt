# Native-backend capability checks + resource guard.
#
# The Rust (extendr) / C++ (cpp11) crypto crates are optional. Until they are
# built (see tools/setup_toolchain.R and src/rust), every native primitive
# reports unavailable and the pure-R schemes carry the app. Nothing here loads a
# native library yet; it is the single place that will, once compiled.

# Names of capabilities provided by the native package (Phase 4+).
NATIVE_CAPS <- c(
  "argon2id", "ml-kem", "ml-dsa", "slh-dsa", "fn-dsa", "hpke-hybrid",
  "cp-abe", "ibe", "fpe-ff1", "tlock", "shamir", "frost",
  "tfhe", "zk-stark", "psi", "oprf", "opaque", "sse-native"
)  # NB: "pre" is NOT here -- Proxy Re-Encryption lives in the optional GPL
   # companion package shinyEncryptPRE, not the MIT core's native backend.

# Is a native capability available in this session?
crypto_backend_available <- function(name) {
  isTRUE(getOption("shinyEncrypt.native.enabled", FALSE)) &&
    name %in% getOption("shinyEncrypt.native.caps", character())
}

# Locate the built native dll (build artifact from tools/build_native.R).
native_lib_path <- function() {
  cand <- c(
    getOption("shinyEncrypt.native.libpath", ""),   # explicit override (tests/dev)
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
    # Probe which primitives this particular build actually exports, so an older
    # dll (e.g. argon2-only) never advertises PQC it cannot perform.
    has <- function(nm) isTRUE(tryCatch({ getNativeSymbolInfo(nm); TRUE },
                                        error = function(e) FALSE))
    caps <- "argon2id"
    if (has("wrap__native_hybrid_keygen")) caps <- c(caps, "hpke-hybrid")
    if (has("wrap__native_mldsa_keygen"))  caps <- c(caps, "ml-dsa")
    if (has("wrap__native_shamir_split"))  caps <- c(caps, "shamir")
    if (has("wrap__native_ff1_encrypt"))   caps <- c(caps, "fpe-ff1")
    if (has("wrap__native_timelock_generate")) caps <- c(caps, "tlock")
    if (has("wrap__native_cpabe_setup"))   caps <- c(caps, "cp-abe")
    if (has("wrap__native_ibe_setup"))     caps <- c(caps, "ibe")
    if (has("wrap__native_oprf_keygen"))   caps <- c(caps, "oprf")
    if (has("wrap__native_psi_keygen"))    caps <- c(caps, "psi")
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

.require_native <- function() {
  if (!isTRUE(getOption("shinyEncrypt.native.enabled", FALSE)))
    stop("native backend not loaded (build it via tools/build_native.R).")
}

# ---- Hybrid post-quantum KEM (X25519 + ML-KEM-768) -------------------------
# Byte layouts must match src/rust/src/lib.rs.
.HYB <- list(sk = 2432L, pub = 1216L, encap = 1120L, key = 32L)

# Generate a recipient hybrid keypair. Returns list(secret, public) raw bundles.
native_hybrid_keygen <- function() {
  .require_native()
  b <- .Call("wrap__native_hybrid_keygen")
  list(secret = b[seq_len(.HYB$sk)],
       public = b[(.HYB$sk + 1L):length(b)])
}

# Encapsulate to a recipient public bundle. Returns list(encapsulation, key).
native_hybrid_encaps <- function(public_bundle) {
  .require_native()
  out <- .Call("wrap__native_hybrid_encaps", as_raw(public_bundle))
  list(encapsulation = out[seq_len(.HYB$encap)],
       key = out[(.HYB$encap + 1L):length(out)])
}

# Decapsulate with a recipient secret bundle + encapsulation. Returns the key (raw).
native_hybrid_decaps <- function(secret_bundle, encapsulation) {
  .require_native()
  .Call("wrap__native_hybrid_decaps", as_raw(secret_bundle), as_raw(encapsulation))
}

# ---- ML-DSA-65 signatures (FIPS 204) ---------------------------------------
.MLDSA <- list(sk = 4032L, pk = 1952L, sig = 3309L)

# Generate a signing keypair. Returns list(secret, public) raw bundles.
native_mldsa_keygen <- function() {
  .require_native()
  b <- .Call("wrap__native_mldsa_keygen")
  list(secret = b[seq_len(.MLDSA$sk)],
       public = b[(.MLDSA$sk + 1L):length(b)])
}

native_mldsa_sign <- function(secret_key, message) {
  .require_native()
  .Call("wrap__native_mldsa_sign", as_raw(secret_key), as_raw(message))
}

native_mldsa_verify <- function(public_key, message, signature) {
  .require_native()
  identical(.Call("wrap__native_mldsa_verify", as_raw(public_key),
                  as_raw(message), as_raw(signature)), 1L)
}

# ---- Shamir secret sharing (t-of-n) ----------------------------------------
# Split `secret` (raw) into `n` shares, any `t` of which reconstruct it. Returns
# a list of `n` raw share vectors, each (1 + length(secret)) bytes.
native_shamir_split <- function(secret, t, n) {
  .require_native()
  n <- as.integer(n)
  total <- .Call("wrap__native_shamir_split", as_raw(secret), as.integer(t), n)
  sl <- length(total) %/% n
  lapply(seq_len(n), function(i) total[((i - 1L) * sl + 1L):(i * sl)])
}

# Reconstruct the secret from a raw concatenation of >= t shares, each `share_len`
# bytes. Supplying fewer than the original threshold yields a wrong key (the AEAD
# tag then rejects it on decrypt).
native_shamir_combine <- function(shares_concat, share_len) {
  .require_native()
  .Call("wrap__native_shamir_combine", as_raw(shares_concat), as.integer(share_len))
}

# ---- Time-lock puzzle (RSW sequential squaring) ----------------------------
# Generate a puzzle for `t` squarings at an `bits`-bit modulus. Returns
# list(N, b): the modulus and the trapdoor-computed solution, each bits/8 raw
# bytes. Discard `b` unless keeping a creator master key.
native_timelock_generate <- function(bits, t) {
  .require_native()
  bits <- as.integer(bits); L <- bits %/% 8L
  out <- .Call("wrap__native_timelock_generate", bits, as.numeric(t))
  list(N = out[seq_len(L)], b = out[(L + 1L):(2L * L)])
}

# One chunk of the sequential solve: returns x^(2^steps) mod N (raw, length |N|).
native_timelock_solve_steps <- function(x, N, steps) {
  .require_native()
  .Call("wrap__native_timelock_solve_steps", as_raw(x), as_raw(N), as.integer(steps))
}

# Estimate this machine's sequential-squaring rate (squarings/second).
native_timelock_calibrate <- function(bits = 2048L, millis = 300L) {
  .require_native()
  .Call("wrap__native_timelock_calibrate", as.integer(bits), as.integer(millis))
}

# ---- CP-ABE (BSW attribute-based encryption) -------------------------------
# Authority setup. Returns list(pk, mk): the public key (encrypts under a policy,
# shareable) and the master key (issues attribute keys — SECRET). Both are opaque
# serde_json blobs (raw); the native layer packs them as [u32_be pk_len]||pk||mk.
native_cpabe_setup <- function() {
  .require_native()
  out <- .Call("wrap__native_cpabe_setup")
  pk_len <- readBin(as.raw(out[1:4]), "integer", n = 1L, size = 4L, endian = "big")
  list(pk = out[(4L + 1L):(4L + pk_len)],
       mk = out[(4L + pk_len + 1L):length(out)])
}

# Issue an attribute secret key for `attrs` (character vector) from the authority.
# Returns the key as a raw serde_json blob (SECRET, for one recipient).
native_cpabe_keygen <- function(pk, mk, attrs) {
  .require_native()
  .Call("wrap__native_cpabe_keygen", as_raw(pk), as_raw(mk), as.character(attrs))
}

# Seal `plaintext` (raw) under a boolean `policy` string. Returns the ciphertext
# as a raw serde_json blob.
native_cpabe_encrypt <- function(pk, policy, plaintext) {
  .require_native()
  .Call("wrap__native_cpabe_encrypt", as_raw(pk), as.character(policy)[1], as_raw(plaintext))
}

# Recover the sealed bytes if the attribute key `sk` satisfies the ciphertext's
# policy; errors (fails closed) otherwise. Both args are raw serde_json blobs.
native_cpabe_decrypt <- function(sk, ct) {
  .require_native()
  .Call("wrap__native_cpabe_decrypt", as_raw(sk), as_raw(ct))
}

# ---- IBE (Kiltz-Vahlis identity-based encryption) --------------------------
# Authority (PKG) setup. Returns list(pk, msk): the public key (encrypts to any
# identity, shareable) and the master key (extracts per-identity keys — SECRET).
# Both are opaque fixed-size raw blobs; native packs them as [u32_be pk_len]||pk||msk.
native_ibe_setup <- function() {
  .require_native()
  out <- .Call("wrap__native_ibe_setup")
  pk_len <- readBin(as.raw(out[1:4]), "integer", n = 1L, size = 4L, endian = "big")
  list(pk = out[(4L + 1L):(4L + pk_len)],
       mk = out[(4L + pk_len + 1L):length(out)])
}

# Extract the user secret key for `identity` from the authority (pk, msk).
# Returns the key as a raw blob (SECRET, for that one identity holder).
native_ibe_extract <- function(pk, mk, identity) {
  .require_native()
  .Call("wrap__native_ibe_extract", as_raw(pk), as_raw(mk), as.character(identity)[1])
}

# Seal a fresh 32-byte data key to `identity` under the authority public key.
# Returns list(ct, key): ct is the raw ciphertext (stored in the envelope), key
# is the 32-byte data key to use for AEAD. Native packs [u32_be ct_len]||ct||key.
native_ibe_encaps <- function(pk, identity) {
  .require_native()
  out <- .Call("wrap__native_ibe_encaps", as_raw(pk), as.character(identity)[1])
  ct_len <- readBin(as.raw(out[1:4]), "integer", n = 1L, size = 4L, endian = "big")
  list(ct = out[(4L + 1L):(4L + ct_len)],
       key = out[(4L + ct_len + 1L):length(out)])
}

# Recover the 32-byte data key: decapsulate `ct` with the identity's user key.
# Errors (fails closed) if the key was issued for a different identity.
native_ibe_decaps <- function(usk, ct) {
  .require_native()
  .Call("wrap__native_ibe_decaps", as_raw(usk), as_raw(ct))
}

# ---- OPRF (verifiable oblivious PRF, ristretto255 + SHA-512) ---------------
# A VOPRF computes F_k(input) so that the key holder never sees `input` and the
# client never learns k; the output is pseudorandom in (input, k). Used here to
# harden a low-entropy input with a separately-held OPRF key (see R/oprf.R).

# 32-byte OPRF secret key (a ristretto255 scalar).
native_oprf_keygen <- function() {
  .require_native()
  .Call("wrap__native_oprf_keygen")
}

# Public verification key k*G (32 bytes) for an OPRF secret key.
native_oprf_public_key <- function(key) {
  .require_native()
  .Call("wrap__native_oprf_public_key", as_raw(key))
}

# Client blind step: returns blind_scalar(32) || blinded_element(32). The blinded
# element hides `input` (raw) from the OPRF key holder.
native_oprf_blind <- function(input) {
  .require_native()
  .Call("wrap__native_oprf_blind", as_raw(input))
}

# Server evaluate step: E = k*B plus a DLEQ proof. Returns evaluated(32) ||
# dleq_c(32) || dleq_z(32). The key holder sees only the blinded element.
native_oprf_evaluate <- function(key, blinded) {
  .require_native()
  .Call("wrap__native_oprf_evaluate", as_raw(key), as_raw(blinded))
}

# Client finalize: verify the DLEQ proof (fails closed), unblind, and return the
# 64-byte PRF output. Deterministic in (input, key) despite the random blind.
native_oprf_finalize <- function(input, blind_bundle, evaluated, pubkey) {
  .require_native()
  .Call("wrap__native_oprf_finalize", as_raw(input), as_raw(blind_bundle),
        as_raw(evaluated), as_raw(pubkey))
}

# ---- PSI (private set intersection, ECDH / DH-PSI on ristretto255) ----------
# Two parties learn only the overlap of their sets. Each masks with its own
# secret scalar; the group's commutativity makes a shared element land on the
# same doubly-masked point. Only masked points cross between parties (R/psi.R
# drives the two-party protocol). Elements are length-prefixed raw so arbitrary
# identifiers round-trip exactly.

# 32-byte PSI masking scalar (secret to one party).
native_psi_keygen <- function() {
  .require_native()
  .Call("wrap__native_psi_keygen")
}

# Hash + mask own elements: `elements` is a length-prefixed blob (see
# .psi_pack_elements); returns n*32 bytes (one compressed point per element).
native_psi_hash_mask <- function(scalar, elements) {
  .require_native()
  .Call("wrap__native_psi_hash_mask", as_raw(scalar), as_raw(elements))
}

# Re-mask the other party's masked points: `points` is k*32 bytes; returns the
# same length (each point multiplied by `scalar`). Invalid points fail closed.
native_psi_mask_points <- function(scalar, points) {
  .require_native()
  .Call("wrap__native_psi_mask_points", as_raw(scalar), as_raw(points))
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
