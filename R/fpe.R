# Format-preserving encryption (FF1) for column-level de-identification.
#
# FF1 (NIST SP 800-38G; FF3-1 was withdrawn in 2025) maps a field to another
# field of the SAME length over the SAME alphabet, deterministically \u2014 the same
# key+tweak+value always yields the same token, so joins on a tokenised
# identifier survive. The native primitive (native_ff1_*) operates on sequences
# of numerals; this file owns the character<->numeral mapping, the passthrough
# of non-alphabet characters, and the per-value domain rule, keeping all of that
# testable in pure R.
#
# HONEST CAVEAT: deterministic FPE is PSEUDONYMISATION, not anonymisation. It
# hides an identifier's content but preserves value frequencies and linkage, so
# it does not defend against frequency analysis.

# Built-in alphabets. radix = nchar(chars); characters outside the chosen
# alphabet (spaces, '-', '/', \u2026) are passed through unchanged, so the overall
# format is preserved and the passthrough positions are identical on encrypt and
# decrypt (FF1 preserves length + character class).
FPE_ALPHABETS <- list(
  digits      = list(id = "digits",      chars = "0123456789"),
  alnum_upper = list(id = "alnum_upper", chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
  alnum       = list(id = "alnum",
                     chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
)

fpe_alphabet_by_id <- function(id) {
  a <- FPE_ALPHABETS[[id]]
  if (is.null(a)) stop(sprintf("Unknown FPE alphabet id: %s", id))
  a
}

# Minimum number of alphabet characters a value must contain to be encryptable:
# FF1 requires radix^len >= 1e6 (and len >= 2). Shorter values are left as-is.
fpe_min_len <- function(radix) max(2L, as.integer(ceiling(6 / log10(radix))))

# Pick the smallest built-in alphabet that covers the letter classes present.
fpe_detect_alphabet <- function(values) {
  v <- as.character(values); v <- v[!is.na(v)]
  if (!length(v)) return(FPE_ALPHABETS$digits)
  blob <- paste(v, collapse = "")
  if (grepl("[a-z]", blob)) return(FPE_ALPHABETS$alnum)         # any lowercase -> radix 62
  if (grepl("[A-Z]", blob)) return(FPE_ALPHABETS$alnum_upper)   # digits + upper -> radix 36
  FPE_ALPHABETS$digits                                          # digits only -> radix 10
}

fpe_resolve_alphabet <- function(mode, values) {
  switch(mode %||% "auto",
    "digits"      = FPE_ALPHABETS$digits,
    "alnum_upper" = FPE_ALPHABETS$alnum_upper,
    "alnum"       = FPE_ALPHABETS$alnum,
    fpe_detect_alphabet(values))          # "auto" (and any unknown) => detect
}

# ---- native wrapper --------------------------------------------------------
# numerals: integer vector, each in 0..(radix-1). Returns an integer vector of
# the same length. tweak is bound as bytes (non-secret domain separator).
native_ff1 <- function(key, tweak, radix, numerals, encrypt = TRUE) {
  .require_native()
  sym <- if (encrypt) "wrap__native_ff1_encrypt" else "wrap__native_ff1_decrypt"
  out <- .Call(sym, as_raw(key), as_raw(tweak), as.integer(radix),
               as.raw(as.integer(numerals)))
  as.integer(out)
}

# ---- one column ------------------------------------------------------------
# Tokenise (or restore) one character vector under a fixed alphabet + tweak.
# Values with fewer than fpe_min_len(radix) alphabet characters are returned
# unchanged in BOTH directions (the skip condition is length-preserving, so it
# is identical on encrypt and decrypt). Returns the transformed values + counts.
fpe_column <- function(values, key, tweak, alphabet, encrypt = TRUE) {
  ch    <- as.character(values)
  alpha <- strsplit(alphabet$chars, "", fixed = TRUE)[[1]]
  radix <- length(alpha)
  ml    <- fpe_min_len(radix)
  out <- ch; n_tok <- 0L; n_short <- 0L; n_na <- 0L
  for (i in seq_along(ch)) {
    v <- ch[i]
    if (is.na(v)) { n_na <- n_na + 1L; next }
    chars   <- strsplit(v, "", fixed = TRUE)[[1]]
    pos     <- match(chars, alpha)          # NA where a character is passthrough
    enc_idx <- which(!is.na(pos))
    if (length(enc_idx) < ml) { n_short <- n_short + 1L; next }
    out_num <- native_ff1(key, tweak, radix, pos[enc_idx] - 1L, encrypt = encrypt)
    chars[enc_idx] <- alpha[out_num + 1L]
    out[i] <- paste(chars, collapse = "")
    n_tok <- n_tok + 1L
  }
  list(values = out, n_tokenised = n_tok, n_short = n_short, n_na = n_na)
}

# ---- whole table -----------------------------------------------------------
# Apply FF1 to selected columns. tweak defaults to the column NAME, so equal
# values in different columns tokenise differently, while the same column across
# files tokenises consistently (joins survive). Returns the transformed df, a
# recipe for exact reversal, and per-column counts.
fpe_apply_table <- function(df, cols, key, mode = "auto") {
  df <- as.data.frame(df, stringsAsFactors = FALSE)
  recipe <- list(); stats <- list()
  for (col in cols) {
    if (!col %in% names(df)) stop(sprintf("Column '%s' not found.", col))
    alphabet <- fpe_resolve_alphabet(mode, df[[col]])
    r <- fpe_column(df[[col]], key, col, alphabet, encrypt = TRUE)
    df[[col]] <- r$values
    recipe[[length(recipe) + 1L]] <- list(name = col, alphabet = alphabet$id,
                                           radix = nchar(alphabet$chars), tweak = col)
    stats[[col]] <- r[c("n_tokenised", "n_short", "n_na")]
  }
  list(df = df, recipe = recipe, stats = stats)
}

# Reverse using a parsed kit (key + per-column recipe).
fpe_reverse_table <- function(df, kit) {
  df  <- as.data.frame(df, stringsAsFactors = FALSE)
  key <- sodium::hex2bin(kit$key)
  for (c in kit$columns) {
    if (!c$name %in% names(df))
      stop(sprintf("Column '%s' from the recipe is not in this file.", c$name))
    df[[c$name]] <- fpe_column(df[[c$name]], key, c$tweak,
                               fpe_alphabet_by_id(c$alphabet), encrypt = FALSE)$values
  }
  df
}

# ---- reversible "kit" (secret key + recipe) --------------------------------
# The kit carries the FPE key, so it is SECRET; it is downloaded alongside the
# de-identified CSV and is all that is needed (plus the CSV) to reverse.
fpe_build_kit <- function(key, recipe) {
  as.character(jsonlite::toJSON(
    list(v = 1L, alg = "ff1-aes256", key = sodium::bin2hex(as_raw(key)),
         columns = recipe),
    auto_unbox = TRUE, pretty = TRUE))
}

fpe_parse_kit <- function(txt) {
  kit <- jsonlite::fromJSON(paste(txt, collapse = "\n"), simplifyDataFrame = FALSE)
  if (is.null(kit$key) || is.null(kit$columns))
    stop("Not a valid .fpekit (missing key or column recipe).")
  kit
}

# Read a CSV/XLSX to a data.frame with every column as character, so leading
# zeros and other formatting survive round-trip (crucial for ID columns).
fpe_read_df <- function(path, name = path) {
  ext <- tolower(tools::file_ext(name %||% path))
  if (ext %in% c("xlsx", "xls"))
    as.data.frame(readxl::read_excel(path, col_types = "text"), stringsAsFactors = FALSE)
  else
    as.data.frame(readr::read_csv(path, col_types = readr::cols(.default = "c"),
                                  show_col_types = FALSE, progress = FALSE),
                  stringsAsFactors = FALSE)
}
