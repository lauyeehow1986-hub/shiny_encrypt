# Small shared helpers.

`%||%` <- function(a, b) if (is.null(a) || length(a) == 0L) b else a

# Coerce character/raw input to a raw vector.
as_raw <- function(x) {
  if (is.raw(x)) return(x)
  if (is.character(x)) return(charToRaw(paste(x, collapse = "")))
  stop("Expected raw or character input.")
}

# ISO-8601 UTC timestamp.
now_utc <- function() format(as.POSIXct(Sys.time(), tz = "UTC"), "%Y-%m-%dT%H:%M:%SZ")

# Guard: ensure a key is exactly n bytes, hashing it down if not.
coerce_key <- function(key, n = 32L) {
  key <- as_raw(key)
  if (length(key) == n) return(key)
  sodium::sha256(key)[seq_len(n)]
}
