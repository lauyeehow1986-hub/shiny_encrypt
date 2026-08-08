# Import + (de)serialize + Base64, plus optional gzip.
#
# CSV/XLSX are read into a data.frame and serialized (R's native serialize()),
# so the encrypted payload is a faithful RDS-equivalent that can be restored and
# re-materialized to CSV/XLSX on decrypt. RDS / other binaries are taken verbatim.

detect_kind <- function(path) {
  ext <- tolower(tools::file_ext(path))
  switch(ext,
    "csv"  = "csv",
    "tsv"  = "csv",
    "xlsx" = "xlsx",
    "xls"  = "xlsx",
    "rds"  = "rds",
    "binary"
  )
}

# Cap a data.frame preview so wide/tall tables never flood the browser.
.cap_preview <- function(df, max_rows = 10L, max_cols = 15L) {
  full <- dim(df)
  pv <- df[seq_len(min(max_rows, nrow(df))),
           seq_len(min(max_cols, ncol(df))), drop = FALSE]
  list(preview = pv, dims = full,
       truncated = full[1] > max_rows || full[2] > max_cols)
}

# Read an input file to the raw bytes that will be encrypted.
# Returns list(raw, kind, preview, dims, truncated, orig_name).
import_to_raw <- function(path, kind = c("auto", "csv", "xlsx", "rds", "binary"),
                          orig_name = basename(path)) {
  kind <- match.arg(kind)
  if (kind == "auto") kind <- detect_kind(path)

  preview <- NULL; dims <- NULL; truncated <- FALSE
  raw <- switch(kind,
    "csv" = {
      df <- as.data.frame(readr::read_csv(path, show_col_types = FALSE, progress = FALSE))
      cp <- .cap_preview(df); preview <- cp$preview; dims <- cp$dims; truncated <- cp$truncated
      serialize(df, connection = NULL)
    },
    "xlsx" = {
      df <- as.data.frame(readxl::read_excel(path))
      cp <- .cap_preview(df); preview <- cp$preview; dims <- cp$dims; truncated <- cp$truncated
      serialize(df, connection = NULL)
    },
    "rds" = readBin(path, "raw", n = file.info(path)$size),
    "binary" = readBin(path, "raw", n = file.info(path)$size)
  )
  list(raw = raw, kind = kind, preview = preview, dims = dims,
       truncated = truncated, orig_name = orig_name)
}

# Restore the original object from decrypted bytes (for CSV/XLSX kinds).
restore_object <- function(raw, kind) {
  if (kind %in% c("csv", "xlsx")) unserialize(raw) else raw
}

raw_to_base64 <- function(raw) openssl::base64_encode(as_raw(raw))
base64_to_raw <- function(txt) openssl::base64_decode(gsub("[[:space:]]", "", txt))

gzip_raw   <- function(raw) memCompress(as_raw(raw), type = "gzip")
gunzip_raw <- function(raw) memDecompress(as_raw(raw), type = "gzip")
