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

# Read an input file to the raw bytes that will be encrypted.
# Returns list(raw, kind, preview, orig_name).
import_to_raw <- function(path, kind = c("auto", "csv", "xlsx", "rds", "binary"),
                          orig_name = basename(path)) {
  kind <- match.arg(kind)
  if (kind == "auto") kind <- detect_kind(path)

  preview <- NULL
  raw <- switch(kind,
    "csv" = {
      df <- readr::read_csv(path, show_col_types = FALSE, progress = FALSE)
      df <- as.data.frame(df)
      preview <- utils::head(df, 20L)
      serialize(df, connection = NULL)
    },
    "xlsx" = {
      df <- as.data.frame(readxl::read_excel(path))
      preview <- utils::head(df, 20L)
      serialize(df, connection = NULL)
    },
    "rds" = {
      readBin(path, "raw", n = file.info(path)$size)
    },
    "binary" = {
      readBin(path, "raw", n = file.info(path)$size)
    }
  )
  list(raw = raw, kind = kind, preview = preview, orig_name = orig_name)
}

# Restore the original object from decrypted bytes (for CSV/XLSX kinds).
restore_object <- function(raw, kind) {
  if (kind %in% c("csv", "xlsx")) unserialize(raw) else raw
}

raw_to_base64 <- function(raw) openssl::base64_encode(as_raw(raw))
base64_to_raw <- function(txt) openssl::base64_decode(gsub("[[:space:]]", "", txt))

gzip_raw   <- function(raw) memCompress(as_raw(raw), type = "gzip")
gunzip_raw <- function(raw) memDecompress(as_raw(raw), type = "gzip")
