# Dev loader: source the engine + register schemes without installing the package.
# Usage:  source("dev/load.R")  from the package root, or Rscript dev/load.R
if (!exists(".SE_ROOT")) {
  .SE_ROOT <- tryCatch(dirname(dirname(normalizePath(sys.frame(1)$ofile))),
                       error = function(e) getwd())
}
suppressMessages({
  library(sodium); library(openssl); library(digest)
  library(jsonlite); library(readr); library(readxl)
})
.se_rfiles <- list.files(file.path(.SE_ROOT, "R"), pattern = "\\.R$", full.names = TRUE)
invisible(lapply(.se_rfiles, source))
register_all_schemes()
