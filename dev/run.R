# Dev launcher — works from any working directory.
# PowerShell:  & "C:/Program Files/R/R-4.5.2/bin/x64/Rscript.exe" "C:/Users/lauye/Downloads/shiny_embedding_crytography/dev/run.R"
# Locate this script's own directory, then the package root (its parent).
.args <- commandArgs(trailingOnly = FALSE)
.self <- sub("^--file=", "", .args[grepl("^--file=", .args)])
.root <- if (length(.self)) normalizePath(file.path(dirname(.self), "..")) else getwd()
setwd(.root)

suppressMessages({
  library(shiny); library(bslib); library(sodium); library(openssl)
  library(digest); library(jsonlite); library(readr); library(readxl)
})
invisible(lapply(list.files(file.path(.root, "R"), pattern = "[.]R$", full.names = TRUE), source))
register_all_schemes()
options(shiny.maxRequestSize = 1024 * 1024^2)   # 1 GB uploads
cat("shinyEncrypt loading from:", .root, "\n")
shiny::runApp(shiny::shinyApp(app_ui(), app_server),
              host = "127.0.0.1", port = 7788, launch.browser = TRUE)
