suppressMessages({library(shiny);library(sodium);library(openssl);library(digest);library(jsonlite);library(readr);library(readxl);library(testthat)})
invisible(lapply(list.files("R", pattern="[.]R$", full.names=TRUE), source))
reporter <- testthat::test_dir("tests/testthat", stop_on_failure=TRUE, reporter="summary")
