suppressMessages({library(shiny);library(bslib);library(sodium);library(openssl);library(digest);library(jsonlite);library(readr);library(readxl)})
invisible(lapply(list.files("R", pattern="[.]R$", full.names=TRUE), source))
register_all_schemes()
ui <- app_ui(); cat("UI class:", class(ui)[1], "\n")
cat("server is function:", is.function(app_server), "\n")
s <- list_schemes()[,c("tier","label","available")]
print(s, row.names=FALSE)
