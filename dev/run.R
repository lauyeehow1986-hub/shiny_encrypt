suppressMessages({library(shiny);library(bslib);library(sodium);library(openssl);library(digest);library(jsonlite);library(readr);library(readxl)})
invisible(lapply(list.files("R", pattern="[.]R$", full.names=TRUE), source))
register_all_schemes()
shiny::runApp(shiny::shinyApp(app_ui(), app_server), host="127.0.0.1", port=7788, launch.browser=FALSE)
