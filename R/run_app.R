#' Launch the shinyEncrypt application.
#'
#' @param ... passed to shiny::runApp / shinyApp options (e.g. port, launch.browser)
#' @export
run_app <- function(...) {
  register_all_schemes()
  shiny::shinyApp(ui = app_ui(), server = app_server, ...)
}
