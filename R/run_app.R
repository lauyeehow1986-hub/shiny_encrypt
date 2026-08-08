#' Launch the shinyEncrypt application.
#'
#' @param max_upload_mb maximum upload size in MB (default 1024 = 1 GB).
#' @param ... passed to shiny::runApp / shinyApp options (e.g. port, launch.browser)
#' @export
run_app <- function(max_upload_mb = 1024, ...) {
  register_all_schemes()
  options(shiny.maxRequestSize = max_upload_mb * 1024^2)
  shiny::shinyApp(ui = app_ui(), server = app_server, ...)
}
