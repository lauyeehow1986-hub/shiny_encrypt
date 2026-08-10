# Private Set Intersection (PSI) tab — find the overlap between two parties'
# identifier lists without either side revealing its full list. Shipped as a
# single-machine two-party simulation with an exportable wire transcript (see
# R/psi.R for the ECDH-PSI protocol). Needs the native backend.

ui_psi <- function() {
  bslib::layout_sidebar(
    sidebar = bslib::sidebar(
      width = 380, title = "Private set intersection",
      shiny::helpText(
        "Find which identifiers two datasets share — without either side ",
        "revealing its non-shared rows. Upload both sets, pick the ID column in ",
        "each, and only the overlap is revealed."),
      shiny::tags$b(class = "small", "Party A (your set)"),
      shiny::fileInput("psi_a_file", "Dataset A (CSV / XLSX)",
                       accept = c(".csv", ".tsv", ".xlsx", ".xls")),
      shiny::uiOutput("psi_a_col"),
      shiny::tags$hr(),
      shiny::tags$b(class = "small", "Party B (their set)"),
      shiny::fileInput("psi_b_file", "Dataset B (CSV / XLSX)",
                       accept = c(".csv", ".tsv", ".xlsx", ".xls")),
      shiny::uiOutput("psi_b_col"),
      shiny::actionButton("psi_run", "Compute private intersection",
                          class = "btn-primary w-100 mb-1"),
      .disclaimer()
    ),
    bslib::card(
      bslib::card_header("Private set intersection"),
      bslib::card_body(
        shiny::uiOutput("psi_status"),
        shiny::verbatimTextOutput("psi_result"),
        shiny::tableOutput("psi_table"),
        shiny::uiOutput("psi_transcript"),
        shiny::uiOutput("psi_downloads")
      )
    )
  )
}

psi_server <- function(input, output, session, rv) {

  psi_a_data <- shiny::reactive({
    shiny::req(input$psi_a_file)
    fpe_read_df(input$psi_a_file$datapath, input$psi_a_file$name)
  })
  psi_b_data <- shiny::reactive({
    shiny::req(input$psi_b_file)
    fpe_read_df(input$psi_b_file$datapath, input$psi_b_file$name)
  })

  output$psi_a_col <- shiny::renderUI({
    df <- tryCatch(psi_a_data(), error = function(e) NULL)
    shiny::req(df)
    shiny::selectInput("psi_a_colname", "ID column in A", choices = names(df))
  })
  output$psi_b_col <- shiny::renderUI({
    df <- tryCatch(psi_b_data(), error = function(e) NULL)
    shiny::req(df)
    shiny::selectInput("psi_b_colname", "ID column in B", choices = names(df))
  })

  shiny::observeEvent(input$psi_run, {
    tryCatch({
      if (!isTRUE(crypto_backend_available("psi")))
        stop("Native PSI backend not built — run tools/build_native.R and restart.")
      dfa <- psi_a_data(); dfb <- psi_b_data()
      ca <- input$psi_a_colname; cb <- input$psi_b_colname
      shiny::req(ca, cb)
      res <- shiny::withProgress(message = "Running private intersection…", value = 0.5,
                                 psi_two_party(dfa[[ca]], dfb[[cb]]))
      rv$psi_out <- c(res, list(a_df = dfa, a_col = ca,
                                name_a = input$psi_a_file$name,
                                name_b = input$psi_b_file$name))
      rv$psi_msg <- NULL
    }, error = function(e) { rv$psi_out <- NULL; rv$psi_msg <- conditionMessage(e) })
  })

  output$psi_status <- shiny::renderUI({
    if (!isTRUE(crypto_backend_available("psi")))
      return(shiny::div(class = "alert alert-warning small py-2",
        shiny::HTML("Private set intersection needs the native backend. Build it via <code>tools/build_native.R</code> and restart the app.")))
    shiny::tagList(
      if (!is.null(rv$psi_msg))
        shiny::div(class = "alert alert-danger py-2 small", rv$psi_msg),
      shiny::div(class = "alert alert-info small py-2",
        shiny::HTML(paste0(
          "Each identifier is hashed to a curve point and masked with a per-party secret. ",
          "Only the <b>masked points</b> (uniform-random without the other party's secret) cross the wire — ",
          "the raw lists never do. The party running the match learns the overlap and the other set's <i>size</i>, ",
          "nothing more. Honest-but-curious two-party model, simulated on one machine.")))
    )
  })

  output$psi_result <- shiny::renderText({
    o <- rv$psi_out
    if (is.null(o))
      return("Upload two datasets, choose the ID column in each, and compute the intersection.")
    hdr <- "Private set intersection"
    paste(c(
      hdr, strrep("-", nchar(hdr)),
      sprintf("Set A            : %s unique IDs", format(o$n_a, big.mark = ",")),
      sprintf("Set B            : %s unique IDs", format(o$n_b, big.mark = ",")),
      sprintf("Shared (A ∩ B)   : %s IDs", format(o$n_inter, big.mark = ",")),
      sprintf("Jaccard overlap  : %.4f", o$jaccard),
      "",
      "Only the shared IDs are revealed. B's non-shared rows stay private."
    ), collapse = "\n")
  })

  output$psi_table <- shiny::renderTable({
    o <- rv$psi_out
    if (is.null(o) || length(o$intersection) == 0L) return(NULL)
    utils::head(data.frame(shared_id = o$intersection, check.names = FALSE), 200L)
  })

  output$psi_transcript <- shiny::renderUI({
    o <- rv$psi_out
    if (is.null(o)) return(NULL)
    preview <- utils::head(o$transcript$a_masked, 4L)
    shiny::tagList(
      shiny::tags$hr(),
      shiny::div(class = "small text-muted",
        sprintf("Wire transcript — the %d masked points party A sends look like random 32-byte values:",
                length(o$transcript$a_masked))),
      shiny::tags$pre(class = "small", paste(preview, collapse = "\n"))
    )
  })

  output$psi_downloads <- shiny::renderUI({
    o <- rv$psi_out
    if (is.null(o) || o$n_inter == 0L) return(NULL)
    shiny::tagList(
      shiny::div(class = "d-inline-block me-2 mb-2",
        shiny::downloadButton("psi_dl_inter", "Download shared IDs (CSV)",
                              class = "btn-outline-primary")),
      shiny::div(class = "d-inline-block me-2 mb-2",
        shiny::downloadButton("psi_dl_rows", "Download matched rows of A (CSV)",
                              class = "btn-outline-primary")),
      shiny::div(class = "d-inline-block me-2 mb-2",
        shiny::downloadButton("psi_dl_transcript", "Download exchange transcript",
                              class = "btn-outline-secondary")))
  })

  output$psi_dl_inter <- shiny::downloadHandler(
    filename = function() "psi_shared_ids.csv",
    content  = function(file)
      utils::write.csv(data.frame(shared_id = rv$psi_out$intersection),
                       file, row.names = FALSE, na = ""))

  output$psi_dl_rows <- shiny::downloadHandler(
    filename = function() paste0("psi_matched_", tools::file_path_sans_ext(rv$psi_out$name_a), ".csv"),
    content  = function(file) {
      o <- rv$psi_out
      keep <- as.character(o$a_df[[o$a_col]]) %in% o$intersection
      utils::write.csv(o$a_df[keep, , drop = FALSE], file, row.names = FALSE, na = "")
    })

  output$psi_dl_transcript <- shiny::downloadHandler(
    filename = function() "psi_wire_transcript.txt",
    content  = function(file) {
      o <- rv$psi_out
      writeLines(c(
        "# shinyEncrypt PSI — wire transcript (what would cross between parties)",
        "# Each line is a masked ristretto255 point (hex). Uniform-random without",
        "# the receiving party's secret scalar; reveals nothing about the raw IDs.",
        sprintf("# A sent %d masked points, B sent %d masked points.",
                length(o$transcript$a_masked), length(o$transcript$b_masked)),
        "",
        "[A -> B] masked set A:",
        o$transcript$a_masked,
        "",
        "[B -> A] masked set B:",
        o$transcript$b_masked
      ), file)
    })
}
