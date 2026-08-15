# Zero-knowledge range-proof tab. A prover shows that a hidden value lies in a
# public range [min, max] without revealing it; a verifier checks the proof file
# and learns only that the statement holds. Self-contained on ristretto255 (see
# R/zk.R) \u2014 no trusted setup. Needs the native backend.

ui_zk <- function() {
  bslib::layout_sidebar(
    sidebar = bslib::sidebar(
      width = 380, title = "Zero-knowledge range proof",
      shiny::helpText(
        "Prove that a hidden number lies within a range \u2014 e.g. \u201Cmy cohort ",
        "size is between 100 and 500\u201D \u2014 without revealing the number itself."),
      shiny::tags$b(class = "small", "1. Choose the hidden value"),
      shiny::radioButtons("zk_source", NULL,
        choices = c("Type a number" = "type",
                    "Row count of a dataset" = "rows",
                    "Sum of a numeric column" = "sum"),
        selected = "type"),
      shiny::conditionalPanel("input.zk_source == 'type'",
        shiny::numericInput("zk_value", "Hidden value", value = 300, min = 0, step = 1)),
      shiny::conditionalPanel("input.zk_source != 'type'",
        shiny::fileInput("zk_infile", "Dataset (CSV/XLSX/RDS)",
                         accept = c(".csv", ".xlsx", ".xls", ".rds", ".txt")),
        shiny::helpText(class = "small text-muted",
          "The value is computed from your data and never shown \u2014 only the ",
          "in-range proof leaves this machine.")),
      shiny::conditionalPanel("input.zk_source == 'sum'",
        shiny::uiOutput("zk_col_ui")),
      shiny::div(class = "row g-2",
        shiny::div(class = "col-6",
          shiny::numericInput("zk_min", "Range min", value = 100, min = 0, step = 1)),
        shiny::div(class = "col-6",
          shiny::numericInput("zk_max", "Range max", value = 500, min = 0, step = 1))),
      shiny::actionButton("zk_prove", "Create range proof",
                          class = "btn-primary w-100 mb-2"),
      shiny::tags$hr(),
      shiny::tags$b(class = "small", "2. Verify a proof file"),
      shiny::helpText(class = "small text-muted",
        "The bounds travel inside the proof \u2014 the verifier needs only the file."),
      shiny::fileInput("zk_verify_file", NULL, accept = c(".txt", ".bin", ".proof")),
      shiny::actionButton("zk_verify", "Verify uploaded proof",
                          class = "btn-outline-primary w-100 mb-1"),
      .disclaimer()
    ),
    bslib::card(
      bslib::card_header("Prove a value is in range without revealing it"),
      bslib::card_body(
        shiny::uiOutput("zk_status"),
        shiny::uiOutput("zk_prove_out"),
        shiny::uiOutput("zk_transcript"),
        shiny::uiOutput("zk_downloads"),
        shiny::uiOutput("zk_verify_out")
      )
    )
  )
}

zk_server <- function(input, output, session, rv) {

  # Optional dataset for the "row count" / "column sum" value sources.
  zk_data <- shiny::reactive({
    shiny::req(input$zk_infile)
    fpe_read_df(input$zk_infile$datapath, input$zk_infile$name)
  })

  output$zk_col_ui <- shiny::renderUI({
    df <- tryCatch(zk_data(), error = function(e) NULL)
    shiny::req(df)
    num <- names(df)[vapply(df, function(c)
      any(is.finite(suppressWarnings(as.numeric(c)))), logical(1))]
    shiny::selectInput("zk_col", "Numeric column to sum",
                       choices = if (length(num)) num else names(df))
  })

  # Resolve the (hidden) value from the chosen source.
  zk_value_of <- function() {
    switch(input$zk_source,
      "type" = as.numeric(input$zk_value),
      "rows" = nrow(zk_data()),
      "sum"  = {
        df <- zk_data()
        col <- input$zk_col %||% names(df)[1]
        vals <- suppressWarnings(as.numeric(df[[col]]))
        if (!any(is.finite(vals))) stop("Selected column has no numeric values.")
        max(0, round(sum(vals[is.finite(vals)])))
      })
  }

  shiny::observeEvent(input$zk_prove, {
    tryCatch({
      if (!isTRUE(crypto_backend_available("zk-range")))
        stop("Native zero-knowledge backend not built \u2014 run tools/build_native.R and restart.")
      val <- zk_value_of()
      rv$zk_res <- zk_demo(val, as.numeric(input$zk_min), as.numeric(input$zk_max))
      rv$zk_msg <- NULL
    }, error = function(e) { rv$zk_res <- NULL; rv$zk_msg <- conditionMessage(e) })
  })

  shiny::observeEvent(input$zk_verify, {
    tryCatch({
      if (!isTRUE(crypto_backend_available("zk-range")))
        stop("Native zero-knowledge backend not built \u2014 run tools/build_native.R and restart.")
      shiny::req(input$zk_verify_file)
      raw <- .zk_read_proof_file(input$zk_verify_file$datapath)
      ok <- tryCatch(zk_range_verify(raw), error = function(e) NA)
      rv$zk_verify_res <- list(ok = ok, bytes = length(raw),
                               name = input$zk_verify_file$name)
      rv$zk_verify_msg <- NULL
    }, error = function(e) { rv$zk_verify_res <- NULL; rv$zk_verify_msg <- conditionMessage(e) })
  })

  output$zk_status <- shiny::renderUI({
    if (!isTRUE(crypto_backend_available("zk-range")))
      return(shiny::div(class = "alert alert-warning small py-2",
        shiny::HTML("Zero-knowledge range proofs need the native backend. Build it via <code>tools/build_native.R</code> and restart the app.")))
    shiny::tagList(
      if (!is.null(rv$zk_msg))
        shiny::div(class = "alert alert-danger py-2 small", rv$zk_msg),
      shiny::div(class = "alert alert-info small py-2",
        shiny::HTML(paste0(
          "The value is hidden inside a <b>Pedersen commitment</b> ",
          "C = v\u00B7G + r\u00B7H. A per-bit <b>OR proof</b> shows it decomposes ",
          "into bits within the range, and a matching proof on (max \u2212 v) pins ",
          "it from above \u2014 together proving <b>min \u2264 v \u2264 max</b> while ",
          "revealing nothing else. No trusted setup; verifiable by anyone.")))
    )
  })

  output$zk_prove_out <- shiny::renderUI({
    o <- rv$zk_res
    if (is.null(o)) return(NULL)
    if (!isTRUE(o$success)) {
      return(shiny::div(class = "alert alert-danger py-2 small mt-2",
        shiny::HTML(sprintf(paste0(
          "<b>No proof produced.</b> The value is not inside [%s, %s], and a false ",
          "statement cannot be proved \u2014 it failed closed: %s"),
          .zk_fmt(o$min), .zk_fmt(o$max), o$error))))
    }
    shiny::tagList(
      shiny::div(class = "alert alert-success py-2 small mt-2",
        shiny::HTML(sprintf(paste0(
          "<b>Proved:</b> the hidden value lies in [%s, %s]. The verifier %s, and ",
          "the value is never revealed. Proof: %d bytes, %d-bit range."),
          .zk_fmt(o$min), .zk_fmt(o$max),
          if (isTRUE(o$verified)) "<b>accepts</b>"
          else "<span class='text-danger'>does NOT accept</span>",
          o$size, o$bits))),
      shiny::div(class = "alert py-2 small",
        class = if (isTRUE(o$tamper_rejected)) "alert-secondary" else "alert-danger",
        shiny::HTML(if (isTRUE(o$tamper_rejected))
          "<b>Tamper check:</b> flipping a single byte of the proof makes the verifier reject it."
        else "<b>Tamper check FAILED:</b> a modified proof still verified (this should not happen).")))
  })

  output$zk_transcript <- shiny::renderUI({
    o <- rv$zk_res
    if (is.null(o) || !isTRUE(o$success)) return(NULL)
    lines <- c(
      sprintf("statement : min <= (hidden value) <= max, for [%s, %s]",
              .zk_fmt(o$min), .zk_fmt(o$max)),
      sprintf("bit width : %d  (two-sided; %d bit-OR proofs)", o$bits, 2L * o$bits),
      sprintf("proof size: %d bytes", o$size),
      sprintf("verifies  : %s", if (isTRUE(o$verified)) "yes" else "NO"),
      sprintf("commitment: %s\u2026", substr(.zk_hex(utils::head(o$proof, 25L)[-(1:2)]), 1L, 48L)))
    shiny::tagList(
      shiny::tags$hr(),
      shiny::div(class = "small text-muted", "Proof transcript:"),
      shiny::tags$pre(class = "small", paste(lines, collapse = "\n"))
    )
  })

  output$zk_downloads <- shiny::renderUI({
    o <- rv$zk_res
    if (is.null(o) || !isTRUE(o$success)) return(NULL)
    shiny::div(class = "d-inline-block me-2 mb-2 mt-1",
      shiny::downloadButton("zk_dl_proof", "Download proof file",
                            class = "btn-outline-secondary"))
  })

  output$zk_dl_proof <- shiny::downloadHandler(
    filename = function() "zk_range_proof.txt",
    content  = function(file) {
      o <- rv$zk_res
      writeLines(c(
        "# shinyEncrypt zero-knowledge range proof (ristretto255)",
        "# Proves a hidden value lies in [min, max]; the value is NOT here.",
        sprintf("# range : [%s, %s]", .zk_fmt(o$min), .zk_fmt(o$max)),
        sprintf("# bits  : %d", o$bits),
        sprintf("# bytes : %d", o$size),
        "# proof (hex):",
        .zk_hex(o$proof)
      ), file)
    })

  output$zk_verify_out <- shiny::renderUI({
    v <- rv$zk_verify_res
    if (is.null(v) && is.null(rv$zk_verify_msg)) return(NULL)
    shiny::tagList(
      shiny::tags$hr(),
      if (!is.null(rv$zk_verify_msg))
        shiny::div(class = "alert alert-danger py-2 small", rv$zk_verify_msg),
      if (!is.null(v)) {
        if (isTRUE(v$ok))
          shiny::div(class = "alert alert-success py-2 small",
            shiny::HTML(sprintf("<b>Proof valid.</b> \u201C%s\u201D (%d bytes) proves its hidden value is in range.",
                                v$name, v$bytes)))
        else
          shiny::div(class = "alert alert-danger py-2 small",
            shiny::HTML(sprintf("<b>Proof rejected.</b> \u201C%s\u201D did not verify \u2014 it is invalid or was altered.",
                                v$name)))
      }
    )
  })
}

# Read a proof back from a downloaded file: either the hex-in-a-comment-wrapped
# .txt this tab writes, or a raw binary blob.
.zk_read_proof_file <- function(path) {
  txt <- tryCatch(readLines(path, warn = FALSE), error = function(e) character())
  hexlines <- txt[grepl("^[0-9a-fA-F]+$", trimws(txt)) & nchar(trimws(txt)) > 1L]
  if (length(hexlines)) {
    hx <- paste(trimws(hexlines), collapse = "")
    if (nchar(hx) %% 2L == 0L)
      return(as.raw(strtoi(substring(hx, seq(1L, nchar(hx), 2L), seq(2L, nchar(hx), 2L)), 16L)))
  }
  readBin(path, "raw", n = file.info(path)$size)
}

# Format a bound for display without scientific notation.
.zk_fmt <- function(x) format(x, scientific = FALSE, trim = TRUE)
