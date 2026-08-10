# Compute-on-ciphertext tab (fully homomorphic encryption, Zama tfhe-rs).
#
# A client encrypts numbers under a secret key; a "server" holding only the
# evaluation key adds the ciphertexts without decrypting; the client decrypts
# the single result and confirms it equals the plaintext sum. Demonstrates that
# the server computed on data it could never read. Heavy tier: size-guarded and
# capped (see R/fhe.R). Needs the native backend.

ui_fhe <- function() {
  bslib::layout_sidebar(
    sidebar = bslib::sidebar(
      width = 380, title = "Compute on ciphertext (FHE)",
      shiny::helpText(
        "Encrypt numbers, let an untrusted server add them together while they ",
        "stay encrypted, then decrypt only the result. The server never sees ",
        "the values and cannot decrypt anything."),
      shiny::tags$b(class = "small", "Numbers to encrypt and sum"),
      shiny::radioButtons("fhe_source", NULL,
        choices = c("Type numbers" = "type",
                    "Numeric column of a dataset" = "col"),
        selected = "type"),
      shiny::conditionalPanel("input.fhe_source == 'type'",
        shiny::textInput("fhe_values", "Comma-separated non-negative integers",
                         value = "12, 40, 7, 105, 33")),
      shiny::conditionalPanel("input.fhe_source == 'col'",
        shiny::fileInput("fhe_infile", "Dataset (CSV/XLSX)",
                         accept = c(".csv", ".xlsx", ".xls")),
        shiny::uiOutput("fhe_col_ui"),
        shiny::helpText(class = "small text-muted",
          "The column values are rounded to non-negative integers and encrypted ",
          "one per ciphertext; only their encrypted sum is decrypted.")),
      shiny::actionButton("fhe_run", "Encrypt & compute on ciphertext",
                          class = "btn-primary w-100 mb-2"),
      shiny::helpText(class = "small text-muted",
        "Keygen and each homomorphic add are real bootstrapped circuits, so this ",
        "takes a few seconds and is capped to a small number of values."),
      .disclaimer()
    ),
    bslib::card(
      bslib::card_header("Add encrypted numbers without ever decrypting them"),
      bslib::card_body(
        shiny::uiOutput("fhe_status"),
        shiny::uiOutput("fhe_result"),
        shiny::uiOutput("fhe_transcript"),
        shiny::uiOutput("fhe_downloads")
      )
    )
  )
}

fhe_server <- function(input, output, session, rv) {

  fhe_data <- shiny::reactive({
    shiny::req(input$fhe_infile)
    fpe_read_df(input$fhe_infile$datapath, input$fhe_infile$name)
  })

  output$fhe_col_ui <- shiny::renderUI({
    df <- tryCatch(fhe_data(), error = function(e) NULL)
    shiny::req(df)
    num <- names(df)[vapply(df, function(c)
      any(is.finite(suppressWarnings(as.numeric(c)))), logical(1))]
    shiny::selectInput("fhe_col", "Numeric column",
                       choices = if (length(num)) num else names(df))
  })

  fhe_values_of <- function() {
    if (identical(input$fhe_source, "type")) {
      parts <- trimws(strsplit(input$fhe_values %||% "", "[,\\s]+")[[1]])
      parts <- parts[nzchar(parts)]
      v <- suppressWarnings(as.numeric(parts))
      if (!length(v) || any(is.na(v))) stop("Enter numbers separated by commas.")
      v
    } else {
      df <- fhe_data()
      col <- input$fhe_col %||% names(df)[1]
      v <- suppressWarnings(as.numeric(df[[col]]))
      v <- v[is.finite(v)]
      if (!length(v)) stop("Selected column has no numeric values.")
      v
    }
  }

  shiny::observeEvent(input$fhe_run, {
    tryCatch({
      if (!isTRUE(crypto_backend_available("tfhe")))
        stop("Native TFHE backend not built — run tools/build_native.R and restart.")
      vals <- fhe_values_of()
      shiny::withProgress(message = "Homomorphic compute (keygen, encrypt, add)…",
                          value = 0.3, {
        rv$fhe_res <- fhe_sum_demo(vals)
      })
      rv$fhe_msg <- NULL
    }, error = function(e) { rv$fhe_res <- NULL; rv$fhe_msg <- conditionMessage(e) })
  })

  output$fhe_status <- shiny::renderUI({
    if (!isTRUE(crypto_backend_available("tfhe")))
      return(shiny::div(class = "alert alert-warning small py-2",
        shiny::HTML("Compute-on-ciphertext needs the native TFHE backend. Build it via <code>tools/build_native.R</code> and restart the app.")))
    shiny::tagList(
      if (!is.null(rv$fhe_msg))
        shiny::div(class = "alert alert-danger py-2 small", rv$fhe_msg),
      shiny::div(class = "alert alert-info small py-2",
        shiny::HTML(paste0(
          "Each number is encrypted under a secret <b>client key</b>. The ",
          "<b>server key</b> can add ciphertexts but <b>cannot decrypt</b> — ",
          "the sum is computed blind and only its single ciphertext is sent ",
          "back for the client to open.")))
    )
  })

  output$fhe_result <- shiny::renderUI({
    o <- rv$fhe_res
    if (is.null(o)) return(NULL)
    shiny::tagList(
      shiny::div(class = "alert py-2 small mt-2",
        class = if (isTRUE(o$correct)) "alert-success" else "alert-danger",
        shiny::HTML(sprintf(paste0(
          "<b>Decrypted result: %s.</b> The server added %d encrypted values ",
          "without the client key; the decrypted total %s the plaintext sum ",
          "(%s). The server saw only ciphertext."),
          .fhe_fmt(o$fhe_result), o$n,
          if (isTRUE(o$correct)) "<b>matches</b>" else "<span class='text-danger'>does NOT match</span>",
          .fhe_fmt(o$plaintext_sum)))),
      shiny::div(class = "alert alert-secondary py-2 small",
        shiny::HTML(sprintf(paste0(
          "The homomorphic sum received a <b>%s server key</b> and the ",
          "ciphertexts — never the client key. There is no server-side decrypt ",
          "operation; only the holder of the client key can read any result."),
          .fhe_human_bytes(o$server_key_bytes)))))
  })

  output$fhe_transcript <- shiny::renderUI({
    o <- rv$fhe_res
    if (is.null(o)) return(NULL)
    lines <- c(
      sprintf("values encrypted : %d (e.g. %s%s)", o$n,
              paste(o$values_sample, collapse = ", "),
              if (o$n > length(o$values_sample)) ", …" else ""),
      sprintf("client key       : %s (can decrypt)", .fhe_human_bytes(o$client_key_bytes)),
      sprintf("server key       : %s (compute only, cannot decrypt)",
              .fhe_human_bytes(o$server_key_bytes)),
      sprintf("ciphertext / value: %s", .fhe_human_bytes(o$ct_each_bytes)),
      sprintf("encrypted result : %s", .fhe_human_bytes(o$result_bytes)),
      sprintf("plaintext sum    : %s", .fhe_fmt(o$plaintext_sum)),
      sprintf("decrypted sum    : %s  (%s)", .fhe_fmt(o$fhe_result),
              if (isTRUE(o$correct)) "correct" else "MISMATCH"),
      sprintf("sample ciphertext: %s…", o$sample_ct_hex),
      o$guard)
    shiny::tagList(
      shiny::tags$hr(),
      shiny::div(class = "small text-muted", "Transcript:"),
      shiny::tags$pre(class = "small", paste(lines, collapse = "\n")))
  })

  output$fhe_downloads <- shiny::renderUI({
    o <- rv$fhe_res
    if (is.null(o)) return(NULL)
    shiny::div(class = "d-inline-block me-2 mb-2 mt-1",
      shiny::downloadButton("fhe_dl_result", "Download encrypted result",
                            class = "btn-outline-secondary"))
  })

  output$fhe_dl_result <- shiny::downloadHandler(
    filename = function() "fhe_encrypted_sum.bin",
    content  = function(file) writeBin(rv$fhe_res$enc_result, file))
}

# Format a number for display without scientific notation.
.fhe_fmt <- function(x) format(x, scientific = FALSE, trim = TRUE, big.mark = ",")

# Human-readable byte size.
.fhe_human_bytes <- function(b) {
  b <- as.numeric(b)
  if (!is.finite(b)) return("?")
  if (b >= 1024^2) sprintf("%.1f MB", b / 1024^2)
  else if (b >= 1024) sprintf("%.1f KB", b / 1024)
  else sprintf("%d B", as.integer(b))
}
