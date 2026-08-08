# Shiny server logic.

# crude passphrase strength estimate (no external dep): bits ~ len * log2(charset)
.estimate_bits <- function(s) {
  if (is.null(s) || !nzchar(s)) return(0)
  classes <- c(grepl("[a-z]", s) * 26, grepl("[A-Z]", s) * 26,
               grepl("[0-9]", s) * 10, grepl("[^a-zA-Z0-9]", s) * 33)
  pool <- max(sum(classes), 1)
  round(nchar(s) * log2(pool), 1)
}

app_server <- function(input, output, session) {

  rv <- shiny::reactiveValues(env = NULL, keyres = NULL, keyfiles = list(),
                              dec_env = NULL, dec_pt = NULL)

  # populate encryption scheme choices with what is actually available
  shiny::observe({
    sch <- list_schemes()
    avail <- sch[sch$available & sch$tier == "Core", ]
    choices <- stats::setNames(avail$id, sprintf("%s  [%s]", avail$label, avail$tier))
    shiny::updateSelectInput(session, "scheme", choices = choices)
  })

  # ---------- Import ----------
  imported <- shiny::reactive({
    shiny::req(input$infile)
    import_to_raw(input$infile$datapath, kind = input$kind,
                  orig_name = input$infile$name)
  })

  output$import_info <- shiny::renderText({
    im <- imported()
    sprintf("Imported '%s' as kind='%s'  (%s bytes serialized)%s",
            im$orig_name, im$kind, length(im$raw),
            if (!is.null(im$preview)) sprintf("\nPreview: %d rows x %d cols",
                                              nrow(im$preview), ncol(im$preview)) else "")
  })
  output$preview <- shiny::renderTable({
    im <- imported(); shiny::req(!is.null(im$preview)); utils::head(im$preview, 10)
  })

  output$strength <- shiny::renderUI({
    b <- .estimate_bits(input$freetext)
    lab <- if (b < 40) "weak" else if (b < 70) "fair" else "strong"
    col <- if (b < 40) "danger" else if (b < 70) "warning" else "success"
    shiny::HTML(sprintf(
      "<span class='badge bg-%s'>~%s bits (%s)</span> <span class='small text-muted'>A bare hash is not a KDF — keep 'harden' on.</span>",
      col, b, lab))
  })

  # ---------- payload (optional gzip) ----------
  payload_raw <- shiny::reactive({
    im <- imported()
    if (isTRUE(input$gzip)) gzip_raw(im$raw) else im$raw
  })

  key_spec <- function() {
    switch(input$keysrc,
      "random"        = list(type = "random"),
      "passphrase"    = list(type = "passphrase", passphrase = input$passphrase,
                             kdf = input$kdf),
      "freetext_hash" = list(type = "freetext_hash", text = input$freetext,
                             hash_algo = input$hashalgo, harden = input$harden),
      "keyfile"       = list(type = "keyfile",
                             bytes = read_secret_bytes(shiny::req(input$keyfile_up)$datapath)))
  }

  # ---------- Encrypt ----------
  shiny::observeEvent(input$do_encrypt, {
    shiny::req(input$infile, input$scheme)
    tryCatch({
      im  <- imported()
      spec <- key_spec()
      kr  <- resolve_key(spec)
      params <- list()
      if (nzchar(input$nonce)) {
        params$nonce <- input$nonce; params$iv <- input$nonce
      }
      env <- se_encrypt(payload_raw(), input$scheme, kr, params = params,
                        meta = list(orig_name = im$orig_name, orig_kind = im$kind,
                                    compressed = isTRUE(input$gzip)))
      rv$env <- env; rv$keyres <- kr
      rv$keyfiles <- key_material_files(kr, input$scheme)
      shiny::showNotification("Encrypted successfully.", type = "message")
    }, error = function(e) {
      shiny::showNotification(paste("Encrypt failed:", conditionMessage(e)),
                              type = "error", duration = 10)
    })
  })

  output$enc_summary <- shiny::renderText({
    env <- rv$env; shiny::req(env)
    p <- env$params
    sprintf(paste0("Scheme     : %s\nOriginal   : %s (kind=%s%s)\n",
                   "Ciphertext : %d bytes (base64)\nDigest(%s) : %s\n",
                   "Nonce/IV   : %s\nKey source : %s%s"),
      env$scheme, env$orig_name, env$orig_kind,
      if (env$compressed) ", gzip" else "",
      nchar(env$ciphertext_b64), env$pt_algo, env$pt_digest,
      p$nonce %||% p$iv %||% "(n/a)",
      env$key_source$type,
      if (!is.null(rv$keyres$key_export))
        "  ⚠ DOWNLOAD THE KEY BELOW — it is the only copy." else "")
  })

  output$downloads <- shiny::renderUI({
    shiny::req(rv$env)
    tagList <- shiny::tagList
    els <- list(
      shiny::downloadButton("dl_txt", "Download ciphertext (.txt)", class = "btn-outline-primary"),
      shiny::downloadButton("dl_r", "Download reproducible script (.R)", class = "btn-outline-primary")
    )
    if (length(rv$keyfiles) > 0)
      els <- c(els, list(shiny::downloadButton("dl_keys", "Download key material (.zip)",
                                               class = "btn-outline-danger")))
    do.call(shiny::tagList, lapply(els, function(e) shiny::div(class = "d-inline-block me-2 mb-2", e)))
  })

  output$dl_txt <- shiny::downloadHandler(
    filename = function() paste0("exported_", tools::file_path_sans_ext(rv$env$orig_name), ".txt"),
    content  = function(file) writeLines(build_txt_export(rv$env, get_scheme(rv$env$scheme)$label), file))

  output$dl_r <- shiny::downloadHandler(
    filename = function() paste0("exported_", tools::file_path_sans_ext(rv$env$orig_name), ".R"),
    content  = function(file) writeLines(build_r_export(rv$env, get_scheme(rv$env$scheme)$label), file))

  output$dl_keys <- shiny::downloadHandler(
    filename = function() paste0("keymaterial_", tools::file_path_sans_ext(rv$env$orig_name), ".zip"),
    content  = function(file) {
      td <- tempfile(); dir.create(td); fs <- character()
      for (kf in rv$keyfiles) { p <- file.path(td, kf$name); writeLines(kf$text, p); fs <- c(fs, p) }
      zip::zip(file, files = basename(fs), root = td)
    })

  # ---------- Decrypt ----------
  dec_env <- shiny::reactive({
    shiny::req(input$artifact)
    txt <- paste(readLines(input$artifact$datapath, warn = FALSE), collapse = "\n")
    envelope_parse(txt)
  })

  output$dec_source_hint <- shiny::renderUI({
    env <- tryCatch(dec_env(), error = function(e) NULL)
    if (is.null(env)) return(shiny::helpText("Upload an artifact to see what it needs."))
    t <- env$key_source$type
    msg <- switch(t,
      "random"        = "This artifact used a RANDOM key — upload its key file below.",
      "keyfile"       = "This artifact used a KEY FILE — upload it below.",
      "passphrase"    = "This artifact used a PASSPHRASE — type it above.",
      "freetext_hash" = "This artifact used FREE TEXT — type the exact text above.",
      "Provide the matching secret.")
    shiny::div(class = "alert alert-info small py-2",
               sprintf("Scheme: %s · original: %s · %s", env$scheme, env$orig_name, msg))
  })

  shiny::observeEvent(input$do_decrypt, {
    tryCatch({
      env <- dec_env()
      t <- env$key_source$type
      secret <- if (t %in% c("random", "keyfile")) {
        read_secret_bytes(shiny::req(input$dec_keyfile)$datapath)
      } else {
        shiny::req(nzchar(input$dec_secret)); input$dec_secret
      }
      pt <- se_decrypt(env, secret)
      if (isTRUE(env$compressed)) pt <- gunzip_raw(pt)
      rv$dec_env <- env; rv$dec_pt <- pt
      shiny::showNotification("Decrypted and integrity-verified.", type = "message")
    }, error = function(e) {
      rv$dec_pt <- NULL
      shiny::showNotification(paste("Decrypt failed:", conditionMessage(e)),
                              type = "error", duration = 10)
    })
  })

  output$dec_summary <- shiny::renderText({
    shiny::req(rv$dec_pt)
    sprintf("Recovered %d bytes. Original: %s (kind=%s). Integrity: VERIFIED.",
            length(rv$dec_pt), rv$dec_env$orig_name, rv$dec_env$orig_kind)
  })

  output$dec_preview <- shiny::renderTable({
    shiny::req(rv$dec_pt, rv$dec_env$orig_kind %in% c("csv", "xlsx"))
    utils::head(as.data.frame(restore_object(rv$dec_pt, rv$dec_env$orig_kind)), 10)
  })

  output$dec_downloads <- shiny::renderUI({
    shiny::req(rv$dec_pt)
    kind <- rv$dec_env$orig_kind
    els <- if (kind %in% c("csv", "xlsx")) list(
      shiny::downloadButton("dl_obj", "Download recovered object (.rds)", class = "btn-outline-primary"),
      shiny::downloadButton("dl_csv", "Re-materialize as CSV", class = "btn-outline-primary")
    ) else list(
      shiny::downloadButton("dl_orig", "Download original binary", class = "btn-outline-primary"))
    do.call(shiny::tagList, lapply(els, function(e) shiny::div(class = "d-inline-block me-2 mb-2", e)))
  })

  output$dl_orig <- shiny::downloadHandler(
    filename = function() rv$dec_env$orig_name,
    content  = function(file) writeBin(as.vector(rv$dec_pt), file))
  output$dl_obj <- shiny::downloadHandler(
    filename = function() paste0(tools::file_path_sans_ext(rv$dec_env$orig_name), ".rds"),
    content  = function(file) writeBin(as.vector(rv$dec_pt), file))
  output$dl_csv <- shiny::downloadHandler(
    filename = function() paste0(tools::file_path_sans_ext(rv$dec_env$orig_name), ".csv"),
    content  = function(file) utils::write.csv(restore_object(rv$dec_pt, rv$dec_env$orig_kind),
                                               file, row.names = FALSE))

  # ---------- Schemes catalogue ----------
  output$scheme_table <- shiny::renderTable({
    s <- list_schemes()
    s$available <- ifelse(s$available, "✓", "—")
    names(s) <- c("id", "tier", "scheme", "available", "notes")
    s
  })

  # ---------- Help ----------
  output$help_md <- shiny::renderUI({
    path <- system.file("app", "usage.html", package = "shinyEncrypt")
    if (nzchar(path) && file.exists(path)) return(shiny::includeHTML(path))
    shiny::HTML(help_html())
  })

  # Catalogue + help are cheap and reference material — render eagerly so they
  # are ready before their tab is first shown.
  shiny::outputOptions(output, "scheme_table", suspendWhenHidden = FALSE)
  shiny::outputOptions(output, "help_md", suspendWhenHidden = FALSE)
}
