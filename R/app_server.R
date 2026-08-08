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
                              dec_env = NULL, dec_pt = NULL, pqc_keys = NULL,
                              sign_keys = NULL)

  # populate encryption scheme choices with what is actually available
  shiny::observe({
    sch <- list_schemes()
    avail <- sch[sch$available & sch$tier == "Core", ]
    choices <- stats::setNames(avail$id, sprintf("%s  [%s]", avail$label, avail$tier))
    shiny::updateSelectInput(session, "scheme", choices = choices)

    # KDF choices: prefer native Argon2id when the backend is loaded.
    labs <- c(argon2id = "Argon2id (native, memory-hard)",
              scrypt = "scrypt (memory-hard)", bcrypt_pbkdf = "bcrypt_pbkdf")
    kdfs <- intersect(c("argon2id", "scrypt", "bcrypt_pbkdf"), available_kdfs())
    shiny::updateSelectInput(session, "kdf",
                             choices = stats::setNames(kdfs, labs[kdfs]))

    # Offer the PQC hybrid key source only when the native backend is loaded.
    ksrc <- c("Random key (download it!)" = "random",
              "Passphrase (KDF)" = "passphrase",
              "Free text → hash" = "freetext_hash",
              "Key file" = "keyfile")
    if (isTRUE(crypto_backend_available("hpke-hybrid")))
      ksrc <- c(ksrc, "Recipient public key (PQC hybrid)" = "hybrid_pqc")
    if (isTRUE(crypto_backend_available("shamir")))
      ksrc <- c(ksrc, "Random key, split into Shamir shares (t-of-n)" = "shamir")
    shiny::updateSelectInput(session, "keysrc", choices = ksrc,
                             selected = shiny::isolate(input$keysrc))
  })

  # ---------- Import ----------
  imported <- shiny::reactive({
    shiny::req(input$infile)
    inf <- input$infile
    shiny::withProgress(message = "Reading & serializing…", value = 0.4, {
      tryCatch(
        import_to_raw(inf$datapath, kind = input$kind, orig_name = inf$name),
        error = function(e) {
          shiny::showNotification(paste("Import failed:", conditionMessage(e)),
                                  type = "error", duration = 12)
          NULL
        })
    })
  })

  output$import_info <- shiny::renderText({
    shiny::req(input$infile)
    im <- imported()
    if (is.null(im)) return("Import failed — see the notification. Try a different 'Interpret as' setting.")
    dimtxt <- if (!is.null(im$dims))
      sprintf("\nData: %d rows x %d cols%s", im$dims[1], im$dims[2],
              if (isTRUE(im$truncated)) sprintf("  (preview shows first %d x %d)",
                                                nrow(im$preview), ncol(im$preview)) else "") else ""
    sz <- input$infile$size %||% NA
    sprintf("Imported '%s' as kind='%s'\nUpload size: %s bytes  ·  serialized payload: %s bytes%s",
            im$orig_name, im$kind, format(sz, big.mark = ","),
            format(length(im$raw), big.mark = ","), dimtxt)
  })
  output$preview <- shiny::renderTable({
    im <- imported(); shiny::req(!is.null(im) && !is.null(im$preview)); im$preview
  }, striped = TRUE, bordered = TRUE, spacing = "xs")

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
                             bytes = read_secret_bytes(shiny::req(input$keyfile_up)$datapath)),
      "hybrid_pqc"    = list(type = "hybrid_pqc", public_bundle = {
        if (!is.null(input$pqc_pub_up)) read_secret_bytes(input$pqc_pub_up$datapath)
        else if (!is.null(rv$pqc_keys)) rv$pqc_keys$public
        else stop("Generate a PQC keypair or upload a recipient public key first.")
      }),
      "shamir"        = list(type = "shamir",
                             t = as.integer(input$shamir_t %||% 2L),
                             n = as.integer(input$shamir_n %||% 3L)))
  }

  # ---- PQC keypair generation (hybrid X25519 + ML-KEM-768) ----
  shiny::observeEvent(input$gen_pqc, {
    tryCatch({
      rv$pqc_keys <- native_hybrid_keygen()
      shiny::showNotification(
        "PQC keypair generated. Download BOTH files — the secret is the only way to decrypt.",
        type = "warning", duration = 12)
    }, error = function(e)
      shiny::showNotification(paste("Keygen failed:", conditionMessage(e)), type = "error"))
  })

  output$pqc_key_status <- shiny::renderUI({
    if (is.null(rv$pqc_keys)) return(NULL)
    shiny::div(class = "alert alert-warning small py-2",
      shiny::HTML("Keypair ready. The <b>.pub</b> encrypts; the <b>.secret</b> decrypts and is the only copy — store it safely."),
      shiny::div(class = "mt-2",
        shiny::downloadButton("dl_pqc_pub", ".pub", class = "btn-outline-primary btn-sm me-2"),
        shiny::downloadButton("dl_pqc_sec", ".secret", class = "btn-outline-danger btn-sm")))
  })

  .pqc_hex_file <- function(bytes, kind)
    paste0("# shinyEncrypt PQC hybrid ", kind, " (X25519+ML-KEM-768), hex:\n",
           sodium::bin2hex(as_raw(bytes)), "\n")
  output$dl_pqc_pub <- shiny::downloadHandler(
    filename = function() "recipient_pqc.pub",
    content  = function(file) writeLines(.pqc_hex_file(rv$pqc_keys$public, "PUBLIC key"), file))
  output$dl_pqc_sec <- shiny::downloadHandler(
    filename = function() "recipient_pqc.secret",
    content  = function(file) writeLines(.pqc_hex_file(rv$pqc_keys$secret, "SECRET key"), file))

  # ---- Envelope signing (ML-DSA-65) ----
  # Only offered when the native backend actually exports the signature symbols.
  output$sign_ui <- shiny::renderUI({
    if (!isTRUE(crypto_backend_available("ml-dsa"))) return(NULL)
    shiny::tagList(
      shiny::hr(),
      shiny::checkboxInput("sign_env", "Sign this envelope (ML-DSA-65)", FALSE),
      shiny::conditionalPanel(
        "input.sign_env == true",
        shiny::helpText(class = "small text-muted",
          "Post-quantum signature over the ciphertext + metadata. Generate a ",
          "signing keypair; the recipient checks the signature and its fingerprint."),
        shiny::actionButton("gen_sign", "Generate signing keypair",
                            class = "btn-outline-primary btn-sm mb-2 w-100"),
        shiny::uiOutput("sign_key_status")))
  })

  shiny::observeEvent(input$gen_sign, {
    tryCatch({
      rv$sign_keys <- native_mldsa_keygen()
      shiny::showNotification(
        "Signing keypair generated. Keep the .signsecret private; share the .signpub fingerprint out-of-band.",
        type = "warning", duration = 12)
    }, error = function(e)
      shiny::showNotification(paste("Signing keygen failed:", conditionMessage(e)), type = "error"))
  })

  output$sign_key_status <- shiny::renderUI({
    if (is.null(rv$sign_keys)) return(NULL)
    shiny::div(class = "alert alert-warning small py-2",
      shiny::HTML(sprintf(
        "Signing keypair ready. Fingerprint: <code>%s</code>. Recipients confirm this against your known key.",
        sign_fingerprint(rv$sign_keys$public))),
      shiny::div(class = "mt-2",
        shiny::downloadButton("dl_sign_pub", ".signpub", class = "btn-outline-primary btn-sm me-2"),
        shiny::downloadButton("dl_sign_sec", ".signsecret", class = "btn-outline-danger btn-sm")))
  })

  .sign_hex_file <- function(bytes, kind)
    paste0("# shinyEncrypt ML-DSA-65 signing ", kind, ", hex:\n",
           sodium::bin2hex(as_raw(bytes)), "\n")
  output$dl_sign_pub <- shiny::downloadHandler(
    filename = function() "signer_mldsa.signpub",
    content  = function(file) writeLines(.sign_hex_file(rv$sign_keys$public, "PUBLIC key"), file))
  output$dl_sign_sec <- shiny::downloadHandler(
    filename = function() "signer_mldsa.signsecret",
    content  = function(file) writeLines(.sign_hex_file(rv$sign_keys$secret, "SECRET key"), file))

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
      if (isTRUE(input$sign_env)) {
        if (is.null(rv$sign_keys))
          stop("Signing is on but no signing keypair exists — click 'Generate signing keypair' first.")
        env <- envelope_sign(env, rv$sign_keys$secret, rv$sign_keys$public)
      }
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
    sig <- if (!is.null(env$signature))
      sprintf("\nSigned     : %s · fp %s", env$signature$alg,
              sign_fingerprint(sodium::hex2bin(env$signature$public_key))) else ""
    sprintf(paste0("Scheme     : %s\nOriginal   : %s (kind=%s%s)\n",
                   "Ciphertext : %d bytes (base64)\nDigest(%s) : %s\n",
                   "Nonce/IV   : %s\nKey source : %s%s%s"),
      env$scheme, env$orig_name, env$orig_kind,
      if (env$compressed) ", gzip" else "",
      nchar(env$ciphertext_b64), env$pt_algo, env$pt_digest,
      p$nonce %||% p$iv %||% "(n/a)",
      env$key_source$type,
      if (!is.null(rv$keyres$key_export))
        "  ⚠ DOWNLOAD THE KEY BELOW — it is the only copy." else "",
      sig)
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
      "hybrid_pqc"    = "This artifact used a PQC HYBRID key — upload the recipient's .secret key below.",
      "shamir"        = sprintf("This artifact used SHAMIR custody — upload at least %d of the %d share files below.",
                                as.integer(env$key_source$t %||% 2L), as.integer(env$key_source$n %||% 3L)),
      "Provide the matching secret.")
    shiny::div(class = "alert alert-info small py-2",
               sprintf("Scheme: %s · original: %s · %s", env$scheme, env$orig_name, msg))
  })

  # Shamir share upload: shown only when the artifact used the shamir source.
  output$dec_shares_ui <- shiny::renderUI({
    env <- tryCatch(dec_env(), error = function(e) NULL)
    if (is.null(env) || !identical(env$key_source$type, "shamir")) return(NULL)
    t <- as.integer(env$key_source$t %||% 2L); n <- as.integer(env$key_source$n %||% 3L)
    shiny::tagList(
      shiny::fileInput("dec_shares", sprintf("Shamir shares (upload any %d of %d)", t, n),
                       multiple = TRUE),
      shiny::helpText(class = "small text-muted",
        sprintf("Select %d or more share_*.txt files at once. Fewer than %d cannot recover the key.", t, t)))
  })

  # Optional signer-key pinning: shown only for signed artifacts. Uploading the
  # sender's out-of-band .signpub upgrades "valid by someone" to "valid by them".
  output$dec_signpub_ui <- shiny::renderUI({
    env <- tryCatch(dec_env(), error = function(e) NULL)
    if (is.null(env) || is.null(env$signature)) return(NULL)
    shiny::tagList(
      shiny::fileInput("dec_signpub", "Pin expected signer public key (.signpub) — optional"),
      shiny::helpText(class = "small text-muted",
        "Upload the sender's .signpub (obtained out-of-band) to confirm the signature is from them specifically, not just from someone."))
  })

  output$dec_signature <- shiny::renderUI({
    env <- tryCatch(dec_env(), error = function(e) NULL)
    if (is.null(env)) return(NULL)
    exp_pub <- if (!is.null(input$dec_signpub))
      tryCatch(read_secret_bytes(input$dec_signpub$datapath), error = function(e) NULL) else NULL
    v <- tryCatch(envelope_verify(env, expected_public = exp_pub),
                  error = function(e) list(status = "invalid", expected_match = NA))
    if (identical(v$status, "unsigned")) return(NULL)   # nothing to show
    danger <- function(html) shiny::div(class = "alert alert-danger small py-2", shiny::HTML(html))
    if (!identical(v$status, "valid"))
      return(danger("&#9888; Signature <b>INVALID</b> — this artifact was altered or was not signed by the claimed key. Do not trust it."))
    # cryptographically valid — refine by the pin, if one was supplied
    if (isFALSE(v$expected_match))
      return(danger(sprintf(paste0(
        "&#9888; Signature is cryptographically valid, but the signer key <code>%s</code> does <b>NOT</b> match the .signpub you pinned. ",
        "This is not from your expected sender — reject it."), v$fingerprint)))
    if (isTRUE(v$expected_match))
      return(shiny::div(class = "alert alert-success small py-2",
        shiny::HTML(sprintf(
          "&#128274; Signature <b>VALID</b> (%s) and matches your <b>pinned</b> signer: <code>%s</code>. Authenticated.",
          v$alg, v$fingerprint))))
    shiny::div(class = "alert alert-success small py-2",
      shiny::HTML(sprintf(
        "&#128274; Signature <b>VALID</b> (%s). Signer fingerprint: <code>%s</code> — confirm it matches the sender's known key (or pin their .signpub below).",
        v$alg, v$fingerprint)))
  })

  shiny::observeEvent(input$do_decrypt, {
    tryCatch({
      env <- dec_env()
      t <- env$key_source$type
      secret <- if (t == "shamir") {
        if (is.null(input$dec_shares) || nrow(input$dec_shares) < 1)
          stop("This artifact needs its SHAMIR shares — upload the share_*.txt files below.")
        need <- as.integer(env$key_source$t %||% 2L)
        if (nrow(input$dec_shares) < need)
          stop(sprintf("Need at least %d shares to reconstruct the key; you uploaded %d.",
                       need, nrow(input$dec_shares)))
        do.call(c, lapply(input$dec_shares$datapath, read_secret_bytes))  # concat shares
      } else if (t %in% c("random", "keyfile", "hybrid_pqc")) {
        if (is.null(input$dec_keyfile))
          stop(if (t == "hybrid_pqc")
                 "This artifact needs the recipient's PQC SECRET key — upload it in the key-file box below."
               else "This artifact needs its KEY FILE — upload it in the key-file box below.")
        read_secret_bytes(input$dec_keyfile$datapath)
      } else {
        if (!nzchar(input$dec_secret %||% ""))
          stop(sprintf("This artifact needs its %s — type it in the box above (not a key file; the salt is already inside the artifact).",
                       if (t == "passphrase") "PASSPHRASE" else "FREE TEXT"))
        input$dec_secret
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
    df <- as.data.frame(restore_object(rv$dec_pt, rv$dec_env$orig_kind))
    .cap_preview(df)$preview   # cap cols too, or wide tables freeze the browser
  }, striped = TRUE, bordered = TRUE, spacing = "xs")

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

  # Render outputs eagerly. bslib nav panels render their content hidden during
  # the first pass, so Shiny suspends the initially-active tab's outputs and does
  # not wake them until a tab change — which leaves the Encrypt tab blank after an
  # upload. Disabling suspend-when-hidden for the display outputs fixes that.
  for (id in c("import_info", "preview", "strength", "enc_summary", "downloads",
               "pqc_key_status", "sign_ui", "sign_key_status", "dec_signature",
               "dec_signpub_ui", "dec_shares_ui", "dec_source_hint", "dec_summary", "dec_preview",
               "dec_downloads", "scheme_table", "help_md")) {
    shiny::outputOptions(output, id, suspendWhenHidden = FALSE)
  }
}
