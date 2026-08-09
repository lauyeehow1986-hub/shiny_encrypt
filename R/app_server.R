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
                              sign_keys = NULL, fpe_out = NULL, fpe_rev = NULL,
                              cpabe_keys = NULL, cpabe_issued = NULL,
                              ibe_keys = NULL, ibe_issued = NULL)

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
    if (isTRUE(crypto_backend_available("tlock")))
      ksrc <- c(ksrc, "Time-lock (decrypt only after a delay)" = "timelock")
    if (isTRUE(crypto_backend_available("cp-abe")))
      ksrc <- c(ksrc, "Attribute policy (CP-ABE)" = "cpabe")
    if (isTRUE(crypto_backend_available("ibe")))
      ksrc <- c(ksrc, "Recipient identity (IBE)" = "ibe")
    if (isTRUE(crypto_backend_available("oprf")))
      ksrc <- c(ksrc, "OPRF-hardened input (oblivious PRF)" = "oprf")
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
                             n = as.integer(input$shamir_n %||% 3L)),
      "timelock"      = {
        secs <- as.numeric(input$tl_amount %||% 10) * as.numeric(input$tl_unit %||% 60)
        rate <- tl_current_rate(input$tl_bits %||% 2048L)
        if (!is.finite(rate) || rate <= 0) rate <- 1e6
        list(type = "timelock", bits = as.integer(input$tl_bits %||% 2048L),
             t_squarings = timelock_squarings(secs, rate),
             rate_est = rate, target_seconds = secs,
             keep_master = isTRUE(input$tl_keep_master))
      },
      "cpabe"         = list(type = "cpabe", policy = input$cpabe_policy %||% "", pk = {
        if (!is.null(input$cpabe_pk_up)) read_secret_bytes(input$cpabe_pk_up$datapath)
        else if (!is.null(rv$cpabe_keys)) rv$cpabe_keys$pk
        else stop("Generate a CP-ABE authority or upload its public key (.pub) first.")
      }),
      "ibe"           = list(type = "ibe", identity = input$ibe_identity %||% "", pk = {
        if (!is.null(input$ibe_pk_up)) read_secret_bytes(input$ibe_pk_up$datapath)
        else if (!is.null(rv$ibe_keys)) rv$ibe_keys$pk
        else stop("Generate an IBE authority or upload its public key (.pub) first.")
      }),
      "oprf"          = list(type = "oprf", text = input$oprf_input %||% "", oprf_key = {
        if (!is.null(input$oprf_key_up)) read_secret_bytes(input$oprf_key_up$datapath)
        else if (!is.null(rv$oprf_key)) rv$oprf_key
        else stop("Generate a new OPRF key or upload an existing .oprfkey first.")
      }))
  }

  # split a comma/newline-separated attribute list into a clean character vector
  .cpabe_split_attrs <- function(s) {
    if (is.null(s)) return(character())
    parts <- trimws(strsplit(s, "[,\n]+")[[1]])
    parts[nzchar(parts)]
  }

  # Live estimate of the time-lock puzzle size for the chosen delay/modulus.
  output$tl_estimate <- shiny::renderUI({
    shiny::req(identical(input$keysrc, "timelock"))
    rate <- tl_current_rate(input$tl_bits %||% 2048L)
    secs <- as.numeric(input$tl_amount %||% 0) * as.numeric(input$tl_unit %||% 1)
    if (!is.finite(rate) || rate <= 0)
      return(shiny::div(class = "small text-muted", "Calibrating this machine…"))
    Tsq <- timelock_squarings(secs, rate)
    shiny::div(class = "alert alert-info small py-2",
      shiny::HTML(sprintf(
        paste0("Puzzle size: <b>%s</b> sequential squarings (this machine does ",
               "~%s/sec). The recipient must compute non-stop for about the chosen ",
               "delay; the <b>actual</b> time depends on the solver's single-core ",
               "speed and cannot be parallelised away."),
        format(Tsq, big.mark = ",", scientific = FALSE),
        format(round(rate), big.mark = ",", scientific = FALSE))))
  })

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

  # ---- CP-ABE authority (BSW attribute-based encryption) ----
  shiny::observeEvent(input$gen_cpabe, {
    tryCatch({
      rv$cpabe_keys <- native_cpabe_setup()
      shiny::showNotification(
        "CP-ABE authority generated. Keep the .master SECRET (it issues attribute keys); share the .pub so others can encrypt under a policy.",
        type = "warning", duration = 12)
    }, error = function(e)
      shiny::showNotification(paste("CP-ABE setup failed:", conditionMessage(e)), type = "error"))
  })

  output$cpabe_key_status <- shiny::renderUI({
    if (is.null(rv$cpabe_keys)) return(NULL)
    shiny::div(class = "alert alert-warning small py-2",
      shiny::HTML("Authority ready. The <b>.pub</b> encrypts under a policy; the <b>.master</b> issues attribute keys and is SECRET."),
      shiny::div(class = "mt-2",
        shiny::downloadButton("dl_cpabe_pub", ".pub", class = "btn-outline-primary btn-sm me-2"),
        shiny::downloadButton("dl_cpabe_master", ".master", class = "btn-outline-danger btn-sm")))
  })

  .cpabe_hex_file <- function(bytes, kind)
    paste0("# shinyEncrypt CP-ABE (BSW) authority ", kind, ", hex(JSON):\n",
           sodium::bin2hex(as_raw(bytes)), "\n")
  output$dl_cpabe_pub <- shiny::downloadHandler(
    filename = function() "cpabe_authority.pub",
    content  = function(file) writeLines(.cpabe_hex_file(rv$cpabe_keys$pk, "PUBLIC key"), file))
  output$dl_cpabe_master <- shiny::downloadHandler(
    filename = function() "cpabe_authority.master",
    content  = function(file) writeLines(.cpabe_hex_file(rv$cpabe_keys$mk, "MASTER key (SECRET)"), file))

  # Issue a per-recipient attribute key from the authority master.
  shiny::observeEvent(input$cpabe_issue, {
    tryCatch({
      mk <- if (!is.null(input$cpabe_master_up)) read_secret_bytes(input$cpabe_master_up$datapath)
            else if (!is.null(rv$cpabe_keys)) rv$cpabe_keys$mk
            else stop("Generate an authority or upload its .master to issue keys.")
      pk <- if (!is.null(input$cpabe_pk_up)) read_secret_bytes(input$cpabe_pk_up$datapath)
            else if (!is.null(rv$cpabe_keys)) rv$cpabe_keys$pk
            else stop("Also provide the authority .pub (generate or upload it).")
      attrs <- .cpabe_split_attrs(input$cpabe_issue_attrs)
      if (length(attrs) == 0) stop("Enter at least one attribute (comma-separated).")
      sk <- native_cpabe_keygen(pk, mk, attrs)
      rv$cpabe_issued <- list(sk = sk, attrs = attrs)
      shiny::showNotification(
        sprintf("Issued an attribute key for: %s. Download it below (SECRET — give it to that recipient).",
                paste(attrs, collapse = ", ")), type = "warning", duration = 12)
    }, error = function(e)
      shiny::showNotification(paste("Issue failed:", conditionMessage(e)), type = "error"))
  })

  output$cpabe_issue_status <- shiny::renderUI({
    if (is.null(rv$cpabe_issued)) return(NULL)
    shiny::div(class = "alert alert-warning small py-2 mt-2",
      shiny::HTML(sprintf(
        "Attribute key ready for <code>%s</code>. It decrypts only files whose policy these attributes satisfy.",
        paste(rv$cpabe_issued$attrs, collapse = ", "))),
      shiny::div(class = "mt-2",
        shiny::downloadButton("dl_cpabe_attr", "Download attribute key", class = "btn-outline-danger btn-sm")))
  })

  output$dl_cpabe_attr <- shiny::downloadHandler(
    filename = function() sprintf("cpabe_attrkey_%s.txt",
      gsub("[^A-Za-z0-9]+", "-", paste(rv$cpabe_issued$attrs, collapse = "_"))),
    content  = function(file) writeLines(paste0(
      "# shinyEncrypt CP-ABE ATTRIBUTE KEY (SECRET) for: ",
      paste(rv$cpabe_issued$attrs, collapse = ", "), "\n",
      "# Upload on the Decrypt tab to open files whose policy these attributes satisfy. hex(JSON):\n",
      sodium::bin2hex(as_raw(rv$cpabe_issued$sk)), "\n"), file))

  # ---- IBE authority (Kiltz-Vahlis identity-based encryption) ----
  shiny::observeEvent(input$gen_ibe, {
    tryCatch({
      rv$ibe_keys <- native_ibe_setup()
      shiny::showNotification(
        "IBE authority generated. Keep the .master SECRET (it extracts identity keys); share the .pub so others can encrypt to an identity.",
        type = "warning", duration = 12)
    }, error = function(e)
      shiny::showNotification(paste("IBE setup failed:", conditionMessage(e)), type = "error"))
  })

  output$ibe_key_status <- shiny::renderUI({
    if (is.null(rv$ibe_keys)) return(NULL)
    shiny::div(class = "alert alert-warning small py-2",
      shiny::HTML("Authority ready. The <b>.pub</b> encrypts to any identity; the <b>.master</b> extracts identity keys and is SECRET."),
      shiny::div(class = "mt-2",
        shiny::downloadButton("dl_ibe_pub", ".pub", class = "btn-outline-primary btn-sm me-2"),
        shiny::downloadButton("dl_ibe_master", ".master", class = "btn-outline-danger btn-sm")))
  })

  .ibe_hex_file <- function(bytes, kind)
    paste0("# shinyEncrypt IBE (Kiltz-Vahlis) authority ", kind, ", hex:\n",
           sodium::bin2hex(as_raw(bytes)), "\n")
  output$dl_ibe_pub <- shiny::downloadHandler(
    filename = function() "ibe_authority.pub",
    content  = function(file) writeLines(.ibe_hex_file(rv$ibe_keys$pk, "PUBLIC key"), file))
  output$dl_ibe_master <- shiny::downloadHandler(
    filename = function() "ibe_authority.master",
    content  = function(file) writeLines(.ibe_hex_file(rv$ibe_keys$mk, "MASTER key (SECRET)"), file))

  # Extract a per-identity key from the authority master.
  shiny::observeEvent(input$ibe_issue, {
    tryCatch({
      mk <- if (!is.null(input$ibe_master_up)) read_secret_bytes(input$ibe_master_up$datapath)
            else if (!is.null(rv$ibe_keys)) rv$ibe_keys$mk
            else stop("Generate an authority or upload its .master to issue keys.")
      pk <- if (!is.null(input$ibe_pk_up)) read_secret_bytes(input$ibe_pk_up$datapath)
            else if (!is.null(rv$ibe_keys)) rv$ibe_keys$pk
            else stop("Also provide the authority .pub (generate or upload it).")
      identity <- trimws(input$ibe_issue_id %||% "")
      if (!nzchar(identity)) stop("Enter the identity to issue a key for.")
      usk <- native_ibe_extract(pk, mk, identity)
      rv$ibe_issued <- list(usk = usk, identity = identity)
      shiny::showNotification(
        sprintf("Issued an identity key for: %s. Download it below (SECRET — give it to that recipient).",
                identity), type = "warning", duration = 12)
    }, error = function(e)
      shiny::showNotification(paste("Issue failed:", conditionMessage(e)), type = "error"))
  })

  output$ibe_issue_status <- shiny::renderUI({
    if (is.null(rv$ibe_issued)) return(NULL)
    shiny::div(class = "alert alert-warning small py-2 mt-2",
      shiny::HTML(sprintf(
        "Identity key ready for <code>%s</code>. It decrypts only files sealed to that exact identity.",
        rv$ibe_issued$identity)),
      shiny::div(class = "mt-2",
        shiny::downloadButton("dl_ibe_attr", "Download identity key", class = "btn-outline-danger btn-sm")))
  })

  output$dl_ibe_attr <- shiny::downloadHandler(
    filename = function() sprintf("ibe_idkey_%s.txt",
      gsub("[^A-Za-z0-9]+", "-", rv$ibe_issued$identity)),
    content  = function(file) writeLines(paste0(
      "# shinyEncrypt IBE IDENTITY KEY (SECRET) for: ", rv$ibe_issued$identity, "\n",
      "# Upload on the Decrypt tab to open files sealed to this identity. hex:\n",
      sodium::bin2hex(as_raw(rv$ibe_issued$usk)), "\n"), file))

  # ---- OPRF hardening key (verifiable oblivious PRF) ----
  shiny::observeEvent(input$gen_oprf, {
    tryCatch({
      rv$oprf_key <- oprf_new_key()
      shiny::showNotification(
        "OPRF key generated. Download the .oprfkey and keep it secret — decrypting needs BOTH it and your exact input.",
        type = "warning", duration = 12)
    }, error = function(e)
      shiny::showNotification(paste("OPRF keygen failed:", conditionMessage(e)), type = "error"))
  })

  output$oprf_key_status <- shiny::renderUI({
    if (is.null(rv$oprf_key)) return(NULL)
    shiny::div(class = "alert alert-warning small py-2",
      shiny::HTML("OPRF key ready. It is SECRET and combines with your input to make the key — store the <b>.oprfkey</b> apart from the input."),
      shiny::div(class = "mt-2",
        shiny::downloadButton("dl_oprf_key", ".oprfkey", class = "btn-outline-danger btn-sm")))
  })

  output$dl_oprf_key <- shiny::downloadHandler(
    filename = function() "oprf_key.oprfkey",
    content  = function(file) writeLines(paste0(
      "# shinyEncrypt OPRF KEY (SECRET) - hardens your input for the encrypted file.\n",
      "# Decrypting needs BOTH this key AND the exact input you typed.\n",
      "# Keep it apart from the input (different device/custodian). hex(32 bytes):\n",
      sodium::bin2hex(as_raw(rv$oprf_key)), "\n"), file))

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
      "timelock"      = sprintf("This artifact is TIME-LOCKED (sealed for ~%s) — solve the puzzle below, or supply the creator's master key.",
                                .tl_human(env$key_source$target_seconds)),
      "cpabe"         = sprintf("This artifact is CP-ABE encrypted under the policy %s — upload a matching attribute key below.",
                                env$key_source$policy %||% "(unknown)"),
      "ibe"           = sprintf("This artifact is IBE-sealed to the identity %s — upload that identity's key below.",
                                env$key_source$identity %||% "(unknown)"),
      "oprf"          = "This artifact used an OPRF-HARDENED input — type the exact input and upload its .oprfkey below.",
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

  # Time-lock: choose to solve the puzzle (wait) or supply the creator's master.
  output$dec_timelock_ui <- shiny::renderUI({
    env <- tryCatch(dec_env(), error = function(e) NULL)
    if (is.null(env) || !identical(env$key_source$type, "timelock")) return(NULL)
    sm <- env$key_source
    shiny::tagList(
      shiny::helpText(class = "small text-muted",
        sprintf("Sealed for ~%s (%s sequential squarings). Solving runs your CPU non-stop for about that long; a faster CPU finishes sooner.",
                .tl_human(sm$target_seconds),
                format(as.numeric(sm$t_squarings %||% 0), big.mark = ",", scientific = FALSE))),
      shiny::radioButtons("tl_dec_mode", NULL,
        c("Solve the puzzle now (compute the delay)" = "solve",
          "I have the creator's master key" = "master"),
        selected = "solve"),
      shiny::conditionalPanel(
        "input.tl_dec_mode == 'master'",
        shiny::fileInput("tl_master_up", "Creator master key (timelock_master.key.txt)")))
  })

  # CP-ABE: upload an attribute key; it opens the file only if its attributes
  # satisfy the ciphertext's policy.
  output$dec_cpabe_ui <- shiny::renderUI({
    env <- tryCatch(dec_env(), error = function(e) NULL)
    if (is.null(env) || !identical(env$key_source$type, "cpabe")) return(NULL)
    shiny::tagList(
      shiny::fileInput("dec_cpabe_key", "CP-ABE attribute key (cpabe_attrkey_*.txt)"),
      shiny::helpText(class = "small text-muted",
        sprintf("Policy: %s. Your attribute key opens the file only if its attributes satisfy this policy.",
                env$key_source$policy %||% "(unknown)")))
  })

  # IBE: upload the recipient's identity key; it opens the file only if it was
  # extracted for the exact identity the artifact was sealed to.
  output$dec_ibe_ui <- shiny::renderUI({
    env <- tryCatch(dec_env(), error = function(e) NULL)
    if (is.null(env) || !identical(env$key_source$type, "ibe")) return(NULL)
    shiny::tagList(
      shiny::fileInput("dec_ibe_key", "IBE identity key (ibe_idkey_*.txt)"),
      shiny::helpText(class = "small text-muted",
        sprintf("Identity: %s. Only the key issued for this exact identity opens the file.",
                env$key_source$identity %||% "(unknown)")))
  })

  # OPRF: needs BOTH the exact input and the OPRF key file to reproduce the key.
  output$dec_oprf_ui <- shiny::renderUI({
    env <- tryCatch(dec_env(), error = function(e) NULL)
    if (is.null(env) || !identical(env$key_source$type, "oprf")) return(NULL)
    shiny::tagList(
      shiny::passwordInput("dec_oprf_input", "The exact input you hardened"),
      shiny::fileInput("dec_oprf_key", "OPRF key (oprf_key.oprfkey)"),
      shiny::helpText(class = "small text-muted",
        "Both are required: the input alone cannot derive the key without the OPRF key, and vice versa."))
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
      } else if (t == "timelock") {
        sm <- env$key_source
        if (identical(input$tl_dec_mode %||% "solve", "master")) {
          if (is.null(input$tl_master_up))
            stop("Choose 'Solve the puzzle' or upload the creator's master key file.")
          read_secret_bytes(input$tl_master_up$datapath)     # secret = b (the solution)
        } else {
          N   <- base64_to_raw(sm$modulus %||% stop("Artifact is missing its time-lock modulus."))
          Tsq <- as.numeric(sm$t_squarings %||% stop("Artifact is missing its squaring count."))
          shiny::withProgress(message = "Solving the time-lock puzzle…", value = 0, {
            timelock_solve(N, Tsq, on_progress = function(done, total)
              shiny::setProgress(
                value = done / total,
                detail = sprintf("%s / %s squarings",
                                 format(done, big.mark = ",", scientific = FALSE),
                                 format(total, big.mark = ",", scientific = FALSE))))
          })
        }
      } else if (t == "cpabe") {
        if (is.null(input$dec_cpabe_key))
          stop("This artifact needs a CP-ABE attribute key — upload it below.")
        read_secret_bytes(input$dec_cpabe_key$datapath)
      } else if (t == "ibe") {
        if (is.null(input$dec_ibe_key))
          stop("This artifact needs an IBE identity key — upload it below.")
        read_secret_bytes(input$dec_ibe_key$datapath)
      } else if (t == "oprf") {
        if (!nzchar(input$dec_oprf_input %||% ""))
          stop("This artifact needs the exact input you hardened — type it below.")
        if (is.null(input$dec_oprf_key))
          stop("This artifact needs its OPRF key — upload the .oprfkey file below.")
        list(text = input$dec_oprf_input,
             oprf_key = read_secret_bytes(input$dec_oprf_key$datapath))
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

  # ---------- De-identify (format-preserving encryption, FF1) ----------
  fpe_in <- shiny::reactive({
    shiny::req(input$fpe_infile)
    fpe_read_df(input$fpe_infile$datapath, input$fpe_infile$name)
  })

  output$fpe_status <- shiny::renderUI({
    if (!isTRUE(crypto_backend_available("fpe-ff1")))
      return(shiny::div(class = "alert alert-warning small py-2",
        shiny::HTML("Format-preserving encryption needs the native backend. Build it via <code>tools/build_native.R</code> and restart the app.")))
    shiny::div(class = "alert alert-info small py-2",
      shiny::HTML(paste0(
        "FF1 keeps each field's length &amp; character class (e.g. <code>0012345</code> &rarr; <code>0847213</code>). ",
        "It is <b>deterministic pseudonymisation</b> — the same value always maps to the same token (so joins survive), ",
        "which means it hides identifier <i>content</i> but preserves value frequencies and linkage. It is not anonymisation.")))
  })

  output$fpe_col_ui <- shiny::renderUI({
    df <- tryCatch(fpe_in(), error = function(e) NULL)
    if (is.null(df)) return(shiny::helpText(class = "small text-muted",
                                            "Upload a file to choose which columns to de-identify."))
    shiny::checkboxGroupInput("fpe_cols", "Columns to de-identify", choices = names(df))
  })

  shiny::observeEvent(input$fpe_apply, {
    tryCatch({
      if (!isTRUE(crypto_backend_available("fpe-ff1")))
        stop("Native FF1 backend not built — run tools/build_native.R and restart.")
      df <- fpe_in()
      cols <- input$fpe_cols
      if (length(cols) == 0) stop("Select at least one column to de-identify.")
      key <- if (!is.null(input$fpe_kit_reuse))
        sodium::hex2bin(fpe_parse_kit(readLines(input$fpe_kit_reuse$datapath, warn = FALSE))$key)
      else sodium::random(32L)
      res <- shiny::withProgress(message = "De-identifying…", value = 0.5,
        fpe_apply_table(df, cols, key, mode = input$fpe_alpha))
      rv$fpe_out <- list(df = res$df, kit = fpe_build_kit(key, res$recipe),
                         stats = res$stats, name = input$fpe_infile$name)
      shiny::showNotification(
        "De-identified. Download the CSV and the .fpekit — the .fpekit holds the key and is the only way to reverse it.",
        type = "warning", duration = 12)
    }, error = function(e)
      shiny::showNotification(paste("FPE failed:", conditionMessage(e)), type = "error", duration = 10))
  })

  shiny::observeEvent(input$fpe_reverse, {
    tryCatch({
      if (!isTRUE(crypto_backend_available("fpe-ff1")))
        stop("Native FF1 backend not built — run tools/build_native.R and restart.")
      shiny::req(input$fpe_rev_infile, input$fpe_rev_kit)
      df  <- fpe_read_df(input$fpe_rev_infile$datapath, input$fpe_rev_infile$name)
      kit <- fpe_parse_kit(readLines(input$fpe_rev_kit$datapath, warn = FALSE))
      out <- shiny::withProgress(message = "Restoring…", value = 0.5,
                                 fpe_reverse_table(df, kit))
      rv$fpe_rev <- list(df = out, name = input$fpe_rev_infile$name,
                         cols = vapply(kit$columns, function(c) c$name, character(1)))
      shiny::showNotification("Restored original values.", type = "message")
    }, error = function(e)
      shiny::showNotification(paste("Restore failed:", conditionMessage(e)), type = "error", duration = 10))
  })

  output$fpe_summary <- shiny::renderText({
    if (identical(input$fpe_mode, "reverse")) {
      r <- rv$fpe_rev; shiny::req(r)
      sprintf("Restored %d row(s). Columns reversed from the recipe: %s.",
              nrow(r$df), paste(r$cols, collapse = ", "))
    } else {
      o <- rv$fpe_out; shiny::req(o)
      lines <- vapply(names(o$stats), function(cn) {
        s <- o$stats[[cn]]
        sprintf("  %s: %d tokenised, %d left as-is (too short for FF1), %d NA",
                cn, s$n_tokenised, s$n_short, s$n_na)
      }, character(1))
      paste0(sprintf("De-identified %d column(s) of '%s':\n", length(o$stats), o$name),
             paste(lines, collapse = "\n"),
             "\n\nDownload BOTH files below. Reverse with the de-identified CSV + the .fpekit.")
    }
  })

  output$fpe_preview <- shiny::renderTable({
    df <- if (identical(input$fpe_mode, "reverse")) {
      shiny::req(rv$fpe_rev); rv$fpe_rev$df
    } else if (!is.null(rv$fpe_out)) rv$fpe_out$df
      else tryCatch(fpe_in(), error = function(e) NULL)
    shiny::req(!is.null(df))
    .cap_preview(df)$preview
  }, striped = TRUE, bordered = TRUE, spacing = "xs")

  output$fpe_downloads <- shiny::renderUI({
    if (identical(input$fpe_mode, "reverse")) {
      shiny::req(rv$fpe_rev)
      shiny::div(class = "d-inline-block me-2 mb-2",
        shiny::downloadButton("fpe_dl_restored", "Download restored CSV", class = "btn-outline-primary"))
    } else {
      shiny::req(rv$fpe_out)
      shiny::tagList(
        shiny::div(class = "d-inline-block me-2 mb-2",
          shiny::downloadButton("fpe_dl_csv", "Download de-identified CSV", class = "btn-outline-primary")),
        shiny::div(class = "d-inline-block me-2 mb-2",
          shiny::downloadButton("fpe_dl_kit", "Download .fpekit (key + recipe)", class = "btn-outline-danger")))
    }
  })

  output$fpe_dl_csv <- shiny::downloadHandler(
    filename = function() paste0("deidentified_", tools::file_path_sans_ext(rv$fpe_out$name), ".csv"),
    content  = function(file) utils::write.csv(rv$fpe_out$df, file, row.names = FALSE, na = ""))
  output$fpe_dl_kit <- shiny::downloadHandler(
    filename = function() paste0("deidentified_", tools::file_path_sans_ext(rv$fpe_out$name), ".fpekit"),
    content  = function(file) writeLines(rv$fpe_out$kit, file))
  output$fpe_dl_restored <- shiny::downloadHandler(
    filename = function() paste0("restored_", tools::file_path_sans_ext(rv$fpe_rev$name), ".csv"),
    content  = function(file) utils::write.csv(rv$fpe_rev$df, file, row.names = FALSE, na = ""))

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

  # Private stats (DP) tab handlers (pure-R, always available).
  dp_server(input, output, session, rv)

  # Proxy Re-Encryption tab handlers — only when the optional GPL companion is present.
  if (pre_companion_available()) pre_server(input, output, session, rv)

  # Render outputs eagerly. bslib nav panels render their content hidden during
  # the first pass, so Shiny suspends the initially-active tab's outputs and does
  # not wake them until a tab change — which leaves the Encrypt tab blank after an
  # upload. Disabling suspend-when-hidden for the display outputs fixes that.
  for (id in c("import_info", "preview", "strength", "enc_summary", "downloads",
               "pqc_key_status", "cpabe_key_status", "cpabe_issue_status",
               "ibe_key_status", "ibe_issue_status",
               "sign_ui", "sign_key_status", "dec_signature", "tl_estimate",
               "dec_signpub_ui", "dec_shares_ui", "dec_timelock_ui", "dec_cpabe_ui",
               "dec_ibe_ui", "dec_oprf_ui", "oprf_key_status",
               "dec_source_hint", "dec_summary", "dec_preview",
               "dec_downloads", "fpe_status", "fpe_col_ui", "fpe_summary", "fpe_downloads",
               "fpe_preview", "dp_group_ui", "dp_value_ui", "dp_status",
               "dp_result", "dp_table", "scheme_table", "help_md")) {
    shiny::outputOptions(output, id, suspendWhenHidden = FALSE)
  }
}
