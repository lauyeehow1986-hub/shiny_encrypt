# Proxy Re-Encryption (PRE) tab — powered by the OPTIONAL, GPL-licensed companion
# package shinyEncryptPRE. This tab and its server handlers only activate when that
# package is installed and its native backend loads; the MIT core never depends on it.
#
# PRE lets a delegator seal a file to their OWN key, then have an untrusted proxy
# re-encrypt the ciphertext for a chosen receiver — without decrypting it. Here all
# roles run on one machine; each secret/artifact is downloadable so a real receiver
# on another machine can recover it with shinyEncryptPRE::pre_decrypt_reencrypted().

# Is the GPL PRE companion installed and usable this session?
pre_companion_available <- function() {
  requireNamespace("shinyEncryptPRE", quietly = TRUE) &&
    isTRUE(tryCatch(shinyEncryptPRE::pre_available(), error = function(e) FALSE))
}

# Short display fingerprint for a key/artifact (not a security control).
.pre_fp <- function(x) if (is.null(x) || !length(x)) "—" else substr(sodium::bin2hex(x), 1L, 12L)

ui_pre <- function() {
  bslib::layout_sidebar(
    sidebar = bslib::sidebar(
      width = 380, title = "Proxy re-encryption (Umbral)",
      shiny::helpText(
        "Grant a receiver access to a file without ever decrypting it. The delegator ",
        "seals to their own key; an untrusted proxy then re-encrypts the ciphertext for ",
        "the receiver. All roles run here for one machine — download the pieces to run a ",
        "real cross-party flow."),
      shiny::tags$h6("1 · Keys"),
      shiny::actionButton("pre_gen_delegator", "Generate delegator keypair",
                          class = "btn-outline-primary w-100 mb-1"),
      shiny::actionButton("pre_gen_receiver", "Generate receiver keypair",
                          class = "btn-outline-primary w-100 mb-1"),
      shiny::fileInput("pre_receiver_pub_up",
                       "…or upload a receiver public key (.pub hex)",
                       accept = c(".pub", ".txt")),
      shiny::tags$h6("2 · Encrypt"),
      shiny::fileInput("pre_infile", "File to protect (any type)"),
      shiny::actionButton("pre_encrypt", "Encrypt to delegator",
                          class = "btn-primary w-100 mb-1"),
      shiny::tags$h6("3 · Grant + proxy re-encrypt"),
      shiny::actionButton("pre_grant", "Re-encrypt for the receiver",
                          class = "btn-primary w-100 mb-1"),
      shiny::tags$h6("4 · Receiver"),
      shiny::actionButton("pre_recover", "Recover as receiver",
                          class = "btn-primary w-100"),
      .disclaimer()
    ),
    bslib::card(
      bslib::card_header("Umbral proxy re-encryption (GPL companion)"),
      bslib::card_body(
        shiny::uiOutput("pre_status"),
        shiny::verbatimTextOutput("pre_summary"),
        shiny::uiOutput("pre_downloads")
      )
    )
  )
}

# Wire the PRE handlers into the flat app server. Call only when the companion is
# available. `rv` is the app's shared reactiveValues; PRE state lives under rv$pre_*.
pre_server <- function(input, output, session, rv) {
  P <- shinyEncryptPRE::pre_available  # ensure namespace resolvable

  .set_msg <- function(type, text) rv$pre_msg <- list(type = type, text = text)

  # Read a hex public key from an uploaded file.
  .read_pub <- function(path) sodium::hex2bin(trimws(paste(readLines(path, warn = FALSE), collapse = "")))

  # The receiver public key currently in play: an uploaded one wins, else generated.
  .receiver_pub <- function() {
    if (!is.null(input$pre_receiver_pub_up))
      return(tryCatch(.read_pub(input$pre_receiver_pub_up$datapath), error = function(e) NULL))
    if (!is.null(rv$pre_receiver)) rv$pre_receiver$public else NULL
  }

  shiny::observeEvent(input$pre_gen_delegator, {
    tryCatch({
      rv$pre_delegator <- shinyEncryptPRE::pre_keygen()
      .set_msg("ok", "Generated a delegator keypair. Keep the secret seed private.")
    }, error = function(e) .set_msg("error", conditionMessage(e)))
  })

  shiny::observeEvent(input$pre_gen_receiver, {
    tryCatch({
      rv$pre_receiver <- shinyEncryptPRE::pre_keygen()
      .set_msg("ok", "Generated a receiver keypair. Hand the receiver their secret seed.")
    }, error = function(e) .set_msg("error", conditionMessage(e)))
  })

  shiny::observeEvent(input$pre_encrypt, {
    tryCatch({
      if (is.null(rv$pre_delegator)) stop("Generate a delegator keypair first.")
      shiny::req(input$pre_infile)
      raw <- readBin(input$pre_infile$datapath, "raw",
                     n = file.info(input$pre_infile$datapath)$size)
      enc <- shinyEncryptPRE::pre_encrypt(rv$pre_delegator$public, raw)
      rv$pre_enc <- list(capsule = enc$capsule, ciphertext = enc$ciphertext,
                         name = input$pre_infile$name, nbytes = length(raw))
      rv$pre_grant <- NULL; rv$pre_recovered <- NULL
      .set_msg("ok", sprintf("Sealed %s (%d bytes) to the delegator public key.",
                             input$pre_infile$name, length(raw)))
    }, error = function(e) .set_msg("error", conditionMessage(e)))
  })

  shiny::observeEvent(input$pre_grant, {
    tryCatch({
      if (is.null(rv$pre_delegator)) stop("Generate a delegator keypair first.")
      if (is.null(rv$pre_enc)) stop("Encrypt a file first.")
      rpub <- .receiver_pub()
      if (is.null(rpub)) stop("Provide a receiver public key (generate or upload one).")
      rekey <- shinyEncryptPRE::pre_rekey(rv$pre_delegator$secret, rpub)
      cfrag <- shinyEncryptPRE::pre_reencrypt(rv$pre_enc$capsule, rekey,
                                              rv$pre_delegator$public, rpub)
      rv$pre_grant <- list(rekey = rekey, cfrag = cfrag, rpub = rpub)
      rv$pre_recovered <- NULL
      .set_msg("ok", "Minted a re-encryption key and re-encrypted the capsule for the receiver.")
    }, error = function(e) .set_msg("error", conditionMessage(e)))
  })

  shiny::observeEvent(input$pre_recover, {
    tryCatch({
      if (is.null(rv$pre_receiver)) stop("Recovery here needs a receiver keypair generated in this app.")
      if (is.null(rv$pre_enc) || is.null(rv$pre_grant)) stop("Encrypt and re-encrypt first.")
      pt <- shinyEncryptPRE::pre_decrypt_reencrypted(
        rv$pre_receiver$secret, rv$pre_delegator$public,
        rv$pre_enc$capsule, rv$pre_grant$cfrag, rv$pre_enc$ciphertext)
      rv$pre_recovered <- list(bytes = pt, name = rv$pre_enc$name)
      ok <- length(pt) == rv$pre_enc$nbytes
      .set_msg(if (ok) "ok" else "error",
               sprintf("Receiver recovered %d bytes%s.", length(pt),
                       if (ok) " — matches the original length" else " (length differs!)"))
    }, error = function(e) .set_msg("error", conditionMessage(e)))
  })

  output$pre_status <- shiny::renderUI({
    m <- rv$pre_msg
    if (is.null(m)) return(shiny::div(class = "text-muted small",
      "All roles run on this machine. Secret seeds and the re-encryption key are secret."))
    cls <- if (identical(m$type, "ok")) "alert alert-success" else "alert alert-danger"
    shiny::div(class = paste(cls, "py-2 small"), m$text)
  })

  output$pre_summary <- shiny::renderText({
    d <- rv$pre_delegator; r <- rv$pre_receiver
    rpub <- .receiver_pub()
    lines <- c(
      sprintf("Delegator public : %s", .pre_fp(if (!is.null(d)) d$public else NULL)),
      sprintf("Receiver public  : %s%s", .pre_fp(rpub),
              if (!is.null(input$pre_receiver_pub_up)) "  (uploaded)"
              else if (!is.null(r)) "  (generated here)" else ""),
      sprintf("Encrypted file   : %s", if (!is.null(rv$pre_enc))
        sprintf("%s (%d bytes, capsule %d B)", rv$pre_enc$name, rv$pre_enc$nbytes,
                length(rv$pre_enc$capsule)) else "—"),
      sprintf("Re-encryption key: %s", .pre_fp(if (!is.null(rv$pre_grant)) rv$pre_grant$rekey else NULL)),
      sprintf("Capsule fragment : %s", .pre_fp(if (!is.null(rv$pre_grant)) rv$pre_grant$cfrag else NULL)),
      sprintf("Recovered        : %s", if (!is.null(rv$pre_recovered))
        sprintf("%d bytes", length(rv$pre_recovered$bytes)) else "—")
    )
    paste(lines, collapse = "\n")
  })

  output$pre_downloads <- shiny::renderUI({
    btns <- list()
    hx <- function(id, label, cls) shiny::downloadButton(id, label, class = cls)
    if (!is.null(rv$pre_delegator)) btns <- c(btns, list(
      hx("pre_dl_deleg_secret", "Delegator secret seed (.preseed)", "btn-outline-danger btn-sm me-1 mb-1"),
      hx("pre_dl_deleg_pub", "Delegator public (.pub)", "btn-outline-secondary btn-sm me-1 mb-1")))
    if (!is.null(rv$pre_receiver)) btns <- c(btns, list(
      hx("pre_dl_recv_secret", "Receiver secret seed (.preseed)", "btn-outline-danger btn-sm me-1 mb-1"),
      hx("pre_dl_recv_pub", "Receiver public (.pub)", "btn-outline-secondary btn-sm me-1 mb-1")))
    if (!is.null(rv$pre_enc)) btns <- c(btns, list(
      hx("pre_dl_capsule", "Capsule (.capsule)", "btn-outline-secondary btn-sm me-1 mb-1"),
      hx("pre_dl_ciphertext", "Ciphertext (.ct)", "btn-outline-secondary btn-sm me-1 mb-1")))
    if (!is.null(rv$pre_grant)) btns <- c(btns, list(
      hx("pre_dl_rekey", "Re-encryption key (.rekey)", "btn-outline-danger btn-sm me-1 mb-1"),
      hx("pre_dl_cfrag", "Capsule fragment (.cfrag)", "btn-outline-secondary btn-sm me-1 mb-1")))
    if (!is.null(rv$pre_recovered)) btns <- c(btns, list(
      hx("pre_dl_recovered", "Recovered file", "btn-primary btn-sm me-1 mb-1")))
    if (!length(btns)) return(NULL)
    shiny::div(shiny::tags$hr(),
      shiny::div(class = "small text-muted mb-1",
        "Give the receiver: their secret seed, the delegator public, the capsule, the ",
        "capsule fragment, and the ciphertext. They recover it with ",
        shiny::tags$code("shinyEncryptPRE::pre_decrypt_reencrypted()"), "."),
      btns)
  })

  # ---- download handlers (hex for keys/artifacts; raw for the recovered file) ----
  .dl_hex <- function(get) shiny::downloadHandler(
    filename = function() attr(get(), "fname"),
    content  = function(file) writeLines(sodium::bin2hex(get()), file))
  tag <- function(x, fname) { attr(x, "fname") <- fname; x }

  output$pre_dl_deleg_secret <- .dl_hex(function() tag(rv$pre_delegator$secret, "delegator.preseed"))
  output$pre_dl_deleg_pub    <- .dl_hex(function() tag(rv$pre_delegator$public, "delegator.pub"))
  output$pre_dl_recv_secret  <- .dl_hex(function() tag(rv$pre_receiver$secret, "receiver.preseed"))
  output$pre_dl_recv_pub     <- .dl_hex(function() tag(rv$pre_receiver$public, "receiver.pub"))
  output$pre_dl_capsule      <- .dl_hex(function() tag(rv$pre_enc$capsule, "message.capsule"))
  output$pre_dl_ciphertext   <- .dl_hex(function() tag(rv$pre_enc$ciphertext, "message.ct"))
  output$pre_dl_rekey        <- .dl_hex(function() tag(rv$pre_grant$rekey, "grant.rekey"))
  output$pre_dl_cfrag        <- .dl_hex(function() tag(rv$pre_grant$cfrag, "message.cfrag"))
  output$pre_dl_recovered <- shiny::downloadHandler(
    filename = function() paste0("recovered_", rv$pre_recovered$name),
    content  = function(file) writeBin(rv$pre_recovered$bytes, file))
}
