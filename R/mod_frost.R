# FROST threshold-signature tab — a t-of-n group jointly signs one message with
# a single Schnorr signature, no custodian ever holding the whole key. Shipped as
# a single-machine simulation with an exportable transcript (see R/frost.R). Any
# t of the n custodians can sign; a smaller quorum fails closed. Needs the native
# backend.

ui_frost <- function() {
  bslib::layout_sidebar(
    sidebar = bslib::sidebar(
      width = 380, title = "Threshold signature (FROST)",
      shiny::helpText(
        "Split one signing key across n custodians so any t of them can jointly ",
        "produce a single ordinary signature. No one holds the whole key, and ",
        "fewer than t cannot sign."),
      shiny::tags$b(class = "small", "1. Deal the group key"),
      shiny::div(class = "row g-2",
        shiny::div(class = "col-6",
          shiny::numericInput("frost_n", "Participants (n)", value = 5, min = 2, max = 20, step = 1)),
        shiny::div(class = "col-6",
          shiny::numericInput("frost_t", "Threshold (t)", value = 3, min = 1, max = 20, step = 1))),
      shiny::actionButton("frost_keygen", "Generate group key (deal shares)",
                          class = "btn-primary w-100 mb-2"),
      shiny::tags$hr(),
      shiny::tags$b(class = "small", "2. Sign with a quorum"),
      shiny::textInput("frost_msg", "Message to sign",
                       value = "Approve release of dataset #42"),
      shiny::uiOutput("frost_signer_picker"),
      shiny::actionButton("frost_sign", "Sign with the selected quorum",
                          class = "btn-primary w-100 mb-1"),
      .disclaimer()
    ),
    bslib::card(
      bslib::card_header("Flexible Round-Optimized Schnorr Threshold signatures"),
      bslib::card_body(
        shiny::uiOutput("frost_status"),
        shiny::uiOutput("frost_keygen_out"),
        shiny::uiOutput("frost_sign_out"),
        shiny::uiOutput("frost_transcript"),
        shiny::uiOutput("frost_downloads")
      )
    )
  )
}

frost_server <- function(input, output, session, rv) {

  shiny::observeEvent(input$frost_keygen, {
    tryCatch({
      if (!isTRUE(crypto_backend_available("frost")))
        stop("Native FROST backend not built — run tools/build_native.R and restart.")
      rv$frost_keys <- frost_keygen(input$frost_n, input$frost_t)
      rv$frost_sign_res <- NULL         # a fresh group invalidates old signatures
      rv$frost_msg <- NULL
    }, error = function(e) { rv$frost_keys <- NULL; rv$frost_msg <- conditionMessage(e) })
  })

  shiny::observeEvent(input$frost_sign, {
    tryCatch({
      if (is.null(rv$frost_keys)) stop("Deal a group key first.")
      rv$frost_sign_res <- frost_sign(input$frost_msg, rv$frost_keys, input$frost_signers)
      rv$frost_msg <- NULL
    }, error = function(e) { rv$frost_sign_res <- NULL; rv$frost_msg <- conditionMessage(e) })
  })

  # Quorum picker — always reflects the current group; pre-selects exactly t.
  output$frost_signer_picker <- shiny::renderUI({
    k <- rv$frost_keys
    if (is.null(k)) return(shiny::helpText(class = "small text-muted",
      "Deal a group key to choose signers."))
    ids <- vapply(k$shares, function(s) s$id, integer(1))
    shiny::tagList(
      shiny::checkboxGroupInput("frost_signers",
        sprintf("Signing quorum (need ≥ %d of %d)", k$t, k$n),
        choices = stats::setNames(ids, paste("Custodian", ids)),
        selected = utils::head(ids, k$t), inline = TRUE),
      shiny::helpText(class = "small text-muted",
        "Tip: pick fewer than t and watch the signature fail closed.")
    )
  })

  output$frost_status <- shiny::renderUI({
    if (!isTRUE(crypto_backend_available("frost")))
      return(shiny::div(class = "alert alert-warning small py-2",
        shiny::HTML("Threshold signatures (FROST) need the native backend. Build it via <code>tools/build_native.R</code> and restart the app.")))
    shiny::tagList(
      if (!is.null(rv$frost_msg))
        shiny::div(class = "alert alert-danger py-2 small", rv$frost_msg),
      shiny::div(class = "alert alert-info small py-2",
        shiny::HTML(paste0(
          "A trusted dealer splits one Schnorr key into <b>n</b> shares via a ",
          "degree-(t−1) polynomial. Signing takes two rounds: each chosen signer ",
          "first commits to fresh nonces, then — given the whole commitment set — ",
          "emits a partial signature. The coordinator sums the partials into a ",
          "single <b>(R, z)</b> that verifies like any Schnorr signature under the ",
          "one group public key. Simulated on one machine.")))
    )
  })

  output$frost_keygen_out <- shiny::renderUI({
    k <- rv$frost_keys
    if (is.null(k)) return(NULL)
    shiny::tagList(
      shiny::div(class = "alert alert-success py-2 small mb-2",
        shiny::HTML(sprintf(paste0(
          "<b>Group dealt.</b> %d custodians, threshold %d. Each holds a 32-byte ",
          "share; no one holds the whole key. Any %d can sign, any %d cannot."),
          k$n, k$t, k$t, k$t - 1L))),
      shiny::div(class = "small text-muted", "Group public key (the single verification key):"),
      shiny::tags$pre(class = "small", .frost_hex(k$group_pk))
    )
  })

  output$frost_sign_out <- shiny::renderUI({
    o <- rv$frost_sign_res
    if (is.null(o)) return(NULL)
    quorum <- paste(o$signer_ids, collapse = ", ")
    if (!isTRUE(o$success)) {
      return(shiny::div(class = "alert alert-danger py-2 small mt-2",
        shiny::HTML(sprintf(paste0(
          "<b>No signature produced.</b> Quorum {%s} is below the threshold of %d ",
          "(or a share was bad), so it failed closed: %s"),
          quorum, o$threshold, o$error))))
    }
    shiny::tagList(
      shiny::div(class = "alert alert-success py-2 small mt-2",
        shiny::HTML(sprintf(paste0(
          "<b>Signed by quorum {%s}.</b> %d partial signatures combined into one ",
          "Schnorr signature, which %s under the group public key."),
          quorum, length(o$shares),
          if (isTRUE(o$verified)) "<b>verifies</b>"
          else "<span class='text-danger'>does NOT verify</span>"))),
      shiny::div(class = "small text-muted", "Aggregated signature  R (32) ‖ z (32):"),
      shiny::tags$pre(class = "small", .frost_hex(o$signature))
    )
  })

  output$frost_transcript <- shiny::renderUI({
    o <- rv$frost_sign_res
    if (is.null(o)) return(NULL)
    lines <- c(
      sprintf("message   : %s", o$message),
      sprintf("quorum    : {%s}  (threshold %d of %d)",
              paste(o$signer_ids, collapse = ", "), o$threshold, o$n),
      sprintf("package   : %d commitments, %d bytes", length(o$commitments), length(o$package)),
      vapply(seq_along(o$shares), function(i)
        sprintf("share z_%-2s : %s…", o$signer_ids[i],
                substr(.frost_hex(utils::head(o$shares[[i]], 16L)), 1L, 32L)),
        character(1)))
    shiny::tagList(
      shiny::tags$hr(),
      shiny::div(class = "small text-muted",
        "Signing transcript — round-1 commitments and each signer's partial:"),
      shiny::tags$pre(class = "small", paste(lines, collapse = "\n"))
    )
  })

  output$frost_downloads <- shiny::renderUI({
    o <- rv$frost_sign_res
    if (is.null(o)) return(NULL)
    shiny::div(class = "d-inline-block me-2 mb-2 mt-1",
      shiny::downloadButton("frost_dl_transcript", "Download signing transcript",
                            class = "btn-outline-secondary"))
  })

  output$frost_dl_transcript <- shiny::downloadHandler(
    filename = function() "frost_signing_transcript.txt",
    content  = function(file) {
      o <- rv$frost_sign_res; k <- rv$frost_keys
      shareblock <- vapply(seq_along(o$shares), function(i)
        sprintf("  z_%s = %s", o$signer_ids[i], .frost_hex(o$shares[[i]])), character(1))
      writeLines(c(
        "# shinyEncrypt FROST — t-of-n threshold Schnorr signing transcript",
        sprintf("# group      : %d custodians, threshold %d", o$n, o$threshold),
        sprintf("# group pubkey: %s", if (is.null(k)) "" else .frost_hex(k$group_pk)),
        sprintf("# message    : %s", o$message),
        sprintf("# quorum     : {%s}", paste(o$signer_ids, collapse = ", ")),
        sprintf("# result     : %s",
                if (isTRUE(o$success))
                  sprintf("valid signature (%s)",
                          if (isTRUE(o$verified)) "verified" else "DID NOT verify")
                else sprintf("failed closed (%s)", o$error)),
        "",
        "# signing package (count || per-signer id || D || E), hex:",
        .frost_hex(o$package),
        "",
        "# per-signer partial signatures:",
        shareblock,
        "",
        if (isTRUE(o$success)) c("# aggregated signature R || z, hex:",
                                 .frost_hex(o$signature)) else NULL
      ), file)
    })
}
