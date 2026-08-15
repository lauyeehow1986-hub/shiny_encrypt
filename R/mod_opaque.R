# OPAQUE (PAKE) tab \u2014 a password login where the server never sees the password
# and stores no password-equivalent. Shipped as a single-machine two-party
# simulation with an exportable KE1/KE2/KE3 transcript (see R/opaque.R). On a
# successful login both parties derive the same session key and the client
# recovers a stable export key. Needs the native backend.

ui_opaque <- function() {
  bslib::layout_sidebar(
    sidebar = bslib::sidebar(
      width = 380, title = "Password login (OPAQUE)",
      shiny::helpText(
        "An asymmetric PAKE: register a password, then log in with it. The ",
        "server authenticates you WITHOUT ever seeing the password and without ",
        "storing anything a thief could replay."),
      shiny::tags$b(class = "small", "1. Register"),
      shiny::passwordInput("opaque_reg_pw", "Choose a password", value = ""),
      shiny::actionButton("opaque_register", "Register on the server",
                          class = "btn-primary w-100 mb-2"),
      shiny::tags$hr(),
      shiny::tags$b(class = "small", "2. Log in"),
      shiny::passwordInput("opaque_login_pw", "Enter the password", value = ""),
      shiny::actionButton("opaque_login", "Log in (run the AKE)",
                          class = "btn-primary w-100 mb-1"),
      .disclaimer()
    ),
    bslib::card(
      bslib::card_header("Password-authenticated key exchange"),
      bslib::card_body(
        shiny::uiOutput("opaque_status"),
        shiny::uiOutput("opaque_register_out"),
        shiny::uiOutput("opaque_login_out"),
        shiny::uiOutput("opaque_transcript"),
        shiny::uiOutput("opaque_downloads")
      )
    )
  )
}

opaque_server <- function(input, output, session, rv) {

  shiny::observeEvent(input$opaque_register, {
    tryCatch({
      if (!isTRUE(crypto_backend_available("opaque")))
        stop("Native OPAQUE backend not built \u2014 run tools/build_native.R and restart.")
      # Reuse one server identity across registrations so it is the same server.
      if (is.null(rv$opaque_server_kp)) rv$opaque_server_kp <- opaque_server_setup()
      reg <- opaque_register(input$opaque_reg_pw, rv$opaque_server_kp)
      rv$opaque_record     <- reg$record
      rv$opaque_reg_export <- reg$export_key
      rv$opaque_login_res  <- NULL          # a new registration invalidates old logins
      rv$opaque_msg <- NULL
    }, error = function(e) { rv$opaque_msg <- conditionMessage(e) })
  })

  shiny::observeEvent(input$opaque_login, {
    tryCatch({
      if (!isTRUE(crypto_backend_available("opaque")))
        stop("Native OPAQUE backend not built \u2014 run tools/build_native.R and restart.")
      if (is.null(rv$opaque_record))
        stop("Register a password first, then log in.")
      rv$opaque_login_res <- opaque_login(input$opaque_login_pw,
                                          rv$opaque_record, rv$opaque_server_kp)
      rv$opaque_msg <- NULL
    }, error = function(e) { rv$opaque_login_res <- NULL; rv$opaque_msg <- conditionMessage(e) })
  })

  output$opaque_status <- shiny::renderUI({
    if (!isTRUE(crypto_backend_available("opaque")))
      return(shiny::div(class = "alert alert-warning small py-2",
        shiny::HTML("Password login (OPAQUE) needs the native backend. Build it via <code>tools/build_native.R</code> and restart the app.")))
    shiny::tagList(
      if (!is.null(rv$opaque_msg))
        shiny::div(class = "alert alert-danger py-2 small", rv$opaque_msg),
      shiny::div(class = "alert alert-info small py-2",
        shiny::HTML(paste0(
          "The server stores an <b>OPRF key</b>, a masking key, and an authenticated ",
          "<b>envelope</b> \u2014 never the password or a hash of it. Logging in runs an ",
          "oblivious PRF plus a 3-message Diffie-Hellman (3DH) key exchange: only ",
          "<b>KE1/KE2/KE3</b> cross the wire, and both sides end up holding the same ",
          "session key. Honest-but-curious two-party model, simulated on one machine.")))
    )
  })

  output$opaque_register_out <- shiny::renderUI({
    if (is.null(rv$opaque_record)) return(NULL)
    rec <- rv$opaque_record
    shiny::tagList(
      shiny::div(class = "alert alert-success py-2 small mb-2",
        shiny::HTML(paste0(
          "<b>Registered.</b> The server stored a ", length(rec),
          "-byte record: a per-user OPRF key, masking key, client public key, and ",
          "envelope \u2014 <b>no password, no password hash</b>."))),
      shiny::div(class = "small text-muted",
        "Client export key (a password-derived key you could encrypt data with):"),
      shiny::tags$pre(class = "small", .opaque_hex(rv$opaque_reg_export))
    )
  })

  output$opaque_login_out <- shiny::renderUI({
    o <- rv$opaque_login_res
    if (is.null(o)) return(NULL)
    if (!isTRUE(o$success)) {
      who <- if (identical(o$stage, "server")) "The server rejected the login"
             else "The client aborted the login"
      return(shiny::div(class = "alert alert-danger py-2 small mt-2",
        shiny::HTML(sprintf("<b>Login failed.</b> %s: %s", who, o$error))))
    }
    export_same <- !is.null(rv$opaque_reg_export) &&
                   identical(as.raw(o$export_key), as.raw(rv$opaque_reg_export))
    shiny::tagList(
      shiny::div(class = "alert alert-success py-2 small mt-2",
        shiny::HTML(paste0(
          "<b>Login succeeded \u2014 mutual authentication.</b> ",
          if (isTRUE(o$keys_match))
            "Client and server independently derived the <b>same</b> session key. "
          else
            "<span class='text-danger'>Session keys differ!</span> ",
          if (export_same)
            "The recovered export key matches the one from registration."
          else ""))),
      shiny::div(class = "small text-muted", "Shared session key (client view):"),
      shiny::tags$pre(class = "small", .opaque_hex(o$session_key_client)),
      shiny::div(class = "small text-muted", "Shared session key (server view):"),
      shiny::tags$pre(class = "small", .opaque_hex(o$session_key_server))
    )
  })

  output$opaque_transcript <- shiny::renderUI({
    o <- rv$opaque_login_res
    if (is.null(o)) return(NULL)
    t <- o$transcript
    line <- function(lbl, blob)
      if (is.null(blob)) NULL else
        sprintf("%-5s (%3d bytes)  %s\u2026", lbl, length(blob),
                substr(.opaque_hex(utils::head(blob, 24L)), 1L, 48L))
    shiny::tagList(
      shiny::tags$hr(),
      shiny::div(class = "small text-muted",
        "Wire transcript \u2014 the only bytes that cross between client and server:"),
      shiny::tags$pre(class = "small",
        paste(stats::na.omit(c(
          line("KE1", t$ke1), line("KE2", t$ke2), line("KE3", t$ke3))),
          collapse = "\n"))
    )
  })

  output$opaque_downloads <- shiny::renderUI({
    o <- rv$opaque_login_res
    if (is.null(o)) return(NULL)
    shiny::div(class = "d-inline-block me-2 mb-2 mt-1",
      shiny::downloadButton("opaque_dl_transcript", "Download exchange transcript",
                            class = "btn-outline-secondary"))
  })

  output$opaque_dl_transcript <- shiny::downloadHandler(
    filename = function() "opaque_wire_transcript.txt",
    content  = function(file) {
      o <- rv$opaque_login_res
      t <- o$transcript
      hexblock <- function(lbl, blob) if (is.null(blob)) NULL else c(
        sprintf("[%s] %d bytes:", lbl, length(blob)), .opaque_hex(blob), "")
      writeLines(c(
        "# shinyEncrypt OPAQUE \u2014 wire transcript (what crosses between client and server)",
        "# KE1: client blinded password + ephemeral key.",
        "# KE2: server OPRF evaluation + masked credential response + ephemeral key + MAC.",
        "# KE3: client MAC proving knowledge of the password.",
        sprintf("# Login result: %s.",
                if (isTRUE(o$success)) "success (mutual authentication)"
                else sprintf("failed at the %s (%s)", o$stage, o$error)),
        "",
        hexblock("KE1 (client -> server)", t$ke1),
        hexblock("KE2 (server -> client)", t$ke2),
        hexblock("KE3 (client -> server)", t$ke3)
      ), file)
    })
}
