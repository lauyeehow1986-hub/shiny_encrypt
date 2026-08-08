# Shiny UI (bslib navbar). Kept in one place; server logic in app_server.R.

app_theme <- function() {
  bslib::bs_theme(
    version = 5, preset = "flatly",
    primary = "#2c7fb8", base_font = bslib::font_google("Inter", local = FALSE)
  )
}

.disclaimer <- function() {
  shiny::div(
    class = "small text-muted border-top pt-2 mt-3",
    shiny::HTML("&#9888; Research/utility tool — <b>not for diagnosis or clinical decision-making</b>. ",
                "You are responsible for key custody. Never upload real patient data you are not authorised to process.")
  )
}

ui_encrypt <- function() {
  bslib::layout_sidebar(
    sidebar = bslib::sidebar(
      width = 360, title = "1–5. Encrypt pipeline",
      shiny::fileInput("infile", "Import CSV / XLSX / RDS / binary (up to 1 GB)",
                       accept = c(".csv", ".tsv", ".xlsx", ".xls", ".rds", ".bin")),
      shiny::selectInput("kind", "Interpret as",
                         c("Auto-detect" = "auto", "CSV" = "csv", "Excel (xlsx)" = "xlsx",
                           "RDS" = "rds", "Raw binary" = "binary")),
      shiny::checkboxInput("gzip", "gzip before encrypting (off for sensitive/structured data)", FALSE),
      shiny::hr(),
      shiny::selectInput("keysrc", "Key source",
                         c("Random key (download it!)" = "random",
                           "Passphrase (KDF)" = "passphrase",
                           "Free text → hash" = "freetext_hash",
                           "Key file" = "keyfile")),
      shiny::conditionalPanel(
        "input.keysrc == 'passphrase'",
        shiny::passwordInput("passphrase", "Passphrase"),
        shiny::selectInput("kdf", "KDF", c("scrypt (memory-hard)" = "scrypt",
                                            "bcrypt_pbkdf" = "bcrypt_pbkdf"))),
      shiny::conditionalPanel(
        "input.keysrc == 'freetext_hash'",
        shiny::textAreaInput("freetext", "Free text", rows = 2,
                             placeholder = "any text; hashed to key material"),
        shiny::selectInput("hashalgo", "Hash", c("BLAKE3" = "blake3", "SHA-256" = "sha256",
                                                 "SHA-512" = "sha512", "SHA3-256" = "sha3-256",
                                                 "MD5 (weak)" = "md5")),
        shiny::checkboxInput("harden", "Harden through scrypt (recommended)", TRUE),
        shiny::uiOutput("strength")),
      shiny::conditionalPanel(
        "input.keysrc == 'keyfile'",
        shiny::fileInput("keyfile_up", "Key file (hex text or raw bytes)")),
      shiny::hr(),
      shiny::selectInput("scheme", "Encryption scheme", choices = NULL),
      shiny::textInput("nonce", "Nonce/IV (optional — blank = secure random)", ""),
      shiny::helpText(class = "small text-muted",
                      "Leave blank for a random nonce (recommended). Any text is accepted; exact-length hex is used verbatim."),
      shiny::actionButton("do_encrypt", "Encrypt", class = "btn-primary w-100"),
      .disclaimer()
    ),
    bslib::card(
      bslib::card_header("Input preview"),
      bslib::card_body(shiny::verbatimTextOutput("import_info"),
                       shiny::tableOutput("preview"))
    ),
    bslib::card(
      bslib::card_header("Encryption result"),
      bslib::card_body(
        shiny::verbatimTextOutput("enc_summary"),
        shiny::uiOutput("downloads")
      )
    )
  )
}

ui_decrypt <- function() {
  bslib::layout_sidebar(
    sidebar = bslib::sidebar(
      width = 360, title = "Decrypt (reverse)",
      shiny::fileInput("artifact", "Upload .txt or .R artifact",
                       accept = c(".txt", ".R", ".r")),
      shiny::uiOutput("dec_source_hint"),
      shiny::passwordInput("dec_secret", "Passphrase / free text (if used)"),
      shiny::fileInput("dec_keyfile", "…or key file (for random-key / key-file sources)"),
      shiny::actionButton("do_decrypt", "Decrypt", class = "btn-primary w-100"),
      .disclaimer()
    ),
    bslib::card(
      bslib::card_header("Recovered data"),
      bslib::card_body(
        shiny::verbatimTextOutput("dec_summary"),
        shiny::uiOutput("dec_downloads"),
        shiny::tableOutput("dec_preview")
      )
    )
  )
}

ui_schemes <- function() {
  bslib::card(
    bslib::card_header("Cryptographic scheme catalogue"),
    bslib::card_body(
      shiny::p("Every primitive is listed with its implementation tier and whether it is available in this session. ",
               "Core AEAD works now; Native/Heavy/Interactive activate once the native crate is built; ",
               "Stub rows have no secure implementation anywhere (a mathematical/ecosystem limit, not hardware)."),
      shiny::tableOutput("scheme_table")
    )
  )
}

ui_help <- function() {
  bslib::card(
    bslib::card_header("How to use"),
    bslib::card_body(shiny::uiOutput("help_md"))
  )
}

app_ui <- function() {
  bslib::page_navbar(
    title = "shinyEncrypt", theme = app_theme(), id = "nav",
    bslib::nav_panel("Encrypt", ui_encrypt()),
    bslib::nav_panel("Decrypt", ui_decrypt()),
    bslib::nav_panel("Schemes", ui_schemes()),
    bslib::nav_panel("How to use", ui_help()),
    bslib::nav_spacer(),
    bslib::nav_item(shiny::tags$span(class = "navbar-text small",
                                     "v0.1 · not for clinical use"))
  )
}
