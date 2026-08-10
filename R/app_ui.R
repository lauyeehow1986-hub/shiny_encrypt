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
      shiny::conditionalPanel(
        "input.keysrc == 'hybrid_pqc'",
        shiny::helpText(class = "small text-muted",
          "Post-quantum hybrid (X25519 + ML-KEM-768). Encrypts to a recipient ",
          "public key; only their secret key can decrypt."),
        shiny::actionButton("gen_pqc", "Generate a new PQC keypair",
                            class = "btn-outline-primary btn-sm mb-2 w-100"),
        shiny::uiOutput("pqc_key_status"),
        shiny::fileInput("pqc_pub_up", "…or upload a recipient public key (.pub)")),
      shiny::conditionalPanel(
        "input.keysrc == 'shamir'",
        shiny::helpText(class = "small text-muted",
          "Split a fresh random key across n custodians; any t of them ",
          "reconstruct it, fewer reveal nothing. Download all n share files."),
        shiny::div(class = "d-flex gap-2",
          shiny::numericInput("shamir_t", "Threshold t", value = 2, min = 1, max = 255, step = 1),
          shiny::numericInput("shamir_n", "Shares n", value = 3, min = 1, max = 255, step = 1))),
      shiny::conditionalPanel(
        "input.keysrc == 'timelock'",
        shiny::helpText(class = "small text-muted",
          "Seals a fresh random key behind a sequential-squaring puzzle: the ",
          "artifact opens only after roughly the chosen delay of non-stop ",
          "computation. No key file is produced — time is the key."),
        shiny::div(class = "d-flex gap-2",
          shiny::numericInput("tl_amount", "Delay", value = 10, min = 1, step = 1),
          shiny::selectInput("tl_unit", "Unit",
            c("seconds" = "1", "minutes" = "60", "hours" = "3600", "days" = "86400"),
            selected = "60")),
        shiny::selectInput("tl_bits", "Modulus strength",
          c("2048-bit (standard)" = "2048", "3072-bit (strong)" = "3072",
            "1024-bit (fast, weak)" = "1024"), selected = "2048"),
        shiny::checkboxInput("tl_keep_master",
          "Also keep a master key so I can decrypt instantly (off = true time-lock)", FALSE),
        shiny::uiOutput("tl_estimate")),
      shiny::conditionalPanel(
        "input.keysrc == 'cpabe'",
        shiny::helpText(class = "small text-muted",
          "Seals a fresh random key under a boolean ATTRIBUTE POLICY. Only holders ",
          "of an attribute key that satisfies the policy can decrypt — role-based ",
          "access without a per-recipient key exchange."),
        shiny::actionButton("gen_cpabe", "Generate a new CP-ABE authority",
                            class = "btn-outline-primary btn-sm mb-2 w-100"),
        shiny::uiOutput("cpabe_key_status"),
        shiny::fileInput("cpabe_pk_up", "…or upload an authority public key (.pub)"),
        shiny::textInput("cpabe_policy", "Access policy",
          placeholder = "\"cardiology\" and (\"senior\" or \"admin\")"),
        shiny::helpText(class = "small text-muted",
          shiny::HTML(paste0("Quote each attribute; combine with <code>and</code> / ",
            "<code>or</code> and parentheses. Example: ",
            "<code>\"cardiology\" and \"senior\"</code>."))),
        shiny::hr(),
        shiny::div(class = "small fw-bold mb-1", "Issue attribute keys"),
        shiny::textInput("cpabe_issue_attrs", "Recipient attributes (comma-separated)",
          placeholder = "cardiology, senior"),
        shiny::fileInput("cpabe_master_up",
          "Master key (.master) — needed unless you just generated an authority"),
        shiny::actionButton("cpabe_issue", "Issue attribute key",
                            class = "btn-outline-secondary btn-sm w-100"),
        shiny::uiOutput("cpabe_issue_status")),
      shiny::conditionalPanel(
        "input.keysrc == 'ibe'",
        shiny::helpText(class = "small text-muted",
          "Seals a fresh key straight to a recipient IDENTITY string (an email, a ",
          "role, a study id) — no certificate, no prior key exchange. The authority ",
          "issues that identity its own key; only it can decrypt."),
        shiny::actionButton("gen_ibe", "Generate a new IBE authority",
                            class = "btn-outline-primary btn-sm mb-2 w-100"),
        shiny::uiOutput("ibe_key_status"),
        shiny::fileInput("ibe_pk_up", "…or upload an authority public key (.pub)"),
        shiny::textInput("ibe_identity", "Recipient identity",
          placeholder = "alice@hospital.org"),
        shiny::helpText(class = "small text-muted",
          "Any text is a valid identity; the same string must be used to issue the ",
          "recipient's key. Leading/trailing spaces are ignored."),
        shiny::hr(),
        shiny::div(class = "small fw-bold mb-1", "Issue identity keys"),
        shiny::textInput("ibe_issue_id", "Identity to issue a key for",
          placeholder = "alice@hospital.org"),
        shiny::fileInput("ibe_master_up",
          "Master key (.master) — needed unless you just generated an authority"),
        shiny::actionButton("ibe_issue", "Issue identity key",
                            class = "btn-outline-secondary btn-sm w-100"),
        shiny::uiOutput("ibe_issue_status")),
      shiny::conditionalPanel(
        "input.keysrc == 'oprf'",
        shiny::helpText(class = "small text-muted",
          "Hardens an input (a passphrase, id, or secret) with a SEPARATELY-held ",
          "OPRF key through an oblivious protocol. The key needs BOTH the input ",
          "and the OPRF key, so a weak input resists offline guessing as long as ",
          "the OPRF key is held apart. The key holder never sees your input."),
        shiny::passwordInput("oprf_input", "Input to harden"),
        shiny::actionButton("gen_oprf", "Generate a new OPRF key",
                            class = "btn-outline-primary btn-sm mb-2 w-100"),
        shiny::uiOutput("oprf_key_status"),
        shiny::fileInput("oprf_key_up", "…or upload an existing OPRF key (.oprfkey)")),
      shiny::hr(),
      shiny::selectInput("scheme", "Encryption scheme", choices = NULL),
      shiny::textInput("nonce", "Nonce/IV (optional — blank = secure random)", ""),
      shiny::helpText(class = "small text-muted",
                      "Leave blank for a random nonce (recommended). Any text is accepted; exact-length hex is used verbatim."),
      shiny::uiOutput("sign_ui"),
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
      shiny::uiOutput("dec_signpub_ui"),
      shiny::passwordInput("dec_secret", "Passphrase / free text (if used)"),
      shiny::fileInput("dec_keyfile", "…or key file (for random-key / key-file sources)"),
      shiny::uiOutput("dec_shares_ui"),
      shiny::uiOutput("dec_timelock_ui"),
      shiny::uiOutput("dec_cpabe_ui"),
      shiny::uiOutput("dec_ibe_ui"),
      shiny::uiOutput("dec_oprf_ui"),
      shiny::actionButton("do_decrypt", "Decrypt", class = "btn-primary w-100"),
      .disclaimer()
    ),
    bslib::card(
      bslib::card_header("Recovered data"),
      bslib::card_body(
        shiny::uiOutput("dec_signature"),
        shiny::verbatimTextOutput("dec_summary"),
        shiny::uiOutput("dec_downloads"),
        shiny::tableOutput("dec_preview")
      )
    )
  )
}

ui_fpe <- function() {
  bslib::layout_sidebar(
    sidebar = bslib::sidebar(
      width = 360, title = "Format-preserving de-identification",
      shiny::radioButtons("fpe_mode", NULL,
        c("Apply — de-identify columns" = "apply",
          "Reverse — restore originals" = "reverse")),
      shiny::conditionalPanel(
        "input.fpe_mode == 'apply'",
        shiny::fileInput("fpe_infile", "CSV / XLSX to de-identify",
                         accept = c(".csv", ".tsv", ".xlsx", ".xls")),
        shiny::uiOutput("fpe_col_ui"),
        shiny::selectInput("fpe_alpha", "Alphabet",
          c("Auto-detect per column (recommended)" = "auto",
            "Force digits (0–9)" = "digits",
            "Force A–Z 0–9" = "alnum_upper",
            "Force a–z A–Z 0–9" = "alnum")),
        shiny::fileInput("fpe_kit_reuse",
          "Reuse an existing .fpekit (optional — for matching tokens across files)"),
        shiny::actionButton("fpe_apply", "De-identify", class = "btn-primary w-100")),
      shiny::conditionalPanel(
        "input.fpe_mode == 'reverse'",
        shiny::fileInput("fpe_rev_infile", "De-identified CSV / XLSX",
                         accept = c(".csv", ".tsv", ".xlsx", ".xls")),
        shiny::fileInput("fpe_rev_kit", ".fpekit (key + recipe)"),
        shiny::actionButton("fpe_reverse", "Restore originals", class = "btn-primary w-100")),
      .disclaimer()
    ),
    bslib::card(
      bslib::card_header("Format-preserving encryption (FF1)"),
      bslib::card_body(
        shiny::uiOutput("fpe_status"),
        shiny::verbatimTextOutput("fpe_summary"),
        shiny::uiOutput("fpe_downloads"),
        shiny::tableOutput("fpe_preview")
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
  panels <- list(
    bslib::nav_panel("Encrypt", ui_encrypt()),
    bslib::nav_panel("Decrypt", ui_decrypt()),
    bslib::nav_panel("De-identify (FPE)", ui_fpe()),
    bslib::nav_panel("Private stats (DP)", ui_dp()),
    bslib::nav_panel("Set intersection (PSI)", ui_psi())
  )
  # Proxy Re-Encryption is an optional GPL companion; show its tab only when installed.
  if (pre_companion_available())
    panels <- c(panels, list(bslib::nav_panel("Re-encrypt (PRE)", ui_pre())))
  panels <- c(panels, list(
    bslib::nav_panel("Schemes", ui_schemes()),
    bslib::nav_panel("How to use", ui_help()),
    bslib::nav_spacer(),
    bslib::nav_item(shiny::tags$span(class = "navbar-text small",
                                     "v0.1 · not for clinical use"))
  ))
  do.call(bslib::page_navbar,
          c(list(title = "shinyEncrypt", theme = app_theme(), id = "nav"), panels))
}
