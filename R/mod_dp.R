# Private stats (DP) tab \u2014 release differentially private aggregates over an
# uploaded table (see R/dp.R for the mechanisms). Pure R, always available.
# A running (epsilon, delta) budget tracks the total privacy spend across queries.

ui_dp <- function() {
  bslib::layout_sidebar(
    sidebar = bslib::sidebar(
      width = 380, title = "Private aggregate statistics",
      shiny::helpText(
        "Publish a count, sum, or mean over a table with calibrated noise, so no ",
        "single row measurably changes the answer. Each release spends part of a ",
        "privacy budget (epsilon)."),
      shiny::fileInput("dp_infile", "CSV / XLSX",
                       accept = c(".csv", ".tsv", ".xlsx", ".xls")),
      shiny::selectInput("dp_query", "Statistic",
        c("Count of rows" = "count",
          "Count by group (histogram)" = "group",
          "Sum of a column" = "sum",
          "Mean of a column" = "mean")),
      shiny::conditionalPanel("input.dp_query == 'group'",
        shiny::uiOutput("dp_group_ui")),
      shiny::conditionalPanel("input.dp_query == 'sum' || input.dp_query == 'mean'",
        shiny::uiOutput("dp_value_ui"),
        shiny::div(class = "row",
          shiny::div(class = "col-6", shiny::numericInput("dp_lower", "Clamp lower", 0)),
          shiny::div(class = "col-6", shiny::numericInput("dp_upper", "Clamp upper", 100))),
        shiny::radioButtons("dp_mech", "Mechanism",
          c("Laplace (epsilon-DP)" = "laplace",
            "Gaussian (epsilon, delta-DP)" = "gaussian")),
        shiny::conditionalPanel("input.dp_mech == 'gaussian'",
          shiny::numericInput("dp_delta", "delta", 1e-6, min = 1e-12, max = 0.1, step = 1e-6))),
      shiny::numericInput("dp_epsilon", "Privacy loss epsilon (this release)", 1, min = 0.001, step = 0.1),
      shiny::numericInput("dp_budget", "Total epsilon budget", 5, min = 0.001, step = 0.5),
      shiny::actionButton("dp_run", "Release private statistic", class = "btn-primary w-100 mb-1"),
      shiny::actionButton("dp_reset", "Reset budget", class = "btn-outline-secondary w-100"),
      .disclaimer()
    ),
    bslib::card(
      bslib::card_header("Differential privacy"),
      bslib::card_body(
        shiny::uiOutput("dp_status"),
        shiny::verbatimTextOutput("dp_result"),
        shiny::tableOutput("dp_table")
      )
    )
  )
}

dp_server <- function(input, output, session, rv) {

  dp_data <- shiny::reactive({
    shiny::req(input$dp_infile)
    fpe_read_df(input$dp_infile$datapath, input$dp_infile$name)
  })

  output$dp_group_ui <- shiny::renderUI({
    df <- tryCatch(dp_data(), error = function(e) NULL)
    shiny::req(df)
    shiny::selectInput("dp_group_col", "Group by column", choices = names(df))
  })
  output$dp_value_ui <- shiny::renderUI({
    df <- tryCatch(dp_data(), error = function(e) NULL)
    shiny::req(df)
    # Prefer columns that parse as numeric, but allow any.
    num <- names(df)[vapply(df, function(c) any(is.finite(suppressWarnings(as.numeric(c)))), logical(1))]
    shiny::selectInput("dp_value_col", "Numeric column",
                       choices = if (length(num)) num else names(df))
  })

  shiny::observeEvent(input$dp_reset, {
    rv$dp_spent <- 0; rv$dp_spent_delta <- 0; rv$dp_result <- NULL
    rv$dp_log <- NULL; rv$dp_msg <- NULL
  })

  shiny::observeEvent(input$dp_run, {
    tryCatch({
      df  <- dp_data()
      q   <- input$dp_query
      eps <- as.numeric(input$dp_epsilon)
      if (!is.finite(eps) || eps <= 0) stop("Epsilon must be a positive number.")
      mech  <- input$dp_mech %||% "laplace"
      delta <- if (identical(mech, "gaussian")) as.numeric(input$dp_delta) else 0
      tbl <- NULL; truth <- NULL; res <- NULL; label <- NULL

      if (q == "count") {
        truth <- nrow(df); res <- dp_count(truth, eps)
        label <- "Count of rows"

      } else if (q == "group") {
        col <- input$dp_group_col; shiny::req(col)
        counts <- table(df[[col]], useNA = "ifany")
        gnames <- names(counts); gnames[is.na(gnames)] <- "(missing)"
        noisy  <- dp_histogram(as.integer(counts), eps)
        tbl <- data.frame(group = gnames, true_count = as.integer(counts),
                          private_count = noisy, check.names = FALSE)
        res <- NULL; label <- sprintf("Histogram of '%s' (%d groups)", col, length(counts))

      } else {                                   # sum or mean
        col <- input$dp_value_col; shiny::req(col)
        vals <- suppressWarnings(as.numeric(df[[col]]))
        if (!any(is.finite(vals))) stop("Selected column has no numeric values.")
        lo <- as.numeric(input$dp_lower); hi <- as.numeric(input$dp_upper)
        if (!is.finite(lo) || !is.finite(hi)) stop("Provide numeric clamp bounds.")
        if (hi < lo) stop("Clamp upper must be >= lower.")
        if (identical(mech, "gaussian") && (!is.finite(delta) || delta <= 0 || delta >= 1))
          stop("Delta must be in (0, 1) for the Gaussian mechanism.")
        clamped <- dp_clamp(vals[is.finite(vals)], lo, hi)
        if (q == "sum") { truth <- sum(clamped);  res <- dp_sum(vals, lo, hi, eps, mech, delta) }
        else            { truth <- mean(clamped); res <- dp_mean(vals, lo, hi, eps, mech, delta) }
        label <- sprintf("%s of '%s' (clamped to [%g, %g], %s)",
                         if (q == "sum") "Sum" else "Mean", col, lo, hi, mech)
      }

      rv$dp_spent <- (rv$dp_spent %||% 0) + eps
      rv$dp_spent_delta <- (rv$dp_spent_delta %||% 0) + delta
      rv$dp_result <- list(label = label, eps = eps, delta = delta,
                           res = res, truth = truth, tbl = tbl)
      rv$dp_msg <- NULL
    }, error = function(e) rv$dp_msg <- conditionMessage(e))
  })

  output$dp_status <- shiny::renderUI({
    budget <- as.numeric(input$dp_budget %||% NA)
    spent  <- rv$dp_spent %||% 0
    sd     <- rv$dp_spent_delta %||% 0
    over   <- is.finite(budget) && spent > budget + 1e-12
    bar_cls <- if (over) "bg-danger" else "bg-success"
    pct <- if (is.finite(budget) && budget > 0) min(100, 100 * spent / budget) else 0
    shiny::tagList(
      if (!is.null(rv$dp_msg))
        shiny::div(class = "alert alert-danger py-2 small", rv$dp_msg),
      shiny::div(class = "small text-muted mb-1",
        sprintf("Privacy spent: epsilon = %.3f%s of %.3f budget.",
                spent, if (sd > 0) sprintf(", delta = %.2g", sd) else "",
                if (is.finite(budget)) budget else NA)),
      shiny::div(class = "progress", style = "height:8px;",
        shiny::div(class = paste("progress-bar", bar_cls), role = "progressbar",
                   style = sprintf("width:%.1f%%;", pct))),
      if (over) shiny::div(class = "text-danger small mt-1",
        "Budget exceeded \u2014 further releases keep leaking privacy. Reset or stop.")
    )
  })

  output$dp_result <- shiny::renderText({
    r <- rv$dp_result
    if (is.null(r)) return("Upload a table and release a statistic. Only the private value is safe to share.")
    lines <- c(r$label, strrep("-", nchar(r$label)))
    if (!is.null(r$res))
      lines <- c(lines,
        sprintf("Private value : %s", format(round(r$res, 4), big.mark = ",")),
        sprintf("True value    : %s   (shown for your reference only)",
                format(round(r$truth, 4), big.mark = ",")))
    else
      lines <- c(lines, "See the table below (true vs private counts).")
    lines <- c(lines, sprintf("Privacy cost  : epsilon = %.3f%s",
                              r$eps, if (r$delta > 0) sprintf(", delta = %.2g", r$delta) else ""))
    paste(lines, collapse = "\n")
  })

  output$dp_table <- shiny::renderTable({
    r <- rv$dp_result
    if (is.null(r) || is.null(r$tbl)) return(NULL)
    utils::head(r$tbl, 200L)                    # cap displayed groups
  })
}
