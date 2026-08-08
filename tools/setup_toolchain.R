#!/usr/bin/env Rscript
# One-time setup for the OPTIONAL native crypto backend (Phase 4+).
# Safe to run repeatedly; it checks before acting and never touches secrets.
#
#   Rscript tools/setup_toolchain.R
#
# It installs the R-side helpers (rextendr, cpp11) automatically and CHECKS for
# Rustup/Cargo and Rtools, printing exact next steps if they are missing. It does
# not silently download large native installers.

msg <- function(...) cat(sprintf(...), "\n")
have <- function(cmd) nzchar(Sys.which(cmd))

msg("== shinyEncrypt native toolchain check ==")

## 1) R helper packages
for (p in c("rextendr", "cpp11")) {
  if (!requireNamespace(p, quietly = TRUE)) {
    msg("Installing R package: %s", p)
    try(install.packages(p, repos = "https://cloud.r-project.org"))
  } else msg("OK  R package: %s (%s)", p, as.character(packageVersion(p)))
}

## 2) Rust toolchain
if (have("cargo") && have("rustc")) {
  msg("OK  Rust: %s / %s", system("rustc --version", intern = TRUE)[1],
      system("cargo --version", intern = TRUE)[1])
} else {
  msg("MISSING Rust. Install Rustup, then re-run this script:")
  if (.Platform$OS.type == "windows") {
    msg("  1) Download & run rustup-init.exe from https://rustup.rs")
    msg("  2) Choose the default (stable-msvc) toolchain; restart the shell.")
  } else {
    msg("  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh")
  }
}

## 3) Rtools (Windows compiler chain)
if (.Platform$OS.type == "windows") {
  rtools <- pkgbuild_ok <- requireNamespace("pkgbuild", quietly = TRUE) &&
    isTRUE(tryCatch(pkgbuild::has_rtools(), error = function(e) FALSE))
  if (isTRUE(rtools)) msg("OK  Rtools detected.")
  else msg("MISSING/UNVERIFIED Rtools. Install the matching Rtools for your R version: https://cran.r-project.org/bin/windows/Rtools/")
}

msg("")
msg("Next: build the crate in src/rust (Phase 4). Until then the app runs on the")
msg("Core AEAD schemes and native/heavy schemes report unavailable.")
msg("To enable native schemes once built, set:")
msg("  options(shinyEncrypt.native.enabled = TRUE,")
msg("          shinyEncrypt.native.caps = c('hpke-hybrid','ml-dsa','shamir', ...))")
