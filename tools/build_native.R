#!/usr/bin/env Rscript
# Build the native crypto backend (src/rust) into inst/libs/x64/shinyencrypt_native.dll.
#
# Reproducible on this Windows box (see reference: extendr on Windows). Steps:
#   1. cargo build --release --target x86_64-pc-windows-gnu   (staticlib)
#   2. R CMD SHLIB entrypoint.c + staticlib -> the loadable .dll
# The .dll is a build artifact (gitignored); R/backend.R dyn.loads it if present,
# otherwise the app runs on the pure-R Core AEAD path.
#
# Run:  & "C:/Program Files/R/R-4.5.2/bin/x64/Rscript.exe" tools/build_native.R

# ---- locate this script's project root -------------------------------------
.args <- commandArgs(trailingOnly = FALSE)
.self <- sub("^--file=", "", .args[grepl("^--file=", .args)])
root  <- if (length(.self)) normalizePath(file.path(dirname(.self), "..")) else getwd()

crate     <- "shinyencrypt_native"
rust_dir  <- file.path(root, "src", "rust")
src_dir   <- file.path(root, "src")
out_dir   <- file.path(root, "inst", "libs", "x64")
target    <- "x86_64-pc-windows-gnu"
# Short target dir dodges Windows MAX_PATH on cargo's build-script exes.
cargo_td  <- "C:/se_ct"

rhome <- normalizePath(R.home(), winslash = "/")
cargo_bin <- normalizePath("~/.cargo/bin", winslash = "/", mustWork = FALSE)
rtools <- c("C:/rtools45/usr/bin", "C:/rtools45/x86_64-w64-mingw32.static.posix/bin")
rbin  <- file.path(rhome, "bin", "x64")

Sys.setenv(
  PATH = paste(c(cargo_bin, rtools, rbin, Sys.getenv("PATH")), collapse = .Platform$path.sep),
  R_HOME = rhome,
  CARGO_TARGET_DIR = cargo_td
)

cargo <- Sys.which("cargo")
if (!nzchar(cargo)) stop("cargo not found on PATH (expected in ~/.cargo/bin).")
message("cargo:  ", cargo)
message("R_HOME: ", rhome)

# ---- 1. cargo staticlib -----------------------------------------------------
message("\n[1/3] cargo build --release --target ", target, " ...")
st <- system2("cargo",
              c("build", "--release", "--target", target,
                "--manifest-path", shQuote(file.path(rust_dir, "Cargo.toml"))))
if (st != 0) stop("cargo build failed.")

staticlib <- file.path(cargo_td, target, "release", paste0("lib", crate, ".a"))
if (!file.exists(staticlib)) stop("staticlib not produced: ", staticlib)
file.copy(staticlib, file.path(src_dir, paste0("lib", crate, ".a")), overwrite = TRUE)

# ---- 2. R CMD SHLIB assembles the loadable dll ------------------------------
message("\n[2/3] R CMD SHLIB -> ", crate, ".dll ...")
dll_tmp <- file.path(src_dir, paste0(crate, ".dll"))
pkg_libs <- sprintf("-L. -l%s -lws2_32 -ladvapi32 -luserenv -lbcrypt -lntdll -lkernel32 -ldbghelp",
                    crate)
old <- setwd(src_dir); on.exit(setwd(old), add = TRUE)
Sys.setenv(PKG_LIBS = pkg_libs)
st <- system2(file.path(rbin, "R.exe"),
              c("CMD", "SHLIB", "entrypoint.c", "-o", paste0(crate, ".dll")))
if (st != 0 || !file.exists(dll_tmp)) stop("R CMD SHLIB failed.")

# ---- 3. stage the dll under inst/libs/x64 -----------------------------------
message("\n[3/3] staging dll -> ", out_dir)
dir.create(out_dir, recursive = TRUE, showWarnings = FALSE)
file.copy(dll_tmp, file.path(out_dir, paste0(crate, ".dll")), overwrite = TRUE)

# tidy intermediate objects (keep the staticlib out of git via .gitignore)
unlink(c(dll_tmp, file.path(src_dir, "entrypoint.o"),
         file.path(src_dir, paste0("lib", crate, ".a"))))

message("\nOK -> ", file.path(out_dir, paste0(crate, ".dll")))
message("Restart the app; R/backend.R will dyn.load it and enable native caps.")
