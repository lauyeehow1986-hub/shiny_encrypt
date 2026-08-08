# CLAUDE.md — shinyEncrypt

## What this is
A single flat R package that **is** a Shiny app (`run_app()`) plus a cryptographic
engine. It converts CSV/XLSX (or existing RDS/binary) into a serialized, Base64-encoded
payload and protects it with standard + state-of-the-art cryptography, lets the user tune
parameters live, exports a reproducible `.R` script and/or a ciphertext `.txt` envelope,
downloads key material, and decrypts artifacts back to the original binary.

**Real data-protection tool** — serious key hygiene. Research/utility only, **not for
diagnosis or clinical decisions**. **Never commit real data or keys.**

## Repo / git
- Lives at `C:\Users\lauye\Downloads\shiny_embedding_crytography` as its **own** git repo.
- Remote: `github.com/lauyeehow1986-hub/shiny_encrypt`.
- ⚠ Do **not** entangle with the stray `C:\Users\lauye\.git` home repo (its remote is the
  unrelated `R_slice_ar` Unity project). This package has its own `.git`, which detaches it.

## Layout
```
R/            engine + app (see below)      inst/app/www/  assets
src/rust/     extendr crate (Phase 4+)      tests/testthat/ round-trip + KAT tests
tools/        setup_toolchain.R             docs/usage.md   single-source step-by-step
dev/          load.R, run.R, smoke.R, test_server.R  (not shipped; in .Rbuildignore)
```
Engine files: `utils`, `hashing`, `kdf`, `keysource`, `convert`, `envelope`,
`scheme_registry`, `crypto_aead`, `crypto_registrations`, `backend`, `key_io`,
`export_template`. App files: `run_app`, `app_ui`, `app_server`, `help_content`.

## Architecture
- **Scheme registry** (`scheme_registry.R`): every primitive is a record
  `{id, tier, label, params, encrypt, decrypt, available}`. `se_encrypt()`/`se_decrypt()`
  are the high-level entry points; they build/verify a self-describing **envelope**.
- **Tiers**: `Core` (pure-R AEAD, works now) · `Native`/`Heavy`/`Interactive` (need the
  native crate — `available()` gates them) · `Stub` (no secure impl anywhere; explainer only).
- **Envelope** (`envelope.R`): Base64(JSON) between BEGIN/END markers. Same block goes in the
  `.txt` and is embedded verbatim in the exported `.R`. `envelope_parse()` treats artifacts as
  **data only** — never `source()` an uploaded `.R`.

## Conventions
- snake_case functions; one concern per file; keep the pure-R path dependency-light.
- Verify crypto with round-trips before shipping. Run `Rscript dev/smoke.R` and
  `Rscript dev/test_server.R` (both must exit 0).
- **This machine's gotcha:** libsodium `argon2` fails at runtime ("pwhash failed"); use
  `scrypt` (needs a 32-byte salt). Argon2id comes via the native backend.

## Build & run
- R 4.5.2 at `C:/Program Files/R/R-4.5.2/bin/x64/Rscript.exe`.
- Dev launch: `Rscript dev/run.R` → http://127.0.0.1:7788 (or `run_app()` after install).
- Native phases: `tools/setup_toolchain.R` (Rustup + Rtools + rextendr/cpp11), then build
  `src/rust`. Until built, native/heavy/interactive schemes report unavailable and the app
  runs on Core AEAD.

## Roadmap (from the approved plan)
Phase 0 scaffold ✅ · 1 import/encode ✅ · 2 AEAD+key/param ✅ · 3 export+decrypt+key I/O ✅ ·
4 native PQC · 5 native access/custody · 6 heavy+interactive · 7 stubs+hardening · 8 docs/verify.
Plan: `C:\Users\lauye\.claude\plans\i-want-to-create-squishy-candle.md`.
