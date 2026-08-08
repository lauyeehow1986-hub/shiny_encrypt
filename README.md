# shinyEncrypt

A multi-step **Shiny app + cryptographic engine** in R. It converts **CSV / XLSX** (or an
existing **RDS / binary**) into a serialized, Base64-encoded payload, protects it with
**standard and state-of-the-art cryptography** (parameters adjustable live), exports a
**reproducible `.R` script** and/or a **ciphertext `.txt`** envelope, lets you download the
**key material**, and **decrypts** artifacts back to the original binary.

> ⚠️ Research / utility tool — **not for diagnosis or clinical decision-making**. You are
> responsible for key custody. **Never commit or upload real patient data or keys.**

## Status

| Area | State |
|---|---|
| Import CSV/XLSX/RDS/binary → serialize → Base64 | ✅ working |
| Core AEAD: XSalsa20-Poly1305, AES-256-GCM | ✅ working (pure R) |
| Key sources: random / passphrase(scrypt) / free-text→hash / key file | ✅ working |
| Adjustable params (nonce/IV, KDF, gzip) + integrity digest | ✅ working |
| Export `.R` (portable, self-decrypting) + `.txt` envelope + key `.zip` | ✅ working |
| Decrypt tab → original binary / re-materialize CSV | ✅ working |
| PQC (ML-KEM/ML-DSA), CP-ABE, FPE, PRE, time-lock, Shamir | ⛏ native crate (Phase 4–5) |
| FHE (TFHE), ZK proofs, PSI/OPAQUE/FROST | ⛏ native, size-guarded (Phase 6) |
| FE / Witness / iO / general-MPC / RBE / UE | 🚫 no secure impl — documented stubs |

The full catalogue (with per-session availability) is shown on the app's **Schemes** tab.

## Prerequisites

- **R ≥ 4.2** with: `shiny bslib sodium openssl digest jsonlite readr readxl openxlsx zip`.
- **For the native crypto (optional, Phase 4+):** run [`tools/setup_toolchain.R`](tools/setup_toolchain.R)
  to install **Rustup + Cargo**, **Rtools** (Windows), and **rextendr / cpp11**, then build `src/rust`.
  Until built, the app runs fully on the Core AEAD schemes.

## Install & launch

```r
# from the repo root, dev mode (no install needed):
source("dev/load.R"); run_app()          # or: Rscript dev/run.R  -> http://127.0.0.1:7788
```

To install as a package once native bindings are added: `R CMD INSTALL .` then `shinyEncrypt::run_app()`.

## Step-by-step usage

1. **Import** (Encrypt tab) — upload a CSV/XLSX (converted to an RDS-equivalent) or an RDS/binary; preview appears.
2. **Encode** — automatic serialize + Base64. Optional gzip (leave **off** for sensitive/structured data — compression can leak).
3. **Choose a key source** — Random (download the key — only copy!), Passphrase (scrypt), Free text → hash (keep *Harden* on; a bare hash is not a KDF), or Key file.
4. **Pick a scheme & parameters** — Core AEAD now; nonce/IV blank = random, or set (hex) for reproducible output.
5. **Encrypt** — review the envelope summary (scheme, sizes, integrity digest).
6. **Download** — ciphertext `.txt`, reproducible `.R`, and key material `.zip` (for random keys).
7. **Decrypt (reverse tab)** — upload a `.txt`/`.R`, supply the matching secret/key file, decrypt, verify the digest, download the original (or re-materialize CSV/XLSX).

The exported `.R` is **portable**: it decrypts Core AEAD artifacts with only `sodium` + `openssl`, and the embedded envelope is parsed as **data** — nothing in the artifact is executed.

## Security notes

- Passwords use `passwordInput` and are never logged; keys live in memory only.
- `.gitignore` blocks data, keys, shares, and encrypted outputs. Keep secret key files private.
- Every envelope is versioned and carries a plaintext integrity digest (verified on decrypt).

## Development

```bash
Rscript dev/smoke.R        # engine round-trips + reproducibility + portable .R decrypt
Rscript dev/test_server.R  # headless Shiny server: full encrypt/export/decrypt path
```

## Troubleshooting

- **A scheme shows "unavailable"** → it needs the native crate; build via `tools/setup_toolchain.R`. Core AEAD always works.
- **Argon2id missing** → this machine's libsodium Argon2 fails at runtime; use **scrypt** (default). Argon2id arrives with the native backend.
