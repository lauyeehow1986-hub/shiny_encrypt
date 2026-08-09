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
| **Argon2id KDF** (native, OWASP costs) | ✅ working when native backend built |
| **Hybrid PQC key source** — X25519 + ML-KEM-768 KEM | ✅ working when native backend built |
| **ML-DSA-65 envelope signing** (+ signer pinning on decrypt) | ✅ working when native backend built |
| **Shamir t-of-n** key custody | ✅ working when native backend built |
| **FF1 format-preserving** column de-identification | ✅ working when native backend built |
| **Time-lock** key source (RSW sequential-squaring puzzle) | ✅ working when native backend built |
| **CP-ABE** attribute-policy key source (BSW) | ✅ working when native backend built |
| IBE, PRE | ⛏ native crate (Phase 5) |
| FHE (TFHE), ZK proofs, PSI/OPAQUE/FROST | ⛏ native, size-guarded (Phase 6) |
| FE / Witness / iO / general-MPC / RBE / UE | 🚫 no secure impl — documented stubs |

The full catalogue (with per-session availability) is shown on the app's **Schemes** tab. The
native features above light up automatically once `src/rust` is built and staged — the app
probes the loaded library at startup and only offers what it can actually run.

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
3. **Choose a key source** — Random (download the key — only copy!), Passphrase (scrypt, or **Argon2id** with the native backend), Free text → hash (keep *Harden* on; a bare hash is not a KDF), Key file, **Recipient public key (PQC hybrid)**, or **Random key split into Shamir shares (t-of-n)**.
4. **Pick a scheme & parameters** — Core AEAD now; nonce/IV blank = random, or set (hex) for reproducible output. Optionally tick **Sign this envelope (ML-DSA-65)** to attach a post-quantum signature.
5. **Encrypt** — review the envelope summary (scheme, sizes, integrity digest, and — if signed — the signer fingerprint).
6. **Download** — ciphertext `.txt`, reproducible `.R`, and key material `.zip` (random key, PQC secret bundle, or the `share_k_of_n.txt` files).
7. **Decrypt (reverse tab)** — upload a `.txt`/`.R`, supply the matching secret / key file / PQC secret / **any t Shamir shares**, decrypt, verify the digest, download the original (or re-materialize CSV/XLSX). Any signature is verified automatically; you may **pin** an expected signer key to confirm *who* signed it.

The exported `.R` is **portable**: it decrypts Core AEAD artifacts with only `sodium` + `openssl`, and the embedded envelope is parsed as **data** — nothing in the artifact is executed. Artifacts that use a native key source (Argon2id, PQC hybrid, Shamir) decrypt through the installed package rather than the standalone `.R`, since they need the Rust backend.

## Native crypto features (Phase 4)

Once the native backend is built and staged (`tools/build_native.R` → `inst/libs/x64/shinyencrypt_native.dll`), several additional capabilities appear:

- **Argon2id KDF** — memory-hard passphrase hardening at OWASP costs (m=19456 KiB, t=2, p=1), stored in the envelope so the key re-derives on decrypt. Selected under the Passphrase key source when available. (This machine's libsodium Argon2 is broken; the native backend is the only Argon2id path here — scrypt remains the pure-R default.)
- **Hybrid PQC key source** — an **X25519 + ML-KEM-768** KEM. Generate a keypair in-app, hand out the `.pub`, and encrypt to it; the encapsulation rides in the envelope and only the matching `.secret` bundle decapsulates the data key. Classical **and** post-quantum security — an attacker must break *both* X25519 and ML-KEM.
- **ML-DSA-65 envelope signing** — FIPS 204 post-quantum signatures over the meaning-bearing envelope fields (ciphertext, params, key source, digest — everything but the signature block). The public key is embedded, so the Decrypt tab verifies with no extra upload and shows a signer **fingerprint**. A valid signature proves integrity + "signed by whoever holds that key"; to prove *who*, paste their fingerprint/public key into the **expected signer** field to pin it (green = authenticated, amber = valid-but-unpinned, red = mismatch).
- **Shamir t-of-n custody** — split a fresh random data key across `n` custodians (GF(256) secret sharing). The key itself is never written; you get `n` `share_k_of_n.txt` files. Any **t** reconstruct it; any **t-1** reveal nothing (information-theoretic). Decrypt takes any t shares via a multi-file upload; too few is blocked, and even a bypass fails closed on the AEAD tag.

- **FF1 format-preserving de-identification** — a separate **De-identify (FPE)** tab (not the envelope flow). FF1 (NIST SP 800-38G) tokenises chosen table columns while keeping each field's **exact length and character class** — `0012345` → `0847213`, `AB-1234-CD` → `ZK-8071-MR` (delimiters pass through in place). It's deterministic, so equal values map to equal tokens and joins survive; alphabets are auto-detected per column (radix 10/36/62) and overridable. Output is a de-identified CSV plus a secret `.fpekit` (key + recipe) that reverses it exactly. Deterministic FPE is **pseudonymisation, not anonymisation** — it hides identifier content but preserves value frequencies and linkage; the tab states this plainly.

- **Time-lock key source** — an **RSW sequential-squaring puzzle** (Rivest–Shamir–Wagner) that seals a fresh random data key behind a chosen delay. Offered as the **Time-lock** key source on the Encrypt tab: pick a delay (seconds → days), the app calibrates this machine's squaring rate and sizes the puzzle. It is fully **offline** and self-contained — no key file is produced, and the RSA trapdoor is destroyed at seal time, so **time itself is the key**. To decrypt, the Decrypt tab recomputes the answer by *T* sequential modular squarings, showing a live progress bar. The delay is **approximate**: it cannot be parallelised away (each squaring depends on the last), but a faster single core solves sooner. An optional creator **master key** (the puzzle solution) can be kept to skip the wait; leaving it off is a true time-lock.

- **CP-ABE attribute-policy key source** — **ciphertext-policy attribute-based encryption** (Bethencourt–Sahai–Waters, via the `rabe` crate) seals the data key under a boolean **policy** over attributes, e.g. `"cardiology" and ("senior" or "admin")`. Offered as the **Attribute policy (CP-ABE)** key source on the Encrypt tab: generate (or upload) an **authority** — a public key that encrypts under a policy and a SECRET **master** that issues per-recipient **attribute keys**. A ciphertext opens for any attribute key whose set **satisfies** the policy — role-based access without a per-recipient key exchange or an online server. Non-satisfying keys **fail closed** (they error, and the sealed key is AEAD-protected inside the ABE ciphertext as well). This is access *control*, not multi-authority trust: whoever holds the master can mint any attribute key, so guard it like a CA root.

Each is capability-gated: the app only shows a feature after probing that the loaded library actually exports it, so an older DLL never advertises something it can't do. Enabling a newly-built feature needs an app restart (the running app locks the staged DLL).

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

- **A scheme / key source shows "unavailable"** → it needs the native crate; build via `tools/build_native.R` (toolchain one-time setup: `tools/setup_toolchain.R`). Core AEAD always works.
- **Built the backend but the feature still isn't offered** → the running app locks the staged DLL, so a fresh build can't replace it. Stop the app, run `tools/build_native.R`, then restart.
- **Argon2id / PQC / Shamir missing** → this machine's libsodium Argon2 fails at runtime, so Argon2id (and the PQC + Shamir features) come only from the native backend; without it, use **scrypt** (default) and the Core AEAD key sources.
