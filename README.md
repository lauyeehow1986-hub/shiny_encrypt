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
| **IBE** identity key source (Kiltz-Vahlis IBE1) | ✅ working when native backend built |
| **OPRF** verifiable oblivious-PRF key hardening (ristretto255) | ✅ working when native backend built |
| **Differential privacy** — noisy counts / sums / means with an ε budget | ✅ working (pure-R, own **Private stats (DP)** tab) |
| **PSI** private set intersection (ECDH / DH-PSI, ristretto255) | ✅ working when native backend built (own **Set intersection (PSI)** tab) |
| **OPAQUE** asymmetric PAKE password login (OPAQUE-3DH, ristretto255) | ✅ working when native backend built (own **Password login (OPAQUE)** tab) |
| **PRE** proxy re-encryption (Umbral) | ✅ working via the optional **GPL** companion `shinyEncryptPRE` |
| FHE (TFHE), ZK proofs, FROST | ⛏ native, size-guarded (Phase 6) |
| FE / Witness / iO / general-MPC / RBE / UE | 🚫 no secure impl — documented stubs |

The full catalogue (with per-session availability) is shown on the app's **Schemes** tab. The
native features above light up automatically once `src/rust` is built and staged — the app
probes the loaded library at startup and only offers what it can actually run.

**Proxy re-encryption is a separate, optional package.** This repo is **MIT**, but the only
mature Rust PRE crate (`umbral-pre`) is **GPL-3.0**. So PRE ships as a standalone GPL-3
companion package, **`shinyEncryptPRE`** — its own package with its own native library. Install it
and the app grows a **Re-encrypt (PRE)** tab; skip it and the MIT core is completely unaffected.
This keeps the copyleft dependency out of the main project.

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

- **IBE identity key source** — **identity-based encryption** (Kiltz–Vahlis IBE1, an IND-CCA2 IBKEM on BLS12-381, via the `ibe` crate) seals the data key straight to an **identity string** — an email, a role, a study id — with no certificate and no prior key exchange. Offered as the **Recipient identity (IBE)** key source on the Encrypt tab: generate (or upload) an **authority** — a public key that encrypts to *any* identity and a SECRET **master** (the Private Key Generator) that **extracts** a per-identity key. Anyone with the public key can seal to `alice@hospital.org`; only the key the authority extracted for that exact identity decapsulates it. Wrong-identity keys **fail closed**. Like CP-ABE this is access *control* with an **escrow root** (the master can mint any identity's key) and **no revocation** — rotate the authority to cut identities off.

- **OPRF-hardened key source** — a **verifiable oblivious PRF** (RFC 9497-style, ristretto255 + SHA-512, with a Chaum–Pedersen DLEQ proof) offered as the **OPRF-hardened input** key source on the Encrypt tab. It derives the data key as `VOPRF_k(input)` from a low-entropy **input** (a passphrase, id, or secret) and a **separately-held 32-byte OPRF key** (`.oprfkey`), run through the oblivious protocol so the key holder never sees the input. The derived key needs **both** the input and the OPRF key, so a weak input resists offline brute force as long as the OPRF key is kept apart (ideally on another device/custodian) — the same idea as a password-hardening service, run locally. Decryption reproduces the key because the random blind cancels out (the output is deterministic in `(input, key)`), and the DLEQ proof makes the evaluation verifiable: a wrong or tampered OPRF response **fails closed**. Wire-format is self-consistent (not cross-implementation interop), which is all a single-machine tool needs.

- **Private set intersection (PSI)** — an **ECDH / DH-PSI** protocol on ristretto255 (the same group as the OPRF), exposed as its own **Set intersection (PSI)** tab. Two parties each hold a list of identifiers and want to learn only which ones they share. Each element is hashed to a curve point and masked with a per-party secret scalar; because the group is commutative, a value present in both sets lands on the same doubly-masked point while everything else looks like a uniform-random point. **Only the masked points cross between the parties — the raw identifiers never do** — and the app ships this as a single-machine two-party simulation with an exportable wire transcript. The party running the match learns the overlap and the other set's *size*, nothing more (honest-but-curious model). Practical use: find the patient IDs / MRNs two datasets share without either side disclosing its full list.

- **Password login (OPAQUE)** — an **asymmetric PAKE** (OPAQUE-3DH on ristretto255, internal-envelope mode, reusing the OPRF group), exposed as its own **Password login (OPAQUE)** tab. The defining property: the **server authenticates a client by password without ever seeing the password**, and stores **no password-equivalent** — only a per-user OPRF key, a masking key, the client's public key, and an authenticated envelope. Registration hides the password behind an oblivious PRF; login runs that OPRF plus a **3-message Diffie-Hellman (3DH)** so both sides derive the **same session key** and the client recovers a stable **export key** (a password-derived key it can use to encrypt data). Mutual authentication is enforced: a wrong password **fails closed** at the client's envelope check, a tampered/forged server message fails the client's server-authentication check, and a client that cannot prove the password fails the server's check. A stolen server record still forces a **per-user offline dictionary attack, slowed by Argon2**. Shipped as a single-machine two-party simulation with an exportable **KE1/KE2/KE3** transcript.

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
