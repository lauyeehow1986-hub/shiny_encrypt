# shinyEncrypt — usage (single source for the in-app "How to use" tab)

## Step-by-step

1. **Import** — on the *Encrypt* tab, upload a CSV/XLSX (converted to an RDS-equivalent)
   or an existing RDS/binary. A preview of the first rows appears.
2. **Encode** — the object is serialized and Base64-encoded automatically. Optionally gzip
   first (leave **off** for sensitive/structured data — compression can leak information about
   the plaintext).
3. **Choose a key source**
   - **Random key** (recommended): a fresh key is generated — **download it**, it is the only copy.
   - **Passphrase**: a key is derived with **scrypt** (memory-hard).
   - **Free text → hash**: text is hashed (BLAKE3 / SHA-256 / …). A bare hash is **not** a KDF,
     so keep **Harden through scrypt** on; the strength badge warns about weak input.
   - **Key file**: supply your own key bytes (hex text or raw).
4. **Pick a scheme & parameters** — Core AEAD (**XSalsa20-Poly1305** or **AES-256-GCM**) works
   now. Leave nonce/IV blank for a fresh random value, or set it (hex) for reproducible output.
5. **Encrypt** — review the envelope summary: scheme, ciphertext size, and the plaintext
   integrity digest.
6. **Download** — the ciphertext `.txt`, the reproducible `.R` script, and (for the random-key
   source) the key material `.zip`. Keep secret files private.
7. **Decrypt (reverse tab)** — upload a `.txt` or `.R` artifact, supply the matching
   passphrase/free-text or key file, and decrypt. The integrity digest is verified, then you
   can download the original binary (or re-materialize CSV/XLSX).

## Notes

- The exported `.R` is **portable**: it decrypts Core AEAD artifacts with only `sodium` +
  `openssl` installed, and the embedded envelope is parsed as **data** — nothing in the
  uploaded artifact is executed.
- Every envelope is **versioned** and self-describing (scheme, params, salt, key-source
  description, integrity digest), so it stays decryptable as defaults evolve.
- **Not for diagnosis or clinical decision-making.** You are responsible for key custody.
