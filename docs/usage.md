# shinyEncrypt — usage (single source for the in-app "How to use" tab)

## Step-by-step

1. **Import** — on the *Encrypt* tab, upload a CSV/XLSX (converted to an RDS-equivalent)
   or an existing RDS/binary. A preview of the first rows appears.
2. **Encode** — the object is serialized and Base64-encoded automatically. Optionally gzip
   first (leave **off** for sensitive/structured data — compression can leak information about
   the plaintext).
3. **Choose a key source**
   - **Random key** (recommended): a fresh key is generated — **download it**, it is the only copy.
   - **Passphrase**: a key is derived with **scrypt** (memory-hard), or **Argon2id** when the
     native backend is built (OWASP costs, stored in the envelope so the key re-derives on decrypt).
   - **Free text → hash**: text is hashed (BLAKE3 / SHA-256 / …). A bare hash is **not** a KDF,
     so keep **Harden through scrypt** on; the strength badge warns about weak input.
   - **Key file**: supply your own key bytes (hex text or raw).
   - **Recipient public key (PQC hybrid)** *(native)*: an **X25519 + ML-KEM-768** KEM. Generate a
     keypair in-app, share the `.pub`, and encrypt to it; only the matching `.secret` bundle decrypts.
   - **Random key split into Shamir shares (t-of-n)** *(native)*: a fresh key is split across `n`
     custodians; the key is never stored, and any **t** of the `share_k_of_n.txt` files rebuild it.
4. **Pick a scheme & parameters** — Core AEAD (**XSalsa20-Poly1305** or **AES-256-GCM**) works
   now. Leave nonce/IV blank for a fresh random value, or set it (hex) for reproducible output.
   Optionally tick **Sign this envelope (ML-DSA-65)** *(native)* to attach a post-quantum signature;
   generate a signing keypair in-app and keep the `.signsecret` private.
5. **Encrypt** — review the envelope summary: scheme, ciphertext size, the plaintext
   integrity digest, and — if signed — the signer fingerprint.
6. **Download** — the ciphertext `.txt`, the reproducible `.R` script, and the key material: the
   random-key `.zip`, the PQC secret bundle, or the `share_k_of_n.txt` files. Keep secret files private.
7. **Decrypt (reverse tab)** — upload a `.txt` or `.R` artifact, supply the matching
   passphrase / free-text / key file / **PQC secret** / **any t Shamir shares**, and decrypt. The
   integrity digest is verified, then you can download the original binary (or re-materialize
   CSV/XLSX). Any signature is verified automatically; paste an **expected signer** key/fingerprint
   to *pin* who signed it (green = authenticated, amber = valid but unpinned, red = mismatch).

## Notes

- The exported `.R` is **portable**: it decrypts Core AEAD artifacts with only `sodium` +
  `openssl` installed, and the embedded envelope is parsed as **data** — nothing in the
  uploaded artifact is executed. Artifacts that use a **native** key source (Argon2id, PQC
  hybrid, Shamir) decrypt through the installed package instead, since they need the Rust backend.
- Every envelope is **versioned** and self-describing (scheme, params, salt, key-source
  description, integrity digest), so it stays decryptable as defaults evolve.
- The **native** features (Argon2id, PQC hybrid KEM, ML-DSA signing, Shamir custody) appear only
  when the Rust backend is built and staged; the app probes the loaded library at startup and
  offers just what it can run. A pinned signature only *authenticates* a signer if you compare the
  fingerprint out-of-band — a valid-but-unpinned signature proves integrity, not identity.
- **Not for diagnosis or clinical decision-making.** You are responsible for key custody.
