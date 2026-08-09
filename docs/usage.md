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
   - **Time-lock (decrypt only after a delay)** *(native)*: a fresh key is sealed behind an **RSW
     sequential-squaring puzzle**. Choose a delay (seconds → days); the app calibrates this
     machine and sizes the puzzle. No key file is produced — *time is the key* — and decrypting
     means recomputing the answer through millions of sequential squarings. Optionally keep a
     creator **master key** to skip the wait yourself; off = a true time-lock for everyone.
   - **Attribute policy (CP-ABE)** *(native)*: a fresh key is sealed under a boolean **policy** over
     attributes — `"cardiology" and ("senior" or "admin")`. Generate (or upload) an **authority**:
     a `.pub` that encrypts under a policy and a SECRET `.master` that issues per-recipient
     **attribute keys**. Anyone whose attribute key *satisfies* the policy can decrypt; others fail
     closed. Role-based access with no per-recipient key exchange — but the master mints any key, so
     guard it like a CA root.
   - **Recipient identity (IBE)** *(native)*: a fresh key is sealed straight to an **identity
     string** — `alice@hospital.org`, a role, a study id — with no certificate. Generate (or upload)
     an **authority**: a `.pub` that encrypts to *any* identity and a SECRET `.master` (the Private
     Key Generator) that **extracts** a per-identity key. Only the key issued for that exact identity
     decrypts; others fail closed. Like CP-ABE the master is an escrow root and there is no
     revocation — rotate the authority to cut identities off.
4. **Pick a scheme & parameters** — Core AEAD (**XSalsa20-Poly1305** or **AES-256-GCM**) works
   now. Leave nonce/IV blank for a fresh random value, or set it (hex) for reproducible output.
   Optionally tick **Sign this envelope (ML-DSA-65)** *(native)* to attach a post-quantum signature;
   generate a signing keypair in-app and keep the `.signsecret` private.
5. **Encrypt** — review the envelope summary: scheme, ciphertext size, the plaintext
   integrity digest, and — if signed — the signer fingerprint.
6. **Download** — the ciphertext `.txt`, the reproducible `.R` script, and the key material: the
   random-key `.zip`, the PQC secret bundle, or the `share_k_of_n.txt` files. Keep secret files private.
7. **Decrypt (reverse tab)** — upload a `.txt` or `.R` artifact, supply the matching
   passphrase / free-text / key file / **PQC secret** / **any t Shamir shares** / **solved
   time-lock** (the tab solves the puzzle for you, with a progress bar, or takes the creator's
   master key) / **CP-ABE attribute key** (decrypts only if its attributes satisfy the policy) /
   **IBE identity key** (decrypts only if issued for the sealed identity),
   and decrypt. The integrity digest is verified, then you can download the original
   binary (or re-materialize CSV/XLSX). Any signature is verified automatically; paste an
   **expected signer** key/fingerprint to *pin* who signed it (green = authenticated, amber =
   valid but unpinned, red = mismatch).

## De-identify (FPE) — a separate tab

Format-preserving encryption is its own workflow, not part of the encrypt/decrypt
envelope flow. Use it to tokenise identifier **columns** of a table while keeping
their format.

1. **Apply** — upload a CSV/XLSX, tick the columns to de-identify, and pick an
   alphabet (**Auto-detect** per column is recommended; you can force digits,
   A–Z 0–9, or a–z A–Z 0–9). Each field becomes another field of the **same
   length and character class** (`0012345` → `0847213`); characters outside the
   alphabet (spaces, `-`, `/`) stay in place. It's deterministic, so equal values
   map to equal tokens — joins on a tokenised ID still work. Values too short for
   FF1's domain rule are left unchanged (and reported).
2. **Download** — the de-identified CSV **and** the `.fpekit` (it holds the key
   and the per-column recipe; treat it as secret — it is the only way to reverse).
3. **Reverse** — switch to Reverse mode, upload the de-identified CSV + its
   `.fpekit`, and the original values are restored exactly.
4. **Consistent tokens across files** — reuse one `.fpekit` when de-identifying a
   second file so the same identifier tokenises to the same value in both.

> Deterministic FPE is **pseudonymisation, not anonymisation**: it hides an
> identifier's content but preserves value frequencies and linkage, so it does
> not defend against frequency analysis. Columns are read as text so leading
> zeros survive; make sure ID columns really are text in your source file.

## Notes

- The exported `.R` is **portable**: it decrypts Core AEAD artifacts with only `sodium` +
  `openssl` installed, and the embedded envelope is parsed as **data** — nothing in the
  uploaded artifact is executed. Artifacts that use a **native** key source (Argon2id, PQC
  hybrid, Shamir, time-lock, CP-ABE, IBE) decrypt through the installed package instead, since they
  need the Rust backend.
- Every envelope is **versioned** and self-describing (scheme, params, salt, key-source
  description, integrity digest), so it stays decryptable as defaults evolve.
- The **native** features (Argon2id, PQC hybrid KEM, ML-DSA signing, Shamir custody, time-lock,
  CP-ABE, IBE) appear only when the Rust backend is built and staged; the app probes the loaded library at
  startup and offers just what it can run. A pinned signature only *authenticates* a signer if you
  compare the fingerprint out-of-band — a valid-but-unpinned signature proves integrity, not identity.
- The **time-lock** delay is a compute cost, not a wall-clock guarantee: it depends on the solver's
  single-core speed (a faster CPU or optimised code finishes sooner) and cannot be shortened by
  adding cores. The legitimate recipient must burn that CPU time too. It rests on factoring the
  RSA modulus being hard *and* on there being no shortcut to the repeated squaring without the
  (destroyed) trapdoor. For a delay tied to real calendar time instead, a beacon scheme like drand
  `tlock` would be needed — but that requires network access, which this offline tool avoids.
- **CP-ABE** is access *control*, not distributed *trust*: a single authority holds the master key
  and can mint an attribute key for any attribute set, so it can decrypt anything — guard the
  `.master` like a certificate-authority root. Attribute strings are matched exactly (case- and
  spelling-sensitive), and the policy is stored in the envelope in clear (it describes *who* may
  decrypt, not a secret). Revocation is not built in: to cut off a holder you must re-key and
  re-encrypt under a fresh authority.
- **IBE** shares CP-ABE's trust shape: the authority master is a Private Key Generator that can
  extract — and therefore decrypt as — *any* identity, so it is an escrow root; guard the `.master`
  the same way. The identity is stored in the envelope in clear (it names *who* may decrypt), matched
  exactly, and there is no revocation — rotate the authority to cut an identity off.
- **Not for diagnosis or clinical decision-making.** You are responsible for key custody.
