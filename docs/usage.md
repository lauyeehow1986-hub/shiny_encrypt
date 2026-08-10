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
   - **OPRF-hardened input** *(native)*: derives the key from a **low-entropy input** (a
     passphrase, id, or secret) hardened by a **separately-held OPRF key** (`.oprfkey`), run
     through a **verifiable oblivious PRF** so the key holder never sees the input. Generate (or
     upload) the 32-byte OPRF key, type the input, and encrypt. The key needs **both** parts, so a
     weak input resists offline guessing as long as the OPRF key is kept apart. Decryption needs
     the exact input **and** the `.oprfkey`; a wrong OPRF key is rejected (DLEQ proof), a wrong
     input fails closed on the AEAD tag.
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

## Private stats (DP) — a separate tab

Differential privacy lets you publish an **aggregate** (a count, sum, or mean) over a table
while provably bounding how much any single row can affect the answer. It is its own tab, not
part of the encrypt/decrypt flow.

1. **Upload** a CSV/XLSX and pick a **statistic**: count of rows, count by group (a histogram),
   sum of a column, or mean of a column.
2. **Set the privacy loss** `epsilon` for this release (smaller = more private = noisier). For
   sums/means, give **clamp bounds** `[lower, upper]` — every value is clipped into that range so
   the sensitivity is bounded — and choose **Laplace** (ε-DP) or **Gaussian** (ε, δ-DP).
3. **Release** — the noisy statistic is shown (with the true value alongside, for your reference
   only — *only the noisy value is safe to share*). A running **budget bar** tracks the total ε
   (and δ) spent across releases; each query adds to it (sequential composition), while the bins of
   one histogram share a single ε (parallel composition).

Counts and histograms use a **discrete** (integer) Laplace mechanism that avoids the floating-point
pitfalls of naive continuous samplers; all noise is drawn from a cryptographically secure source.

## Set intersection (PSI) — a separate tab

Private set intersection finds which identifiers **two** parties share, without either side
revealing its non-shared entries. It is its own tab (native backend required), shipped as a
single-machine two-party simulation.

1. **Upload dataset A** (your set) and pick its **ID column**.
2. **Upload dataset B** (their set) and pick its **ID column**.
3. **Compute** — the shared IDs are listed with the set sizes and the Jaccard overlap. Download the
   shared IDs, the matched rows of A, or the **wire transcript** (the masked points that would
   actually cross between parties — uniform-random without the other party's secret).

Each identifier is hashed to a ristretto255 point and masked with a per-party secret scalar; the
group is commutative, so a shared value lands on the same doubly-masked point while everything else
looks random. Only masked points cross the wire — the raw lists never do. It reuses the same curve
as the OPRF module.

> PSI is **honest-but-curious**: the party running the match learns the overlap and the other set's
> *size*, and both sides must run the protocol faithfully. Values are matched exactly (as text), so
> normalise identifiers (case, whitespace, leading zeros) before comparing. Duplicates within a set
> are ignored — it is a set operation.

## Password login (OPAQUE) — a separate tab

OPAQUE is an **asymmetric PAKE**: a client logs in by password while the **server never sees the
password** and stores **no password-equivalent**. It is its own tab (native backend required),
shipped as a single-machine two-party simulation.

1. **Register** — choose a password. The server stores a per-user OPRF key, a masking key, the
   client public key, and an authenticated envelope — never the password and never a hash of it.
2. **Log in** — enter the password. The app runs an oblivious PRF plus a **3-message Diffie-Hellman
   (3DH)** exchange. On success both sides derive the **same session key** and the client recovers a
   stable **export key** (a password-derived key usable to encrypt data).
3. **Inspect / download** the **KE1/KE2/KE3** transcript — the only bytes that cross between client
   and server.

A wrong password **fails closed** at the envelope check; a tampered or forged server message fails
the client's server-authentication check; a client that cannot prove the password fails the server's
check. This is OPAQUE-3DH on ristretto255 (internal-envelope mode), reusing the same curve as the
OPRF module.

> A stolen server record still forces a **per-user offline dictionary attack**, slowed by Argon2 —
> the record leaks no plaintext password. Honest-but-curious, two-party model.

## Threshold signature (FROST) — a separate tab

FROST lets **n custodians** share one signing key so that **any t of them can jointly produce a
single ordinary Schnorr signature**, and **no custodian ever holds the whole key**. It is its own tab
(native backend required), shipped as a single-machine simulation.

1. **Deal the group key** — choose the number of participants **n** and a threshold **t**. A trusted
   dealer splits the key with a degree-(t−1) polynomial and gives each custodian one 32-byte share.
   The single **group public key** is the verification key.
2. **Sign with a quorum** — type a message and tick which custodians sign. Each first commits to fresh
   nonces, then emits a partial signature bound to the whole commitment set; the coordinator sums the
   partials into one signature **(R, z)**.
3. **Inspect / download** the signing transcript — the round-one commitments, each partial, and the
   aggregated signature — and confirm it verifies under the group public key.

A quorum **below the threshold** fails closed: the shares no longer interpolate the group secret, so
the combined signature does not verify and aggregation is rejected. This is FROST on ristretto255,
reusing the same curve as the OPRF module.

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
- **OPRF hardening** is *not* public-key encryption: there is no recipient keypair. It is a way to
  turn a weak input into a strong key using a second secret (the OPRF key) held apart, so neither
  the input nor the OPRF key alone can derive it, and the party holding the OPRF key never sees the
  input (the oblivious property). The security rests on keeping the two apart — put the `.oprfkey`
  on a different device or with a different custodian than the input. Losing either loses the file.
- **Private set intersection (PSI)** reveals *only* the overlap of two identifier sets, but it is
  honest-but-curious and not anonymisation: the matching party learns which of its own IDs are shared
  and the counterparty's set size, and a shared identifier is still a real identifier once matched.
  Only masked curve points cross between parties, never the raw lists. It is a two-party protocol
  shipped as a single-machine simulation; a genuine cross-organisation run needs the counterparty to
  execute their half. Match keys are compared exactly, so normalise them first.
- **Password login (OPAQUE)** is an **asymmetric PAKE**: the server never learns the password and its
  stored record contains no password-equivalent, so a database theft still forces a per-user offline
  dictionary attack (slowed by Argon2). Both sides derive the same session key and the client recovers
  a stable export key. It is honest-but-curious and shipped as a single-machine two-party simulation
  (client and server run in one process); a genuine cross-machine login needs the counterparty to run
  their half. It authenticates a password — it does not by itself encrypt your file.
- **Threshold signature (FROST)** distributes *signing authority*, not encryption: any **t of n**
  custodians can jointly sign, no single custodian can, and the result is one ordinary Schnorr
  signature under a single group public key. This build uses a **trusted dealer** for key generation
  (the dealer briefly knows the whole key before discarding it) rather than a distributed key
  generation, and runs all custodians in one process as a simulation — a real deployment would place
  each share on a separate device and exchange the two signing rounds over the network. A sub-threshold
  quorum fails closed. It proves *who authorized* a message; it does not by itself encrypt your file.
- **Proxy re-encryption (PRE)** is an **optional GPL-3 companion package** (`shinyEncryptPRE`), not
  part of this MIT repo — the only mature Rust PRE crate (`umbral-pre`) is GPL-3.0, so it is kept
  separate. Install it and the app gains a **Re-encrypt (PRE)** tab: a delegator seals a file to
  their own key, then an untrusted proxy re-encrypts the ciphertext for a chosen receiver **without
  decrypting it**. Only the receiver's secret opens the result; every key/capsule fragment is
  verified, so wrong-receiver or tampered fragments fail closed. Whoever holds the re-encryption key
  plus a cooperating proxy can re-target the ciphertext to the named receiver — guard re-encryption
  keys accordingly.
- **Differential privacy** is not encryption and not de-identification: it releases a *noisy
  aggregate*, not the rows. The guarantee holds only if you respect the **budget** — every release
  spends ε, and spending too much (or re-running until the noise looks small) erodes the protection.
  Clamp bounds must be chosen from domain knowledge, *not* by peeking at the data. The Gaussian
  mechanism trades a small failure probability δ for less noise; Laplace gives pure ε-DP.
- **Not for diagnosis or clinical decision-making.** You are responsible for key custody.
