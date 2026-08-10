# In-app "How to use" content. Kept in sync with docs/usage.md (same steps).
help_html <- function() {
'<h4>Step-by-step</h4>
<ol>
  <li><b>Import</b> — on the <i>Encrypt</i> tab, upload a CSV/XLSX (converted to an
      RDS-equivalent) or an existing RDS/binary. A preview appears.</li>
  <li><b>Encode</b> — the object is serialized and Base64-encoded automatically.
      Optionally gzip first (leave off for sensitive/structured data — compression
      can leak information).</li>
  <li><b>Choose a key source</b> —
      <ul>
        <li><b>Random key</b> (recommended): a fresh key is generated — you must
            download it, it is the only copy.</li>
        <li><b>Passphrase</b>: a key is derived with scrypt (memory-hard), or
            <b>Argon2id</b> when the native backend is built (OWASP costs, stored in
            the envelope so the key re-derives on decrypt).</li>
        <li><b>Free text → hash</b>: text is hashed (BLAKE3/SHA-256/…). A bare hash
            is <i>not</i> a KDF, so keep <b>Harden through scrypt</b> on; the strength
            badge warns about weak input.</li>
        <li><b>Key file</b>: supply your own key bytes.</li>
        <li><b>Recipient public key (PQC hybrid)</b> <i>(native)</i>: an
            X25519&nbsp;+&nbsp;ML-KEM-768 KEM. Generate a keypair in-app, share the
            <code>.pub</code>, and encrypt to it; only the matching <code>.secret</code>
            bundle decrypts.</li>
        <li><b>Random key split into Shamir shares (t-of-n)</b> <i>(native)</i>: the key
            is split across <i>n</i> custodians and never stored; any <i>t</i> of the
            <code>share_k_of_n.txt</code> files rebuild it.</li>
        <li><b>Time-lock (decrypt only after a delay)</b> <i>(native)</i>: a fresh key is
            sealed behind a sequential-squaring puzzle. Pick a delay; no key file is
            produced, so <b>time itself is the key</b>. Decrypting recomputes the answer
            through millions of sequential squarings (a progress bar counts them down),
            and cannot be sped up by adding cores. Optionally keep a creator master key
            to skip the wait.</li>
        <li><b>Attribute policy (CP-ABE)</b> <i>(native)</i>: seals the key under a boolean
            <b>policy</b> over attributes, e.g. <code>"cardiology" and ("senior" or "admin")</code>.
            Generate an authority (a <code>.pub</code> that encrypts under a policy and a SECRET
            <code>.master</code> that issues attribute keys), then hand each recipient an attribute
            key. A file opens for any attribute key whose set <b>satisfies</b> the policy; others
            fail closed. The master can mint any key, so guard it like a CA root.</li>
        <li><b>Recipient identity (IBE)</b> <i>(native)</i>: seals the key straight to an
            <b>identity string</b> (an email, a role, a study id), e.g.
            <code>alice@hospital.org</code> — no certificate. Generate an authority (a
            <code>.pub</code> that encrypts to any identity and a SECRET <code>.master</code> that
            extracts identity keys), then hand each recipient the key issued for their identity.
            Only the key for the sealed identity opens the file; others fail closed. Like CP-ABE the
            master is an escrow root and there is no revocation — rotate the authority to cut an
            identity off.</li>
        <li><b>OPRF-hardened input</b> <i>(native)</i>: derives the key from a low-entropy
            <b>input</b> (a passphrase, id, or secret) strengthened by a <b>separately-held OPRF
            key</b> (<code>.oprfkey</code>), run through a verifiable oblivious PRF so the key
            holder never sees the input. Generate or upload the 32-byte OPRF key, type the input,
            and encrypt. The key needs <b>both</b> parts, so a weak input resists offline guessing
            as long as the OPRF key is kept apart (another device or custodian). Decrypting needs
            the exact input <b>and</b> the <code>.oprfkey</code>: a wrong OPRF key is rejected by a
            DLEQ proof, a wrong input fails closed on the AEAD tag.</li>
      </ul></li>
  <li><b>Pick a scheme &amp; parameters</b> — Core AEAD (XSalsa20-Poly1305 or
      AES-256-GCM) is available now. Leave nonce/IV blank for a fresh random value,
      or set it (hex) for reproducible output. Optionally tick <b>Sign this envelope
      (ML-DSA-65)</b> <i>(native)</i> to attach a post-quantum signature; keep the
      <code>.signsecret</code> private.</li>
  <li><b>Encrypt</b> — review the envelope summary (scheme, sizes, integrity digest,
      and — if signed — the signer fingerprint).</li>
  <li><b>Download</b> — the ciphertext <code>.txt</code>, the reproducible
      <code>.R</code> script, and the key material: the random-key <code>.zip</code>,
      the PQC secret bundle, or the <code>share_k_of_n.txt</code> files. Keep secret
      files private.</li>
  <li><b>Decrypt (reverse tab)</b> — upload a <code>.txt</code> or <code>.R</code>
      artifact, supply the matching passphrase / free-text / key file /
      <b>PQC secret</b> / <b>any t Shamir shares</b>, and decrypt. The integrity digest
      is verified, then you can download the original binary (or re-materialize
      CSV/XLSX). Any signature is verified automatically; paste an <b>expected signer</b>
      key to pin who signed it (green = authenticated, amber = valid but unpinned,
      red = mismatch).</li>
</ol>
<p class="text-muted small">The exported <code>.R</code> is portable: it decrypts Core
AEAD artifacts with only <code>sodium</code> + <code>openssl</code> installed, and the
embedded envelope is parsed as data — nothing in the artifact is executed. Artifacts using
a native key source (Argon2id, PQC hybrid, Shamir, time-lock, CP-ABE, IBE) decrypt through the installed
package instead, since they need the Rust backend. The native features appear only when that
backend is built and staged.</p>
<p class="text-muted small"><b>Proxy re-encryption (PRE)</b> is an optional GPL-3 companion package
(<code>shinyEncryptPRE</code>), kept separate from this MIT app because the umbral-pre crate is
GPL-3.0. When it is installed, a <b>Re-encrypt (PRE)</b> tab appears: a delegator seals a file to
their own key, then an untrusted proxy re-encrypts the ciphertext for a chosen receiver without
decrypting it. Only the receiver secret opens the result, and mismatched or tampered fragments
fail closed.</p>
<h4>De-identify (FPE) — a separate tab</h4>
<p>Format-preserving encryption tokenises identifier <b>columns</b> of a table while
keeping their format — it is its own tab, not part of the encrypt/decrypt flow (native
backend required).</p>
<ol>
  <li><b>Apply</b> — upload a CSV/XLSX, tick the columns to de-identify, and choose an
      alphabet (<b>Auto-detect</b> per column recommended). Each field becomes another of
      the <b>same length and character class</b> (<code>0012345</code> &rarr;
      <code>0847213</code>); delimiters like <code>-</code> pass through in place. It is
      deterministic, so equal values map to equal tokens and joins survive. Values too
      short for the FF1 domain rule are left unchanged.</li>
  <li><b>Download</b> the de-identified CSV <b>and</b> the <code>.fpekit</code> (key +
      recipe — secret; the only way to reverse).</li>
  <li><b>Reverse</b> — switch to Reverse mode and upload the CSV + its <code>.fpekit</code>
      to restore the originals exactly. Reuse one kit across files for matching tokens.</li>
</ol>
<p class="text-muted small">Deterministic FPE is <b>pseudonymisation, not anonymisation</b>:
it hides identifier content but preserves value frequencies and linkage.</p>
<h4>Private stats (DP) &mdash; a separate tab</h4>
<p>Differential privacy publishes a noisy <b>aggregate</b> (a count, sum, or mean) over a table
while bounding how much any single row can change the answer.</p>
<ol>
  <li><b>Upload</b> a CSV/XLSX and pick a <b>statistic</b>: count of rows, count by group (a
      histogram), sum of a column, or mean of a column.</li>
  <li><b>Set epsilon</b> for this release (smaller means more private and noisier). For sums and
      means, give <b>clamp bounds</b> so each value is clipped into a known range, and pick
      <b>Laplace</b> (epsilon-DP) or <b>Gaussian</b> (epsilon, delta-DP).</li>
  <li><b>Release</b> &mdash; the noisy value appears next to the true value (the true value is for
      your reference; only the noisy value is safe to share). A <b>budget bar</b> tracks the total
      epsilon spent across releases.</li>
</ol>
<p class="text-muted small">DP is not encryption and not de-identification: it releases a noisy
answer, not the rows. The guarantee holds only if you respect the budget and choose clamp bounds
from domain knowledge rather than by peeking at the data. Counts use an integer (discrete) noise
mechanism; all noise comes from a secure random source.</p>
<h4>Set intersection (PSI) &mdash; a separate tab</h4>
<p>Private set intersection finds which identifiers two parties share, without either side revealing
its non-shared entries. It is its own tab (native backend required), shipped as a single-machine
two-party simulation.</p>
<ol>
  <li><b>Upload dataset A</b> (your set) and pick its <b>ID column</b>; do the same for
      <b>dataset B</b>.</li>
  <li><b>Compute</b> &mdash; the shared IDs are listed with both set sizes and the Jaccard overlap.</li>
  <li><b>Download</b> the shared IDs, the matched rows of A, or the wire <b>transcript</b> &mdash; the
      masked points that would cross between parties, uniform-random without the other secret.</li>
</ol>
<p class="text-muted small">Each identifier is hashed to a ristretto255 point and masked with a
per-party secret scalar; the group is commutative, so a shared value lands on the same doubly-masked
point while everything else looks random. Only masked points cross the wire, never the raw lists.
PSI is honest-but-curious: the matching party learns the overlap and the other set size, nothing more.
Values are matched exactly as text, so normalise case and spacing first; duplicates within a set are
ignored. It reuses the same curve as the OPRF module.</p>
<h4>Password login (OPAQUE) &mdash; a separate tab</h4>
<p>OPAQUE is an asymmetric password-authenticated key exchange: a client logs in by password while the
server never sees the password and stores no password-equivalent. It is its own tab (native backend
required), shipped as a single-machine two-party simulation.</p>
<ol>
  <li><b>Register</b> &mdash; choose a password. The server stores a per-user OPRF key, a masking key,
      the client public key, and an authenticated envelope &mdash; never the password and never a hash
      of it.</li>
  <li><b>Log in</b> &mdash; enter the password. The app runs an oblivious PRF plus a 3-message
      Diffie-Hellman (3DH) exchange. On success both sides derive the same session key and the client
      recovers a stable export key (a password-derived key usable to encrypt data).</li>
  <li><b>Inspect</b> the KE1/KE2/KE3 transcript &mdash; the only bytes that cross between client and
      server &mdash; and download it.</li>
</ol>
<p class="text-muted small">A wrong password fails closed at the envelope check; a tampered or forged
server message fails the client server-authentication check; a client that cannot prove the password
fails the server check. A stolen server record still forces a per-user offline dictionary attack,
slowed by Argon2. This is OPAQUE-3DH on ristretto255, reusing the same curve as the OPRF module.</p>
<h4>Threshold signature (FROST) &mdash; a separate tab</h4>
<p>FROST lets a group of n custodians share one signing key so that any t of them can jointly produce a
single ordinary Schnorr signature &mdash; and no custodian ever holds the whole key. It is its own tab
(native backend required), shipped as a single-machine simulation.</p>
<ol>
  <li><b>Deal the group key</b> &mdash; choose n custodians and a threshold t. A trusted dealer splits
      the key with a degree-(t&minus;1) polynomial and hands each custodian one 32-byte share. The
      single group public key is the verification key.</li>
  <li><b>Sign with a quorum</b> &mdash; type a message and tick which custodians sign. Each first
      commits to fresh nonces, then emits a partial signature bound to the whole commitment set; the
      coordinator sums the partials into one signature.</li>
  <li><b>Inspect and download</b> the transcript &mdash; the round-one commitments, each partial, and
      the aggregated signature &mdash; and confirm it verifies under the group public key.</li>
</ol>
<p class="text-muted small">Any t custodians sign; a smaller quorum fails closed &mdash; the shares no
longer interpolate the group secret, so the combined signature does not verify and aggregation is
rejected. Binding factors over the whole commitment set defeat known attacks on naive multi-signing.
This is FROST on ristretto255, reusing the same curve as the OPRF module.</p>

<h4>Zero-knowledge proof (ZK) &mdash; a separate tab</h4>
<p>A zero-knowledge range proof convinces a verifier that a hidden number lies inside a public range
[min, max] &mdash; for example that a cohort size is between 100 and 500 &mdash; without revealing the
number itself. It is its own tab (native backend required) and needs no trusted setup: anyone can check
a proof from the file alone.</p>
<ol>
  <li><b>Choose the hidden value</b> &mdash; type a number, or point at a dataset and use its row count
      or the sum of a numeric column. When the value comes from data it is computed on this machine and
      never shown.</li>
  <li><b>Set the range and create the proof</b> &mdash; the value is placed inside a Pedersen commitment
      C = v&middot;G + r&middot;H; a per-bit proof shows it decomposes into bits within the range, and a
      matching proof on (max &minus; v) pins it from above, together proving min &le; v &le; max.</li>
  <li><b>Verify or share</b> &mdash; the app checks the proof, shows that a single flipped byte makes it
      reject, and lets you download the proof file. Hand that file to anyone and they can verify it on
      the same tab; the bounds travel inside it.</li>
</ol>
<p class="text-muted small">A false statement cannot be proved &mdash; if the value is outside the range
the proof simply cannot be produced (it fails closed) &mdash; and a tampered proof does not verify. This
is a transparent Pedersen + Chaum-Pedersen range proof on ristretto255, reusing the same curve as the
OPRF module (no new dependency). It protects a single number, not the whole file.</p>

<h4>Compute on ciphertext (FHE) &mdash; a separate tab</h4>
<p>Fully homomorphic encryption lets an untrusted server compute on data while it stays encrypted. This
tab (native backend required) shows it with a homomorphic sum, using the Zama tfhe-rs library (TFHE) on
the CPU. Because every operation is a real bootstrapped circuit and the keys and ciphertexts are large,
the tab is size-guarded and the number of values is capped.</p>
<ol>
  <li><b>Choose the numbers</b> &mdash; type comma-separated non-negative integers, or point at a dataset
      and pick a numeric column (values are rounded to non-negative integers). Each number is encrypted
      under a fresh secret client key.</li>
  <li><b>Encrypt and compute</b> &mdash; the app hands the ciphertexts and only the evaluation (server)
      key to the homomorphic sum, which adds them without decrypting, then decrypts the single result
      with the client key.</li>
  <li><b>Read the transcript</b> &mdash; it shows the decrypted total matches the plaintext sum, the
      client and server key sizes, the ciphertext size, and a sample ciphertext. You can download the
      encrypted result.</li>
</ol>
<p class="text-muted small">The server key cannot decrypt anything &mdash; there is no such operation
&mdash; so the server learns neither the inputs nor the total. This is a bounded demonstration of the
property (compute on data you cannot read), not a bulk file encryptor: TFHE keys and ciphertexts are
large, so it is size-guarded to stay within the memory and time budget.</p>'
}
