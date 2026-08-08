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
a native key source (Argon2id, PQC hybrid, Shamir) decrypt through the installed package
instead, since they need the Rust backend. The native features appear only when that backend
is built and staged.</p>'
}
