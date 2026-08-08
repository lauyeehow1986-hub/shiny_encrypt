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
        <li><b>Passphrase</b>: a key is derived with scrypt (memory-hard).</li>
        <li><b>Free text → hash</b>: text is hashed (BLAKE3/SHA-256/…). A bare hash
            is <i>not</i> a KDF, so keep <b>Harden through scrypt</b> on; the strength
            badge warns about weak input.</li>
        <li><b>Key file</b>: supply your own key bytes.</li>
      </ul></li>
  <li><b>Pick a scheme &amp; parameters</b> — Core AEAD (XSalsa20-Poly1305 or
      AES-256-GCM) is available now. Leave nonce/IV blank for a fresh random value,
      or set it (hex) for reproducible output.</li>
  <li><b>Encrypt</b> — review the envelope summary (scheme, sizes, integrity digest).</li>
  <li><b>Download</b> — the ciphertext <code>.txt</code>, the reproducible
      <code>.R</code> script, and (for the random-key source) the key material
      <code>.zip</code>. Keep secret files private.</li>
  <li><b>Decrypt (reverse tab)</b> — upload a <code>.txt</code> or <code>.R</code>
      artifact, supply the matching passphrase/free-text or key file, and decrypt.
      The integrity digest is verified, then you can download the original binary
      (or re-materialize CSV/XLSX).</li>
</ol>
<p class="text-muted small">The exported <code>.R</code> is portable: it decrypts Core
AEAD artifacts with only <code>sodium</code> + <code>openssl</code> installed, and the
embedded envelope is parsed as data — nothing in the artifact is executed.</p>'
}
