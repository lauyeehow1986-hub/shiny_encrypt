# [Core] Authenticated symmetric encryption (always available, pure R).
#
#  * aead-secretbox : XSalsa20-Poly1305 (libsodium secretbox), 24-byte nonce.
#  * aead-aesgcm    : AES-256-GCM (OpenSSL), 12-byte IV.
#
# Both are AEAD: tampering is detected on decrypt. Nonce/IV are random by default
# and recorded (hex) in the envelope params so decryption is deterministic.

# Normalize a user-entered nonce/IV to exactly nbytes raw bytes.
#   * blank / whitespace            -> NULL  (caller generates a random nonce)
#   * clean hex of the exact length -> decoded verbatim (interop / reproducibility)
#   * anything else                 -> deterministically derived to nbytes via a
#                                      hash of the input, so "123" or a word still
#                                      works. The real nonce is always written back
#                                      into the envelope params, so decrypt matches.
.normalize_nonce <- function(text, nbytes) {
  text <- gsub("[[:space:]]", "", text %||% "")
  if (!nzchar(text)) return(NULL)
  if (grepl("^[0-9a-fA-F]+$", text) && nchar(text) == 2L * nbytes)
    return(sodium::hex2bin(text))
  as_raw(sodium::hash(charToRaw(text)))[seq_len(nbytes)]
}

.register_core_aead <- function() {

  register_scheme(
    id = "aead-secretbox", tier = "Core",
    label = "XSalsa20-Poly1305 (libsodium secretbox)",
    params = list(
      list(name = "nonce", type = "hex", default = NULL,
           label = "Nonce (24 bytes, hex; blank = random)")
    ),
    encrypt = function(pt, key, params) {
      nonce <- .normalize_nonce(params$nonce, 24L) %||% sodium::random(24L)
      ct <- sodium::data_encrypt(as_raw(pt), coerce_key(key, 32L), nonce)
      params$nonce <- sodium::bin2hex(nonce)
      list(ciphertext = as.raw(ct), params = params)
    },
    decrypt = function(ct, key, params) {
      nonce <- sodium::hex2bin(params$nonce)
      as.raw(sodium::data_decrypt(as_raw(ct), coerce_key(key, 32L), nonce))
    }
  )

  register_scheme(
    id = "aead-aesgcm", tier = "Core",
    label = "AES-256-GCM (OpenSSL)",
    params = list(
      list(name = "iv", type = "hex", default = NULL,
           label = "IV (12 bytes, hex; blank = random)")
    ),
    encrypt = function(pt, key, params) {
      iv <- .normalize_nonce(params$iv, 12L) %||% openssl::rand_bytes(12L)
      ct <- openssl::aes_gcm_encrypt(as_raw(pt), key = coerce_key(key, 32L), iv = iv)
      params$iv <- sodium::bin2hex(iv)
      list(ciphertext = as.raw(ct), params = params)
    },
    decrypt = function(ct, key, params) {
      iv <- sodium::hex2bin(params$iv)
      as.raw(openssl::aes_gcm_decrypt(as_raw(ct), key = coerce_key(key, 32L), iv = iv))
    }
  )
}
