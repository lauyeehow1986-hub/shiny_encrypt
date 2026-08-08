# [Core] Authenticated symmetric encryption (always available, pure R).
#
#  * aead-secretbox : XSalsa20-Poly1305 (libsodium secretbox), 24-byte nonce.
#  * aead-aesgcm    : AES-256-GCM (OpenSSL), 12-byte IV.
#
# Both are AEAD: tampering is detected on decrypt. Nonce/IV are random by default
# and recorded (hex) in the envelope params so decryption is deterministic.

.register_core_aead <- function() {

  register_scheme(
    id = "aead-secretbox", tier = "Core",
    label = "XSalsa20-Poly1305 (libsodium secretbox)",
    params = list(
      list(name = "nonce", type = "hex", default = NULL,
           label = "Nonce (24 bytes, hex; blank = random)")
    ),
    encrypt = function(pt, key, params) {
      nonce <- if (!is.null(params$nonce) && nzchar(params$nonce %||% ""))
        sodium::hex2bin(params$nonce) else sodium::random(24L)
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
      iv <- if (!is.null(params$iv) && nzchar(params$iv %||% ""))
        sodium::hex2bin(params$iv) else openssl::rand_bytes(12L)
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
