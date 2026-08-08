# Round-trip + KAT tests for the crypto engine. Uses internal helpers via the
# package namespace (register_all_schemes, resolve_key, se_encrypt, ...).

register_all_schemes()

payload <- charToRaw(paste(rep("row;anon;value=42;", 40), collapse = ""))

test_that("Core AEAD schemes round-trip across all key sources", {
  for (scheme in c("aead-secretbox", "aead-aesgcm")) {
    kr <- resolve_key(list(type = "random"))
    env <- se_encrypt(payload, scheme, kr, meta = list(orig_name = "x.bin"))
    expect_identical(se_decrypt(env, kr$key_export), payload)

    kr2 <- resolve_key(list(type = "passphrase", passphrase = "pw-123", kdf = "scrypt"))
    env2 <- se_encrypt(payload, scheme, kr2, meta = list(orig_name = "x.bin"))
    expect_identical(se_decrypt(env2, "pw-123"), payload)
    expect_error(se_decrypt(env2, "wrong"))

    kr3 <- resolve_key(list(type = "freetext_hash", text = "phrase",
                            hash_algo = "blake3", harden = TRUE))
    env3 <- se_encrypt(payload, scheme, kr3, meta = list(orig_name = "x.bin"))
    expect_identical(se_decrypt(env3, "phrase"), payload)
  }
})

test_that("envelope serialize/parse is stable and preserves integrity digest", {
  kr <- resolve_key(list(type = "passphrase", passphrase = "pw", kdf = "scrypt"))
  env <- se_encrypt(payload, "aead-secretbox", kr, meta = list(orig_name = "d.rds"))
  env_rt <- envelope_parse(build_txt_export(env))
  expect_identical(env_rt$ciphertext_b64, env$ciphertext_b64)
  expect_identical(env_rt$pt_digest, env$pt_digest)
})

test_that("fixed key + nonce gives deterministic ciphertext (reproducibility)", {
  kr <- resolve_key(list(type = "random"))
  nonce <- sodium::bin2hex(sodium::random(24))
  e1 <- se_encrypt(payload, "aead-secretbox", kr, params = list(nonce = nonce))
  e2 <- se_encrypt(payload, "aead-secretbox", kr, params = list(nonce = nonce))
  expect_identical(e1$ciphertext_b64, e2$ciphertext_b64)
})

test_that("CSV import -> encrypt -> decrypt -> restore data.frame", {
  tmp <- tempfile(fileext = ".csv")
  utils::write.csv(data.frame(id = 1:3, age = c(40, 55, 66)), tmp, row.names = FALSE)
  imp <- import_to_raw(tmp)
  kr <- resolve_key(list(type = "random"))
  env <- se_encrypt(imp$raw, "aead-aesgcm", kr,
                    meta = list(orig_name = basename(tmp), orig_kind = imp$kind))
  df <- restore_object(se_decrypt(env, kr$key_export), "csv")
  expect_true(is.data.frame(df) && df$age[2] == 55)
})

test_that("hash KATs (known answers)", {
  expect_identical(hash_hex("abc", "md5"), "900150983cd24fb0d6963f7d28e17f72")
  expect_identical(hash_hex("abc", "sha256"),
                   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
  expect_identical(hash_hex("abc", "blake3"),
                   "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")
})

test_that("native Argon2id (if built) matches a KAT and round-trips", {
  skip_if_not(crypto_backend_available("argon2id"), "native backend not built")
  # KAT: cross-checked against argon2-cffi (m=19456, t=2, p=1, len=32).
  k <- native_argon2id(charToRaw("correct horse battery staple"),
                       charToRaw("0123456789abcdef"), 19456L, 2L, 1L, 32L)
  expect_identical(
    paste(sprintf("%02x", as.integer(k)), collapse = ""),
    "832e52b959b967b570ee4781f6c7bda7ced019ca266ac781fd2d94d4e853b0cd")
  # end-to-end: passphrase via Argon2id, through JSON, decrypts; costs are stored.
  kr <- resolve_key(list(type = "passphrase", passphrase = "pw-argon", kdf = "argon2id"))
  expect_identical(kr$source_meta$kdf, "argon2id")
  env <- se_encrypt(payload, "aead-aesgcm", kr, meta = list(orig_name = "a.bin"))
  env_rt <- envelope_parse(build_txt_export(env))
  expect_identical(se_decrypt(env_rt, "pw-argon"), payload)
  expect_error(se_decrypt(env_rt, "wrong"))
})

test_that("native hybrid KEM (if built) agrees, and rejects the wrong recipient", {
  skip_if_not(isTRUE(getOption("shinyEncrypt.native.enabled", FALSE)), "native backend not built")
  kp <- native_hybrid_keygen()
  expect_length(kp$secret, 2432); expect_length(kp$public, 1216)
  e <- native_hybrid_encaps(kp$public)
  expect_length(e$encapsulation, 1120); expect_length(e$key, 32)
  expect_identical(native_hybrid_decaps(kp$secret, e$encapsulation), e$key)
  other <- native_hybrid_keygen()
  expect_false(identical(native_hybrid_decaps(other$secret, e$encapsulation), e$key))
})

test_that("native ML-DSA-65 (if built) signs, verifies, and rejects tampering", {
  skip_if_not(isTRUE(getOption("shinyEncrypt.native.enabled", FALSE)), "native backend not built")
  kp <- native_mldsa_keygen()
  expect_length(kp$secret, 4032); expect_length(kp$public, 1952)
  msg <- charToRaw("authenticate this envelope")
  sig <- native_mldsa_sign(kp$secret, msg)
  expect_length(sig, 3309)
  expect_true(native_mldsa_verify(kp$public, msg, sig))
  bad <- msg; bad[1] <- as.raw(bitwXor(as.integer(bad[1]), 1L))
  expect_false(native_mldsa_verify(kp$public, bad, sig))
})

test_that("catalogue lists all tiers and only Core is available now", {
  s <- list_schemes()
  expect_true(all(c("Core","Native","Heavy","Interactive","Stub") %in% s$tier))
  expect_setequal(s$id[s$available], c("aead-secretbox", "aead-aesgcm"))
})
