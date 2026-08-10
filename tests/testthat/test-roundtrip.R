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
  skip_if_not(crypto_backend_available("hpke-hybrid"), "native PQC backend not built")
  kp <- native_hybrid_keygen()
  expect_length(kp$secret, 2432); expect_length(kp$public, 1216)
  e <- native_hybrid_encaps(kp$public)
  expect_length(e$encapsulation, 1120); expect_length(e$key, 32)
  expect_identical(native_hybrid_decaps(kp$secret, e$encapsulation), e$key)
  other <- native_hybrid_keygen()
  expect_false(identical(native_hybrid_decaps(other$secret, e$encapsulation), e$key))
})

test_that("native ML-DSA-65 (if built) signs, verifies, and rejects tampering", {
  skip_if_not(crypto_backend_available("hpke-hybrid"), "native PQC backend not built")
  kp <- native_mldsa_keygen()
  expect_length(kp$secret, 4032); expect_length(kp$public, 1952)
  msg <- charToRaw("authenticate this envelope")
  sig <- native_mldsa_sign(kp$secret, msg)
  expect_length(sig, 3309)
  expect_true(native_mldsa_verify(kp$public, msg, sig))
  bad <- msg; bad[1] <- as.raw(bitwXor(as.integer(bad[1]), 1L))
  expect_false(native_mldsa_verify(kp$public, bad, sig))
})

test_that("hybrid PQC key source (if built) encrypts to a public key, decrypts with the secret", {
  skip_if_not(crypto_backend_available("hpke-hybrid"), "native PQC backend not built")
  kp <- native_hybrid_keygen()
  kr <- resolve_key(list(type = "hybrid_pqc", public_bundle = kp$public))
  expect_identical(kr$source_meta$type, "hybrid_pqc")
  expect_true(nchar(kr$source_meta$encapsulation) > 0)   # encapsulation is stored
  env <- se_encrypt(payload, "aead-aesgcm", kr, meta = list(orig_name = "p.bin"))
  env_rt <- envelope_parse(build_txt_export(env))
  expect_identical(se_decrypt(env_rt, kp$secret), payload)   # recipient secret decrypts
  other <- native_hybrid_keygen()
  expect_error(se_decrypt(env_rt, other$secret))             # wrong recipient fails
})

test_that("ML-DSA envelope signing (if built) survives round-trip and catches tampering", {
  skip_if_not(crypto_backend_available("ml-dsa"), "native PQC backend not built")
  sk <- native_mldsa_keygen()
  kr <- resolve_key(list(type = "random"))
  env <- se_encrypt(payload, "aead-aesgcm", kr, meta = list(orig_name = "s.bin"))

  # unsigned envelope reports as such
  expect_identical(envelope_verify(env)$status, "unsigned")

  signed <- envelope_sign(env, sk$secret, sk$public)
  expect_identical(signed$signature$alg, "ml-dsa-65")

  # survives serialize -> parse and verifies valid
  rt <- envelope_parse(build_txt_export(signed))
  v <- envelope_verify(rt)
  expect_identical(v$status, "valid")
  expect_identical(v$fingerprint, sign_fingerprint(sk$public))

  # tampering with the ciphertext breaks the signature
  bad <- rt; bad$ciphertext_b64 <- paste0("A", substring(bad$ciphertext_b64, 2))
  expect_identical(envelope_verify(bad)$status, "invalid")

  # substituting a different signer's public key is rejected too
  other <- native_mldsa_keygen()
  wrong <- rt; wrong$signature$public_key <- sodium::bin2hex(other$public)
  expect_identical(envelope_verify(wrong)$status, "invalid")

  # pinning the expected signer: no pin -> NA, right key -> TRUE, wrong -> FALSE
  expect_true(is.na(envelope_verify(rt)$expected_match))
  expect_true(envelope_verify(rt, expected_public = sk$public)$expected_match)
  expect_true(envelope_verify(rt, expected_public = sodium::bin2hex(sk$public))$expected_match)
  expect_false(envelope_verify(rt, expected_public = other$public)$expected_match)
})

test_that("native Shamir (if built) splits t-of-n, recombines, and needs the threshold", {
  skip_if_not(crypto_backend_available("shamir"), "native Shamir backend not built")
  secret <- sodium::random(32L)
  shares <- native_shamir_split(secret, t = 3L, n = 5L)
  expect_length(shares, 5)
  expect_true(all(vapply(shares, length, integer(1)) == 33L))   # 1 + 32

  # any 3 recombine to the exact secret, in any order
  pick <- do.call(c, shares[c(5, 1, 3)])
  expect_identical(native_shamir_combine(pick, 33L), secret)
  # a different 3 also works
  expect_identical(native_shamir_combine(do.call(c, shares[c(2, 4, 5)]), 33L), secret)
  # fewer than t yields the WRONG secret (Shamir does not error; the AEAD tag does)
  expect_false(identical(native_shamir_combine(do.call(c, shares[c(1, 2)]), 33L), secret))
})

test_that("Shamir key source (if built) round-trips through t shares, fails under threshold", {
  skip_if_not(crypto_backend_available("shamir"), "native Shamir backend not built")
  kr <- resolve_key(list(type = "shamir", t = 2L, n = 3L))
  expect_identical(kr$source_meta$type, "shamir")
  expect_length(kr$shares, 3)
  sl <- kr$source_meta$share_len

  env <- se_encrypt(payload, "aead-aesgcm", kr, meta = list(orig_name = "sh.bin"))
  env_rt <- envelope_parse(build_txt_export(env))
  # any 2 of 3 shares decrypt
  expect_identical(se_decrypt(env_rt, do.call(c, kr$shares[c(1, 3)])), payload)
  # 1 share cannot (wrong key -> AEAD tag rejects)
  expect_error(se_decrypt(env_rt, kr$shares[[2]]))
})

test_that("native FF1 (if built) round-trips, preserves length, and is deterministic", {
  skip_if_not(crypto_backend_available("fpe-ff1"), "native FF1 backend not built")
  key <- sodium::random(32L)
  tweak <- charToRaw("patient_id")
  numerals <- c(0L, 0L, 1L, 2L, 3L, 4L, 5L)     # 7 digits, radix 10 (>= 1e6 domain)
  ct <- native_ff1(key, tweak, 10L, numerals, encrypt = TRUE)
  expect_length(ct, length(numerals))
  expect_true(all(ct >= 0L & ct <= 9L))
  expect_false(identical(ct, numerals))          # actually changed
  expect_identical(native_ff1(key, tweak, 10L, ct, encrypt = FALSE), numerals)
  # deterministic: same key+tweak+input -> same output
  expect_identical(native_ff1(key, tweak, 10L, numerals, encrypt = TRUE), ct)
  # a different tweak diverges
  expect_false(identical(native_ff1(key, charToRaw("other"), 10L, numerals, TRUE), ct))
  # domain rule: too few numerals is rejected
  expect_error(native_ff1(key, tweak, 10L, c(1L, 2L, 3L), encrypt = TRUE))
})

test_that("FF1 column/table de-identification (if built) preserves format and reverses", {
  skip_if_not(crypto_backend_available("fpe-ff1"), "native FF1 backend not built")
  df <- data.frame(
    mrn   = c("0012345", "0012345", "9987654", "42"),   # dup + one too-short
    code  = c("AB-1234-CD", "ZZ-0000-YY", "MM-5678-NN", "QQ-4321-RR"),
    stringsAsFactors = FALSE)
  key <- sodium::random(32L)
  res <- fpe_apply_table(df, c("mrn", "code"), key, mode = "auto")

  # mrn: radix-10 alphabet; tokens are 7 digits, unchanged length, still digits
  tok <- res$df$mrn
  expect_true(all(nchar(tok) == nchar(df$mrn)))
  expect_true(grepl("^[0-9]{7}$", tok[1]))
  expect_false(tok[1] == df$mrn[1])              # actually tokenised
  expect_identical(tok[1], tok[2])               # equal inputs -> equal tokens (joins survive)
  expect_identical(res$df$mrn[4], "42")          # too short -> left as-is
  expect_equal(res$stats$mrn$n_tokenised, 3L)
  expect_equal(res$stats$mrn$n_short, 1L)

  # code: dashes pass through in place; alphanumerics stay in the same class
  expect_true(all(grepl("^..-....-..$", res$df$code)))
  expect_false(any(res$df$code == df$code))

  # reverse through the kit restores the exact original
  kit <- fpe_parse_kit(fpe_build_kit(key, res$recipe))
  expect_identical(as.character(fpe_reverse_table(res$df, kit)$mrn), df$mrn)
  expect_identical(as.character(fpe_reverse_table(res$df, kit)$code), df$code)
})

test_that("native time-lock (if built): trapdoor fast-path equals the sequential solve", {
  skip_if_not(crypto_backend_available("tlock"), "native time-lock backend not built")
  t <- 20000
  puz <- native_timelock_generate(1024L, t)
  expect_length(puz$N, 128L); expect_length(puz$b, 128L)   # 1024-bit modulus = 128 bytes
  # solving from x = 2 for t squarings reproduces the trapdoor-computed solution,
  # independent of the chunk size used to walk there
  expect_identical(timelock_solve(puz$N, t, chunk = 5000), puz$b)
  expect_identical(timelock_solve(puz$N, t, chunk = 1234), puz$b)
  # calibration returns a positive rate; degenerate params are rejected
  expect_true(is.finite(native_timelock_calibrate(1024L, 50L)))
  expect_true(native_timelock_calibrate(1024L, 50L) > 0)
  expect_error(native_timelock_generate(1024L, 0))            # t must be >= 1
  expect_error(native_timelock_solve_steps(puz$b, puz$N, 0L)) # steps must be >= 1
})

test_that("time-lock key source (if built) seals a key that the solved puzzle recovers", {
  skip_if_not(crypto_backend_available("tlock"), "native time-lock backend not built")
  kr <- resolve_key(list(type = "timelock", bits = 1024L, t_squarings = 20000,
                         target_seconds = 1, rate_est = 20000, keep_master = TRUE))
  expect_identical(kr$source_meta$type, "timelock")
  expect_null(kr$key_export)                       # no key file — time is the key
  expect_length(kr$timelock_master, 128L)          # creator kept the solution b
  expect_true(nchar(kr$source_meta$modulus) > 0 && nchar(kr$source_meta$masked_key) > 0)

  env <- se_encrypt(payload, "aead-aesgcm", kr, meta = list(orig_name = "tl.bin"))
  env_rt <- envelope_parse(build_txt_export(env))

  # solve the puzzle straight from the envelope, then decrypt with the answer
  sm <- env_rt$key_source
  b  <- timelock_solve(base64_to_raw(sm$modulus), sm$t_squarings, chunk = 5000)
  expect_identical(b, kr$timelock_master)          # solving == the trapdoor answer
  expect_identical(se_decrypt(env_rt, b), payload)
  # the creator's master key decrypts instantly (same value)
  expect_identical(se_decrypt(env_rt, kr$timelock_master), payload)
  # a wrong solution fails closed on the AEAD tag
  wrong <- b; wrong[1] <- as.raw(bitwXor(as.integer(wrong[1]), 1L))
  expect_error(se_decrypt(env_rt, wrong))
})

test_that("time-lock without a master keeps no shortcut (true time-lock)", {
  skip_if_not(crypto_backend_available("tlock"), "native time-lock backend not built")
  kr <- resolve_key(list(type = "timelock", bits = 1024L, t_squarings = 5000,
                         target_seconds = 1, rate_est = 5000, keep_master = FALSE))
  expect_null(kr$timelock_master)                  # trapdoor destroyed, no b retained
  env <- se_encrypt(payload, "aead-aesgcm", kr, meta = list(orig_name = "tl2.bin"))
  env_rt <- envelope_parse(build_txt_export(env))
  sm <- env_rt$key_source
  b <- timelock_solve(base64_to_raw(sm$modulus), sm$t_squarings, chunk = 2500)
  expect_identical(se_decrypt(env_rt, b), payload) # only the solved puzzle opens it
})

test_that("native CP-ABE (if built): a policy-satisfying key decrypts, others fail closed", {
  skip_if_not(crypto_backend_available("cp-abe"), "native CP-ABE backend not built")
  auth <- native_cpabe_setup()
  expect_true(length(auth$pk) > 0 && length(auth$mk) > 0)
  datakey <- sodium::random(32L)
  policy  <- "\"cardiology\" and \"senior\""
  ct <- native_cpabe_encrypt(auth$pk, policy, datakey)

  # a key holding both required attributes recovers the exact sealed bytes
  good <- native_cpabe_keygen(auth$pk, auth$mk, c("cardiology", "senior"))
  expect_identical(native_cpabe_decrypt(good, ct), as.raw(datakey))

  # missing one required attribute -> error (fails closed, not garbage)
  short <- native_cpabe_keygen(auth$pk, auth$mk, "cardiology")
  expect_error(native_cpabe_decrypt(short, ct))
  # unrelated attributes -> error
  other <- native_cpabe_keygen(auth$pk, auth$mk, c("radiology", "junior"))
  expect_error(native_cpabe_decrypt(other, ct))
  # degenerate inputs are rejected
  expect_error(native_cpabe_keygen(auth$pk, auth$mk, character()))
  expect_error(native_cpabe_encrypt(auth$pk, "", datakey))
})

test_that("CP-ABE key source (if built) seals under a policy; attribute keys gate decryption", {
  skip_if_not(crypto_backend_available("cp-abe"), "native CP-ABE backend not built")
  auth   <- native_cpabe_setup()
  policy <- "\"cardiology\" and (\"senior\" or \"admin\")"
  kr <- resolve_key(list(type = "cpabe", pk = auth$pk, policy = policy))
  expect_identical(kr$source_meta$type, "cpabe")
  expect_identical(kr$source_meta$policy, policy)
  expect_null(kr$key_export)                       # no key file — an attribute key opens it
  expect_true(nchar(kr$source_meta$ct) > 0)

  env    <- se_encrypt(payload, "aead-aesgcm", kr, meta = list(orig_name = "abe.bin"))
  env_rt <- envelope_parse(build_txt_export(env))

  # {cardiology, admin} satisfies "cardiology AND (senior OR admin)" -> decrypts
  ok <- native_cpabe_keygen(auth$pk, auth$mk, c("cardiology", "admin"))
  expect_identical(se_decrypt(env_rt, ok), payload)
  # a key missing the required "cardiology" cannot (fails closed)
  no <- native_cpabe_keygen(auth$pk, auth$mk, c("senior", "admin"))
  expect_error(se_decrypt(env_rt, no))
  # a blank policy is rejected at seal time
  expect_error(resolve_key(list(type = "cpabe", pk = auth$pk, policy = "   ")))
})

test_that("native IBE (if built): the sealed identity's key decrypts, others fail closed", {
  skip_if_not(crypto_backend_available("ibe"), "native IBE backend not built")
  auth <- native_ibe_setup()
  expect_true(length(auth$pk) > 0 && length(auth$mk) > 0)

  enc <- native_ibe_encaps(auth$pk, "alice@hospital.org")   # list(ct, key)
  expect_equal(length(enc$key), 32L)

  # the key extracted for the sealed identity recovers the exact encapsulated key
  usk <- native_ibe_extract(auth$pk, auth$mk, "alice@hospital.org")
  expect_identical(native_ibe_decaps(usk, enc$ct), enc$key)

  # a key for a different identity cannot recover it (explicit or implicit reject)
  bad <- native_ibe_extract(auth$pk, auth$mk, "eve@hospital.org")
  got <- tryCatch(native_ibe_decaps(bad, enc$ct), error = function(e) NULL)
  expect_false(identical(got, enc$key))

  # blank identities are rejected on both seal and extract
  expect_error(native_ibe_encaps(auth$pk, "   "))
  expect_error(native_ibe_extract(auth$pk, auth$mk, ""))
})

test_that("IBE key source (if built) seals to an identity; only that identity's key opens it", {
  skip_if_not(crypto_backend_available("ibe"), "native IBE backend not built")
  auth <- native_ibe_setup()
  kr <- resolve_key(list(type = "ibe", pk = auth$pk, identity = "alice@hospital.org"))
  expect_identical(kr$source_meta$type, "ibe")
  expect_identical(kr$source_meta$identity, "alice@hospital.org")
  expect_null(kr$key_export)                       # no key file — an identity key opens it
  expect_true(nchar(kr$source_meta$ct) > 0)

  env    <- se_encrypt(payload, "aead-aesgcm", kr, meta = list(orig_name = "ibe.bin"))
  env_rt <- envelope_parse(build_txt_export(env))

  # the key issued for the sealed identity decrypts
  ok <- native_ibe_extract(auth$pk, auth$mk, "alice@hospital.org")
  expect_identical(se_decrypt(env_rt, ok), payload)
  # a key for another identity cannot (the AEAD tag rejects the wrong KEM output)
  no <- native_ibe_extract(auth$pk, auth$mk, "eve@hospital.org")
  expect_error(se_decrypt(env_rt, no))
  # a blank identity is rejected at seal time
  expect_error(resolve_key(list(type = "ibe", pk = auth$pk, identity = "   ")))
})

test_that("catalogue lists all tiers; Core AEAD always available, PQC gated on the build", {
  s <- list_schemes()
  expect_true(all(c("Core","Native","Heavy","Interactive","Stub") %in% s$tier))
  expect_true(all(c("aead-secretbox", "aead-aesgcm") %in% s$id[s$available]))
  # The hybrid KEM + ML-DSA rows report available only when the backend is built.
  expect_equal("hpke-hybrid" %in% s$id[s$available],
               crypto_backend_available("hpke-hybrid"))
  expect_equal("ml-dsa" %in% s$id[s$available],
               crypto_backend_available("ml-dsa"))
  expect_equal("shamir" %in% s$id[s$available],
               crypto_backend_available("shamir"))
  expect_equal("fpe-ff1" %in% s$id[s$available],
               crypto_backend_available("fpe-ff1"))
  expect_equal("tlock" %in% s$id[s$available],
               crypto_backend_available("tlock"))
  expect_equal("cp-abe" %in% s$id[s$available],
               crypto_backend_available("cp-abe"))
  expect_equal("ibe" %in% s$id[s$available],
               crypto_backend_available("ibe"))
  expect_equal("oprf" %in% s$id[s$available],
               crypto_backend_available("oprf"))
  expect_equal("psi" %in% s$id[s$available],
               crypto_backend_available("psi"))
  expect_equal("opaque" %in% s$id[s$available],
               crypto_backend_available("opaque"))
})

test_that("native OPRF (if built): deterministic in (input, key), verifiable, fails closed", {
  skip_if_not(crypto_backend_available("oprf"), "native OPRF backend not built")
  k1 <- native_oprf_keygen()
  expect_length(k1, 32L)

  # the derived key is a PRF of (input, key): same pair -> same key, despite the
  # random blind (two blinds of one input differ, yet finalize agrees)
  d1 <- oprf_derive_key("patient-42", k1)
  d2 <- oprf_derive_key("patient-42", k1)
  expect_length(d1$key, 32L)
  expect_identical(d1$key, d2$key)
  b1 <- native_oprf_blind(charToRaw("patient-42"))
  b2 <- native_oprf_blind(charToRaw("patient-42"))
  expect_false(identical(b1, b2))                  # blinding is randomised

  # sensitivity: a different input, or a different OPRF key, changes the output
  expect_false(identical(d1$key, oprf_derive_key("patient-99", k1)$key))
  k2 <- native_oprf_keygen()
  expect_false(identical(d1$key, oprf_derive_key("patient-42", k2)$key))

  # verifiable: finalize with the WRONG public key fails closed (DLEQ rejects)
  bl <- native_oprf_blind(charToRaw("patient-42"))
  ev <- native_oprf_evaluate(k1, bl[33:64])
  expect_error(native_oprf_finalize(charToRaw("patient-42"), bl, ev,
                                    native_oprf_public_key(k2)))
  # tampered response (flip a byte in E) also fails closed
  ev_bad <- ev; ev_bad[1] <- as.raw(bitwXor(as.integer(ev_bad[1]), 1L))
  expect_error(native_oprf_finalize(charToRaw("patient-42"), bl, ev_bad,
                                    native_oprf_public_key(k1)))
  # degenerate inputs are rejected
  expect_error(oprf_derive_key("", k1))            # empty input
  expect_error(oprf_derive_key("x", sodium::random(31L)))  # wrong key length
})

test_that("OPRF key source (if built) needs both the input and the OPRF key", {
  skip_if_not(crypto_backend_available("oprf"), "native OPRF backend not built")
  okey <- native_oprf_keygen()
  kr <- resolve_key(list(type = "oprf", text = "s3cret-phrase", oprf_key = okey))
  expect_identical(kr$source_meta$type, "oprf")
  expect_null(kr$key_export)                        # the input is remembered, not stored
  expect_identical(kr$oprf_key, okey)              # offered for download as .oprfkey
  expect_true(nchar(kr$source_meta$public_key) > 0)

  env    <- se_encrypt(payload, "aead-aesgcm", kr, meta = list(orig_name = "oprf.bin"))
  env_rt <- envelope_parse(build_txt_export(env))

  # both the exact input and the OPRF key recover the file
  ok <- list(text = "s3cret-phrase", oprf_key = okey)
  expect_identical(se_decrypt(env_rt, ok), payload)
  # wrong input, right key -> fails closed
  expect_error(se_decrypt(env_rt, list(text = "wrong", oprf_key = okey)))
  # right input, wrong key -> rejected before the AEAD even runs (pubkey mismatch)
  expect_error(se_decrypt(env_rt, list(text = "s3cret-phrase",
                                       oprf_key = native_oprf_keygen())))
  # an empty input is rejected at seal time
  expect_error(resolve_key(list(type = "oprf", text = "", oprf_key = okey)))
})

test_that("native PSI (if built): finds the true overlap, only the overlap, fails closed", {
  skip_if_not(crypto_backend_available("psi"), "native PSI backend not built")
  A <- paste0("MRN", sprintf("%04d", 1:8))
  B <- paste0("MRN", sprintf("%04d", 5:12))

  res <- psi_two_party(A, B)
  expect_setequal(res$intersection, intersect(A, B))    # exactly the shared IDs
  expect_equal(res$n_inter, 4L)
  expect_equal(res$n_a, 8L); expect_equal(res$n_b, 8L)
  expect_equal(res$jaccard, 4 / 12)

  # no overlap -> empty; full overlap -> everything
  expect_equal(psi_two_party(c("x", "y"), c("p", "q"))$n_inter, 0L)
  full <- psi_two_party(A, A)
  expect_setequal(full$intersection, A)
  expect_equal(full$jaccard, 1)

  # sets, not multisets: duplicates are de-duplicated before the protocol
  expect_equal(psi_two_party(c("a", "a", "b"), "a")$n_a, 2L)

  # the wire transcript is masked points, never the raw IDs; single-masked points
  # of the two parties differ (each carries only its own scalar), and none of the
  # 64-hex strings equals any plaintext identifier
  expect_length(res$transcript$a_masked, 8L)
  expect_true(all(nchar(res$transcript$a_masked) == 64L))
  expect_false(any(res$transcript$a_masked %in% res$transcript$b_masked))
  expect_false(any(A %in% res$transcript$a_masked))

  # determinism of the RESULT despite fresh random scalars each run
  expect_setequal(psi_two_party(A, B)$intersection, res$intersection)

  # arbitrary (non-ASCII) identifiers round-trip exactly through the packing
  U <- c("caf\u00e9", "na\u00efve", "\u65e5\u672c", "MRN0001")
  expect_setequal(psi_two_party(U, c("na\u00efve", "\u65e5\u672c", "zzz"))$intersection,
                  c("na\u00efve", "\u65e5\u672c"))

  # degenerate inputs are rejected
  expect_error(psi_two_party(character(0), A))
  expect_error(psi_two_party(A, c(NA, "")))

  # native primitives fail closed on a malformed point buffer / bad scalar
  expect_error(native_psi_mask_points(native_psi_keygen(), as.raw(1:33)))  # not a multiple of 32
  expect_error(native_psi_hash_mask(sodium::random(31L), .psi_pack_elements("x")))  # 31-byte scalar
})

test_that("native OPAQUE (if built): registers, logs in with mutual auth, fails closed on wrong inputs", {
  skip_if_not(crypto_backend_available("opaque"), "native OPAQUE backend not built")
  pw <- "correct-horse-battery-staple"

  kp <- opaque_server_setup()
  expect_length(kp, 64L)

  reg <- opaque_register(pw, kp)
  expect_length(reg$record, 224L)      # ku || client_pub || masking_key || envelope
  expect_length(reg$export_key, 64L)

  # the stored record contains no verbatim copy of the password bytes
  pwb <- charToRaw(pw); rec <- reg$record; m <- length(pwb)
  contains_pw <- any(vapply(seq_len(length(rec) - m + 1L),
                            function(i) identical(rec[i:(i + m - 1L)], pwb), logical(1)))
  expect_false(contains_pw)

  # correct password: mutual auth, identical session keys both sides, and the
  # client recovers the SAME export key it got at registration
  ok <- opaque_login(pw, reg$record, kp)
  expect_true(ok$success)
  expect_true(ok$keys_match)
  expect_identical(as.raw(ok$session_key_client), as.raw(ok$session_key_server))
  expect_identical(as.raw(ok$export_key), as.raw(reg$export_key))
  expect_length(ok$session_key_client, 64L)

  # a second login draws fresh blinds/ephemerals (different KE1) yet still agrees
  # and yields the same stable export key
  ok2 <- opaque_login(pw, reg$record, kp)
  expect_true(ok2$success && ok2$keys_match)
  expect_false(identical(ok2$transcript$ke1, ok$transcript$ke1))
  expect_identical(as.raw(ok2$export_key), as.raw(reg$export_key))

  # wrong password: the client aborts at the envelope check (no KE3 ever leaves)
  bad <- opaque_login("wrong-password", reg$record, kp)
  expect_false(bad$success)
  expect_identical(bad$stage, "client")
  expect_null(bad$transcript$ke3)

  # a different server identity cannot satisfy the envelope bound to the first
  cross <- opaque_login(pw, reg$record, opaque_server_setup())
  expect_false(cross$success)

  # tampering with KE2 in flight breaks the client's verification (fails closed)
  ci <- native_opaque_client_init(pwb)
  st <- ci[1:64]; ke1 <- ci[65:160]
  sr <- native_opaque_server_respond(kp[1:32], reg$record, ke1)
  ke2 <- sr[1:320]
  ke2_bad <- ke2; ke2_bad[80] <- as.raw(bitwXor(as.integer(ke2_bad[80]), 1L))
  expect_error(native_opaque_client_finish(pwb, st, ke1, ke2_bad))

  # native primitives fail closed on malformed buffers
  expect_error(native_opaque_server_respond(kp[1:32], reg$record, as.raw(1:10)))   # short KE1
  expect_error(native_opaque_server_finish(sr[321:448], as.raw(rep(0L, 64L))))     # forged KE3
  expect_error(native_opaque_register_finalize(pwb, as.raw(1:10),
               reg$record[33:64], kp[33:64]))                                       # short blind bundle
})
