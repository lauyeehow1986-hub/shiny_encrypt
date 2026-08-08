# Engine smoke test (run: Rscript dev/smoke.R). Exits non-zero on any failure.
.SE_ROOT <- getwd()
suppressMessages({
  library(sodium); library(openssl); library(digest); library(jsonlite)
  library(readr); library(readxl)
})
invisible(lapply(list.files("R", pattern="\\.R$", full.names=TRUE), source))
register_all_schemes()

ok <- TRUE
check <- function(label, cond) {
  cat(sprintf("[%s] %s\n", if (isTRUE(cond)) "PASS" else "FAIL", label))
  if (!isTRUE(cond)) ok <<- FALSE
}

payload <- charToRaw(paste(rep("Sensitive research row; patient=ANON;", 50), collapse=" "))

# --- AEAD schemes x key sources round-trip ---
for (scheme in c("aead-secretbox", "aead-aesgcm")) {
  # random key
  kr <- resolve_key(list(type="random"))
  env <- se_encrypt(payload, scheme, kr, meta=list(orig_name="x.bin", orig_kind="binary"))
  pt  <- se_decrypt(env, kr$key_export)
  check(paste(scheme, "random-key round-trip"), identical(pt, payload))

  # passphrase (scrypt)
  kr2 <- resolve_key(list(type="passphrase", passphrase="correct horse battery staple", kdf="scrypt"))
  env2 <- se_encrypt(payload, scheme, kr2, meta=list(orig_name="x.bin"))
  pt2  <- se_decrypt(env2, "correct horse battery staple")
  check(paste(scheme, "passphrase round-trip"), identical(pt2, payload))
  wrong <- tryCatch({ se_decrypt(env2, "wrong pass"); FALSE }, error=function(e) TRUE)
  check(paste(scheme, "wrong passphrase rejected"), wrong)

  # free-text hash, hardened
  kr3 <- resolve_key(list(type="freetext_hash", text="my secret phrase", hash_algo="blake3", harden=TRUE))
  env3 <- se_encrypt(payload, scheme, kr3, meta=list(orig_name="x.bin"))
  pt3  <- se_decrypt(env3, "my secret phrase")
  check(paste(scheme, "freetext-hash(hardened) round-trip"), identical(pt3, payload))

  # free-text hash, bare
  kr4 <- resolve_key(list(type="freetext_hash", text="abc123", hash_algo="sha256", harden=FALSE))
  env4 <- se_encrypt(payload, scheme, kr4, meta=list(orig_name="x.bin"))
  pt4  <- se_decrypt(env4, "abc123")
  check(paste(scheme, "freetext-hash(bare) round-trip"), identical(pt4, payload))
}

# --- envelope serialize/parse stability ---
kr <- resolve_key(list(type="passphrase", passphrase="pw", kdf="scrypt"))
env <- se_encrypt(payload, "aead-secretbox", kr, meta=list(orig_name="d.rds", orig_kind="rds"))
txt <- build_txt_export(env)
env_rt <- envelope_parse(txt)
check("envelope .txt parse round-trip", identical(env_rt$ciphertext_b64, env$ciphertext_b64))
check("envelope digest preserved", identical(env_rt$pt_digest, env$pt_digest))

# --- CSV import -> encrypt -> decrypt -> restore ---
tmp_csv <- tempfile(fileext=".csv")
write.csv(data.frame(id=1:5, age=c(50,61,72,43,58), grp=c("A","B","A","B","A")), tmp_csv, row.names=FALSE)
imp <- import_to_raw(tmp_csv)
kr  <- resolve_key(list(type="random"))
env <- se_encrypt(imp$raw, "aead-aesgcm", kr, meta=list(orig_name=basename(tmp_csv), orig_kind=imp$kind))
rec <- se_decrypt(env, kr$key_export)
df  <- restore_object(rec, "csv")
check("CSV import->encrypt->decrypt->data.frame", is.data.frame(df) && nrow(df)==5 && df$age[2]==61)

# --- reproducibility: same key + fixed nonce -> identical ciphertext ---
fixed_nonce <- sodium::bin2hex(sodium::random(24))
e1 <- se_encrypt(payload, "aead-secretbox", kr, params=list(nonce=fixed_nonce), meta=list())
e2 <- se_encrypt(payload, "aead-secretbox", kr, params=list(nonce=fixed_nonce), meta=list())
check("deterministic ciphertext for fixed key+nonce", identical(e1$ciphertext_b64, e2$ciphertext_b64))

# --- exported .R script actually decrypts (portable path) ---
krp <- resolve_key(list(type="passphrase", passphrase="scriptpw", kdf="scrypt"))
envp <- se_encrypt(payload, "aead-secretbox", krp, meta=list(orig_name="from_script.bin", orig_kind="binary"))
rscript <- build_r_export(envp, "XSalsa20-Poly1305")
rscript <- sub('secret <- NULL', 'secret <- "scriptpw"', rscript, fixed=TRUE)
sfile <- tempfile(fextrap <- fileext <- ".R"); writeLines(rscript, sfile)
outdir <- tempfile(); dir.create(outdir); old <- setwd(outdir)
res <- tryCatch({ source(sfile, local=new.env()); TRUE }, error=function(e){cat("script err:",conditionMessage(e),"\n");FALSE})
recovered <- if (file.exists("from_script.bin")) readBin("from_script.bin","raw",n=1e6) else raw()
setwd(old)
check("exported .R script decrypts to original", res && identical(recovered, payload))

cat(if (ok) "\nALL SMOKE TESTS PASSED\n" else "\nSMOKE TESTS FAILED\n")
quit(status = if (ok) 0 else 1)
