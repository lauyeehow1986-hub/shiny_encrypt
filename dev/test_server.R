suppressMessages({library(shiny);library(bslib);library(sodium);library(openssl);library(digest);library(jsonlite);library(readr);library(readxl)})
invisible(lapply(list.files("R", pattern="[.]R$", full.names=TRUE), source))
register_all_schemes()

tmp <- tempfile(fileext=".csv")
write.csv(data.frame(id=1:4, age=c(50,61,72,43)), tmp, row.names=FALSE)

ok <- TRUE
say <- function(l,c){cat(sprintf("[%s] %s\n", if(isTRUE(c))"PASS" else "FAIL", l)); if(!isTRUE(c)) ok<<-FALSE}

testServer(app_server, {
  # scheme_table output renders
  st <- output$scheme_table
  say("scheme_table output non-empty", is.list(st) && nchar(st$html %||% "") > 50 || grepl("XSalsa|AES", paste(unlist(st), collapse=" ")))
  # help renders
  say("help_md renders", grepl("Step-by-step", paste(unlist(output$help_md), collapse=" ")))
  # strength renders (freetext source)
  session$setInputs(keysrc="freetext_hash", freetext="hunter2", hashalgo="blake3", harden=TRUE)
  say("strength renders", grepl("bits", paste(unlist(output$strength), collapse=" ")))

  # full encrypt path
  session$setInputs(infile=list(datapath=tmp, name="patients.csv"),
                    kind="auto", gzip=FALSE, keysrc="passphrase",
                    passphrase="s3cret-pass", kdf="scrypt", scheme="aead-aesgcm", nonce="")
  say("import_info shows csv", grepl("csv", paste(unlist(output$import_info), collapse=" ")))
  session$setInputs(do_encrypt=1)
  say("env created after encrypt", !is.null(rv$env))
  say("enc_summary shows scheme", grepl("aead-aesgcm", paste(unlist(output$enc_summary), collapse=" ")))

  # export + decrypt round-trip through the server logic
  env <- rv$env
  txt <- build_txt_export(env)
  af <- tempfile(fileext=".txt"); writeLines(txt, af)
  session$setInputs(artifact=list(datapath=af, name="a.txt"), dec_secret="s3cret-pass")
  session$setInputs(do_decrypt=1)
  say("decrypt recovered bytes", !is.null(rv$dec_pt))
  df <- restore_object(rv$dec_pt, rv$dec_env$orig_kind)
  say("recovered data.frame matches", is.data.frame(df) && df$age[2]==61)
  say("dec_summary VERIFIED", grepl("VERIFIED", paste(unlist(output$dec_summary), collapse=" ")))
})
cat(if(ok)"\nSERVER TESTS PASSED\n" else "\nSERVER TESTS FAILED\n")
quit(status=if(ok)0 else 1)
