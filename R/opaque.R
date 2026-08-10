# OPAQUE — an asymmetric PAKE (OPAQUE-3DH over ristretto255), shipped as a
# single-machine two-party simulation. The whole point of an aPAKE: the server
# authenticates a client by password WITHOUT ever seeing the password and
# WITHOUT storing anything a thief could replay. A stolen server record still
# forces a per-user offline dictionary attack, slowed by Argon2.
#
# Two phases (the native layer in R/backend.R does the crypto; this file just
# shuttles the fixed-length message blobs across the simulated client/server
# boundary):
#   Registration  password -> {server record kept by the server, export key kept
#                 by the client}. The server learns nothing about the password.
#   Login (AKE)   KE1 (client) -> KE2 (server) -> KE3 (client) -> verify (server).
#                 On success both sides derive the SAME session key, and the
#                 client recovers its stable export key — a password-derived key
#                 it can use to encrypt data.
#
# On a wrong password the client's envelope check fails closed at KE3; a tampered
# or forged KE2 fails the client's server-authentication check; a client that
# cannot prove the password fails the server's KE3 check.

.opaque_hex <- function(raw) paste(sprintf("%02x", as.integer(raw)), collapse = "")

.opaque_pw_raw <- function(password) {
  password <- as.character(password)
  if (length(password) != 1L || is.na(password) || !nzchar(password))
    stop("Enter a (non-empty) password.")
  charToRaw(enc2utf8(password))
}

.opaque_require <- function() {
  if (!isTRUE(crypto_backend_available("opaque")))
    stop("Native OPAQUE backend not built — run tools/build_native.R and restart.")
}

# Server long-term identity keypair (server_priv||server_pub, 64 bytes). Created
# once per "server"; reused across registrations and logins so envelopes stay
# valid (the server's public key is bound into every user's envelope).
opaque_server_setup <- function() {
  .opaque_require()
  native_opaque_server_setup()
}

# Register `password` against a server keypair. Returns the 224-byte server
# record (stored server-side, contains no password-equivalent) and the client's
# 64-byte export key. The password never leaves the client in any form.
opaque_register <- function(password, server_kp) {
  .opaque_require()
  pw <- .opaque_pw_raw(password)
  server_pub <- server_kp[33:64]

  # 1. Client blinds the password (the server sees only a random-looking point).
  blind_bundle <- native_oprf_blind(pw)          # blind(32) || blinded(32)
  blinded <- blind_bundle[33:64]
  # 2. Server mints a fresh per-user OPRF key and evaluates it.
  resp <- native_opaque_register_response(blinded, server_pub) # ku || eval || pub
  ku        <- resp[1:32]
  evaluated <- resp[33:64]
  # 3. Client builds its credential + export key; the server stores {ku, ...}.
  fin <- native_opaque_register_finalize(pw, blind_bundle, evaluated, server_pub) # 256
  record_from_client <- fin[1:192]  # client_pub || masking_key || envelope
  export_key <- fin[193:256]

  list(record = c(ku, record_from_client),   # 224-byte server record
       export_key = export_key)
}

# Log in with `password` against a stored record + server keypair. Runs the full
# KE1/KE2/KE3 exchange over the simulated boundary. Returns a status list: on
# success, both session keys (which must match) and the export key; on failure,
# which side rejected and why. Only KE1/KE2/KE3 ever "cross the wire".
opaque_login <- function(password, record, server_kp) {
  .opaque_require()
  pw <- .opaque_pw_raw(password)
  server_priv <- server_kp[1:32]

  # KE1 — client sends a fresh blinded password + ephemeral key.
  ci <- native_opaque_client_init(pw)   # client_state(64) || KE1(96)
  client_state <- ci[1:64]
  ke1 <- ci[65:160]

  # KE2 — server evaluates the OPRF, masks the credential response, runs 3DH.
  sr <- native_opaque_server_respond(server_priv, record, ke1) # KE2(320) || state(128)
  ke2 <- sr[1:320]
  server_state <- sr[321:448]

  fail <- function(stage, e)
    list(success = FALSE, stage = stage, error = conditionMessage(e),
         transcript = list(ke1 = ke1, ke2 = ke2, ke3 = NULL))

  # KE3 — client verifies the envelope (wrong password fails here) and the
  # server's MAC (server authentication), then produces its proof.
  cf <- tryCatch(native_opaque_client_finish(pw, client_state, ke1, ke2),
                 error = function(e) e)
  if (inherits(cf, "error")) return(fail("client", cf))
  ke3                <- cf[1:64]
  session_key_client <- cf[65:128]
  export_key         <- cf[129:192]

  # Server verifies the client's proof (knowledge of the password).
  ss <- tryCatch(native_opaque_server_finish(server_state, ke3),
                 error = function(e) e)
  if (inherits(ss, "error"))
    return(c(fail("server", ss),
             list(transcript = list(ke1 = ke1, ke2 = ke2, ke3 = ke3))))

  list(success = TRUE,
       session_key_client = session_key_client,
       session_key_server = ss,
       keys_match = identical(as.raw(session_key_client), as.raw(ss)),
       export_key = export_key,
       transcript = list(ke1 = ke1, ke2 = ke2, ke3 = ke3))
}
