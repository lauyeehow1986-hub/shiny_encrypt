/* C entrypoint that R CMD SHLIB compiles and links against the Rust staticlib
 * (libshinyencrypt_native.a) to produce shinyencrypt_native.dll.
 *
 * extendr emits each exported function as `wrap__<name>`. R CMD SHLIB's
 * auto-generated .def only exports symbols from this file, so we must declare
 * and *explicitly register* each wrapper here for .Call(...) to find it. Add one
 * extern line + one R_CallMethodDef row per new #[extendr] fn (arity = R args). */
#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>

extern SEXP wrap__native_argon2id(SEXP secret, SEXP salt, SEXP mem_kib,
                                  SEXP iters, SEXP lanes, SEXP size);
extern SEXP wrap__native_hybrid_keygen(void);
extern SEXP wrap__native_hybrid_encaps(SEXP public_bundle);
extern SEXP wrap__native_hybrid_decaps(SEXP secret_bundle, SEXP encapsulation);
extern SEXP wrap__native_mldsa_keygen(void);
extern SEXP wrap__native_mldsa_sign(SEXP sk_bytes, SEXP msg);
extern SEXP wrap__native_mldsa_verify(SEXP pk_bytes, SEXP msg, SEXP sig);
extern SEXP wrap__native_shamir_split(SEXP secret, SEXP t, SEXP n);
extern SEXP wrap__native_shamir_combine(SEXP shares_concat, SEXP share_len);
extern SEXP wrap__native_ff1_encrypt(SEXP key, SEXP tweak, SEXP radix, SEXP numerals);
extern SEXP wrap__native_ff1_decrypt(SEXP key, SEXP tweak, SEXP radix, SEXP numerals);
extern SEXP wrap__native_timelock_generate(SEXP bits, SEXP t);
extern SEXP wrap__native_timelock_solve_steps(SEXP x, SEXP n, SEXP steps);
extern SEXP wrap__native_timelock_calibrate(SEXP bits, SEXP millis);
extern SEXP wrap__native_cpabe_setup(void);
extern SEXP wrap__native_cpabe_keygen(SEXP pk, SEXP mk, SEXP attrs);
extern SEXP wrap__native_cpabe_encrypt(SEXP pk, SEXP policy, SEXP plaintext);
extern SEXP wrap__native_cpabe_decrypt(SEXP sk, SEXP ct);
extern SEXP wrap__native_ibe_setup(void);
extern SEXP wrap__native_ibe_extract(SEXP pk, SEXP sk, SEXP identity);
extern SEXP wrap__native_ibe_encaps(SEXP pk, SEXP identity);
extern SEXP wrap__native_ibe_decaps(SEXP usk, SEXP ct);
extern SEXP wrap__native_oprf_keygen(void);
extern SEXP wrap__native_oprf_public_key(SEXP key);
extern SEXP wrap__native_oprf_blind(SEXP input);
extern SEXP wrap__native_oprf_evaluate(SEXP key, SEXP blinded);
extern SEXP wrap__native_oprf_finalize(SEXP input, SEXP blind_bundle, SEXP evaluated, SEXP pubkey);
extern SEXP wrap__native_backend_version(void);

static const R_CallMethodDef CallEntries[] = {
    {"wrap__native_argon2id",        (DL_FUNC) &wrap__native_argon2id,        6},
    {"wrap__native_hybrid_keygen",   (DL_FUNC) &wrap__native_hybrid_keygen,   0},
    {"wrap__native_hybrid_encaps",   (DL_FUNC) &wrap__native_hybrid_encaps,   1},
    {"wrap__native_hybrid_decaps",   (DL_FUNC) &wrap__native_hybrid_decaps,   2},
    {"wrap__native_mldsa_keygen",    (DL_FUNC) &wrap__native_mldsa_keygen,    0},
    {"wrap__native_mldsa_sign",      (DL_FUNC) &wrap__native_mldsa_sign,      2},
    {"wrap__native_mldsa_verify",    (DL_FUNC) &wrap__native_mldsa_verify,    3},
    {"wrap__native_shamir_split",    (DL_FUNC) &wrap__native_shamir_split,    3},
    {"wrap__native_shamir_combine",  (DL_FUNC) &wrap__native_shamir_combine,  2},
    {"wrap__native_ff1_encrypt",     (DL_FUNC) &wrap__native_ff1_encrypt,     4},
    {"wrap__native_ff1_decrypt",     (DL_FUNC) &wrap__native_ff1_decrypt,     4},
    {"wrap__native_timelock_generate",    (DL_FUNC) &wrap__native_timelock_generate,    2},
    {"wrap__native_timelock_solve_steps", (DL_FUNC) &wrap__native_timelock_solve_steps, 3},
    {"wrap__native_timelock_calibrate",   (DL_FUNC) &wrap__native_timelock_calibrate,   2},
    {"wrap__native_cpabe_setup",     (DL_FUNC) &wrap__native_cpabe_setup,     0},
    {"wrap__native_cpabe_keygen",    (DL_FUNC) &wrap__native_cpabe_keygen,    3},
    {"wrap__native_cpabe_encrypt",   (DL_FUNC) &wrap__native_cpabe_encrypt,   3},
    {"wrap__native_cpabe_decrypt",   (DL_FUNC) &wrap__native_cpabe_decrypt,   2},
    {"wrap__native_ibe_setup",       (DL_FUNC) &wrap__native_ibe_setup,       0},
    {"wrap__native_ibe_extract",     (DL_FUNC) &wrap__native_ibe_extract,     3},
    {"wrap__native_ibe_encaps",      (DL_FUNC) &wrap__native_ibe_encaps,      2},
    {"wrap__native_ibe_decaps",      (DL_FUNC) &wrap__native_ibe_decaps,      2},
    {"wrap__native_oprf_keygen",     (DL_FUNC) &wrap__native_oprf_keygen,     0},
    {"wrap__native_oprf_public_key", (DL_FUNC) &wrap__native_oprf_public_key, 1},
    {"wrap__native_oprf_blind",      (DL_FUNC) &wrap__native_oprf_blind,      1},
    {"wrap__native_oprf_evaluate",   (DL_FUNC) &wrap__native_oprf_evaluate,   2},
    {"wrap__native_oprf_finalize",   (DL_FUNC) &wrap__native_oprf_finalize,   4},
    {"wrap__native_backend_version", (DL_FUNC) &wrap__native_backend_version, 0},
    {NULL, NULL, 0}
};

void R_init_shinyencrypt_native(DllInfo *dll) {
    R_registerRoutines(dll, NULL, CallEntries, NULL, NULL);
    R_useDynamicSymbols(dll, FALSE);
}
