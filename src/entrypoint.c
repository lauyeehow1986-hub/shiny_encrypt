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
extern SEXP wrap__native_backend_version(void);

static const R_CallMethodDef CallEntries[] = {
    {"wrap__native_argon2id",        (DL_FUNC) &wrap__native_argon2id,        6},
    {"wrap__native_backend_version", (DL_FUNC) &wrap__native_backend_version, 0},
    {NULL, NULL, 0}
};

void R_init_shinyencrypt_native(DllInfo *dll) {
    R_registerRoutines(dll, NULL, CallEntries, NULL, NULL);
    R_useDynamicSymbols(dll, FALSE);
}
