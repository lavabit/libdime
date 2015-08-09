#include "dime/error_codes.h"

static error_t const CRYPTO_ERROR = {
  ERRCODE_CRYPTO,
  "cryptographic error"
};
error_t const * const
ERR_CRYPTO = &CRYPTO_ERROR;

static error_t const NOMEM_ERROR = {
  ERRCODE_NOMEM,
  "out of memory error"
};
error_t const * const
ERR_NOMEM = &NOMEM_ERROR;
