#include "dime/error_codes.h"

static derror_t const CRYPTO_ERROR = {
  ERRCODE_CRYPTO,
  "cryptographic error"
};
derror_t const * const
ERR_CRYPTO = &CRYPTO_ERROR;

static derror_t const NOMEM_ERROR = {
  ERRCODE_NOMEM,
  "out of memory error"
};
derror_t const * const
ERR_NOMEM = &NOMEM_ERROR;
