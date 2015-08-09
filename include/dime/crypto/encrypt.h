#ifndef ENCRYPT_H
#define ENCRYPT_H

#include "dime/dime_ctx.h"
#include "dime/error_codes.h"

typedef struct encrypt_ctx encrypt_ctx_t;
typedef struct { char unused[1]; } *encrypt_keypair_t;

derror_t const *
encrypt_ctx_new(
    dime_ctx_t *dime_ctx,
    encrypt_ctx_t *result);

void
encrypt_ctx_free(encrypt_ctx_t *ctx);

#endif
