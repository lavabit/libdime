#ifndef ERROR_CODES_H
#define ERROR_CODES_H

typedef enum {
  ERRCODE_NOMEM,
  ERRCODE_CRYPTO
} errcode_t;

typedef struct {
  errcode_t code;
  char const * message;
} error_t;

extern error_t const * const
ERR_CRYPTO;
extern error_t const * const
ERR_NOMEM;

#endif
