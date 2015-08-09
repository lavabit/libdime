#ifndef ERROR_CODES_H
#define ERROR_CODES_H

typedef enum {
  ERRCODE_NOMEM,
  ERRCODE_CRYPTO
} errcode_t;

typedef struct {
  errcode_t code;
  char const * message;
} derror_t;

extern derror_t const * const
ERR_CRYPTO;
extern derror_t const * const
ERR_NOMEM;

#endif
