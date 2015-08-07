#ifndef ERROR_CODES_H
#define ERROR_CODES_H

typedef enum {
  SUCCESS,
  CRYPTO,
  NOMEM
} errcode_t;

typedef struct {
  errcode_t code;
  char const * message
} error_t;

#endif
