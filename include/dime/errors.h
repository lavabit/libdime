#ifndef ERRORS_H
#define ERRORS_H

#include "error_codes.h"

#define OK ((error_t) { SUCCESS, "success!" })
#define ERR_CRYPTO ((error_t) { CRYPTO, "unspecified error" })
#define ERR_NOMEM ((error_t) { NOMEM, "out of memory" })

#endif
