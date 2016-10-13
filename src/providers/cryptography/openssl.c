
/**
 * @file /magma/providers/cryptography/openssl.c
 *
 * @brief	The interface to OpenSSL routines.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#include "core/core.h"
#include "providers/symbols.h"
#include "providers/cryptography/cryptography.h"

/**
 * @brief	Get a textual representation of the last OpenSSL error message.
 * @param	buffer	a buffer that will receive the last OpenSSL error message.
 * @param	length	the size, in bytes, of the buffer that will contain the last OpenSSL error message.
 * @return	NULL on failure, or a pointer to the buffer where the last OpenSSL error message has been stored.
 */
char * ssl_error_string(chr_t *buffer, int_t length) {

	if (!buffer) {
		return NULL;
	}

	if (length < 120) {
		log_pedantic("The buffer created to hold the SSL error string should be at least 120 bytes.");
	}

	ERR_error_string_n_d(ERR_get_error_d(), buffer, length);

	return buffer;
}
