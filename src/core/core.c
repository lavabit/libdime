
/**
 * @file /libdime/src/core/core.c
 *
 * @brief DESCRIPTIONxxxGOESxxxHERE
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#include "core/core.h"

__thread uint_t rand_ctx = 0;

core_t core = {
	.page_length = 4096
};

void log_core(const char *format, ...) {
	va_list args;

	va_start(args, format);
	vfprintf(stdout, format, args);
	va_end(args);

	return;
}

uint64_t rand_get_uint64(void) {

	uint64_t result;

	// Use system supplied pseudo random number generator if an error occurs.
	result = rand_r(&rand_ctx);
	result = result << 32;
	result = result | rand_r(&rand_ctx);

	return result;
}
