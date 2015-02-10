
#include "magma.h"


/**
 * @brief	Generate a random unsigned 64 bit number.
 * @note	This is a stripped down copy of rand_get_uint64() originally dependent upon a 3rd party provider.
 * @note	This function attempts to generate random data securely, but falls back on the pseudo-random number generator.
 * @result	the newly generated unsigned 64 bit integer.
 */
uint64_t _rand_get_uint64(void) {

	uint64_t result;
	static unsigned int rand_ctx = 0;
	time_t now;

	if (!rand_ctx) {
		time(&now);
		rand_ctx = now;
	}

	result = rand_r(&rand_ctx);
	result = result << 32; 
	result = result | rand_r(&rand_ctx);

	return result;
}
