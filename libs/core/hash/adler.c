/**
 * @brief	An x86 implementation of the Adler hash algorithm.
 */

#include <core/magma.h>

/**
 * @brief	Return an Adler-32 hash of the specified data.
 * @param	buffer	a pointer to the data to be hashed.
 * @param	length	the length, in bytes, of the data to be hashed.
 * @result	a 32 bit number containing the Adler-32 hash of the data.
 */
uint32_t hash_adler32(const void *buffer, size_t length) {

	size_t input;
	uint64_t a = 1, b = 0;

	while (length > 0) {

		// Every 5550 octets we need to modulo.
		input = length > 5550 ? 5550 : length;
		length -= input;

		do {
			a += *(uchr_t *)buffer++;
			b += a;
		} while (--input);

		a = (a & 0xffff) + (a >> 16) * (65536 - 65521);
		b = (b & 0xffff) + (b >> 16) * (65536 - 65521);
	}

	// If a is greater than the mod number, modulo.
	if (a >= 65521) {
		a -= 65521;
	}

	b = (b & 0xffff) + (b >> 16) * (65536 - 65521);
	if (b >= 65521) {
		b -= 65521;
	}

	return (b << 16) | a;
}
