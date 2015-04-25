/**
 * @file /magma/core/parsers/trim.c
 *
 * @brief	Functions used to trim whitespace from strings.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#include <core/magma.h>

static bool_t is_trimspace(chr_t ch) {
	return ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t' || ch == '\v';
}

// Removes any leading and trailing whitespace from a stringer.
void st_trim(stringer_t *string) {

	chr_t *start, *end;

	start = st_char_get(string);
	end = start + st_length_get(string);

	while (start != end && is_trimspace(*start)) {
		start++;
	}

	while (start != end && is_trimspace(end[-1])) {
		end--;
	}

	if (start == end) {
		st_length_set(string, 0);
	}
	else if (start + st_length_get(string) != end) {
		mm_move(st_char_get(string), start, end - start);
		st_length_set(string, end - start);
		mm_wipe(st_char_get(string) + st_length_get(string), st_avail_get(string) - st_length_get(string));
	}

}

placer_t pl_trim(placer_t place) {

	chr_t *start, *end;

	start = pl_char_get(place);
	end = start + pl_length_get(place);

	while (start != end && is_trimspace(*start)) {
		start++;
	}
	while (start != end && is_trimspace(end[-1])) {
		end--;
	}

	if (start == end)
		return pl_null();

	return pl_init(start, end - start);
}

/**
 * @brief	Trim the leading whitespace from a placer.
 * @param	place	a placer containing the string to have its leading whitespace trimmed.
 * @return	a placer pointing to the trimmed value inside the originally specified input string.
 */
placer_t pl_trim_start(placer_t place) {

	chr_t *start, *end;

	start = pl_char_get(place);
	end = start + pl_length_get(place);

	while (start != end && is_trimspace(*start)) {
		start++;
	}

	if (start == end)
		return pl_null();

	return pl_init(start, end - start);
}

placer_t pl_trim_end(placer_t place) {

	chr_t *start, *end;

	start = pl_char_get(place);
	end = start + pl_length_get(place);

	while (start != end && is_trimspace(end[-1])) {
		end--;
	}

	if (start == end)
		return pl_null();

	return pl_init(start, end - start);
}
