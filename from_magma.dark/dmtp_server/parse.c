
/**
 * @file /magma/servers/dmtp/parse.c
 *
 * @brief	Functions used to parse command parameters from DMTP clients.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#include "magma.h"

/**
 * @brief	Determine whether a domain name passed to a DMTP command is valid.
 * @note	Valid domain names may only contain letters, numbers, periods and hyphens.
 * @param	domain	a managed string containing the domain name to be analyzed.
 * @return	true if the specified domain was valid or false if it was not.
 */
bool_t dmtp_is_valid_domain(stringer_t *domain) {

	chr_t *ptr = st_char_get(domain);
	size_t len = st_length_get(domain);

	for (int i = 0; i < len; i++, ptr++) {

		if ((*ptr < 'A' || *ptr > 'Z') && (*ptr < 'a' || *ptr > 'z') && (*ptr < '0' || *ptr > '9') && *ptr != '-' && *ptr != '.') {
			return false;
		}

	}

	return true;
}

/**
 * @brief	Determine whether a dmail address passed to a DMTP command is valid.
 * @see		dmtp_is_valid_domain()
 * @param	address	a managed string containing the dmail address to be analyzed.
 * @return	true if the specified dmail address was valid or false if it was not.
 */
bool_t dmtp_is_valid_address(stringer_t *address) {

	placer_t username = pl_null(), domain = pl_null();
	uchr_t *ptr;
	size_t usize;

	// Get the username and domain portions separately.
	if (tok_get_st(address, '@', 0, &username) || tok_get_st(address, '@', 1, &domain) != 1) {
		return false;
	}

	if (!(usize = pl_length_get(username))) {
		return false;
	}

	ptr = (uchr_t *) pl_char_get(username);

	// Neither the first nor last character of the email's local part can be a period.
	if (ptr[0] == '.' || ptr[usize-1] == '.') {
		return false;
	}

	for (size_t i = 0; i < usize; i++) {

		if (!chr_is_class(ptr[i], (uchr_t *)"!#$%&'*+-/=?^_`{|}~.", 20) && !chr_alphanumeric(ptr[i])) {
			return false;
		}

		// No consecutive periods
		if (i && ptr[i] == '.' && ptr[i-1] == '.') {
			return false;
		}

	}

	if (!dmtp_is_valid_domain(&domain)) {
		return false;
	}

	return true;
}
