
/**
 * @file /magma/objects/dime/resolv.c
 *
 * @brief	Interface to DNS routines for retrieving DIME policy records.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#include "magma.h"

/**
 * @brief	Retrieve a DIME policy record from DNS.



 */
bool_t dime_get_policy_record (stringer_t *domain, void *buf, size_t blen) {

	/*stringer_t *dx_domain;

	if (!(dx_domain = st_merge("nns", DIME_DNS_PREFIX, ".", domain))) {
		log_error("Could not build DIME DNS lookup from domain name.");
		return false;
	}

	if (res_query(domain, C_IN, T_TXT, st_char_get(dx_domain), st_length_get(dx_domain)) < 0) {
		st_free(dx_domain);
		return false;
	}

	st_free(dx_domain); */

	return true;
}
