
/**
 * @file /magma/objects/signets/signets.c
 *
 * @brief	Assorted server-side interfaces for signets.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#include "magma.h"


/**
 * @brief	Destroy a signet retrieved from the database.
 * @param	signet_db	a pointer to the signet database structure to be freed.
 * @return	This function returns no value.
 */
void signet_db_destroy(signet_db_t *signet_db) {

	if (!signet_db) {
		return;
	}

	st_cleanup(signet_db->name);
	st_cleanup(signet_db->data);
	st_cleanup(signet_db->fingerprint_full);
	st_cleanup(signet_db->fingerprint_core);
	st_cleanup(signet_db->signed_next);

	mm_free(signet_db);

	return;
}

/**
 * @brief	Create a deep clone of a signet object.
 * @param	signet_db	a pointer to the signet object to be cloned.
 * @return	a pointer to the newly cloned signet object on success, or NULL on failure.
 */
signet_db_t * signet_db_clone(signet_db_t *signet_db) {

	signet_db_t *result;

	if (!signet_db) {
		return NULL;
	}

	if (!(result = mm_alloc(sizeof(signet_db_t)))) {
		log_error("Unable to allocate space for signet clone.");
		return NULL;
	}

	result->num = signet_db->num;
	result->name = st_dupe(signet_db->name);
	result->data = st_dupe(signet_db->data);
	result->fingerprint_full = st_dupe(signet_db->fingerprint_full);
	result->fingerprint_core = st_dupe(signet_db->fingerprint_core);

	if (!st_empty(signet_db->signed_next)) {
		result->signed_next = st_dupe(signet_db->signed_next);
	}

	if (!result->name || !result->data || !result->fingerprint_full || !result->fingerprint_core ||
			(!result->signed_next && !st_empty(signet_db->signed_next))) {
		log_error("Unable to clone signet.");
		signet_db_destroy(result);
	}

	return result;
}

/**
 * @brief	Construct an absolute filename pointing to the system signet directory.
 * @see		magma.dmap.signet_dir
 * @param	basename	the basename of the absolute file path to be returned.
 * @param	extension	the file extension of the absolute file path to be returned.
 * @return	a newly allocated null-terminated string containing the full requested file path on
 * 			success, or NULL on failure.
 */
chr_t * get_signet_filename(stringer_t *basename, stringer_t *extension) {

	stringer_t *strfname;
	chr_t *result;

	if (!magma.dmap.signet_dir) {
		log_pedantic("Attempted to resolve signet file but magma.dmap.signet_dir was not set.");
		return NULL;
	}

	if (!(strfname = st_merge("nnsn", magma.dmap.signet_dir, "/", basename, extension ))) {
		log_error("Unable to construct signet filename");
		return NULL;
	}

	// Temporary: we have to do this to ensure the filename is null-terminated.
	if (!(result = mm_alloc(st_length_get(strfname)+1))) {
		st_free(strfname);
		log_error("Unable to allocate space for signet filename.");
		return NULL;
	}

	mm_set(result, 0, st_length_get(strfname)+1);
	mm_copy(result, st_char_get(strfname), st_length_get(strfname));
	st_free(strfname);

	return result;
}


/**
 * @brief	Sign a user signet.
 * @param	username
 * @param	ssr
 * @param	errstring	if not NULL, a pointer to a variable to receive the address of an error message on failure.
 * @return
 *
 *
 */
signet_t * sign_user_signet(stringer_t *username, stringer_t *ssr, chr_t **errstring) {

	signet_t *builder;
	signet_state_t state;
	stringer_t *ssrtmp;
	placer_t domain;
	ED25519_KEY *signkey;
	unsigned char *keydata;
	chr_t *fname;
	size_t dstart, kdlen;

	if (st_empty(username) || st_empty(ssr)) {
		return NULL;
	}

	// Get the domain portion of the username.
	if (!(st_search_chr(username, '@', &dstart))) {
		log_pedantic("SSR request was made without a valid username.");
		return NULL;
	}

	dstart++;
	domain = pl_init((st_char_get(username) + dstart), st_length_get(username) - dstart);

	if (!(fname = get_signet_filename(&domain, ".keys"))) {
		log_error("Unable to construct signet keyfile path.");
		return NULL;
	}

	if (!(keydata = keys_get_binary((const char *)fname, &kdlen))) {
		log_pedantic("Unable to get key from file: %s", fname);
		mm_free(fname);
		return NULL;
	}

	mm_free(fname);

	if (keys_get_type(keydata, kdlen) != KEYS_TYPE_ORG) {
		log_pedantic("Retrieved key was not from an org key file and cannot be used to sign a user signet.");
		free(keydata);
		return NULL;
	}

	if (!(signkey = keys_fetch_sign_key(keydata, kdlen))) {
		log_pedantic("Signing key could not be read from keyfile data.");
		free(keydata);
		return NULL;
	}

	free(keydata);

	// The SSR name must also be null-terminated for the external API.
	if (!(ssrtmp = st_nullify(st_char_get(ssr), st_length_get(ssr)))) {
		log_error("SSR operation failed failed from memory allocation error.");
		free_ed25519_key(signkey);
		return NULL;
	}

	if (!(builder = signet_deserialize_b64(st_char_get(ssrtmp)))) {
		log_pedantic("Unable to deserialize SSR request.");
		free_ed25519_key(signkey);
		st_free(ssrtmp);
		return NULL;
	}

	st_free(ssrtmp);

	if ((state = signet_full_verify(builder, NULL, NULL)) != SS_SSR) {
		log_pedantic("The provided signet file did not contain a valid SSR.");
		free_ed25519_key(signkey);
		signet_destroy(builder);
		return NULL;
	}

	signet_sign_initial_sig(builder, signkey);

	// Dummy fields that could be added.
	//signet_builder_add_field(builder, SIGNET_USER_NAME, NULL, wizard_string, 0);
	//signet_builder_add_field(builder, SIGNET_USER_ADDRESS, NULL, wizard_string, 0);
	//signet_builder_add_field(builder, SIGNET_USER_COUNTRY, NULL, wizard_string, 0);
	//signet_builder_add_field(builder, SIGNET_USER_POSTAL, NULL, wizard_string, 0);
	//signet_builder_add_field(builder, SIGNET_USER_PHONE, NULL, wizard_string, 0);

	signet_sign_core_sig(builder, signkey);
	signet_set_id(builder, st_char_get(username));
	signet_sign_full_sig(builder, signkey);

	return builder;
}
