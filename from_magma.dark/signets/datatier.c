
/**
 * @file /magma/objects/signets/datatier.c
 *
 * @brief	The database interface for signets.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#include "magma.h"


/**
 * @brief	Insert a new signet into the database.
 * @param	signet_db	a pointer to the signet object to be inserted into the Signets table.
 * @return	true if the signet was successfully added or false if it was not.
 */
bool_t signet_insert_db(signet_db_t *signet_db) {

	MYSQL_BIND parameters[4];

	// Sanity check.
	if (!signet_db) {
		return false;
	}

	mm_wipe(parameters, sizeof(parameters));
	// The signet name.
	parameters[0].buffer_type = MYSQL_TYPE_STRING;
	parameters[0].buffer_length = st_length_get(signet_db->name);
	parameters[0].buffer = st_char_get(signet_db->name);
	// The signet's data.
	parameters[1].buffer_type = MYSQL_TYPE_STRING;
	parameters[1].buffer_length = st_length_get(signet_db->data);
	parameters[1].buffer = st_char_get(signet_db->data);
	// The signet's full fingerprint.
	parameters[2].buffer_type = MYSQL_TYPE_STRING;
	parameters[2].buffer_length = st_length_get(signet_db->fingerprint_full);
	parameters[2].buffer = st_char_get(signet_db->fingerprint_full);
	// The signet's core fingerprint.
	parameters[3].buffer_type = MYSQL_TYPE_STRING;
	parameters[3].buffer_length = st_length_get(signet_db->fingerprint_core);
	parameters[3].buffer = st_char_get(signet_db->fingerprint_core);

	if (!stmt_exec(stmts.insert_new_signet, parameters)) {
		log_pedantic("Failed to insert new signet into database.");
		return false;
	}

	return true;
}

/**
 * @brief	Fetch the collection of signets from the database matching a specified owner name.
 * @param	owner	the name of the signet to have all its iterations retrieved from the database.
 * @return	a linked list holding all variants of the specified signet, or NULL on failure.
 */
inx_t * signets_fetch_by_name(stringer_t *owner) {

	inx_t *result;
	signet_db_t *signet_db;
	row_t *row;
	table_t *table;
	MYSQL_BIND parameters[1];
	multi_t key;

	// Sanity check.
	if (!owner) {
		return NULL;
	}

	mm_wipe(parameters, sizeof(parameters));
	parameters[0].buffer_type = MYSQL_TYPE_STRING;
	parameters[0].buffer_length = st_length_get(owner);
	parameters[0].buffer = st_char_get(owner);

	if (!(table = stmt_get_result(stmts.select_signets_by_name, parameters))) {
		log_pedantic("Failed to fetch signet from database.");
		return NULL;
	}

	if (!res_row_count(table)) {
		res_table_free(table);
		return NULL;
	}

	// Allocate a list to hold the result signet set.
	 if (!(result = inx_alloc(M_INX_LINKED, &signet_db_destroy))) {
		 res_table_free(table);
		 log_error("Unable to allocate result set to hold signets from database.");
	 }

	 key.type = M_TYPE_STRINGER;

	 while ((row = res_row_next(table))) {

		 if (!(signet_db = mm_alloc(sizeof(signet_db_t)))) {
			 log_error("Unable to allocate memory for signet from database.");
			 res_table_free(table);
			 inx_free(result);
			 return NULL;
		 }

		 signet_db->num = res_field_uint64(row, 0);
		 signet_db->name = res_field_string(row, 1);
		 signet_db->data = res_field_string(row, 2);
		 signet_db->fingerprint_full = res_field_string(row, 3);
		 signet_db->fingerprint_core = res_field_string(row, 4);
		 signet_db->signed_next = res_field_string(row, 5);

		 key.val.st = signet_db->fingerprint_core;

		 if (!inx_insert(result, key, signet_db)) {
			 log_error("Unable to add signet from database to result set.");
			 res_table_free(table);
			 inx_free(result);
			 signet_db_destroy(signet_db);
			 return NULL;
		 }


	 }

	res_table_free(table);

	return result;
}

/**
 * @brief	Fetch the most current signet from the database by name.
 * @param	owner	a managed string containing the name of the organization or individual signet holder.
 * @return	a pointer to a signet structure for the requested record on success or NULL on failure.
 */
signet_db_t * signet_fetch_current(stringer_t *owner) {

	signet_db_t *result;
	row_t *row;
	table_t *table;
	MYSQL_BIND parameters[1];

	// Sanity check.
	if (!owner) {
		return false;
	}

	mm_wipe(parameters, sizeof(parameters));
	// The signet owner name.
	parameters[0].buffer_type = MYSQL_TYPE_STRING;
	parameters[0].buffer_length = st_length_get(owner);
	parameters[0].buffer = st_char_get(owner);

	if (!(table = stmt_get_result(stmts.select_current_signet_by_name, parameters))) {
		log_pedantic("Failed to fetch signet from database.");
		return NULL;
	}

	if (!res_row_count(table) || !(row = res_row_next(table))) {
		res_table_free(table);
		return NULL;
	}

	if (!(result = mm_alloc(sizeof(signet_db_t)))) {
		log_error("Unable to allocate memory for signet from database.");
		res_table_free(table);
		return NULL;
	}

	result->num = res_field_uint64(row, 0);
	result->name = res_field_string(row, 1);
	result->data = res_field_string(row, 2);
	result->fingerprint_full = res_field_string(row, 3);
	result->fingerprint_core = res_field_string(row, 4);
	result->signed_next = res_field_string(row, 5);

	res_table_free(table);

	return result;
}


/**
 * @brief	Fetch a signet from the database by its full fingerprint.
 * @param	owner			a managed string containing the name of the organization or individual signet holder.
 * @param	fingerprint		a managed string containing the full fingerprint that must match the requested signet.
 * @return	a pointer to a signet structure for the requested record on success or NULL on failure.
 */
signet_db_t * signet_fetch_by_full_fingerprint(stringer_t *owner, stringer_t *fingerprint) {

	signet_db_t *result;
	row_t *row;
	table_t *table;
	MYSQL_BIND parameters[2];

	// Sanity check.
	if (!owner || !fingerprint) {
		return false;
	}

	mm_wipe(parameters, sizeof(parameters));
	// The signet owner name.
	parameters[0].buffer_type = MYSQL_TYPE_STRING;
	parameters[0].buffer_length = st_length_get(owner);
	parameters[0].buffer = st_char_get(owner);
	// The signet's fingerprint
	parameters[1].buffer_type = MYSQL_TYPE_STRING;
	parameters[1].buffer_length = st_length_get(fingerprint);
	parameters[1].buffer = st_char_get(fingerprint);

	if (!(table = stmt_get_result(stmts.select_signet_by_full_fingerprint, parameters))) {
		log_pedantic("Failed to fetch signet from database.");
		return NULL;
	}

	if (!res_row_count(table) || !(row = res_row_next(table))) {
		res_table_free(table);
		return NULL;
	}

	if (!(result = mm_alloc(sizeof(signet_db_t)))) {
		log_error("Unable to allocate memory for signet from database.");
		res_table_free(table);
		return NULL;
	}

	result->num = res_field_uint64(row, 0);
	result->name = res_field_string(row, 1);
	result->data = res_field_string(row, 2);
	result->fingerprint_full = res_field_string(row, 3);
	result->fingerprint_core = res_field_string(row, 4);
	result->signed_next = res_field_string(row, 5);

	res_table_free(table);

	return result;
}


/**
 * @brief	Fetch a signet from the database by full or core fingerprint.
 * @param	owner			a managed string containing the name of the organization or individual signet holder.
 * @param	fingerprint		a managed string containing the full or core fingerprint that must match the requested signet.
 * @return	a pointer to a signet structure for the requested record on success or NULL on failure.
 */
signet_db_t * signet_fetch_by_any_fingerprint(stringer_t *owner, stringer_t *fingerprint) {

	signet_db_t *result;
	row_t *row;
	table_t *table;
	MYSQL_BIND parameters[3];

	// Sanity check.
	if (!owner || !fingerprint) {
		return false;
	}

	mm_wipe(parameters, sizeof(parameters));
	// The signet owner name.
	parameters[0].buffer_type = MYSQL_TYPE_STRING;
	parameters[0].buffer_length = st_length_get(owner);
	parameters[0].buffer = st_char_get(owner);
	// The signet's full fingerprint
	parameters[1].buffer_type = MYSQL_TYPE_STRING;
	parameters[1].buffer_length = st_length_get(fingerprint);
	parameters[1].buffer = st_char_get(fingerprint);
	// The signet's core fingerprint (same as the last parameter)
	parameters[2].buffer_type = MYSQL_TYPE_STRING;
	parameters[2].buffer_length = st_length_get(fingerprint);
	parameters[2].buffer = st_char_get(fingerprint);

	if (!(table = stmt_get_result(stmts.select_signet_by_any_fingerprint, parameters))) {
		log_pedantic("Failed to fetch signet from database.");
		return NULL;
	}

	if (!res_row_count(table) || !(row = res_row_next(table))) {
		res_table_free(table);
		return NULL;
	}

	if (!(result = mm_alloc(sizeof(signet_db_t)))) {
		log_error("Unable to allocate memory for signet from database.");
		res_table_free(table);
		return NULL;
	}

	result->num = res_field_uint64(row, 0);
	result->name = res_field_string(row, 1);
	result->data = res_field_string(row, 2);
	result->fingerprint_full = res_field_string(row, 3);
	result->fingerprint_core = res_field_string(row, 4);
	result->signed_next = res_field_string(row, 5);

	res_table_free(table);

	return result;
}


inx_t * get_signet_coc(inx_t *signets, stringer_t *start_fp, stringer_t *end_fp) {

	signet_db_t *sigdb;
	inx_t *result;
	multi_t key;

	if (!signets || !start_fp) {
		return NULL;
	}

	// So there's no confusion with placers.
	if (st_empty(end_fp)) {
		end_fp = NULL;
	}

	key.type = M_TYPE_STRINGER;
	key.val.st = start_fp;

	// We must find the starting core signature.
	if (!(sigdb = inx_find(signets, key))) {
		return NULL;
	}

	// If an ending signature was specified, make sure that it too exists.
	if (end_fp) {
		key.val.st = end_fp;

		if (!inx_find(signets, key)) {
			return NULL;
		}

	}

	// Allocate a list for the return.
	if (!(result = inx_alloc(M_INX_LINKED, &signet_db_destroy))) {
		log_error("Unable to allocate result set to hold signet chain of custody.");
		return NULL;
	}


	while (sigdb) {

		key.val.st = sigdb->fingerprint_core;

		// We need to add a clone of the item so we can eventually free both lists without corruption.
		if (!(sigdb = signet_db_clone(sigdb))) {
			inx_free(result);
			log_error("Unable to clone data into chain of custody reply.");
			return NULL;
		}

		if (!inx_insert(result, key, sigdb)) {
			inx_free(result);
			log_error("Unable to add signet to chain of custody reply.");
			return NULL;
		}

		// Are we end at the desired chain of custody?
		if (end_fp && !st_cmp_cs_eq(end_fp, sigdb->fingerprint_core)) {

			return result;
		} else if (!end_fp && st_empty(sigdb->signed_next)) {

			return result;
		}
		// Otherwise maybe we've hit the end before we reached out target end fingerprint (error).
		else if (end_fp && st_empty(sigdb->signed_next)) {
			inx_free(result);

			return NULL;
		}

		// Continue traversing the list, looking for the next signed signet.
		key.val.st = sigdb->signed_next;
		sigdb = inx_find(signets, key);
	}

	// If we got this far we never found the end. Return an error instead.
	inx_free(result);
	return NULL;
}
