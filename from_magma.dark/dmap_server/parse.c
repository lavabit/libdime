/**
 * @file /magma/servers/dmap/parse.c
 *
 * @brief	Functions used to handle DMAP commands and actions.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#include "magma.h"

/**
 * @brief	Parse an input line containing a DMAP command.
 * @note	This function updates the protocol-specific DMAP structure with parsed values for the session's tag, command, and arguments fields.
 * 			Special handling is performed for any command that is preceded by a "UID" prefix.
 * @param	con		the DMAP client connection issuing the command.
 * @return	1 on success or < 0 on error.
 *         -1: the tag could not be read.
 *         -2: the DMAP command could not be read.
 *         -3: the arguments to the DMAP command could not be read.
 */
int_t dmap_command_parser(connection_t *con) {

	chr_t *holder;
	size_t length;

	if (!con) {
		log_pedantic("Invalid connection passed to dmap command parser.");
		return 0;
	}

	// Free the previous tag.
	st_cleanup(con->dmap.tag);
	con->imap.tag = NULL;

	// Free the previous command.
	st_cleanup(con->dmap.command);
	con->dmap.command = NULL;

	// Free the previous arguments array.
	if (con->dmap.arguments) {
		ar_free(con->dmap.arguments);
		con->dmap.arguments = NULL;
	}

	// Debug info.
	if (magma.log.dmap) {
		log_info("%.*s", st_length_int(&con->network.line), st_char_get(&con->network.line));
	}

	// Get setup.
	holder = st_data_get(&(con->network.line));
	length = st_length_get(&(con->network.line));

	// Get the tag.
	if (imap_parse_astring(&(con->dmap.tag), &holder, &length) != 1 || !con->dmap.tag) {
		return -1;
	}

	// Get the command.
	if (imap_parse_astring(&(con->dmap.command), &holder, &length) != 1 || !con->dmap.command) {
		return -2;
	}

	// Check for the UID modifier.
	if (!st_cmp_ci_eq(con->dmap.command, PLACER("UID", 3))) {
		con->dmap.uid = 1;
		st_cleanup(con->dmap.command);
		con->dmap.command = NULL;

		if (imap_parse_astring(&(con->dmap.command), &holder, &length) != 1 || !con->dmap.command) {
			return -2;
		}

	}
	else if (con->dmap.uid == 1) {
		con->dmap.uid = 0;
	}

	// Now append the arguments to the array.
	if (imap_parse_arguments(con, &holder, &length) != 1) {
		return -3;
	}

	return 1;
}
