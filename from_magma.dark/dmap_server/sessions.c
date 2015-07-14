
/**
 * @file /magma/servers/dmap/sessions.c
 *
 * @brief	Functions used to handle DMAP sessions.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#include "magma.h"

/**
 * @brief	Destroy the data associated with a DMAP session.
 * @param	con		the DMAP client connection to be destroyed.
 * @return	This function returns no value.
 */
void dmap_session_destroy(connection_t *con) {

	meta_user_wlock(con->dmap.user);

	// Add some stuff in here later.

	meta_user_unlock(con->imap.user);

	// Is there a user session.
	if (con->dmap.user) {

		if (con->dmap.username) {
			meta_remove(con->dmap.username, META_PROT_DMAP);
		}

	}

	st_cleanup(con->dmap.username);
	st_cleanup(con->dmap.tag);
	st_cleanup(con->dmap.command);

	if (con->dmap.arguments) {
		ar_free(con->dmap.arguments);
	}

	log_pedantic("Destroyed dmap session.");

	return;
}
