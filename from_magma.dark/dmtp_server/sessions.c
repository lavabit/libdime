
/**
 * @file /magma/servers/dmtp/sessions.c
 *
 * @brief	Functions used to handle DMTP sessions.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#include "magma.h"

/**
 * @brief	Reset a DMTP session to its initialized state.
 * @param	con		the DMTP client connection to be reset.
 * @return	This function returns no value.
 */
void dmtp_srv_session_reset(connection_t *con) {

	st_cleanup(con->dmtp.mailfrom);
	con->dmtp.mailfrom = NULL;
	con->dmtp.msgsize = 0;
	st_cleanup(con->dmtp.stats_nonce);
	con->dmtp.stats_nonce = NULL;
	con->dmtp.verbose = false;

	return;
}

/**
 * @brief	Destroy the data associated with a DMTP session.
 * @param	con		the DMTP client connection to be destroyed.
 * @return	This function returns no value.
 */
void dmtp_srv_session_destroy(connection_t *con) {

	st_cleanup(con->dmtp.ehlo);
	st_cleanup(con->dmtp.mailfrom);
	st_cleanup(con->dmtp.stats_nonce);

	//log_pedantic("Destroyed dmtp session.");
	return;
}
