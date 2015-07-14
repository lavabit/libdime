
/**
 * @file /magma/servers/dmtp/commands.c
 *
 * @brief	The functions involved with parsing and routing DMTP commands.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#include "magma.h"
#include "commands.h"


/**
 * @brief	Sort the DMTP command table to be ready for binary searches.
 * @return	This function returns no value.
 */
void dmtp_srv_sort(void) {

	qsort(dmtp_commands, sizeof(dmtp_commands) / sizeof(dmtp_commands[0]), sizeof(command_t), &cmd_compare);
	return;
}

/**
 * @brief	The re-entry point for the DMTP command processor.
 * @note	This function will quit gracefully if there is an error or violation condition, or continue processing user input otherwise.
 * @param	con		the DMTP connection object dispatched for processing.
 * @return	This function returns no value.
 */
void dmtp_srv_requeue(connection_t *con) {

	if (!status() || con_status(con) < 0 || con->protocol.violations > con->server->violations.cutoff) {
		enqueue(&dmtp_srv_quit, con);
	}
	else {
		enqueue(&dmtp_srv_process, con);
	}

	return;
}

/**
 * @brief	If possible, fall back into SMTP mode from DMTP when an SMTP command has been issued by a client.
 * @param	con		the client connection issuing the DMTP command.
 * @return	This function returns no value.
 */
void dmtp_srv_do_fallback(connection_t *con) {

	server_t *smtp_fallback = NULL;

	// In this case we can't fall back because we've established a DMTP session with the DMTP-style STARTTLS command.
	if (con->dmtp.no_fallback) {
		log_pedantic("DMTP client issued legacy SMTP command but had established DMTP session.");
		requeue(&dmtp_srv_nofallback, &dmtp_srv_requeue, con);
		return;
	}

	// Make sure this action is allowed
	if (!magma.dmtp.dualmode) {
		log_pedantic("DMTP client issued legacy SMTP command but dual mode does not exist.");
		requeue(&dmtp_srv_nodual, &dmtp_srv_requeue, con);
		return;
	}

	// Otherwise, create a bridge with the SMTP protocol handler.
	//log_pedantic("DMTP client entered SMTP legacy mode.");
	con_increment_stats(con, "smtp.connections.total", "smtp.connections.secure");
	con_decrement_stats(con, "dmtp.connections.total", "dmtp.connections.secure");
	dmtp_srv_session_destroy(con);
	mm_wipe(&(con->dmtp), sizeof(sizeof(dmtp_srv_session_t)));
	mm_wipe(&(con->smtp), sizeof(sizeof(smtp_session_t)));

	for (uint32_t i = 0; i < MAGMA_SERVER_INSTANCES; i++) {

		// TODO: This should probably also be a sanity check at startup
		if (magma.servers[i] && magma.servers[i]->protocol == SMTP && magma.servers[i]->network.ipv6 == con->server->network.ipv6 &&
			magma.servers[i]->network.type == con->server->network.type) {
			smtp_fallback = magma.servers[i];
			break;
		}

	}

	if (!smtp_fallback) {
		con_print(con, "421 %.*s SMTP SERVICE CONFIGURATION ERROR\r\n", st_length_int(con->server->domain), st_char_get(con->server->domain));
		enqueue(&dmtp_srv_quit, con);
	}
	else {
		con->server = smtp_fallback;
		smtp_dispatch_command(con);
	}

	return;
}

/**
 * @brief	The main entry point in the DMTP server for processing commands issued by clients.
 * @param	con		the client connection issuing the DMTP command.
 * @return	This function returns no value.
 */
void dmtp_srv_process(connection_t *con) {

	command_t *command, client = { .function = NULL };
	//server_t *smtp_fallback = NULL;
	bool dmtp_command = true;

	// QUESTION: Is this the only comparison?
	if (con_read_line(con, false) < 0) {
		con->command = NULL;
		enqueue(&dmtp_srv_quit, con);
		return;
	}
	else if (pl_empty(con->network.line) && ((con->protocol.spins++) + con->protocol.violations) > con->server->violations.cutoff) {
		con->command = NULL;
		enqueue(&dmtp_srv_quit, con);
		return;
	}
	else if (pl_empty(con->network.line)) {
		con->command = NULL;
		enqueue(&dmtp_srv_process, con);
		return;
	}

	client.string = pl_char_get(con->network.line);
	client.length = pl_length_get(con->network.line);

	if ((command = bsearch(&client, dmtp_commands, sizeof(dmtp_commands) / sizeof(dmtp_commands[0]), sizeof(command_t), cmd_compare))) {
		con->command = command;
		con->protocol.spins = 0;

		// The EHLO command is a special case.
		if ((command->function == &dmtp_srv_ehlo) && !st_search_chr(&(con->network.line), '>', NULL) && !st_search_chr(&(con->network.line), '<', NULL)) {
		//if ((command->function == &dmtp_srv_ehlo) && st_search_chr(&(con->network.line), '@', NULL)) {
			//printf("xxx: trying EHLO\n");
			dmtp_srv_do_fallback(con);
		}
		// Otherwise only the QUIT, MODE and STARTTLS commands are allowed without secure transport outside of dual mode.
		else if (command->function != &dmtp_srv_quit && command->function != &dmtp_srv_mode && command->function != &dmtp_srv_starttls && con_secure(con) != 1) {

			// If DMTP only, we need TLS for any other command.
			if (!magma.dmtp.dualmode) {
				requeue(&dmtp_srv_needstls, &dmtp_srv_requeue, con);
			}
			//
			else if (dmtp_command) {
				requeue(&dmtp_srv_needstls, &dmtp_srv_requeue, con);
			} else {
				con->dmtp.fallback = true;
			}

		} else if (/*command->function == &dmtp_data || */command->function == &dmtp_srv_quit) {
			enqueue(command->function, con);
		}
		else {
			requeue(command->function, &dmtp_srv_requeue, con);
		}
	}
	else {

		// If we didn't find the command and we're in fallback, or we're not using TLS, it must be an SMTP legacy mode request.
		if (con->dmtp.fallback || con_secure(con) != 1) {

			// Is that allowed?
			/*if (!magma.dmtp.dualmode) {
				requeue(&dmtp_nodual, &dmtp_srv_requeue, con);
			}
			// Otherwise, create a bridge with the SMTP protocol handler, but only if it is an SMTP command.
			else*/ if (smtp_match_command(con)) {
				dmtp_srv_do_fallback(con);
				/*con_print(con, "250-%.*s SMTP LEGACY MODE INITIATED\r\n", st_length_int(con->server->domain), st_char_get(con->server->domain));
				con_increment_stats(con, "smtp.connections.total", "smtp.connections.secure");
				con_decrement_stats(con, "dmtp.connections.total", "dmtp.connections.secure");
				dmtp_session_destroy(con);

				for (uint32_t i = 0; i < MAGMA_SERVER_INSTANCES; i++) {

					// TODO: This should probably also be a sanity check at startup
					if (magma.servers[i] && magma.servers[i]->protocol == SMTP && magma.servers[i]->network.ipv6 == con->server->network.ipv6 &&
						magma.servers[i]->network.type == con->server->network.type) {
						smtp_fallback = magma.servers[i];
						break;
					}

				}

				if (!smtp_fallback) {
					con_print(con, "421 %.*s SMTP SERVICE CONFIGURATION ERROR\r\n", st_length_int(con->server->domain), st_char_get(con->server->domain));
					enqueue(&dmtp_srv_quit, con);
				}
				else {
					con->server = smtp_fallback;
					smtp_dispatch_command(con);
				}*/

			}
			else {
				con->command = NULL;
				requeue(&dmtp_srv_invalid, &dmtp_srv_requeue, con);
			}

		} else {
			con->command = NULL;
			requeue(&dmtp_srv_invalid, &dmtp_srv_requeue, con);
		}

	}

	return;
}
