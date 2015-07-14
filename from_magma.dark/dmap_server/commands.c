
/**
 * @file /magma/servers/dmap/commands.c
 *
 * @brief	The functions involved with parsing and routing DMAP commands.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#include "magma.h"
#include "commands.h"


/**
 * @brief	Sort the DMAP command table to be ready for binary searches.
 * @return	This function returns no value.
 */
void dmap_sort(void) {

	qsort(dmap_commands, sizeof(dmap_commands) / sizeof(dmap_commands[0]), sizeof(command_t), &cmd_compare);
	return;
}

/**
 * @brief	The re-entry point for the DMAP command processor.
 * @note	This function will quit gracefully if there is an error or violation condition, or continue processing user input otherwise.
 * @param	con		the DMAP connection object dispatched for processing.
 * @return	This function returns no value.
 */
void dmap_requeue(connection_t *con) {

	if (!status() || con_status(con) < 0 || con_status(con) == 2 || con->protocol.violations > con->server->violations.cutoff) {
		enqueue(&dmap_logout, con);
	}
	else {
		enqueue(&dmap_process, con);
	}

	return;
}

/**
 * @brief	The main entry point in the DMAP server for processing commands issued by clients.
 * @param	con		the client connection issuing the DMAP command.
 * @return	This function returns no value.
 */
void dmap_process(connection_t *con) {

	int_t state;
	command_t *command, client = { .function = NULL };

	// If the connection indicates an error occurred, or the socket was closed by the client we send the connection to the logout function.
	if (((state = con_read_line(con, false)) < 0) || (state == -2)) {
		con->command = NULL;
		enqueue(&dmap_logout, con);
		return;
	}
	else if (pl_empty(con->network.line) && ((con->protocol.spins++) + con->protocol.violations) > con->server->violations.cutoff) {
		con->command = NULL;
		enqueue(&dmap_logout, con);
		return;
	}
	else if (pl_empty(con->network.line)) {
		con->command = NULL;
		enqueue(&dmap_process, con);
		return;
	}

	// Parse the line into its tag and command elements.
	if ((state = dmap_command_parser(con)) < 0) {

		// Try to be helpful about the parsing error.
		if (state == -1) {
			con_write_bl(con, "* BAD Unable to parse the command tag.\r\n", 40);
		}
		else if (state == -2) {
			con_print(con, "%.*s BAD Unable to parse the command.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		}
		else {
			con_print(con, "%.*s BAD The command arguments were submitted using an invalid syntax.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		}

		// If the client keeps breaking rules drop them.
		if (((con->protocol.spins++) + con->protocol.violations) > con->server->violations.cutoff) {
			con->command = NULL;
			enqueue(&dmap_logout, con);
			return;
		}

		// Requeue and hope the next line of data is useful.
		con->command = NULL;
		enqueue(&dmap_process, con);
		return;

	}

	client.string = st_char_get(con->dmap.command);
	client.length = st_length_get(con->dmap.command);

	if ((command = bsearch(&client, dmap_commands, sizeof(dmap_commands) / sizeof(dmap_commands[0]), sizeof(command_t), cmd_compare))) {

		con->command = command;
		con->protocol.spins = 0;

		if (command->function == &dmap_logout) {
			enqueue(command->function, con);
		}
		else {
			requeue(command->function, &dmap_requeue, con);
		}
	}
	else {
		con->command = NULL;
		requeue(&dmap_invalid, &dmap_requeue, con);
	}

	return;
}

