
/**
 * @file /magma/servers/dmap/commands.h
 *
 * @brief	The data structure involved with parsing and routing DMAP commands.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#ifndef MAGMA_SERVERS_DMAP_COMMANDS_H
#define MAGMA_SERVERS_DMAP_COMMANDS_H

command_t dmap_commands[] = {
	{ .string = "LOGOUT",     .length = 6,  .function = &dmap_logout, .noparams = true },
	{ .string = "NOOP",       .length = 4,  .function = &dmap_noop, .noparams = true },
	{ .string = "CAPABILITY", .length = 10, .function = &dmap_capability, .noparams = true },
	{ .string = "STARTTLS",   .length = 8,  .function = &dmap_starttls, .noparams = true },
	{ .string = "SELECT",     .length = 6,  .function = &dmap_invalid },
	{ .string = "LOGIN",      .length = 5,  .function = &dmap_login },
	{ .string = "AUTH",       .length = 4,  .function = &dmap_auth },
	{ .string = "LIST",       .length = 4,  .function = &dmap_list },
	{ .string = "FETCH",      .length = 5,  .function = &dmap_fetch },
	{ .string = "SUBMIT",     .length = 6,  .function = &dmap_submit },
	{ .string = "SSR",        .length = 3,  .function = &dmap_ssr },

};

#endif
