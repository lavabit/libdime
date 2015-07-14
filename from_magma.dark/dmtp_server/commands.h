
/**
 * @file /magma/servers/dmtp/commands.h
 *
 * @brief	The data structure involved with parsing and routing DMTP commands.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#ifndef MAGMA_SERVERS_DMTP_COMMANDS_H
#define MAGMA_SERVERS_DMTP_COMMANDS_H

command_t dmtp_commands[] = {
	{ .string = "STARTTLS",   .length = 8, .function = &dmtp_srv_starttls,
		.help = "Negotiate a TLS session using the syntax STARTTLS <domain.tld>" },
	{ .string = "EHLO",       .length = 4, .function = &dmtp_srv_ehlo,
		.help = "Identify the sending domain using the syntax EHLO <domain.tld>"},
	{ .string = "MAIL FROM",  .length = 9, .function = &dmtp_srv_mail_from,
		.help = "Specify a dmail sender using the syntax MAIL FROM <user@domain.tld>"},
	{ .string = "RCPT TO",    .length = 7, .function = &dmtp_srv_rcpt_to,
		.help = "Specify a dmail recipient using the syntax RCPT TO <user@domain.tld>"},
	{ .string = "DATA",       .length = 4, .function = &dmtp_srv_data,
		.help = "Specify the contents of a dmail message using the syntax DATA"},
	{ .string = "SGNT",       .length = 4, .function = &dmtp_srv_sgnt,
		.help = "Look up a signet for a user or domain using the syntax SGNT <[user@]domain.tld> [fingerprint]"},
	{ .string = "HIST",       .length = 4, .function = &dmtp_srv_hist,
		.help = "Retrieve the key chain history for a user or domain between two version of a certificate using the syntax HIST <[user@]domain.tld> [start fingerprint] [end fingerprint]"},
	{ .string = "STATS",       .length = 5, .function = &dmtp_srv_stats,
		.help = "Request system statistics"},
	{ .string = "VRFY",       .length = 4, .function = &dmtp_srv_vrfy,
		.help = "Verify that the fingerprint of a given user or domain certificate is current using the syntax VRFY <[user@]domain.tld> <fingerprint>"},
	{ .string = "HELP",       .length = 4, .function = &dmtp_srv_help,
		.help = "Get help for a specific command using the syntax HELP [command]"},
	{ .string = "RSET",       .length = 4, .function = &dmtp_srv_rset, .noparams = true,
		.help = "Reset the dmtp connection state."},
	{ .string = "NOOP",       .length = 4, .function = &dmtp_srv_noop, .noparams = true,
		.help = "Perform a no-operation."},
	{ .string = "VERB",       .length = 4, .function = &dmtp_srv_verb, .noparams = true,
		.help = "Put the dmtp server into verbose mode."},
	{ .string = "MODE",       .length = 4, .function = &dmtp_srv_mode, .noparams = true,
		.help = "Query the current mode of the mail server."},
	{ .string = "QUIT",       .length = 4, .function = &dmtp_srv_quit, .noparams = true,
		.help = "End this dmtp session."}
};
const size_t dmtp_num_cmds = sizeof(dmtp_commands)/sizeof(command_t);

#endif
