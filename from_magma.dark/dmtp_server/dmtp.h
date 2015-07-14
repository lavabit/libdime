
/**
 * @file /magma/servers/dmtp/dmtp.h
 *
 * @brief	The entry point for the DMTP server module.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#ifndef MAGMA_SERVERS_DMTP_H
#define MAGMA_SERVERS_DMTP_H

/// commands.c
void    dmtp_srv_sort(void);
void    dmtp_srv_requeue(connection_t *con);
void    dmtp_srv_do_fallback(connection_t *con);
void    dmtp_srv_process(connection_t *con);

/// dmtp.c
void    dmtp_srv_init(connection_t *con);
void    dmtp_srv_quit(connection_t *con);
void    dmtp_srv_invalid(connection_t *con);
void    dmtp_srv_needstls(connection_t *con);
void    dmtp_srv_nofallback(connection_t *con);
void    dmtp_srv_nodual(connection_t *con);
void    dmtp_srv_starttls(connection_t *con);
void    dmtp_srv_mail_from(connection_t *con);
void    dmtp_srv_rcpt_to(connection_t *con);
void    dmtp_srv_data(connection_t *con);
void    dmtp_srv_sgnt(connection_t *con);
void    dmtp_srv_hist(connection_t *con);
void    dmtp_srv_stats(connection_t *con);
void    dmtp_srv_vrfy(connection_t *con);
void    dmtp_srv_help(connection_t *con);
void    dmtp_srv_rset(connection_t *con);
void    dmtp_srv_noop(connection_t *con);
void    dmtp_srv_verb(connection_t *con);
void    dmtp_srv_mode(connection_t *con);
void    dmtp_srv_quit(connection_t *con);
void    dmtp_srv_ehlo(connection_t *con);
stringer_t * dmtp_read_raw_data(connection_t *con, size_t expected);

// parse.c
bool_t  dmtp_is_valid_domain(stringer_t *domain);
bool_t  dmtp_is_valid_address(stringer_t *address);

/// sessions.c
void    dmtp_srv_session_reset(connection_t *con);
void    dmtp_srv_session_destroy(connection_t *con);

#endif
