
/**
 * @file /magma/servers/dmap/dmap.h
 *
 * @brief	The entry point for the DMAP server module.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#ifndef MAGMA_SERVERS_DMAP_H
#define MAGMA_SERVERS_DMAP_H

/// commands.c
void    dmap_sort(void);
void    dmap_requeue(connection_t *con);
void    dmap_process(connection_t *con);

/// dmap.c
void   dmap_init(connection_t *con);
void   dmap_logout(connection_t *con);
void   dmap_invalid(connection_t *con);
void   dmap_login(connection_t *con);
void   dmap_starttls(connection_t *con);
void   dmap_noop(connection_t *con);
void   dmap_capability(connection_t *con);
void   dmap_auth(connection_t *con);
void   dmap_list(connection_t *con);
void   dmap_submit(connection_t *con);
void   dmap_fetch(connection_t *con);
void   dmap_ssr(connection_t *con);
stringer_t * dmap_read_raw_data(connection_t *con, size_t expected);

/// parse.c
int_t dmap_command_parser(connection_t *con);

/// sessions.c
void   dmap_session_destroy(connection_t *con);

#endif
