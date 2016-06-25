#include "dime/dmtp/network.h"


static void  dmtp_session_destroy(dmtp_session_t *session);
static sds * dmtp_session_recv(dmtp_session_t *session);
static int   dmtp_session_send(dmtp_session_t *session, sds line);


/**
 * @brief
 * Destroy a dmtp session.
 * @param session
 * Session to be destroyed
*/
static void
dmtp_session_destroy(
    dmtp_session_t *session)
{

    if(session) {

        sdsfree(session->dx);

        if (session->con) {
            _ssl_disconnect(session->con);
        }

        free(session);
    }

}


/**
 * @brief
 * Receive a buffer from the server we have a session with.
 * @param session
 * DMTP session.
 * @return
 * NULL terminated array of sds strings containing one or multiple response
 * lines.
*/
static sds *
dmtp_session_recv(
    dmtp_session_t *session)
{

}


/**
 * @brief
 * Send a buffer to the server connected to in the session.
 * @param session
 * Session with a dmtp server.
 * @param line
 * sds string containing the buffer to be sent.
 * @return
 * 0 on success, -1 on failure.
*/
static int
dmtp_session_send(
    dmtp_session_t *session,
    sds line)
{

}


/**
 * @brief
 * Destroy a dmtp session.
 * @param session
 * Session to be destroyed
*/
void
dime_dmtp_session_destroy(
    dmtp_session_t *session)
{
    PUBLIC_FUNCTION_IMPLEMENT(
        dmtp_session_destroy,
        session);
}

/**
 * @brief
 * Attempt a DMTP dual connection.
 * @param host
 * Hostname of the DMTP server to which we want to connect to.
 * @param port
 * Port we want to connect to (DMTP_PORT_DUAL or DMTP_PORT_DUAL_AUX)
 * @param force_family
 * An optional address family (AF_INET or AF_INET6) to force the TCP connection to take.
 * @return
 * Pointer to dmtp session struct on success, NULL on failure.
 * @free_using
 * dime_dmtp_session_destroy()
*/
dmtp_session_t * dime_dmtp_session_connect_dual(
    sds host,
    unsigned short port,
    int force_family)
{

    dmtp_session_t *result;
    int fd;

    if(!host) {
        PUSH_ERROR(ERR_BAD_PARAM, NULL);
        goto error;
    }

    if((port != DMTP_PORT_DUAL) && (port != DMTP_PORT_DUAL_AUX)) {
        PUSH_ERROR(ERR_BAD_PARAM, NULL);
        goto error;
    }

    // Connect to the remote end and set up a stub DMTP session.
    if ((fd = _connect_host(host, port, force_family)) < 0) {
        PUSH_ERROR(ERR_UNSPEC, "unable to connect to dual mode DMTP server  at %s:%u", host, port);
        goto error;
    }

    if (!(result = malloc(sizeof(dmtp_session_t)))) {
        PUSH_ERROR_SYSCALL("malloc");
        PUSH_ERROR(ERR_NOMEM, "could not establish DMTP session because of memory allocation problem");
        goto cleanup_fd;
    }

    memset(result, 0, sizeof(dmtp_session_t));
    result->_fd = fd;
    result->mode = dmtp_mode_dual;
    result->active = 1;

    if(!(result->dx = sdsdup(host))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to copy sds containing dmtp hostname");
        goto cleanup_result;
    }

    return result;

cleanup_result;
    dmtp_session_destroy(result);
cleanup_fd:
    close(fd);
error:
    return NULL;
}


/**
 * @brief
 * Attempt a DMTP standard conection.
 * @param host
 * Hostname of the DMTP server to which we want to connect to.
 * @param force_family
 * An optional address family (AF_INET or AF_INET6) to force the TCP connection to take.
 * @return
 * Pointer to dmtp session struct on success, NULL on failure.
 * @free_using
 * dime_dmtp_session_destroy()
*/
dmtp_session_t *
dime_dmtp_session_connect_standard(
    sds host,
    int force_family)
{

    dmtp_session_t *result;
    SSL *connection;

    if(!host) {
        PUSH_ERROR(ERR_BAD_PARAM, NULL);
        goto error;
    }

    if (!(connection = _ssl_connect_host(host, DMTP_PORT, force_family))) {
        PUSH_ERROR(ERR_UNSPEC, "could not establish standard DMTP connection to host");
        goto error;
    }

    if (!(result = malloc(sizeof(dmtp_session_t)))) {
        PUSH_ERROR_SYSCALL("malloc");
        PUSH_ERROR(ERR_NOMEM, "could not establish DMTP session because of memory allocation problem");
        goto cleanup_connection;
    }

    memset(result, 0, sizeof(dmtp_session_t));
    result->con = connection;
    result->mode = dmtp_mode_dmtp;
    result->_fd = -1;

    if(!(result->dx = sdsdup(host))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to copy sds containing dmtp server hostname");
        goto cleanup_result;
    }

    return result;

cleanup_result:
    dmtp_session_destroy(result);
cleanup_connection:
    _ssl_disconnect(connection);
error:
    return NULL;
}



/**
 * @brief
 * Send dmtp starttls command.
 * @param session
 * Connection to a dmtp server.
 * @param host
 * string containing host name.
 * @param mode
 * optional server mode parameter.
 * @return
 * 0 on success, -1 on failure.
*/
int
dime_dmtp_session_dual_starttls(
    dmtp_session_t *session,
    sds host,
    dmtp_mode_t mode)
{

    sds command;

    PUBLIC_FUNC_PROLOGUE();

    if(!(command = dime_dmtp_command_starttls(host, mode))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to format starttls command");
        goto error;
    }

    if(dmtp_session_send(session, command) < 0) {
        PUSH_ERROR(ERR_UNSPEC, "unable to issue DMTP command");
        goto error;
    }

    return 0;

error:
    return -1;
}


/**
 * @brief
 * Receive a buffer from the server we have a session with.
 * @param session
 * DMTP session.
 * @return
 * NULL terminated array of sds strings containing one or multiple response
 * lines.
*/
sds *
dime_dmtp_session_recv(
    dmtp_session_t *session)
{
    PUBLIC_FUNCTION_IMPLEMENT(
        dmtp_session_recv,
        session);
}


/**
 * @brief
 * Send a buffer to the server connected to in the session.
 * @param session
 * Session with a dmtp server.
 * @param line
 * sds string containing the buffer to be sent.
 * @return
 * 0 on success, -1 on failure.
*/
int
dime_dmtp_session_send(
    dmtp_session_t *session,
    sds line)
{
    PUBLIC_FUNCTION_IMPLEMENT(
        dmtp_session_send,
        session,
        line);
}


