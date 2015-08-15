#include "dime/dmtp/network.h"


/**
 * @brief   Establish (force) a DMTP connection to a specified DX server on tcp port 26/ssl.
 * @note    This function should only be called externally with care.
 * @param   host        the hostname of the DX server to which the DMTP connection will be established.
 * @param   domain      the dark domain which the DX server is servicing.
 * @param   force_family    an optional address family (AF_INET or AF_INET6) to force the TCP connection to take.
 * @param   dimerec     an optional pointer to a DIME management record to be attached to the session.
 * @return  NULL on failure, or a pointer to a newly established DMTP session on success.
 */
dmtp_session_t * dime_dmtp_session_standard_create(const char *host, const char *domain, int force_family, dime_record_t *dimerec) {

    dmtp_session_t *result;
    SSL *connection;

    if (!host || !domain) {
        RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
    }

    if (!(connection = _ssl_connect_host(host, DMTP_PORT, force_family))) {
        RET_ERROR_PTR(ERR_UNSPEC, "could not establish standard DMTP connection to host");
    }

    if (!(result = malloc(sizeof(dmtp_session_t)))) {
        PUSH_ERROR_SYSCALL("malloc");
        _ssl_disconnect(connection);
        RET_ERROR_PTR(ERR_NOMEM, "could not establish DMTP session because of memory allocation problem");
    }

    memset(result, 0, sizeof(dmtp_session_t));
    result->con = connection;
    result->mode = dmtp_mode_dmtp;
    result->_fd = -1;
    result->drec = dimerec;

    if ((!(result->domain = strdup(domain))) || (!(result->dx = strdup(host)))) {
        PUSH_ERROR_SYSCALL("strdup");
        _destroy_dmtp_session(result);
        RET_ERROR_PTR(ERR_NOMEM, "could not establish DMTP session because of memory allocation problem");
    }

    if (_dmtp_expect_banner(result) < 0) {
        _destroy_dmtp_session(result);
        RET_ERROR_PTR(ERR_UNSPEC, "received incompatible DMTP banner from server");
    }

    return result;
}


/**
 * @brief
 * Establish a DMTP connection to a specified DX server that is running DMTP in dual mode (port 25).
 * @note
 * This function should only be called externally with care.
 * @param host
 * the hostname of the DX server to which the DMTP connection will be established.
 * @param domain
 * the dark domain which the DX server is servicing.
 * @param force_family
 * an optional address family (AF_INET or AF_INET6) to force the TCP connection to take.
 * @param dimerec
 * an optional pointer to a DIME management record to be attached to the session.
 * @param port
 * Port to connect to via dual mode (either 25 or 587)
 * @return
 * NULL on failure, or a pointer to a newly established DMTP session on success.
 */
dmtp_session_t * dime_dmtp_session_dual_create(const char *host, const char *domain, int force_family, dime_record_t *dimerec, unsigned int port) {

    dmtp_session_t *result;
    int fd;

    if (!host || !domain) {
        RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
    }

    // Connect to the remote end and set up a stub DMTP session.
    if ((fd = _connect_host(host, DMTP_PORT_DUAL, force_family)) < 0) {

        if (failover) {
            _dbgprint(1, "Retrying unsuccessful dual mode connection on port 587 ...\n");
            fd = _connect_host(host, 587, force_family);
        }

        if (fd < 0) {
            RET_ERROR_PTR_FMT(ERR_UNSPEC, "unable to connect to dual mode DMTP server  at %s:%u", host, (failover ? 587 : DMTP_PORT_DUAL));
        }

    }

    if (!(result = malloc(sizeof(dmtp_session_t)))) {
        PUSH_ERROR_SYSCALL("malloc");
        close(fd);
        RET_ERROR_PTR(ERR_NOMEM, "could not establish DMTP session because of memory allocation problem");
    }

    memset(result, 0, sizeof(dmtp_session_t));
    result->_fd = fd;

    if ((!(result->domain = strdup(domain))) || (!(result->dx = strdup(host)))) {
        PUSH_ERROR_SYSCALL("strdup");
        _destroy_dmtp_session(result);
        RET_ERROR_PTR(ERR_NOMEM, "could not establish DMTP session because of memory allocation problem");
    }

    result->mode = dmtp_mode_dual;

    // Read in the DMTP banner and make sure everything is good.
    if (_dmtp_expect_banner(result) < 0) {
        _destroy_dmtp_session(result);
        RET_ERROR_PTR(ERR_UNSPEC, "received incompatible DMTP banner from server");
    }

    if (_dmtp_initiate_starttls(result, host) != dmtp_mode_dmtp) {
        _destroy_dmtp_session(result);
        RET_ERROR_PTR(ERR_UNSPEC, "failed to initiate TLS session over dual mode server");
    }

    result->active = 1;
    result->drec = dimerec;

    return result;
}




dmtp_session_t *
dime_dmtp_session_create(
    sds domain,
    dime_record_t *record,
    int force_family)
{

    char **dxptr;

    PUBLIC_FUNC_PROLOGUE();

    if(!domain) {
        PUSH_ERROR(ERR_BAD_PARAM, NULL);
        goto error;
    }

    if(!record) {
        PUSH_ERROR(ERR_BAD_PARAM, NULL);
        goto error;
    }

    if (record->validated < 0) {
        PUSH_ERROR(ERR_UNSPEC, "could not establish DMTP connection to host: DIME management record DNSSEC signature was invalid");
        goto error;
    }

    // There are 3 possible ways this will turn out.
    // 1. The DIME management record has a dx field and we will connect to this server on the standard DMTP port.
    // 2. There is no dx field but the domain has an MX record. We will attempt to connect to this host first
    //    over standard DMTP, and then fall back to dual mode on the SMTP port if unsuccessful.
    // 3. There is no DX field or MX record for the domain. We make an attempt to connect to the standard DMTP port.

    // Case 1: Our record has a DX field.
    if (record->dx) {
        size_t i = 1;
        dxptr = record->dx;

        /* We must try each possible DX server in order. */
        while (*dxptr) {
            _dbgprint(1, "Attempting DMTP connection to DIME record-supplied DX server #%u at %s:%u ...\n", i, *dxptr, DMTP_PORT);

            if ((result = _dx_connect_standard(*dxptr, domain, force_family, record))) {
                break;
            }

            dxptr++, i++;
        }

        // Case 2: There are MX record(s) for our domain.
    } else {

        if ((mxptr = mxs = _get_mx_records(domain))) {

            // Try a maximum of the first 3 MX records.
            for (int i = 0; (i < DMTP_MAX_MX_RETRIES) && *mxptr; i++, mxptr++) {
                _dbgprint(1, "Attempting DMTP connection to MX hostname at %s:%u [pref %u] ...\n", (*mxptr)->name, DMTP_PORT, (*mxptr)->pref);

                if (!(result = _dx_connect_standard((*mxptr)->name, domain, force_family, drec))) {
                    _dbgprint(1, "Re-attempting dual-mode DMTP connection to MX hostname at %s:%u ...\n", (*mxptr)->name, DMTP_PORT_DUAL);
                    result = _dx_connect_dual((*mxptr)->name, domain, force_family, drec, 1);
                }

                if (result) {
                    break;
                }

            }

            free(mxs);
        }

        // Case 3 (final): There is no DX field or MX record for this domain. We try a standard DMTP connection.
        // This is actually executed as failover from Case #2 if it completes unsuccessfully.
        if (!result) {
            _dbgprint(1, "Attempting DMTP connection to assumed DX server at %s:%u ...\n", domain, DMTP_PORT);
            result = _dx_connect_standard(domain, domain, force_family, drec);
        }

    }

    if (!result) {
        RET_ERROR_PTR(ERR_UNSPEC, "connection to DX server failed");
    }

    return result;


error:
    return NULL;
}


sds *
dime_dmtp_session_recv(
    dmtp_session_t *session)
{

    PUBLIC_FUNC_PROLOGUE();

    if(!session) {
        PUSH_ERROR(ERR_BAD_PARAM, NULL);
        goto error;
    }

error:
    return NULL;
}


int
dime_dmtp_session_send(
    dmtp_session_t *session,
    sds line)
{

    PUBLIC_FUNC_PROLOGUE();

    if(!session) {
        PUSH_ERROR(ERR_BAD_PARAM, NULL);
        goto error;
    }

    if(!line) {
        PUSH_ERROR(ERR_BAD_PARAM, NULL);
        goto error;
    }

error:
    return -1;
}


