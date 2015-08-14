#include "dime/dmtp/network.h"


/**
 * @brief
 * Establish a DMTP connection to the DX server of a provided dark domain.
 * @note
 * This function automatically queries the DIME management record of the domain to determine the appropriate
 * way to establish a connection to the domain's DX server. This is the function that should be used by all general callers.
 * @param domain
 * a null-terminated string containing the specified dark domain.
 * @param force_family
 * an optional address family (AF_INET or AF_INET6) to force the TCP connection to take.
 * @return
 * NULL if unable to establish a DMTP connection successfully, or a pointer to the DMTP session on success.
 */
dmtp_session_t *dime_dmtp_session_create(const char *domain, int force_family) {

    dmtp_session_t *result = NULL;
    dime_record_t *drec;
    mx_record_t **mxs, **mxptr;
    unsigned long ttl;
    char **dxptr;

    if (!domain) {
        RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
    }

    if (!(drec = _get_dime_record(domain, &ttl, 1))) {
        RET_ERROR_PTR(ERR_UNSPEC, "DIME management record could not be retrieved");
    }

    // We only continue if DNSSEC validation succeeded, or DNSSEC was not in place at all.
    // DNSSEC signature failure, on the other hand, is a fatal error.
    if (drec->validated < 0) {
        _destroy_dime_record(drec);
        RET_ERROR_PTR(ERR_UNSPEC, "could not establish DMTP connection to host: DIME management record DNSSEC signature was invalid");
    }

    // There are 3 possible ways this will turn out.
    // 1. The DIME management record has a dx field and we will connect to this server on the standard DMTP port.
    // 2. There is no dx field but the domain has an MX record. We will attempt to connect to this host first
    //    over standard DMTP, and then fall back to dual mode on the SMTP port if unsuccessful.
    // 3. There is no DX field or MX record for the domain. We make an attempt to connect to the standard DMTP port.

    // Case 1: Our record has a DX field.
    if (drec->dx) {
        size_t i = 1;
        dxptr = drec->dx;

        /* We must try each possible DX server in order. */
        while (*dxptr) {
            _dbgprint(1, "Attempting DMTP connection to DIME record-supplied DX server #%u at %s:%u ...\n", i, *dxptr, DMTP_PORT);

            if ((result = _dx_connect_standard(*dxptr, domain, force_family, drec))) {
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
}
