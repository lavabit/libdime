#ifndef DIME_DMTP_NETWORK_H
#define DIME_DMTP_NETWORK_H

#include "sds.h"
#include "dime/dmrecord/mrec.h"
#include "dime/dmtp/commands.h"
#include "dime/dmtp/responses.h"

#define DMTP_PORT           26
#define DMTP_PORT_DUAL      25
#define DMTP_PORT_DUAL_AUX  587

#define DMTP_V1_CIPHER_LIST "ECDHE-RSA-AES256-GCM-SHA384"

#define DMTP_MAX_MX_RETRIES 3

#define DMTP_LINE_BUF_SIZE 4096


typedef enum {
    dmtp_mode_unknown = 0,
    dmtp_mode_dual = 1,
    dmtp_mode_dmtp = 2,
    dmtp_mode_smtp = 3,
    dmtp_mode_esmtp = 4
} dmtp_mode_t;


typedef struct {
    char *domain;           ///< The name of the dark domain underlying the DMTP connection.
    char *dx;               ///< The canonical name of the DX that we're connected to.
    SSL *con;               ///< The handle to this DMTP session's underlying SSL connection.
    dime_record_t *drec;    ///< The DIME management record associated with this dark domain.
    dmtp_mode_t mode;       ///< The current mode of this connection (if made through dual mode).
    unsigned int active;    ///< Boolean flag: whether or not this session is active.

    int _fd;
    unsigned char _inbuf[DMTP_LINE_BUF_SIZE + 1];
    size_t _inpos;
} dmtp_session_t;

void             dime_dmtp_session_destroy(dmtp_session_t *session);
dmtp_session_t * dime_dmtp_session_connect_dual(sds host, unsigned short port, int force_family);
dmtp_session_t * dime_dmtp_session_connect_standard(sds host, int force_family);
sds *            dime_dmtp_session_recv(dmtp_session_t *session);
int              dime_dmtp_session_send(dmtp_session_t *session, sds line);
sds              dime_dmtp_session_dual_starttls(dmtp_session_t *session, sds host, dmtp_mode_type_t mode);


#endif
