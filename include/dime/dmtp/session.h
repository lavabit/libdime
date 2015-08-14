#ifndef DIME_DMTP_NETWORK_H
#define DIME_DMTP_NETWORK_H

#include "sds.h"
#include "dime/dmrecord/mrec.h"

#define DMTP_PORT      26
#define DMTP_PORT_DUAL 25

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


typedef enum {
    return_type_default = 0,
    return_type_full = 1,
    return_type_display = 2,
    return_type_header = 3
} dmtp_mail_rettype_t;

typedef enum {
    data_type_default = 0,
    data_type_7bit = 1,
    data_type_8bit = 2
} dmtp_mail_datatype_t;

int   dime_dmtp_session_send(dmtp_session_t *session, sds line);
sds * dime_dmtp_session_recv(dmtp_session_t *session);


#endif
