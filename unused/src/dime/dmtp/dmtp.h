#ifndef DIME_DMTP_DMTP_H
#define DIME_DMTP_DMTP_H

#include "dime/sds/sds.h" 
#include "dime/dmtp/commands.h"
#include "dime/dmtp/responses.h"
#include "dime/dmtp/network.h"
#include "dime/signet/signet.h"
#include "dime/signet-resolver/mrec.h"
#include "dime/common/error.h"
#include "dime/signet-resolver/signet-ssl.h"


#define DMTP_PORT      26
#define DMTP_PORT_DUAL 25

#define DMTP_V1_CIPHER_LIST "ECDHE-RSA-AES256-GCM-SHA384"

#define DMTP_MAX_MX_RETRIES 3

#define DMTP_LINE_BUF_SIZE 4096


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



/** TODO FIXME this stuff is better left to the implementation.
// connection configuration structure
typedef struct {
    unsigned int attempts_standard;     // Number of standard connection attempts to be made. (If < 3, then up to 3 will be perfomed.)
    unsigned int attempts_dual;         // Number of dual mode connection attempts to be made. (If < 3, then up to 3 will be perfomed.)
    int aux_port;                       // Should we try the DMTP_PORT_DUAL_AUX port (587)
    int use_domain;                     // If all else failed, should we try connecting to the target domain itself.
    int force_family;                   // Should we try to force particular IP address family (AF_INET or AF_INET6)
} dmtp_client_connect_config_t;

// signet retrieval configuration structure
typedef struct {
    int place_holder;
} dmtp_client_signet_config_t;

// mail transfer configuration structure
typedef struct {
    int place_holder;
} dmtp_client_mail_config_t;

// global dmtp configuration structure
typedef struct {
    dmtp_client_connect_config_t connect;
    dmtp_client_signet_config_t signet;
    dmtp_client_mail_config_t mail;
} dmtp_client_config_t;


dmtp_client_config_t * dime_dmtp_client_config_create(unsigned int attempts_standard, unsigned int attempts_dual, int aux_port, int use_domain, int force_family);
void                   dime_dmtp_client_config_destroy(dmtp_client_config_t *config);

*/


dmtp_response_t *      dime_dmtp_client_recv_response(dmtp_session_t *session);
int                    dime_dmtp_client_send_helo(dmtp_session_t *session, sds host);
int				       dime_dmtp_client_send_ehlo(dmtp_session_t *session, sds host);
int                    dime_dmtp_client_send_mode(dmtp_session_t *session);
int				       dime_dmtp_client_send_rset(dmtp_session_t *session);
int				       dime_dmtp_client_send_noop(dmtp_session_t *session, sds arg1, sds arg2, sds arg3);
int				       dime_dmtp_client_send_help(dmtp_session_t *session);
int				       dime_dmtp_client_send_quit(dmtp_session_t *session);
int				       dime_dmtp_client_send_mail(dmtp_session_t *session, sds from, sds fingerprint);
int				       dime_dmtp_client_send_rcpt(dmtp_session_t *session, sds to, sds fingerprint);
int				       dime_dmtp_client_send_data(dmtp_session_t *session);
int				       dime_dmtp_client_send_sgnt_user(dmtp_session_t *session, sds address, sds fingerprint);
int				       dime_dmtp_client_send_sgnt_domain(dmtp_session_t *session, sds domain, sds fingerprint);
int				       dime_dmtp_client_send_hist(dmtp_session_t *session, sds address, sds start, sds stop);
int				       dime_dmtp_client_send_vrfy_user(dmtp_session_t *session, sds address, sds fingerprint);
int				       dime_dmtp_client_send_vrfy_domain(dmtp_session_t *session, sds host, sds fingerprint);


#endif
