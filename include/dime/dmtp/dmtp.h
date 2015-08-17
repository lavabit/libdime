#ifndef DIME_DMTP_DMTP_H
#define DIME_DMTP_DMTP_H

#include "sds.h"
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

typedef struct {
    unsigned int attempts_standard;     // Number of standard connection attempts to be made. (If < 3, then up to 3 will be perfomed.)
    unsigned int attempts_dual;         // Number of dual mode connection attempts to be made. (If < 3, then up to 3 will be perfomed.)
    int try_aux_port;                   // Should we try the DMTP_PORT_DUAL_AUX port (587)
    int force_family;                   // Should we try to force particular IP address family (AF_INET or AF_INET6)
} dmtp_client_config_t;


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



dmtp_client_config_t * dime_dmtp_client_config_create(unsigned int attempts_standard, unsigned int attempts_dual, int try_aux_port, int force_family);
void                   dime_dmtp_client_config_destroy(dmtp_client_config_t *config);
dmtp_session_t *       dime_dmtp_client_connect(dmtp_client_connfig_t *config, sds domain, dime_record_t *record);
dmtp_response_t *      dime_dmtp_client_recv_response(dmtp_session_t *session);
sds                    dime_dmtp_client_send_starttls(dmtp_session_t *session, sds host, dmtp_mode_type_t mode);
sds                    dime_dmtp_client_send_helo(dmtp_session_t *session, sds host);
sds				       dime_dmtp_client_send_ehlo(dmtp_session_t *session, sds host);
sds                    dime_dmtp_client_send_mode(dmtp_session_t *session);
sds				       dime_dmtp_client_send_rset(dmtp_session_t *session);
sds				       dime_dmtp_client_send_noop(dmtp_session_t *session, sds arg1, sds arg2, sds arg3);
sds				       dime_dmtp_client_send_help(dmtp_session_t *session);
sds				       dime_dmtp_client_send_quit(dmtp_session_t *session);
sds				       dime_dmtp_client_send_mail(dmtp_session_t *session, sds from, sds fingerprint);
sds				       dime_dmtp_client_send_rcpt(dmtp_session_t *session, sds to, sds fingerprint);
sds				       dime_dmtp_client_send_data(dmtp_session_t *session);
sds				       dime_dmtp_client_send_sgnt_user(dmtp_session_t *session, sds address, sds fingerprint);
sds				       dime_dmtp_client_send_sgnt_domain(dmtp_session_t *session, sds domain, sds fingerprint);
sds				       dime_dmtp_client_send_hist(dmtp_session_t *session, sds address, sds start, sds stop);
sds				       dime_dmtp_client_send_vrfy_user(dmtp_session_t *session, sds address, sds fingerprint);
sds				       dime_dmtp_client_send_vrfy_domain(dmtp_session_t *session, sds host, sds fingerprint);


// High-level interfaces built on DMTP.
PUBLIC_FUNC_DECL(signet_t *,       get_signet,            const char *name, const char *fingerprint, int use_cache);

// General session control routines.
PUBLIC_FUNC_DECL(dmtp_session_t *, dmtp_connect,          const char *domain, int force_family);
PUBLIC_FUNC_DECL(void,             destroy_dmtp_session,  dmtp_session_t *session);
PUBLIC_FUNC_DECL(dmtp_session_t *, dx_connect_standard,   const char *host, const char *domain, int force_family, dime_record_t *dimerec);
PUBLIC_FUNC_DECL(dmtp_session_t *, dx_connect_dual,       const char *host, const char *domain, int force_family, dime_record_t *dimerec, int failover);
PUBLIC_FUNC_DECL(int,              verify_dx_certificate, dmtp_session_t *session);

// Message flow.
PUBLIC_FUNC_DECL(int,              dmtp_ehlo,             dmtp_session_t *session, const char *domain);
PUBLIC_FUNC_DECL(int,              dmtp_mail_from,        dmtp_session_t *session, const char *origin, size_t msgsize, dmtp_mail_rettype_t rettype, dmtp_mail_datatype_t dtype);
PUBLIC_FUNC_DECL(int,              dmtp_rcpt_to,          dmtp_session_t *session, const char *domain);
PUBLIC_FUNC_DECL(char *,           dmtp_data,             dmtp_session_t *session, void *msg, size_t msglen);

// DMTP-protocol specific client commands.
PUBLIC_FUNC_DECL(char *,           dmtp_get_signet,       dmtp_session_t *session, const char *signame, const char *fingerprint);
PUBLIC_FUNC_DECL(int,              dmtp_verify_signet,    dmtp_session_t *session, const char *signame, const char *fingerprint, char **newprint);
PUBLIC_FUNC_DECL(char *,           dmtp_history,          dmtp_session_t *session, const char *signame, const char *startfp, const char *endfp);
PUBLIC_FUNC_DECL(char *,           dmtp_stats,            dmtp_session_t *session, const unsigned char *secret);

// Dual mode/SMTP helper commands.
PUBLIC_FUNC_DECL(dmtp_mode_t,      dmtp_str_to_mode,      const char *modestr);
PUBLIC_FUNC_DECL(dmtp_mode_t,      dmtp_get_mode,         dmtp_session_t *session);
PUBLIC_FUNC_DECL(int,              dmtp_noop,             dmtp_session_t *session);
PUBLIC_FUNC_DECL(int,              dmtp_reset,            dmtp_session_t *session);
PUBLIC_FUNC_DECL(char *,           dmtp_help,             dmtp_session_t *session);
PUBLIC_FUNC_DECL(int,              dmtp_quit,             dmtp_session_t *session, int do_close);




// Internal network and parsing functions.
char *      _read_dmtp_line(dmtp_session_t *session, int *overflow, unsigned short *rcode, int *multiline);
char *      _read_dmtp_multiline(dmtp_session_t *session, int *overflow, unsigned short *rcode);
char *      _parse_line_code(const char *line, unsigned short *rcode, int *multiline);
dmtp_mode_t _dmtp_str_to_mode(const char *modestr);
dmtp_mode_t _dmtp_initiate_starttls(dmtp_session_t *session, const char *dxname);
int         _dmtp_expect_banner(dmtp_session_t *session);
int         _dmtp_issue_command(dmtp_session_t *session, const char *cmd);
char *      _dmtp_send_and_read(dmtp_session_t *session, const char *cmd, unsigned short *rcode);
int         _dmtp_write_data(dmtp_session_t *session, const void *buf, size_t buflen);

#endif
