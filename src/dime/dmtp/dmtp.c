#include <openssl/x509v3.h>

#include "dime/signet-resolver/dmtp.h"
#include "dime/signet-resolver/cache.h"
#include "dime/signet-resolver/dns.h"
#include "dime/signet-resolver/mrec.h"

#include "dime/common/network.h"
#include "dime/common/misc.h"
#include "dime/common/error.h"


/**
 * @brief
 * Create a config structure to be used for connecting to DMTP a server.
 * @param attempts_standard
 * Maximum number of attempts in standard mode.
 * @param attempts_dual
 * Maximum number of attempts in dual mode.
 * @param try_aux_port
 * Should the auxillary port also be used to connect in dual mode.
 * @param force_family
 * Force connection to an IP address family (AF_INET or AF_INET6 or 0 to ignore);
 * @return
 * Pointer to a dmtp connection config structure, NULL on failure.
 * @free_using
 * dime_dmtp_client_config_destroy()
*/
dmtp_client_config_t *
dime_dmtp_client_config_create(
    unsigned int attempts_standard,
    unsigned int attempts_dual,
    int try_aux_port,
    int use_domain,
    int force_family)
{

    dmtp_client_config_t *result;

    PUBLIC_FUNC_PROLOGUE();

    if(!(result = malloc(sizeof(dmtp_client_config_t)))) {
        PUSH_ERROR_SYSCALL("malloc");
        PUSH_ERROR(ERR_NOMEM, "failed to allocate memory for dmtp config struct");
        goto error;
    }

    memset(result, 0, sizeof(dmtp_client_config_t));
    result->connect.attempts_standard = (attempts_standard > 3 ? attempts_standard : 3); 
    result->connect.attempts_dual = (attempts_dual > 3 ? attempts_dual : 3);
    result->connect.aux_port = aux_port;
    result->connect.use_domain = use_domain;
    result->connect.force_family = force_family;

error:
    return NULL;
}


/**
 * @brief
 * Destroy the connection config structure.
 * @param config
 * Pointer to the config structure to be destroyed.
*/
void
dime_dmtp_client_config_destroy(
    dmtp_client_config_t *config)
{

    PUBLIC_FUNC_PROLOGUE();

    if(config) {
        free(config);
    }

}


/**
 * @brief
 * Establish a dmtp connection with the specified domain.
 * @param config
 * Our client-config structure.
 * @param domain
 * sds string containing the target dmtp server domain name.
 * @return
 * A dmtp session on success, NULL on error.
 * @free_using
 * dime_dmtp_session_destroy()
*/
/* TODO FIXME this should go into implementation specific client code.
dmtp_session_t *
dime_dmtp_client_connect(
    dmtp_client_config_t *config,
    sds domain)
{

    dime_record_t *dx_rec;
    dmtp_session_t *result;
    mx_record_t **mx_rec;
    char *dx, *mx;
    size_t num_dx = 0, num_mx = 0, attempts, rnd;
    unsigned long ttl;

    if(!config) {
        PUSH_ERROR(ERR_BAD_PARAM, NULL);
        goto error;
    }

    if(!domain) {
        PUSH_ERROR(ERR_BAD_PARAM, NULL);
        goto error;
    }

    //First we need to try to retrieve the DX record.
    dx_rec = dime_mrec_record_lookup(domain, &ttl);

    //Now we attempt the correct number of DMTP connections using standard mode.
    if(dx_rec && (dx = dx_rec->dx)) {

        while(dx[num_dx]) {
            ++num_dx;
        }

        attempts = (num_dx > config->connect.attempts_standard ? config->connect.attempts_standard : num_dx);

        for(size_t i = 0; i < attempts; ++i) {
            rnd = (rand() % (num_dx - i));

            if((result = dmtp_session_standard_init(dx[rnd], domain, config->connect.force_family)) != NULL) {
                result->drec = dx_rec;
                break;
            }

            temp = dx[rnd];
            dx[rnd] = dx[i];
            dx[i] = temp;
        }

        free(track_attempts);
    }

    //If we either were not able to connect to the DMTP server using standard
    //mode, or we could not find the dx record we need to pull up the mx record.
    mx_rec = dime_dns_mx_lookup(domain);

    //Now we attempt the correct number of DMTP connections using dual mode.
    if(mx_rec) {

        while(dx[num_mx]) {
            ++num_mx;
        }

        attempts = num_mx > config->connect.attempts_dual ? config->connect.attempts_dual : num_mx;


    }

    //If we have still not succeeded, we will try to connect to the domain
    //directly if the our config allows it.
    if(config->connect.use_domain) {

    }

out:
    return result;

cleanup_dx_rec:
    dime_mrec_record_destroy(dx_rec);
error:
    return NULL;
}
*/



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
dime_dmtp_client_send_starttls(
    dmtp_session_t *session,
    sds host,
    dmtp_mode_type_t mode)
{

    sds command;

    PUBLIC_FUNC_PROLOGUE();

    if(!(command = dime_dmtp_command_starttls(host, mode))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to format starttls command");
        goto error;
    }

    if(dime_dmtp_session_send(session, command) < 0) {
        PUSH_ERROR(ERR_UNSPEC, "unable to issue DMTP command");
        goto error;
    }

    return 0;

error:
    return -1;
}


/**
 * @brief
 * Send dmtp helo command.
 * @param session
 * Connection to a dmtp server.
 * @param host
 * string containing host name.
 * @return
 * 0 on success, -1 on failure.
*/
int
dime_dmtp_client_send_helo(
    dmtp_session_t *session,
    sds host)
{

    sds command;

    PUBLIC_FUNC_PROLOGUE();

    if(!(command = dime_dmtp_command_helo(host))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to format helo command");
        goto error;
    }

    if(dime_dmtp_session_send(session, command) < 0) {
        PUSH_ERROR(ERR_UNSPEC, "unable to issue DMTP command");
        goto error;
    }

    return 0;

error:
    return -1;
}


/**
 * @brief
 * Send dmtp ehlo command.
 * @param session
 * Connection to a dmtp server.
 * @param host
 * string containing host name.
 * @return
 * 0 on success, -1 on failure.
*/
int
dime_dmtp_client_send_ehlo(
    dmtp_session_t *session,
    sds host)
{

    sds command;

    PUBLIC_FUNC_PROLOGUE();

    if(!(command = dime_dmtp_command_ehlo(host))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to format ehlo command");
        goto error;
    }

    if(dime_dmtp_session_send(session, command) < 0) {
        PUSH_ERROR(ERR_UNSPEC, "unable to issue DMTP command");
        goto error;
    }

    return 0;

error:
    return -1;
}


/**
 * @brief
 * Send dmtp mode command.
 * @param session
 * Connection to a dmtp server.
 * @return
 * 0 on success, -1 on failure.
*/
int
dime_dmtp_client_send_mode(
    dmtp_session_t *session)
{

    sds command;

    PUBLIC_FUNC_PROLOGUE();

    if(!(command = dime_dmtp_command_mode())) {
        PUSH_ERROR(ERR_UNSPEC, "failed to format mode command");
        goto error;
    }

    if(dime_dmtp_session_send(session, command) < 0) {
        PUSH_ERROR(ERR_UNSPEC, "unable to issue DMTP command");
        goto error;
    }

    return 0;

error:
    return -1;
}


/**
 * @brief
 * Send dmtp rset command.
 * @param session
 * Connection to a dmtp server.
 * @return
 * 0 on success, -1 on failure.
*/
int
dime_dmtp_client_send_rset(
    dmtp_session_t *session)
{

    sds command;

    PUBLIC_FUNC_PROLOGUE();

    if(!(command = dime_dmtp_command_rset())) {
        PUSH_ERROR(ERR_UNSPEC, "failed to format rset command");
        goto error;
    }

    if(dime_dmtp_session_send(session, command) < 0) {
        PUSH_ERROR(ERR_UNSPEC, "unable to issue DMTP command");
        goto error;
    }

    return 0;

error:
    return -1;
}


/**
 * @brief
 * Send dmtp noop command.
 * @param session
 * Connection to a dmtp server.
 * @param arg1
 * optional argument 1.
 * @param arg2
 * optional argument 2.
 * @param arg3
 * optional argument 3.
 * @return
 * 0 on success, -1 on failure.
*/
int
dime_dmtp_client_send_noop(
    dmtp_session_t *session,
    sds arg1,
    sds arg2,
    sds arg3)
{

    sds command;

    PUBLIC_FUNC_PROLOGUE();

    if(!(command = dime_dmtp_command_noop(arg1, arg2, arg3))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to format noop command");
        goto error;
    }

    if(dime_dmtp_session_send(session, command) < 0) {
        PUSH_ERROR(ERR_UNSPEC, "unable to issue DMTP command");
        goto error;
    }

    return 0;

error:
    return -1;
}


/**
 * @brief
 * Send dmtp help command.
 * @param session
 * Connection to a dmtp server.
 * @return
 * 0 on success, -1 on failure.
*/
int
dime_dmtp_client_send_help(
    dmtp_session_t *session)
{

    sds command;

    PUBLIC_FUNC_PROLOGUE();

    if(!(command = dime_dmtp_command_help())) {
        PUSH_ERROR(ERR_UNSPEC, "failed to format help command");
        goto error;
    }

    if(dime_dmtp_session_send(session, command) < 0) {
        PUSH_ERROR(ERR_UNSPEC, "unable to issue DMTP command");
        goto error;
    }

    return 0;

error:
    return -1;
}


/**
 * @brief
 * Send dmtp quit command.
 * @param session
 * Connection to a dmtp server.
 * @return
 * 0 on success, -1 on failure.
*/
int
dime_dmtp_client_send_quit(
    dmtp_session_t *session)
{

    sds command;

    PUBLIC_FUNC_PROLOGUE();

    if(!(command = dime_dmtp_command_quit())) {
        PUSH_ERROR(ERR_UNSPEC, "failed to format quit command");
        goto error;
    }

    if(dime_dmtp_session_send(session, command) < 0) {
        PUSH_ERROR(ERR_UNSPEC, "unable to issue DMTP command");
        goto error;
    }

    return 0;

error:
    return -1;
}


/**
 * @brief
 * Send dmtp mail command.
 * @param session
 * Connection to a dmtp server.
 * @param from
 * string containing mail orign.
 * @param fingerprint
 * string containing origin signet full fingerprint.
 * @return
 * 0 on success, -1 on failure.
*/
int
dime_dmtp_client_send_mail(
    dmtp_session_t *session,
    sds from,
    sds fingerprint)
{

    sds command;

    PUBLIC_FUNC_PROLOGUE();

    if(!(command = dime_dmtp_command_mail(from, fingerprint))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to format mail command");
        goto error;
    }

    if(dime_dmtp_session_send(session, command) < 0) {
        PUSH_ERROR(ERR_UNSPEC, "unable to issue DMTP command");
        goto error;
    }

    return 0;

error:
    return -1;
}


/**
 * @brief
 * Send dmtp rcpt command.
 * @param session
 * Connection to a dmtp server.
 * @param to
 * string containing mail destination.
 * @param fingerprint
 * string containing destination signet full fingerprint.
 * @return
 * 0 on success, -1 on failure.
*/
int
dime_dmtp_client_send_rcpt(
    dmtp_session_t *session,
    sds to,
    sds fingerprint)
{

    sds command;

    PUBLIC_FUNC_PROLOGUE();

    if(!(command = dime_dmtp_command_rcpt(to, fingerprint))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to format rcpt command");
        goto error;
    }

    if(dime_dmtp_session_send(session, command) < 0) {
        PUSH_ERROR(ERR_UNSPEC, "unable to issue DMTP command");
        goto error;
    }

    return 0;

error:
    return -1;
}


/**
 * @brief
 * Send dmtp data command.
 * @param session
 * Connection to a dmtp server.
 * @return
 * 0 on success, -1 on failure.
*/
int
dime_dmtp_client_send_data(
    dmtp_session_t *session)
{

    sds command;

    PUBLIC_FUNC_PROLOGUE();

    if(!(command = dime_dmtp_command_data())) {
        PUSH_ERROR(ERR_UNSPEC, "failed to format data command");
        goto error;
    }

    if(dime_dmtp_session_send(session, command) < 0) {
        PUSH_ERROR(ERR_UNSPEC, "unable to issue DMTP command");
        goto error;
    }

    return 0;

error:
    return -1;
}


/**
 * @brief
 * Send dmtp sgnt command for user signet retrieval.
 * @param session
 * Connection to a dmtp server.
 * @param address
 * string containing user mail address.
 * @param fingerprint
 * optional user signet fingerprint.
 * @return
 * 0 on success, -1 on failure.
*/
int
dime_dmtp_client_send_sgnt_user(
    dmtp_session_t *session,
    sds address,
    sds fingerprint)
{

    sds command;

    PUBLIC_FUNC_PROLOGUE();

    if(!(command = dime_dmtp_command_sgnt_user(address, fingerprint))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to format sgnt command");
        goto error;
    }

    if(dime_dmtp_session_send(session, command) < 0) {
        PUSH_ERROR(ERR_UNSPEC, "unable to issue DMTP command");
        goto error;
    }

    return 0;

error:
    return -1;
}


/**
 * @brief
 * Send dmtp sgnt command for org signet retrieval.
 * @param session
 * Connection to a dmtp server.
 * @param domain
 * string containing domain tld.
 * @param mode
 * optional org signet fingerprint.
 * @return
 * 0 on success, -1 on failure.
*/
int
dime_dmtp_client_send_sgnt_domain(
    dmtp_session_t *session,
    sds domain,
    sds fingerprint)
{

    sds command;

    PUBLIC_FUNC_PROLOGUE();

    if(!(command = dime_dmtp_command_sgnt_domain(domain, fingerprint))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to format sgnt command");
        goto error;
    }

    if(dime_dime_dmtp_session_send(session, command) < 0) {
        PUSH_ERROR(ERR_UNSPEC, "unable to issue DMTP command");
        goto error;
    }

    return 0;

error:
    return -1;
}


/**
 * @brief
 * Send dmtp hist command.
 * @param address
 * Connection to a dmtp server.
 * @param host
 * String containing user mail address.
 * @param start
 * optional starting user signet fingerprint.
 * @param stop
 * optional stopping user signet fingerprint.
 * @return
 * 0 on success, -1 on failure.
*/
int
dime_dmtp_client_send_hist(
    dmtp_session_t *session,
    sds address,
    sds start,
    sds stop)
{

    sds command;

    PUBLIC_FUNC_PROLOGUE();

    if(!(command = dime_dmtp_command_hist(address, start, stop))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to format hist command");
        goto error;
    }

    if(dime_dmtp_session_send(session, command) < 0) {
        PUSH_ERROR(ERR_UNSPEC, "unable to issue DMTP command");
        goto error;
    }

    return 0;

error:
    return -1;
}


/**
 * @brief
 * Send dmtp vrfy command to verify a user signet.
 * @param session
 * Connection to a dmtp server.
 * @param address
 * String containing user mail address.
 * @param fingerprint
 * String containing user signet fingerprint.
 * @return
 * 0 on success, -1 on failure.
*/
int
dime_dmtp_client_send_vrfy_user(
    dmtp_session_t *session,
    sds address,
    sds fingerprint)
{

    sds command;

    PUBLIC_FUNC_PROLOGUE();

    if(!(command = dime_dmtp_command_vrfy_user(address, fingerprint))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to format vrfy command");
        goto error;
    }

    if(dime_dmtp_session_send(session, command) < 0) {
        PUSH_ERROR(ERR_UNSPEC, "unable to issue DMTP command");
        goto error;
    }

    return 0;

error:
    return -1;
}


/**
 * @brief
 * Send dmtp vrfy command to verify an org signet.
 * @param session
 * Connection to a dmtp server.
 * @param domain
 * string containing domain tld.
 * @param fingerprint
 * string containing org signet fingerprint.
 * @return
 * 0 on success, -1 on failure.
*/
int
dime_dmtp_client_send_vrfy_domain(
    dmtp_session_t *session,
    sds host,
    sds fingerprint)
{

    sds command;

    PUBLIC_FUNC_PROLOGUE();

    if(!(command = dime_dmtp_command_vrfy_domain(host, mode))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to format vrfy command");
        goto error;
    }

    if(dime_dmtp_session_send(session, command) < 0) {
        PUSH_ERROR(ERR_UNSPEC, "unable to issue DMTP command");
        goto error;
    }

    return 0;

error:
    return -1;
}


/**
 * @brief
 * Receive response from server and parse it.
 * @param session
 * DMTP session.
 * @return
 * DMTP response, NULL on error.
*/
dmtp_response_t *
dime_dmtp_client_recv_response(
    dmtp_session_t *session)
{

    dmtp_session_t *result;
    sds * lines;

    PUBLIC_FUNC_PROLOGUE();

    if(!session) {
        PUSH_ERROR(ERR_BAD_PARAM, NULL);
        goto error;
    }

    if(!(lines = dime_dmtp_session_recv(session))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to retrieve received data");
        goto error;
    }

    if(!(result = dime_dmtp_response_parse(lines))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to parse received response");
        goto cleanup_lines;
    }

    return result;

cleanup_lines:
    if(lines) {

        for(size_t i = 0; lines[i]; ++i) {
            sdsfree(lines[i]);
        }

        free(lines);
    }
error:
    return NULL;
}


