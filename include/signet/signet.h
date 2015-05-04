#ifndef SIGNET_H
#define SIGNET_H

#include "signet/general.h"



int 			dime_sgnt_create_defined_field(signet_t *signet, unsigned char fid, size_t data_size, const unsigned char *data, unsigned char flags);

signet_t *              dime_sgnt_create_signet(signet_type_t type);

signet_t *              dime_sgnt_create_signet_w_keys(signet_type_t type, const char *keysfile);

int                     dime_sgnt_create_undefined_field(signet_t *signet, size_t name_size, const unsigned char *name, size_t data_size, const unsigned char *data);

void                    dime_sgnt_destroy_signet(signet_t *signet);

void                    dime_sgnt_dump_signet(FILE *fp, signet_t *signet);

EC_KEY *                dime_sgnt_fetch_enckey(const signet_t *signet);

unsigned char *         dime_sgnt_fetch_fid_num(const signet_t *signet, unsigned char fid, unsigned int num, size_t *data_size);

unsigned char **        dime_sgnt_fetch_msg_sign_keys(const signet_t *signet);

ED25519_KEY *           dime_sgnt_fetch_signkey(const signet_t *signet);

unsigned char **        dime_sgnt_fetch_signet_sign_keys(const signet_t *signet);

unsigned char *         dime_sgnt_fetch_undefined_field(const signet_t *signet, size_t name_size, const unsigned char *name, size_t *data_size);

signet_t *              dime_sgnt_file_to_signet(const char *filename);

int                     dime_sgnt_file_create(signet_t *signet, const char *filename);

int                     dime_sgnt_fid_exists(const signet_t *signet, unsigned char fid);

int                     dime_sgnt_fid_get_count(const signet_t *signet, unsigned char fid);

char *                  dime_sgnt_fingerprint_core(const signet_t *signet);

char *                  dime_sgnt_fingerprint_full(const signet_t *signet);

char *                  dime_sgnt_fingerprint_ssr(const signet_t *signet);

char *                  dime_sgnt_fingerprint_user(const signet_t *signet);

int                     dime_sgnt_remove_fid_num(signet_t *signet, unsigned char fid, int num);

int                     dime_sgnt_remove_undefined_field(signet_t *signet, size_t name_size, const unsigned char *name);

signet_t *              dime_sgnt_serial_b64_to_signet(const char *b64_in);

char *                  dime_sgnt_serial_signet_to_b64(signet_t *signet);

signet_t *              dime_sgnt_serial_to_signet(const unsigned char *in, size_t len);

unsigned char *         dime_sgnt_serial_get_binary(signet_t *signet, uint32_t *serial_size);

int                     dime_sgnt_set_defined_field(signet_t *signet, unsigned char fid, size_t data_size, const unsigned char *data, unsigned char flags);

int                     dime_sgnt_set_id_field(signet_t *signet, size_t id_size, const unsigned char *id);

int                     dime_sgnt_sign_coc_sig(signet_t *signet, ED25519_KEY *key);

int                     dime_sgnt_sign_core_sig(signet_t *signet, ED25519_KEY *key);

int                     dime_sgnt_sign_full_sig(signet_t *signet, ED25519_KEY *key);

int                     dime_sgnt_sign_initial_sig(signet_t *signet, ED25519_KEY *key);

int                     dime_sgnt_sign_ssr_sig(signet_t *signet, ED25519_KEY *key);

signet_t *              dime_sgnt_split_core(const signet_t *signet);

signet_t *              dime_sgnt_split_user(const signet_t *signet);

signet_type_t           dime_sgnt_type_get(const signet_t *signet);

int                     dime_sgnt_type_set(signet_t *signet, signet_type_t type);

signet_state_t          dime_sgnt_validate_all(const signet_t *signet, const signet_t *previous, const signet_t *orgsig, const unsigned char **dime_pok);

int                     dime_sgnt_verify_message_sig(const signet_t *signet, ed25519_signature sig, const unsigned char *buf, size_t buf_len);








#endif
