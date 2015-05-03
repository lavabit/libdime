#ifndef SIGNET_H
#define SIGNET_H

#include "signet/general.h"

/* Create a new signet and keysfile */
signet_t *dime_sgnt_keys_create(signet_type_t type, const char *keysfile);

/* Loading signet from and saving to file */
signet_t *dime_sgnt_from_file(const char *filename);
int dime_sgnt_to_file(signet_t *signet, const char *filename);

/* Initializing and destroying signet*/
signet_t *dime_sgnt_deserialize(const unsigned char *in, size_t len);
void dime_sgnt_destroy(signet_t *signet);

/* Serializing signet into binary and b64 */
unsigned char *dime_sgnt_serialize(signet_t *signet, uint32_t *serial_size);

/* Dumps signet into the file descriptor */
void dime_sgnt_dump(FILE *fp, signet_t *signet);

/* Signet state retrieval */
int dime_sgnt_fid_get_count(const signet_t *signet, unsigned char fid);
int dime_sgnt_fid_exists(const signet_t *signet, unsigned char fid);
signet_state_t dime_sgnt_state_get(const signet_t *signet);
signet_type_t dime_sgnt_type_get(const signet_t *signet);

/* Retrieving field data */
unsigned char *dime_sgnt_fetch_fid_num(const signet_t *signet, unsigned char fid, unsigned int num, size_t *data_size);
unsigned char *dime_sgnt_fetch_undef(const signet_t *signet, size_t name_len, const unsigned char *name, size_t *data_size);
ED25519_KEY *dime_sgnt_fetch_signkey(const signet_t *signet);
EC_KEY *dime_sgnt_fetch_enckey(const signet_t *signet);
unsigned char **dime_sgnt_fetch_msg_sign_keys(const signet_t *signet);
unsigned char **dime_sgnt_fetch_sgnt_sign_keys(const signet_t *signet);

/* Modifying the signet */
int dime_sgnt_create_field_defined(signet_t *signet, unsigned char fid, size_t data_size, const unsigned char *data, unsigned char flags);
int dime_sgnt_create_field_undefined(signet_t *signet, size_t name_size, const unsigned char *name, size_t data_size, const unsigned char *data);
int dime_sgnt_remove_fid_num(signet_t *signet, unsigned char fid, int num);
int dime_sgnt_remove_undef(signet_t *signet, size_t name_size, const unsigned char *name);
int dime_sgnt_field_set_defined(signet_t *signet, unsigned char fid, size_t data_size, const unsigned char *data, unsigned char flags);
int dime_sgnt_field_set_id(signet_t *signet, size_t id_size, const unsigned char *id);
int dime_sgnt_type_set(signet_t *signet, signet_type_t type);


/* Signet Splits */
signet_t *dime_sgnt_split_core(const signet_t *signet);
signet_t *dime_sgnt_split_user(const signet_t *signet);

/* Signet Fingerprints */
char *dime_sgnt_fingerprint_full(const signet_t *signet);
char *dime_sgnt_fingerprint_core(const signet_t *signet);
char *dime_sgnt_fingerprint_user(const signet_t *signet);
char *dime_sgnt_fingerprint_ssr(const signet_t *signet);

/* Signet verification */
signet_state_t dime_sgnt_verify_full(const signet_t *signet, const signet_t *orgsig, const unsigned char **dime_pok);
int dime_sgnt_verify_signature(const signet_t *signet, unsigned char sigfid, const unsigned char *key);
int dime_sgnt_verify_signature_key(const signet_t *signet, unsigned char sigfid, ED25519_KEY *key);
int dime_sgnt_verify_message_sig(const signet_t *signet, ed25519_signature_sig, const unsigned char *buf, size_t buf_len);

/* Signet sign */
int dime_sgnt_sign_full_sig(signet_t *signet, ED25519_KEY *key);
int dime_sgnt_sign_core_sig(signet_t *signet, ED25519_KEY *key);
int dime_sgnt_sign_initial_sig(signet_t *signet, ED25519_KEY *key);
int dime_sgnt_sign_ssr_sig(signet_t *signet, ED25519_KEY *key);
int dime_sgnt_sign_coc_sig(signet_t *signet, ED25519_KEY *key);
