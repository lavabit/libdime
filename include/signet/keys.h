#ifndef KEYS_H
#define KEYS_H

#include <signet/general.h>

/* PUBLIC FUNCTIONS */

int dime_keys_file_create(keys_type_t type, ED25519_KEY *sign_key, EC_KEY *enc_key, const char *filename);

/* not implemented yet TODO*/
int dime_keys_file_add_sok(ED25519_KEY *sok, const char *filename);

ED25519_KEY *dime_keys_fetch_sign_key(const char *filename);

EC_KEY *dime_keys_fetch_enc_key(const char *filename);

#endif
