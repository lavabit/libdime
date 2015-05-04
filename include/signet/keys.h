#ifndef KEYS_H
#define KEYS_H

#include <signet/general.h>

/* PUBLIC FUNCTIONS */

/**
 * @brief	Creates a keys file with specified signing and encryption keys.
 * @param	type	        Type of keys file, whether the keys correspond to a user or organizational signet.
 * @param	sign_key        Pointer to the specified ed25519 key, the private portion of which will be stored in the keys file as the signing key.
 * @param	enc_key		Pointer to the specified elliptic curve key, the private portion of which will be stored in the keys file as the encryption key.
 * @param	filename	Pointer to the NULL terminated string containing the filename for the keys file.
 * @return	0 on success, -1 on failure.
*/
int dime_keys_file_create(keys_type_t type, ED25519_KEY *sign_key, EC_KEY *enc_key, const char *filename);

/* not implemented yet TODO*/
int dime_keys_file_add_sok(ED25519_KEY *sok, const char *filename);

/**
 * @brief	Retrieves the signing key from the keys file.
 * @param	filename	Null terminated filename string.
 * @return	Pointer to the ed25519 signing key.
 * @free_using{free_ed25519_key}
*/
ED25519_KEY *dime_keys_fetch_sign_key(const char *filename);

/**
 * @brief	Retrieves the encryption key from the keys file.
 * @param	filename	Null terminated filename string.
 * @return	Pointer to the elliptic curve encryption key.
 * @free_using{free_ec_key}
*/
EC_KEY *dime_keys_fetch_enc_key(const char *filename);

#endif
