#include "../signet/keys.h"

/**
 * @brief	Creates a keys file with specified signing and encryption keys.
 * @param	type	 	Type of keys file, whether the keys correspond to a user or organizational signet.
 * @param	sign_key 	Pointer to the specified ed25519 key, the private portion of which will be stored in the keys file as the signing key.
 * @param	enc_key		Pointer to the specified elliptic curve key, the private portion of which will be stored in the keys file as the encryption key.
 * @param	filename	Pointer to the NULL terminated string containing the filename for the keys file.
 * @return	0 on success, -1 on failure.
*/
int _keys_to_file(keys_type_t type, ED25519_KEY *sign_key, EC_KEY *enc_key, const char *filename) {

	char *b64_keys = NULL;
	size_t serial_size = 0, enc_size = 0;
	unsigned char *serial_keys = NULL, *serial_enc = NULL, serial_sign[ED25519_KEY_SIZE];
	dime_number_t number;

	if(!sign_key || !enc_key || !filename) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	switch(type) {

		case KEYS_TYPE_ORG:
			number = DIME_ORG_KEYS;
			break;
		case KEYS_TYPE_USER:
			number = DIME_USER_KEYS;
			break;
		default:
			RET_ERROR_INT(ERR_BAD_PARAM, NULL);
			break;

	}

	memcpy(serial_sign, sign_key->private, ED25519_KEY_SIZE);

	if(!(serial_enc = _serialize_ec_privkey(enc_key, &enc_size))) {
		_secure_wipe(serial_sign, ED25519_KEY_SIZE);
		RET_ERROR_INT(ERR_UNSPEC, "could not serialize private key");
	}

	serial_size = KEYS_HEADER_SIZE + 1 + ED25519_KEY_SIZE + 1 + enc_size;
	
	if(!(serial_keys = malloc(serial_size))) {
		PUSH_ERROR_SYSCALL("malloc");
		_secure_wipe(serial_sign, ED25519_KEY_SIZE);
		_secure_wipe(serial_enc, enc_size);
		free(serial_enc);
		RET_ERROR_INT(ERR_NOMEM, NULL);
	}

	memset(serial_keys, 0, serial_size);
	_int_no_put_2b(serial_keys, (uint16_t)number);
	_int_no_put_3b(serial_keys+2, (uint32_t)(serial_size - KEYS_HEADER_SIZE));

	serial_keys[KEYS_HEADER_SIZE] = 1;
	memcpy(serial_keys+KEYS_HEADER_SIZE+1, serial_sign, ED25519_KEY_SIZE);
	_secure_wipe(serial_sign, ED25519_KEY_SIZE);
	serial_keys[KEYS_HEADER_SIZE + 1 + ED25519_KEY_SIZE] = 2;
	memcpy(serial_keys+KEYS_HEADER_SIZE + 1 + ED25519_KEY_SIZE + 1, serial_enc, enc_size);
	_secure_wipe(serial_enc, enc_size);
	free(serial_enc);

	b64_keys = _b64encode(serial_keys, serial_size);
	_secure_wipe(serial_keys, serial_size);
	free(serial_keys);

	if (!b64_keys) {
		RET_ERROR_INT(ERR_UNSPEC, "could not base64 encode the keys");
	}

	if(_write_pem_data(b64_keys, SIGNET_PRIVATE_KEYCHAIN, filename) < 0) {
		_secure_wipe(b64_keys, strlen(b64_keys));
		free(b64_keys);
		RET_ERROR_INT(ERR_UNSPEC, "could not store keys in PEM file.");
	}

	_secure_wipe(b64_keys, strlen(b64_keys));	
	free(b64_keys);

	return 0;
}


/**
 * @brief	Retrieves the keys binary from the keys file.
 * @param	filename	Null terminated string containing specified filename.
 * @param	len		Pointer to the length of the output.
 * @return	Pointer to the keys binary string, this memory needs to be wipe before being freed. NULL on error.
*/
unsigned char * _keys_get_binary(const char *filename, size_t *len) {

	char *b64_keys = NULL;
	unsigned char * serial_keys = NULL;

	if(!filename || !len) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!(b64_keys = _read_pem_data(filename, SIGNET_PRIVATE_KEYCHAIN, 1))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not retrieve keys from PEM file");
	}

	if(!(serial_keys = _b64decode(b64_keys, strlen(b64_keys), len))) {
		free(b64_keys);
		RET_ERROR_PTR(ERR_UNSPEC, "could not base64 decode the keys");
	}

	free(b64_keys);

	return serial_keys;
}


/**
 * @brief	Retrieves the keys type (user or organizational) from the keys binary.
 * @param	bin_keys	Pointer to the keys buffer.
 * @param	len		Length of the keys buffer.
 * @return	Keys type on success, KEYS_TYPE_ERROR on error.
*/
keys_type_t _keys_get_type(const unsigned char *bin_keys, size_t len) {

	dime_number_t number;

	if(!bin_keys) {
		RET_ERROR_CUST(KEYS_TYPE_ERROR, ERR_BAD_PARAM, NULL);
	} else if(_keys_check_length(bin_keys, len) < 0) {
		RET_ERROR_CUST(KEYS_TYPE_ERROR, ERR_BAD_PARAM, NULL);
	}

	number = (dime_number_t)_int_no_get_2b((void *)bin_keys);

	if (number == DIME_ORG_KEYS) {
		return KEYS_TYPE_ORG;
	} else if (number == DIME_USER_KEYS) {
		return KEYS_TYPE_USER;
	}

	RET_ERROR_CUST(KEYS_TYPE_ERROR, ERR_UNSPEC, "DIME number is not keys file type");
}


/**
 * @brief	Retrieves the signing key from the keys binary.
 * @param	bin_keys	Pointer to the keys buffer.
 * @param	len		Length of the keys buffer.
 * @return	Pointer to ed25519 signing key, NULL if an error occurred.
*/
ED25519_KEY * _keys_fetch_sign_key(const unsigned char *bin_keys, size_t len) {

	unsigned char sign_fid;
	unsigned int at = 0;
	ED25519_KEY *sign_key;

	if(!bin_keys) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	} else if(_keys_check_length(bin_keys, len) < 0) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	} else if(len < KEYS_HEADER_SIZE + 1 + ED25519_KEY_SIZE) {
		RET_ERROR_PTR(ERR_BAD_PARAM, "keys buffer too small for signing key");
	}

	switch(_keys_get_type(bin_keys, len)) {

		case KEYS_TYPE_ORG:
			sign_fid = KEYS_ORG_PRIVATE_POK;
			break;
		case KEYS_TYPE_USER:
			sign_fid = KEYS_USER_PRIVATE_SIGN;
			break;
		default:
			RET_ERROR_PTR(ERR_UNSPEC, "invalid keys type");
			break;

	}

	at = KEYS_HEADER_SIZE;

	if(bin_keys[at++] != sign_fid) {
		RET_ERROR_PTR(ERR_UNSPEC, "no signing key was found");
	}

	if(!(sign_key = _deserialize_ed25519_privkey(bin_keys + KEYS_HEADER_SIZE + 1))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not deserialize ed25119 signing key");
	}

	return sign_key;
}


/**
 * @brief	Retrieves the signing key from the keys file.
 * @param	filename	Null terminated filename string.
 * @return	Pointer to the ed25519 signing key.
*/
ED25519_KEY * _keys_file_fetch_sign_key(const char *filename) {

	size_t keys_len;
	unsigned char *keys_bin;
	ED25519_KEY *key;

	if(!filename) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	} else if(!strlen(filename)) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!(keys_bin = _keys_get_binary(filename, &keys_len))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not retrieve keys binary string");
	}

	key = _keys_fetch_sign_key(keys_bin, keys_len);
	_secure_wipe(keys_bin, keys_len);
	free(keys_bin);

	if (!key) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not retrieve ed25519 signing key");
	}

	return key;
}


/**
 * @brief	Retrieves the encryption key from the keys binary.
 * @param	bin_keys 	Pointer to the keys buffer.
 * @param	len		Length of the keys buffer.
 * @return	Pointer to elliptic curve key, NULL if an error occurred.
*/
EC_KEY * _keys_fetch_enc_key(const unsigned char *bin_keys, size_t len) {

	unsigned char sign_fid, enc_fid;
	unsigned int at = 0;
	EC_KEY *enc_key;

	if(!bin_keys) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	} else if(_keys_check_length(bin_keys, len) < 0) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	switch(_keys_get_type(bin_keys, len)) {

		case KEYS_TYPE_ORG:
			sign_fid = KEYS_ORG_PRIVATE_POK;
			enc_fid = KEYS_ORG_PRIVATE_ENC;
			break;
		case KEYS_TYPE_USER:
			sign_fid = KEYS_USER_PRIVATE_SIGN;
			enc_fid = KEYS_USER_PRIVATE_ENC;
			break;
		default:
			RET_ERROR_PTR(ERR_UNSPEC, "invalid keys type");
			break;

	}

	at = KEYS_HEADER_SIZE;

	if(bin_keys[at] == sign_fid) {
		at += ED25519_KEY_SIZE + 1;
	}

	if(len < at + 1) {
		RET_ERROR_PTR(ERR_UNSPEC, "keys buffer too small for encryption key");
	}

	if(bin_keys[at++] != enc_fid) {
		RET_ERROR_PTR(ERR_UNSPEC, "no encryption key was found");
	}

	if(len < at + EC_PRIVKEY_SIZE) {
		RET_ERROR_PTR(ERR_UNSPEC, "keys buffer too small for encryption key");
	}

	if(!(enc_key = _deserialize_ec_privkey(bin_keys + at, EC_PRIVKEY_SIZE, 0))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not deserialize encryption key");
	}

	return enc_key;
}


/**
 * @brief	Retrieves the encryption key from the keys file.
 * @param	filename	Null terminated filename string.
 * @return	Pointer to the elliptic curve encryption key.
*/
EC_KEY * _keys_file_fetch_enc_key(const char *filename) {

	size_t keys_len;
	unsigned char *keys_bin;
	EC_KEY *key;

	if(!filename) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	} else if(!strlen(filename)) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!(keys_bin = _keys_get_binary(filename, &keys_len))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not retrieve keys binary string");
	}

	key = _keys_fetch_enc_key(keys_bin, keys_len);
	_secure_wipe(keys_bin, keys_len);
	free(keys_bin);

	if (!key) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not retrieve ed25519 signing key");
	}

	return key;
}


/* PRIVATE FUNCTIONS */

/**
 * @brief	Checks the size of the keys buffer for consistency.
 * @param	in	Keys buffer.
 * @param	in_len	Keys buffer size.
 * @return	0 if the length checks pass, -1 if they do not.
*/
int _keys_check_length(const unsigned char *in, size_t in_len) {

	uint32_t signet_length;

	if (!in || (in_len < SIGNET_HEADER_SIZE)) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	signet_length = _int_no_get_3b((void *)(in+2));

	if ((in_len - SIGNET_HEADER_SIZE) != signet_length) {
		RET_ERROR_INT(ERR_UNSPEC, "length does not match input size");
	}

	return 0;
}
