#include <stdio.h>
#include <string.h>

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/rand.h"

#include "dcrypto.h"
#include "misc.h"
#include "error.h"


EC_GROUP *_signing_group = NULL;
EC_GROUP *_encryption_group = NULL;
const EVP_MD *_ecies_envelope_evp = NULL;


/*
 * @brief	Initialize the cryptographic subsystem.
 * @return	-1 if any part of the initialization process failed, or 0 on success.
 */
int _crypto_init(void) {

	SSL_load_error_strings();
	SSL_library_init();
	OPENSSL_add_all_algorithms_noconf();

	// This has been indefinitely obviated by the fact that we're using ED25519 as a signing curve,
	// via an external provider other than openssl.
/*	if (!(_signing_group = EC_GROUP_new_by_curve_name(EC_SIGNING_CURVE))) {
 *		PUSH_ERROR_OPENSSL();
		RET_ERROR_INT(ERR_UNSPEC, "could not initialize signing curve");
	} */

	if (!(_encryption_group = EC_GROUP_new_by_curve_name(EC_ENCRYPT_CURVE))) {
		PUSH_ERROR_OPENSSL();
//		EC_GROUP_free(_signing_group);
		RET_ERROR_INT(ERR_UNSPEC, "could not initialize encryption curve");
	}

	if (!(_ecies_envelope_evp = EVP_get_digestbyname(OBJ_nid2sn(NID_sha512)))) {
		PUSH_ERROR_OPENSSL();
		RET_ERROR_INT(ERR_UNSPEC, "unable to get SHA-512 digest by NID");
	}

//	EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_COMPRESSED);

	return 0;
}


/*
 * @brief	Shutdown the cryptographic subsystem.
 * @return	This function returns no value.
 */
void _crypto_shutdown(void) {

	if (_signing_group) {
		EC_GROUP_clear_free(_signing_group);
		_signing_group = NULL;
	}

	if (_encryption_group) {
		EC_GROUP_clear_free(_encryption_group);
		_encryption_group = NULL;
	}

	EVP_cleanup();
	ERR_free_strings();

	return;
}


/**
 * @brief	Verify that an elliptic curve signature for a given hashed data buffer is valid.
 * @param	hash	a pointer to the hashed data buffer used to generate the signature.
 * @param	hlen	the length, in bytes, of the hashed data buffer.
 * @param	sig	a pointer to the signature buffer to be verified against the input data.
 * @param	slen	the length, in bytes, of the signature buffer.
 * @param	key	the EC key which will have its public portion used to verify the signature of the supplied hashed data.
 * @return	-1 on general failure, 0 if the signature did not match the hashed data, or 1 if it did.
 */
int _verify_ec_signature(const unsigned char *hash, size_t hlen, const unsigned char *sig, size_t slen, EC_KEY *key) {

	ECDSA_SIG *ec_sig;
	int result;

	if (!hash|| !hlen || !sig || !slen || !key) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if (!(ec_sig = d2i_ECDSA_SIG(NULL, &sig, slen))) {
		PUSH_ERROR_OPENSSL();
		RET_ERROR_INT(ERR_UNSPEC, "unable to read EC signature from buffer");
	}

	if ((result = ECDSA_do_verify(hash, hlen, ec_sig, key)) < 0) {
		PUSH_ERROR_OPENSSL();
		ECDSA_SIG_free(ec_sig);
		RET_ERROR_INT(ERR_UNSPEC, "unable to complete ECDSA signature verification");
	}

	ECDSA_SIG_free(ec_sig);

	return result;
}


/**
 * @brief	Verify that a signature for a given data buffer is valid.
 * @param	data	a pointer to the data buffer used to generate the signature.
 * @param	dlen	the length, in bytes, of the data buffer.
 * @param	shabits	the number of bits for the desired SHA hash (160, 256, or 512).
 * @param	sig	a pointer to the signature buffer to be verified against the input data.
 * @param	slen	the length, in bytes, of the signature buffer.
 * @param	key	the EC key which will have its public portion used to verify the signature of the supplied data.
 * @return	-1 on general failure, 0 if the signature did not match the data, or 1 if it did.
 */
int _verify_ec_sha_signature(const unsigned char *data, size_t dlen, unsigned int shabits, const unsigned char *sig, size_t slen, EC_KEY *key) {

	unsigned char hashbuf[SHA_512_SIZE];

	if (!data || !dlen || !sig || !slen || !key) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	} else if ((shabits != 160) && (shabits != 256) && (shabits != 512)) {
		RET_ERROR_INT(ERR_BAD_PARAM, "ECDSA signature only accepts SHA hash sizes of 160, 256, or 512 bits");
	}

	if (_compute_sha_hash(shabits, data, dlen, hashbuf) < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "unable to compute SHA hash for ECDSA signature verification operation");
	}

	return (_verify_ec_signature(hashbuf, shabits/8, sig, slen, key));
}


/**
 * @brief	Sign a body of data using the ECDSA algorithm.
 * @param	hash	a pointer to the hashed data buffer to be signed.
 * @param	hlen	the length, in bytes, of the hashed data to be signed.
 * @param	key	the EC key which will have its private portion used to sign the supplied data.
 * @param	siglen	a pointer to a variable that will receive the length of the data signature buffer on success.
 * @return	NULL on failure, or a pointer to the newly allocated signature data buffer on success.
 */
unsigned char * _ec_sign_data(const unsigned char *hash, size_t hlen, EC_KEY *key, size_t *siglen) {

	ECDSA_SIG *signature;
	unsigned char *buf = NULL;
	int bsize;

	if (!hash|| !hlen || !key || !siglen) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if (!(signature = ECDSA_do_sign(hash, hlen, key))) {
		PUSH_ERROR_OPENSSL();
		RET_ERROR_PTR(ERR_UNSPEC, "unable to take ECDSA signature of hash buffer");
	}

	if ((bsize = i2d_ECDSA_SIG(signature, &buf)) < 0) {
		PUSH_ERROR_OPENSSL();
		ECDSA_SIG_free(signature);
		RET_ERROR_PTR(ERR_UNSPEC, "unable to serialize ECDSA signature");
	}

	ECDSA_SIG_free(signature);

	*siglen = bsize;

	return buf;
}


/**
 * @brief	Sign a SHA-hashed body of data using the ECDSA algorithm.
 * @param	data	a pointer to the data buffer to be signed.
 * @param	dlen	the length, in bytes, of the data buffer to be signed.
 * @param	shabits	the number of bits for the desired SHA hash (160, 256, or 512).
 * @param	key	the EC key which will have its private portion used to sign the supplied data.
 * @param	siglen	a pointer to a variable that will receive the length of the data signature buffer on success.
 * @return	NULL on failure, or a pointer to the newly allocated signature data buffer on success.
 */
unsigned char * _ec_sign_sha_data(const unsigned char *data, size_t dlen, unsigned int shabits, EC_KEY *key, size_t *siglen) {

	unsigned char hashbuf[SHA_512_SIZE];

	if (!data || !dlen || !key || !siglen) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	} else if ((shabits != 160) && (shabits != 256) && (shabits != 512)) {
		RET_ERROR_PTR(ERR_BAD_PARAM, "ECDSA signature only accepts SHA hash sizes of 160, 256, or 512 bits");
	}

	if (_compute_sha_hash(shabits, data, dlen, hashbuf) < 0) {
		RET_ERROR_PTR(ERR_UNSPEC, "unable to compute SHA hash for ECDSA signature operation");
	}

	return (_ec_sign_data(hashbuf, shabits/8, key, siglen));
}


/**
 * @brief	Serialize an EC public key to be shared.
 * @param	key	a pointer to the EC key pair to have its public key serialized.
 * @param	outsize	a pointer to a variable that will receive the length of the serialized key on success.
 * @return	a pointer to the serialized EC public key on success, or NULL on failure.
 */
unsigned char * _serialize_ec_pubkey(EC_KEY *key, size_t *outsize) {

	unsigned char *buf = NULL;
	int bsize;

	if (!key || !outsize) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if ((bsize = i2o_ECPublicKey(key, &buf)) < 0) {
		PUSH_ERROR_OPENSSL();
		RET_ERROR_PTR(ERR_UNSPEC, "unable to serialize EC public key");
	}

	*outsize = bsize;

	return buf;
}


/**
 * @brief	Deserialize an EC public key stored in binary format.
 * @param	buf	a pointer to the buffer holding the EC public key in binary format.
 * @param	blen	the length, in bytes, of the buffer holding the EC public key.
 * @param	signing	if set, generate a key from the pre-defined EC signing curve;
 * 			if zero, the default encryption curve will be used instead.
 * @return	a pointer to the deserialized EC public key on success, or NULL on failure.
 */
EC_KEY * _deserialize_ec_pubkey(const unsigned char *buf, size_t blen, int signing) {

	EC_KEY *result;
	int nid;

	if (!buf || !blen) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	} else if (signing) {
		RET_ERROR_PTR(ERR_BAD_PARAM, "deserialization of signing keys is not supported");
	}

	nid = signing ? EC_SIGNING_CURVE : EC_ENCRYPT_CURVE;

	if (!(result = EC_KEY_new())) {
		PUSH_ERROR_OPENSSL();
		RET_ERROR_PTR(ERR_UNSPEC, "could not generate new EC key for deserialization");
	}

	if (EC_KEY_set_group(result, EC_GROUP_new_by_curve_name(nid)) != 1) {
		PUSH_ERROR_OPENSSL();
		EC_KEY_free(result);
		RET_ERROR_PTR(ERR_UNSPEC, "could not get curve group for deserialization");
	}

	if (!(result = o2i_ECPublicKey(&result, (const unsigned char **)&buf, blen))) {
		PUSH_ERROR_OPENSSL();
		EC_KEY_free(result);
		RET_ERROR_PTR(ERR_UNSPEC, "deserialization of EC public key portion failed");
	}

	return result;
}


/**
 * @brief	Serialize an EC private key into a data buffer.
 * @param	key	a pointer to the EC key pair to have its private key serialized.
 * @param	outsize	a pointer to a variable that will receive the length of the serialized key on success.
 * @return	a pointer to the serialized EC private key on success, or NULL on failure.
 */
unsigned char * _serialize_ec_privkey(EC_KEY *key, size_t *outsize) {

	unsigned char *buf = NULL;
	int bsize;

	if (!key || !outsize) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if ((bsize = i2d_ECPrivateKey(key, &buf)) < 0) {
		PUSH_ERROR_OPENSSL();
		RET_ERROR_PTR(ERR_UNSPEC, "unable to serialize EC private key");
	}

	*outsize = bsize;

	return buf;
}


/**
 * @brief	Deserialize an EC private key stored in binary format.
 * @param	buf	a pointer to the buffer holding the EC private key in binary format.
 * @param	blen	the length, in bytes, of the buffer holding the EC private key.
 * @param	signing	if set, generate a key from the pre-defined EC signing curve;
 * 			if zero, the default encryption curve will be used instead.
 * @return	a pointer to the deserialized EC private key on success, or NULL on failure.
 */
EC_KEY * _deserialize_ec_privkey(const unsigned char *buf, size_t blen, int signing) {

	EC_KEY *result;
	int nid;

	if (!buf || !blen) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	} else if (signing) {
		RET_ERROR_PTR(ERR_BAD_PARAM, "deserialization of signing keys is not supported");
	}

	nid = signing ? EC_SIGNING_CURVE : EC_ENCRYPT_CURVE;

	if (!(result = EC_KEY_new())) {
		PUSH_ERROR_OPENSSL();
		RET_ERROR_PTR(ERR_UNSPEC, "could not generate new EC key for deserialization");
	}

	if (EC_KEY_set_group(result, EC_GROUP_new_by_curve_name(nid)) != 1) {
		PUSH_ERROR_OPENSSL();
		EC_KEY_free(result);
		RET_ERROR_PTR(ERR_UNSPEC, "could not get curve group for deserialization");
	}

	if (!(result = d2i_ECPrivateKey(&result, (const unsigned char **)&buf, blen))) {
		PUSH_ERROR_OPENSSL();
		EC_KEY_free(result);
		RET_ERROR_PTR(ERR_UNSPEC, "deserialization of EC public key portion failed");
	}

	return result;
}


/**
 * @brief	Load an EC key from a file.
 * @param	filename	the name of the filename from which the key should be loaded.
 * @param	gptr		a pointer to an EC_GROUP variable that will receive the curve group on success.
 * @return	a pointer to the loaded EC key on success, or NULL on failure.
 */

/* old code for loading private key files generated by openssl tool, I'm changing this in order to read files we create programmatically via deserialization.
EC_KEY * _load_ec_privkey(const char *filename, const EC_GROUP **gptr) {


	EC_KEY *result;
	BIO *bio;

	if (!filename || !gptr) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if (!(bio = BIO_new(BIO_s_file()))) {
		PUSH_ERROR_OPENSSL();
		RET_ERROR_PTR(ERR_UNSPEC, NULL);
	}

	if ((BIO_read_filename(bio, filename)) != 1) {
		PUSH_ERROR_OPENSSL();
		BIO_free(bio);
		RET_ERROR_PTR(ERR_UNSPEC, "unable to read contents of EC private keyfile");
	}

	if (!(result = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL))) {
		PUSH_ERROR_OPENSSL();
		BIO_free(bio);
		RET_ERROR_PTR(ERR_UNSPEC, "unable to read EC private keyfile data");
	}

	BIO_free(bio);

	if (gptr && (!(*gptr = EC_KEY_get0_group(result)))) {
		PUSH_ERROR_OPENSSL();
		EC_KEY_free(result);
		RET_ERROR_PTR(ERR_UNSPEC, "unable to get group for EC private key");
	}

	return result;
*/

/**
 * @brief 	Load an EC private key from a file.
 * @param 	filename	the name of the filename from which the key should be loaded
 * @return	result		a pointer to the deserialized private key from the the file.
 */
EC_KEY * _load_ec_privkey(const char *filename) {

		char *filedata;
		unsigned char *bin;
		size_t size;
		EC_KEY *result;

		if(!filename) {
			RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
		}

		if(!(filedata = _read_pem_data(filename, "EC PRIVATE KEY", 1))) {
			RET_ERROR_PTR(ERR_UNSPEC, "could not read ec pubkey pem file");
		}

		if(!(bin = _b64decode(filedata, strlen(filedata), &size))) {
			RET_ERROR_PTR(ERR_UNSPEC, "could not decide b64 data");
		}

		if(!(result = _deserialize_ec_privkey(bin, size, 0))) {
			RET_ERROR_PTR(ERR_UNSPEC, "could not deserialize binary ec pubkey");
		}

		return result;
}

/**
 * @brief 	Load an EC public key from a file.
 * @param 	filename	the name of the filename from which the key should be loaded
 * @return	result		a pointer to the deserialized public key from the the file.
 */
EC_KEY * _load_ec_pubkey(const char *filename) {

	char *filedata;
	unsigned char *bin;
	size_t size;
	EC_KEY *result;

	if(!filename) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!(filedata = _read_pem_data(filename, "PUBLIC KEY", 1))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not read ec pubkey pem file");
	}

	if(!(bin = _b64decode(filedata, strlen(filedata), &size))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not decide b64 data");
	}

	if(!(result = _deserialize_ec_pubkey(bin, size, 0))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not deserialize binary ec pubkey");
	}

	return result;
}



/**
 * @brief	Generate an EC key pair.
 * @param	signing		if set, generate a key from the pre-defined EC signing curve;
 * 				if zero, the default encryption curve will be used instead.
 * @return	a newly allocated and generated EC key pair on success, or NULL on failure.
 */
EC_KEY * _generate_ec_keypair(int signing) {

	EC_GROUP *group;
	EC_KEY *result;

	// Temporarily disabled; see _crypto_init().
	if (signing) {
		RET_ERROR_PTR(ERR_BAD_PARAM, "generation of signing keys is not supported");
	}

	group = signing ? _signing_group : _encryption_group;

	if (!group) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not determine curve group for operation");
	}

	if (!(result = EC_KEY_new())) {
		PUSH_ERROR_OPENSSL();
		RET_ERROR_PTR(ERR_UNSPEC, "unable to allocate new EC key pair for generation");
	}

	if (EC_KEY_set_group(result, group) != 1) {
		PUSH_ERROR_OPENSSL();
		EC_KEY_free(result);
		RET_ERROR_PTR(ERR_UNSPEC, "unable to associate curve group with new EC key pair");
	}

	if (EC_KEY_generate_key(result) != 1) {
		PUSH_ERROR_OPENSSL();
		EC_KEY_free(result);
		RET_ERROR_PTR(ERR_UNSPEC, "unable to generate new EC key pair");
	}

	return result;
}


/**
 * @brief	Free an EC keypair.
 * @param	key	a pointer to the EC keypair to be freed.
 * @return	This function returns no value.
 */
void _free_ec_key(EC_KEY *key) {

	if (!key) {
//		fprintf(stderr, "Error: Attempted to free NULL EC key.\n");
		return;
	}

	EC_KEY_free(key);

	return;
}


/**
 * @brief	Generate an ed25519 key pair.
 * @return	a newly allocated and generated ed25519 key pair on success, or NULL on failure.
 */
ED25519_KEY * _generate_ed25519_keypair(void) {

	ED25519_KEY *result;

	if (!(result = malloc(sizeof(ED25519_KEY)))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, "could not generate ed25519 key because of memory allocation error");
	}

	memset(result, 0, sizeof(ED25519_KEY));

	if (RAND_bytes(result->private, sizeof(result->private)) != 1) {
		PUSH_ERROR_OPENSSL();
		_secure_wipe(result, sizeof(ED25519_KEY));
		free(result);
		RET_ERROR_PTR(ERR_UNSPEC, "could not generate ed25519 secret key");
	}

	ed25519_publickey(result->private, result->public);

	return result;
}


/**
 * @brief	Take an ed25519 signature of a data buffer.
 * @param	data
 * @param	dlen
 * @param	key
 * @param	sigbuf
 * @return	0 on success or -1 on failure.
 */
int _ed25519_sign_data(const unsigned char *data, size_t dlen, ED25519_KEY *key, ed25519_signature sigbuf) {

	if (!data || !dlen || !key || !sigbuf) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	ed25519_sign(data, dlen, key->private, key->public, sigbuf);

	return 0;
}


/**
 * @brief	Verify an ed25519 signature taken over a data buffer.
 * @param	data
 * @param	dlen
 * @param	key
 * @param	sigbuf
 * @return	1 if the signature matched the buffer, 0 if it did not, or -1 on failure.
 */
int _ed25519_verify_sig(const unsigned char *data, size_t dlen, ED25519_KEY *key, ed25519_signature sigbuf) {

	int result;

	if (!data || !dlen || !key || !sigbuf) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	result = ed25519_sign_open(data, dlen, key->public, sigbuf);

	if (!result) {
		return 1;
	}

	return 0;
}


/**
 * @brief	Free an ed25519 keypair.
 * @param	key	a pointer to the ed25519 keypair to be freed.
 * @return	This function returns no value.
 */
void _free_ed25519_key(ED25519_KEY *key) {

	if (!key) {
		return;
	}

	_secure_wipe(key, sizeof(ED25519_KEY));
	free(key);

	return;
}


/**
 * @brief	Load an ed25519 private key from a file.
 * @param	filename	the path of the armored file from which the ed25519 private key will be loaded.
 * @return	a pointer to a newly allocated ed25519 keypair on success, or NULL on failure.
 */
ED25519_KEY * _load_ed25519_privkey(const char *filename) {

	ED25519_KEY *result;
	unsigned char *keydata;
	char *pemdata;
	size_t klen;

	if (!filename) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if (!(pemdata = _read_pem_data(filename, "ED25519 PRIVATE KEY", 1))) {
		RET_ERROR_PTR(ERR_UNSPEC, "unable to read ed25519 private key data from PEM file");
	}

	keydata = _b64decode(pemdata, strlen(pemdata), &klen);
	_secure_wipe(pemdata, strlen(pemdata));
	free(pemdata);

	if (!keydata || (klen != ED25519_KEY_SIZE)) {

		if (keydata) {
			_secure_wipe(keydata, klen);
			free(keydata);
		}

		RET_ERROR_PTR(ERR_UNSPEC, "bad ED25519 key data was read from file");
	}

	if (!(result = malloc(sizeof(ED25519_KEY)))) {
		PUSH_ERROR_SYSCALL("malloc");
		_secure_wipe(keydata, klen);
		free(keydata);
		RET_ERROR_PTR(ERR_NOMEM, "unable to allocate space for ED25519 key");
	}

	memset(result, 0, sizeof(ED25519_KEY));
	memcpy(result->private, keydata, sizeof(result->private));
	_secure_wipe(keydata, klen);
	free(keydata);
	ed25519_publickey(result->private, result->public);

	return result;
}


/**
 * @brief
 * @note	This function was taken from providers/cryptography/openssl.c
 * @param	input
 * @param	ilen
 * @param	output
 * @param	olen
 * @return
 */
void * _ecies_env_derivation(const void *input, size_t ilen, void *output, size_t *olen) {

	if (EVP_Digest(input, ilen, output, (unsigned int *)olen, _ecies_envelope_evp, NULL) != 1) {
		return NULL;
	}

	return output;
}


/**
  *     @brief  Compute a derived AES-256 key from the intersection of a public EC key and a private EC key.
  *     @param  key
  *     @param  ephemeral
  *     @param  keybuf
  *     return
  */
int _compute_aes256_kek(EC_KEY *public_key, EC_KEY *private_key, unsigned char *keybuf) {

	unsigned char aeskey[SHA_512_SIZE];
	int i;

	if (!public_key || !private_key || !keybuf) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if (ECDH_compute_key(aeskey, sizeof(aeskey), EC_KEY_get0_public_key(public_key), private_key, _ecies_env_derivation) != SHA_512_SIZE) {
		PUSH_ERROR_OPENSSL();
		RET_ERROR_INT(ERR_UNSPEC, "could not derive AES key from EC keypair");
	}

	for(i = 0; i < 16; ++i) {
		keybuf[i] = aeskey[i] ^ aeskey[i+16];
	}

	memcpy(keybuf + 16, aeskey+32, 32);
	_secure_wipe(aeskey, sizeof(aeskey));

	return 0;
}


/**
 * @brief	Fill a buffer with a sequence of (securely) random bytes.
 * @param	buf	a pointer to the buffer to be filled with random bytes.
 * @param	len	the length, in bytes, of the buffer to be filled.
 * @return	0 on success or -1 on failure.
 */
int _get_random_bytes(void *buf, size_t len) {

	if (!buf) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if (!RAND_bytes(buf, len)) {
		PUSH_ERROR_OPENSSL();
		RET_ERROR_INT(ERR_UNSPEC, "unable to generate random bytes");
	}

	return 0;
}


/**
 * @brief	Encrypt a data buffer using an AES-256 key (in CBC mode).
 * @param	outbuf	a pointer to the output buffer that will receive the encrypted data. NOTE: the size of this buffer must
 * 			be successfully negotiated by the caller.
 * @param	data	a pointer to the data buffer to be encrypted.
 * @param	dlen	the size, in bytes, of the data buffer to be encrypted.
 * @param	key	a pointer to the 32-byte buffer holding the AES-256 encryption key for the operation.
 * @param	iv	a pointer to the 32-byte initialization vector to be used for the encryption process.
 * @return	the number of bytes successfully encrypted on success, or -1 on failure.
 */
int _encrypt_aes_256(unsigned char *outbuf, const unsigned char *data, size_t dlen, const unsigned char *key, const unsigned char *iv) {

	EVP_CIPHER_CTX *ctx;
	int len, result;

	if (!outbuf || !data || !dlen || !key || !iv) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if (dlen % AES_256_PADDING_SIZE) {
		RET_ERROR_INT(ERR_BAD_PARAM, "input data was not aligned to required padding size");
	}

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		PUSH_ERROR_OPENSSL();
		RET_ERROR_INT(ERR_UNSPEC, "unable to create new context for AES-256 encryption");
	}

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
		PUSH_ERROR_OPENSSL();
		RET_ERROR_INT(ERR_UNSPEC, "unable to initialize context for AES-256 encryption");
	}

	if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
		PUSH_ERROR_OPENSSL();
		RET_ERROR_INT(ERR_UNSPEC, "unable to set no padding for AES-256 encryption");
	}

	if (EVP_EncryptUpdate(ctx, outbuf, &len, data, dlen) != 1) {
		PUSH_ERROR_OPENSSL();
		RET_ERROR_INT(ERR_UNSPEC, "AES-256 encryption update failed");
	}

	result = len;

	if (EVP_EncryptFinal_ex(ctx, (unsigned char *)outbuf+len, &len) != 1) {
		PUSH_ERROR_OPENSSL();
		RET_ERROR_INT(ERR_UNSPEC, "AES-256 encryption finalization failed");
	}

	result += len;
	EVP_CIPHER_CTX_free(ctx);
	ctx = NULL;

	return result;
}


/**
 * @brief	Decrypt a data buffer using an AES-256 key (in CBC mode).
 * @param	outbuf	a pointer to the output buffer that will receive the decrypted data. NOTE: the size of this buffer must
 * 			be successfully negotiated by the caller.
 * @param	data	a pointer to the data buffer to be decrypted.
 * @param	dlen	the size, in bytes, of the data buffer to be decrypted.
 * @param	key	a pointer to the 32-byte buffer holding the AES-256 decryption key for the operation.
 * @param	iv	a pointer to the 32-byte initialization vector to be used for the decryption process.
 * @return	the number of bytes successfully decrypted on success, or -1 on failure.
 */
int _decrypt_aes_256(unsigned char *outbuf, const unsigned char *data, size_t dlen, const unsigned char *key, const unsigned char *iv) {

	EVP_CIPHER_CTX *ctx = NULL;
	int len, result;

	if (!outbuf || !data || !dlen || !key || !iv) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if (dlen % AES_256_PADDING_SIZE) {
		RET_ERROR_INT(ERR_BAD_PARAM, "input data was not aligned to required padding size");
	}

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		PUSH_ERROR_OPENSSL();
		RET_ERROR_INT(ERR_UNSPEC, "unable to create new context for AES-256 decryption");
	}

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
		PUSH_ERROR_OPENSSL();
		RET_ERROR_INT(ERR_UNSPEC, "unable to initialize context for AES-256 decryption");
	}

	if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
		PUSH_ERROR_OPENSSL();
		RET_ERROR_INT(ERR_UNSPEC, "unable to set no padding for AES-256 decryption");
	}

	if (EVP_DecryptUpdate(ctx, outbuf, &len, data, dlen) != 1) {
		PUSH_ERROR_OPENSSL();
		RET_ERROR_INT(ERR_UNSPEC, "AES-256 decryption update failed");
	}

	result = len;

	if (EVP_DecryptFinal_ex(ctx, (unsigned char *)outbuf+len, &len) != 1) {
		PUSH_ERROR_OPENSSL();
		RET_ERROR_INT(ERR_UNSPEC, "AES-256 decryption finalization failed");
	}

	result += len;

	EVP_CIPHER_CTX_free(ctx);
	ctx = NULL;

	return result;
}
