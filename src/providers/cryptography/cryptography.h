
/**
 * @file /magma/providers/cryptography/cryptography.h
 *
 * @brief	Functions used to perform cryptographic operations and provide truly random data.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#ifndef MAGMA_PROVIDERS_CRYPTOGRAPHY_H
#define MAGMA_PROVIDERS_CRYPTOGRAPHY_H

// The STACIE number constants for clamping hash rounds between 8 and 16,777,216, which represents the number of possible
// values for an unsigned 24 bit integer, if you include 0. In other words 0 to 16,777,215 equals 16,777,216.
#define STACIE_KEY_ROUNDS_MIN		8
#define STACIE_KEY_ROUNDS_MAX		16777216

// The STACIE token derivation stage uses a fixed number of hash rounds, and that number is dictated by this parameter.
#define STACIE_TOKEN_ROUNDS			8

// This STACIE implementation will always use salt and nonce values which are 128 bytes in length.
#define STACIE_SALT_LENGTH		128
#define STACIE_NONCE_LENGTH		128

// This STACIE implementation uses SHA-2/512 resulting in key, token, and shard lengths of 64 bytes.
#define STACIE_KEY_LENGTH		64
#define STACIE_TOKEN_LENGTH		64
#define STACIE_SHARD_LENGTH		64

// This STACIE implementation only supports realm encryption of buffers up to 16,777,215 bytews in length.
#define STACIE_ENCRYPT_MIN		1
#define STACIE_ENCRYPT_MAX		16777215
#define STACIE_BLOCK_LENGTH		16
#define STACIE_ENVELOPE_LENGTH	34

/// openssl.c
char *  ssl_error_string(chr_t *buffer, int_t length);

/// random.c
bool_t        rand_start(void);
bool_t        rand_thread_start(void);
int16_t       rand_get_int16(void);
int32_t       rand_get_int32(void);
int64_t       rand_get_int64(void);
int8_t        rand_get_int8(void);
size_t        rand_write(stringer_t *s);
stringer_t *  rand_choices(chr_t *choices, size_t len);
uint16_t      rand_get_uint16(void);
uint32_t      rand_get_uint32(void);
uint64_t      rand_get_uint64(void);
uint8_t       rand_get_uint8(void);
void          rand_stop(void);

/// stacie.c
stringer_t *  stacie_entropy_seed_derive(uint32_t rounds, stringer_t *password, stringer_t *salt);
stringer_t *  stacie_hashed_key_derive(stringer_t *base, uint32_t rounds, stringer_t *username, stringer_t *password, stringer_t *salt);
stringer_t *  stacie_hashed_token_derive(stringer_t *base, stringer_t *username, stringer_t *salt, stringer_t *nonce);
stringer_t *  stacie_nonce_create(stringer_t *output);
stringer_t *  stacie_realm_cipher_key(stringer_t *realm_key);
stringer_t *  stacie_realm_decrypt(stringer_t *vector_key, stringer_t *tag_key, stringer_t *cipher_key, stringer_t *buffer);
stringer_t *  stacie_realm_encrypt(uint16_t serial, stringer_t *vector_key, stringer_t *tag_key, stringer_t *cipher_key, stringer_t *buffer);
stringer_t *  stacie_realm_key_derive(stringer_t *master_key, stringer_t *realm, stringer_t *shard);
stringer_t *  stacie_realm_tag_key(stringer_t *realm_key);
stringer_t *  stacie_realm_vector_key(stringer_t *realm_key);
uint32_t      stacie_rounds_calculate(stringer_t *password, uint32_t bonus);
stringer_t *  stacie_salt_create(stringer_t *output);
stringer_t *  stacie_shard_create(stringer_t *output);

#endif
