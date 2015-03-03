
#ifndef INCLUDE_DMESSAGE_DMESSAGE_H_
#define INCLUDE_DMESSAGE_DMESSAGE_H_

#include <openssl/crypto.h>
#include "core/magma.h"


#define CHUNK_LENGTH_SIZE	3

#define AES256_KEY_SIZE		32

// Common headers that are expected to exist in any message.
#define COMMON_HEADER_TO	1
#define COMMON_HEADER_FROM	2
#define COMMON_HEADER_SUBJECT	3
#define COMMON_HEADER_DATE	4

#define COMMON_HEADERS_TOTAL	4


typedef enum {
	CHUNK_TYPE_ENVELOPE    = 0,
	CHUNK_TYPE_TRACING     = 1,
	CHUNK_TYPE_ORIGIN      = 2,
	CHUNK_TYPE_DESTINTAION = 3
} chunk_type_t;


typedef struct __attribute__ ((__packed__)) {
	unsigned char random[16];		// Random bytes.
	unsigned char iv[16];			// Initialization vector.
	unsigned char aes_key[AES256_KEY_SIZE];
} dmime_keyslot_t;


typedef struct __attribute__ ((__packed__)) {
	unsigned char hmac[ED25519_SIG_SIZE];	// The 64-byte ED25519 HMAC of the chunk plaintext.
	unsigned char type;			// Chunk type.
	unsigned char size[CHUNK_LENGTH_SIZE];	// The 3-byte size of the chunk.
	unsigned char *data;			// The actual data associated with this chunk.
	dmime_keyslot_t *author;		// The AES256 key 'A' slot.
	dmime_keyslot_t *recipient;		// The AES256 key 'R' slot.
	dmime_keyslot_t *other;			// The AES256 key for 'O' or 'D', accordingly.
} dmime_chunk_t;


typedef struct {
	stringer_t *common[COMMON_HEADERS_TOTAL];
	inx_t *other;
} dmsg_header_t;


typedef struct {
	dmime_chunk_t *display_multi_part;
	dmime_chunk_t *display_part;
	dmime_chunk_t *body_multi_part;
	dmime_chunk_t *body_part;
} dmsg_content_t;				// Only encrypted for A+R
						// Encrypted to the delivery address's public key


typedef struct {
	void *user_sigs;			// A fingerprint consisting of the SHA512 hash for the preceding encrypted blocks signed with the sending user's private key.
	void *domain_sigs;			// A fingerprint of the SHA-512 hash of the preceding encrypted blocks plus the dest header in the envelope and user generated signature, encrypted with the domain's private key.
} dmsg_signature_t;


typedef struct {
	void *destination;			// Unencrypted;
	char *receiver;
	char *receiver_key;
	char *origin;
	char *origin_key;
} dmsg_envelope_t;


typedef struct {
	dmsg_envelope_t *envelope; 	// ? Include "reply-to" ?
	dmime_chunk_t *author;			// Encrypted for AOR
	dmime_chunk_t *recipient;		// Encrypted for ADR
	dmsg_content_t *content;
	dmsg_signature_t *signature;
} dmap_msg_t;


placer_t parse_rfc822_headers(stringer_t *message, dmsg_header_t *dheader);
stringer_t *mime_to_dmime(stringer_t *input);
stringer_t *dmime_to_mime(stringer_t *input);

#endif /* INCLUDE_DMESSAGE_DMESSAGE_H_ */
