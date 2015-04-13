#ifndef DMIME_H
#define DMIME_H

#include "core/magma.h"
#include "common/dcrypto.h"
#include "common/error.h"
#include "signet/signet.h"

#define TRACING_LENGTH_SIZE	2
#define TRACING_HEADER_SIZE	4
#define MESSAGE_LENGTH_SIZE	4
#define MESSAGE_HEADER_SIZE	6
#define CHUNK_LENGTH_SIZE	3
#define CHUNK_HEADER_SIZE	4

#define DMIME_CHUNK_TYPE_MAX	256

#define MINIMUM_PAYLOAD_SIZE	256

#define ALTERNATE_PADDING_ALGORITHM_ENABLED	1
#define	ALTERNATE_USER_KEY_APPLIED_TO_DATE	2
#define GZIP_COMPRESSION_ENABLED		4
#define	DATA_SEGMENT_CONTINUATION_ENABLED	128

#define META_BOUNCE				1
#define DISPLAY_BOUNCE				2

#define DEFAULT_CHUNK_FLAGS			0

// Actor type, used to encrypt and retrieve the correct keyslot, kek, maybe more
typedef enum {
	id_author			= 0,
	id_origin			= 1,
	id_destination			= 2,
	id_recipient			= 3
} dmime_actor_t;

// Chunk type, used as index to global table of chunk keys dmime_chunk_keys
typedef enum {
	// The envelope.
	CHUNK_TYPE_NONE			= 0,
	CHUNK_TYPE_EPHEMERAL		= 2,	// The only non-standard chunk for transmitting ephemeral ed25519 public key.
	CHUNK_TYPE_ALTERNATE,			// TODO nothing for alternate chunk types is implemented. Lots of functions will need to be changed for this functionality to be implemented PLEASE BE THOROUGH.
	CHUNK_TYPE_ORIGIN,
	CHUNK_TYPE_DESTINATION,

	// Metadata 
	CHUNK_TYPE_META_COMMON		= 33,
	CHUNK_TYPE_META_OTHER,

	// Display section.
//	CHUNK_TYPE_DISPLAY_MULTI	= 65,
//	CHUNK_TYPE_DISPLAY_ALT		= 66,
	CHUNK_TYPE_DISPLAY_CONTENT	= 67,

	// Attachments section
//	CHUNK_TYPE_ATTACH_MULTI		= 129,
//	CHUNK_TYPE_ATTACH_ALT		= 130,
	CHUNK_TYPE_ATTACH_CONTENT	= 131,

	// Signatures (final section).
	// All signatures are taken over encrypted data, excluding the first 5 bytes (type+length) of the DMIME header.
	CHUNK_TYPE_SIG_AUTHOR_TREE	= 225,	// Required. For light clients wanting to verify chunk hashes provided by the server.
	CHUNK_TYPE_SIG_AUTHOR_FULL	= 226,	// Required

	// Only one of these bounce signatures is recommended, if both are present then.
	CHUNK_TYPE_SIG_ORIGIN_META_BOUNCE	= 248,
	CHUNK_TYPE_SIG_ORIGIN_DISPLAY_BOUNCE    = 249,

	CHUNK_TYPE_SIG_ORIGIN_FULL		= 255	// Required.
} dmime_chunk_type_t;

// Chunk section, is specified for every chunk_type_t in the global table of chunk keys dmime_chunk_keys
typedef enum {
	CHUNK_SECTION_NONE		= 0,
	CHUNK_SECTION_ENVELOPE 		= 1,
	CHUNK_SECTION_METADATA 		= 2,
	CHUNK_SECTION_DISPLAY 		= 4,
	CHUNK_SECTION_ATTACH 		= 8,
	CHUNK_SECTION_SIG 		= 16, 
} dmime_chunk_section_t;

// Chunk payload type is specified for every chunk_type_t in teh global table of chunk keys dmime_chunk_keys
typedef enum {
	PAYLOAD_TYPE_NONE               = 0,
	PAYLOAD_TYPE_EPHEMERAL,
	PAYLOAD_TYPE_STANDARD,
	PAYLOAD_TYPE_SIGNATURE,
} dmime_payload_type_t;


// message chunk state used by message chunks to keep track of encrypted and unencrypted chunks. 
// Must be used in conjunction with the 'encrypted' flag in the global table of chunk types to determine if encryption is necessary.
typedef enum {
	MESSAGE_CHUNK_STATE_NONE        = 0,
	MESSAGE_CHUNK_STATE_UNKNOWN,
	MESSAGE_CHUNK_STATE_CREATION,
	MESSAGE_CHUNK_STATE_ENCODED,
	MESSAGE_CHUNK_STATE_SIGNED,
	MESSAGE_CHUNK_STATE_ENCRYPTED
} dmime_message_chunk_state_t;

// State of dmime_content_t object, used to identify if it is ready to be turned into a dmime_message_t object, maybe more.
typedef enum {
	DMIME_OBJECT_STATE_NONE               = 0,
	DMIME_OBJECT_STATE_CREATION,
	DMIME_OBJECT_STATE_LOADED_ENVELOPE,
	DMIME_OBJECT_STATE_LOADED_SIGNETS,
	DMIME_OBJECT_STATE_INCOMPLETE_ENVELOPE,
	DMIME_OBJECT_STATE_INCOMPLETE_METADATA,
	DMIME_OBJECT_STATE_COMPLETE
} dmime_object_state_t;


// State of dmime_message_t, used to identify if the encrypted message contains the user and domain signatures.
// This is used by origin to determine whether the message is ready to be signed and by destination and recipient whether the message contains required chunks to be valid.
typedef enum {
	MESSAGE_STATE_NONE              = 0,
	MESSAGE_STATE_INCOMPLETE,
	MESSAGE_STATE_EMPTY,
	MESSAGE_STATE_ENCODED,
	MESSAGE_STATE_CHUNKS_SIGNED,
	MESSAGE_STATE_ENCRYPTED,
	MESSAGE_STATE_AUTHOR_SIGNED,
	MESSAGE_STATE_COMPLETE
} dmime_message_state_t;

// structure to easily store the KEKs and IVs
typedef struct __attribute__ ((packed)) {
	unsigned char iv[16];
	unsigned char key[AES_256_KEY_SIZE];
} dmime_kek_t;

typedef dmime_kek_t dmime_kekset_t[4];

// Structure of a dmime_chunk_key_t, dmime_chunk_keys is a global table of these structures, 1 for every chunk_type_t.
typedef struct {

	unsigned int required;
	unsigned int unique;
	unsigned int encrypted;
	unsigned int sequential;

	dmime_chunk_section_t section;
	dmime_payload_type_t payload;

	unsigned int auth_keyslot;
	unsigned int orig_keyslot;
	unsigned int dest_keyslot;
	unsigned int recp_keyslot;

	char *name;
	char *description;
} dmime_chunk_key_t;


// global table of chunk types
extern dmime_chunk_key_t dmime_chunk_keys[DMIME_CHUNK_TYPE_MAX];

// TODO use -Wpacked compiler option, packed structures are below:
// Chunk 

//tracing structure 
typedef struct __attribute__ ((packed)) {
	unsigned char size[TRACING_LENGTH_SIZE];
	unsigned char data[];
} dmime_tracing_t;

//ephemeral payload structure
typedef unsigned char dmime_ephemeral_payload_t[EC_PUBKEY_SIZE];

//standard payload structure
typedef struct __attribute__ ((packed)) {
	unsigned char signature[ED25519_SIG_SIZE];
	unsigned char data_size[CHUNK_LENGTH_SIZE];
	unsigned char flags;
	unsigned char pad_len;
	unsigned char data[];
} dmime_standard_payload_t;

//signature payload structure 
typedef unsigned char dmime_signature_payload_t[ED25519_SIG_SIZE];

//encrypted payload structure
typedef unsigned char * dmime_encrypted_payload_t;

// keyslot contains the aes keys. Each chunk can have between 0 and 4 keyslots.
typedef struct __attribute__ ((packed)) {
	unsigned char random[16];		// Random bytes.
	unsigned char iv[16];			// Initialization vector.
	unsigned char aes_key[AES_256_KEY_SIZE];
} dmime_keyslot_t;

// message chunk 
typedef struct __attribute__ ((packed)) {
	dmime_message_chunk_state_t state;
	size_t serial_size;				// this size is used to serialize the chunk which follows
	unsigned char type;
	unsigned char payload_size[CHUNK_LENGTH_SIZE];
	unsigned char data[];
} dmime_message_chunk_t;

typedef struct {
	// DIME magic number for current version of dmime messages
	dime_number_t dime_num;
	// message size
	uint32_t size;
	// tracing
	dmime_tracing_t *tracing;
	// ephemeral chunk
	dmime_message_chunk_t *ephemeral;
	// origin chunk
	dmime_message_chunk_t *origin;
	// destination chunk
	dmime_message_chunk_t *destination;
	// common headers chunk
	dmime_message_chunk_t *common_headers;
	// other headers chunk
	dmime_message_chunk_t *other_headers;
	// pointer to an array of display chunks terminated by a NULL pointer
	dmime_message_chunk_t **display;
	// pointer to an array of attachment  chunks terminated by a NULL pointer
	dmime_message_chunk_t **attach;
	// author tree sig chunk
	dmime_message_chunk_t *author_tree_sig;
	// author full sig chunk
	dmime_message_chunk_t *author_full_sig;
	// origin meta bounce sig chunk
	dmime_message_chunk_t *origin_meta_bounce_sig;
	// origin display bounce sig chunk
	dmime_message_chunk_t *origin_display_bounce_sig;
	// origin full sig chunk
	dmime_message_chunk_t *origin_full_sig;
	//state
	dmime_message_state_t state;
} dmime_message_t;


// Content chunk contains only information necessary by the consumer. There are no signatures, keyslots or anything else.
// This is the data format that the author loads the information into and the format that the recipient fully decrypts the message chunk into after all validation is completed.

struct object_chunk;

typedef struct object_chunk {
	struct object_chunk *next;
	dmime_chunk_type_t type;
	unsigned char flags;
	size_t data_size;
	unsigned char *data;
} dmime_object_chunk_t;


/*header parsing */
#define DMIME_NUM_COMMON_HEADERS     7

typedef enum {
	HEADER_TYPE_DATE = 0,
	HEADER_TYPE_TO,
	HEADER_TYPE_CC,
	HEADER_TYPE_FROM,
	HEADER_TYPE_ORGANIZATION,
	HEADER_TYPE_SUBJECT,
	HEADER_TYPE_NONE
} dmime_header_type_t;

typedef struct {
	int required;
	char *label;
	size_t label_length;
} dmime_header_key_t;

typedef struct {
	stringer_t * headers[DMIME_NUM_COMMON_HEADERS];
} dmime_common_headers_t;

extern dmime_header_key_t dmime_header_keys[DMIME_NUM_COMMON_HEADERS];

typedef struct {
	// The current actor on the object.
	dmime_actor_t actor;
	// The author and recipient's dmail addresses.
	stringer_t *author;
	stringer_t *recipient;
	// The origin and destination domains.
	stringer_t *origin;
	stringer_t *destination;
	// Signets for the author and recipient and their orgs.
	signet_t *signet_author;
	signet_t *signet_recipient;
	signet_t *signet_origin;
	signet_t *signet_destination;
	// Common headers.
	dmime_common_headers_t *common_headers;
	// Other headers
	stringer_t *other_headers;
	// display and attachment chunks
	dmime_object_chunk_t *display;
	dmime_object_chunk_t *attach;
	// object state
	dmime_object_state_t state;
} dmime_object_t;


typedef struct {
	stringer_t *auth_recp;
	stringer_t *auth_recp_signet;
	stringer_t *dest_orig;
	stringer_t *dest_orig_fingerprint;
} dmime_envelope_object_t;

#endif
