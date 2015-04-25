#include <dmessage/dmsg.h>

/*
 * @brief	Retrieves pointer to the specified chunk type key from the global chunk key structure.
 * @param	type		Specified chunk type.
 * @return	Returns pointer to a dmime_chunk_key_t structure.
*/
dmime_chunk_key_t *_dmsg_get_chunk_type_key(dmime_chunk_type_t type) {

	return &(dmime_chunk_keys[type]);
}


/*
 * @brief	Generates a random value and calculates the padding byte and padding length for a given input size and padding algorithm
 * @param	dsize		input size
 * @param	flags		chunk flags containing the flag which specifies which padding algorithm isz used
 * @return	0 on success, all other values signify failure.
*/
int _dmsg_padlen(size_t dsize, unsigned char flags, unsigned int *padlen, unsigned char *padbyte) {

	unsigned char rand;
	unsigned char temp;

	if(!padlen || !padbyte) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	//TODO FIXME use of random number generator, will need some modification in the future for seeding, thread-safety, etc.

	if(_get_random_bytes(&rand, 1)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not generate a random byte");
	}

	if(flags & ALTERNATE_PADDING_ALGORITHM_ENABLED) {
		*padlen = 16 * rand + 16 - (dsize % 16);
		*padbyte = rand;
	} else {
		if(dsize < MINIMUM_PAYLOAD_SIZE) {
			temp = MINIMUM_PAYLOAD_SIZE - dsize;
			*padlen = temp + (16 * (rand % ((dsize / 16) + 1)));
			*padbyte = (unsigned char)(*padlen);
		} else {
			*padlen = 16 - (dsize % 16) + (16 * (rand % 16));
			*padbyte = (unsigned char)(*padlen);
		}

	}

	return 0;
}


/*
 * @brief	Returns the payload of the specified dmime message chunk.
 * @param	chunk		Pointer to the dmime chunk. Its type, state and payload size must be initialized.
 * @return	Void pointer to be casted to the appropriate payload structure, NULL on failure.
*/
void *_dmsg_get_chunk_payload(dmime_message_chunk_t *chunk) {

	dmime_chunk_key_t *key;

	if(!chunk) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(chunk->state < MESSAGE_CHUNK_STATE_CREATION) {
		RET_ERROR_PTR(ERR_UNSPEC, "cannot retrieve the payload structure from an uninitialized chunk");
	}

	if(!((key = _dmsg_get_chunk_type_key(chunk->type))->section)) {
		RET_ERROR_PTR(ERR_UNSPEC, "cannot retrieve the chunk type key for the specified chunk");
	}

	if(key->payload == PAYLOAD_TYPE_NONE) {
		RET_ERROR_PTR(ERR_UNSPEC, "specified chunk is of unknown type");
	}

	return &(chunk->data[0]);
}


/*
 * @brief	Returns pointer to the specified keyslot of the dmime message chunk.
 * @param	chunk		Pointer to the dmime message chunk.
 * @param	num		number of the desired keyslot.
 * @return	Pointer to the keyslot.
*/
dmime_keyslot_t *_dmsg_get_chunk_keyslot_by_num(dmime_message_chunk_t *chunk, size_t num){

	dmime_chunk_key_t *key;
	size_t num_slots;

	if(!chunk || num < 1 || num > 4) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!((key = _dmsg_get_chunk_type_key(chunk->type))->section)) {
		RET_ERROR_PTR(ERR_UNSPEC, "specified chunk type is invalid");
	}

	if((num_slots = key->auth_keyslot + key->orig_keyslot + key->dest_keyslot + key->recp_keyslot) < num) {
		RET_ERROR_PTR(ERR_UNSPEC, "there are less keyslots than the keyslot number specified");
	}

	switch(key->payload) {

	case PAYLOAD_TYPE_SIGNATURE:
		return (dmime_keyslot_t *)(&(chunk->data[0]) + ED25519_SIG_SIZE + ((num - 1) * sizeof(dmime_keyslot_t)));
	case PAYLOAD_TYPE_STANDARD:
		return (dmime_keyslot_t *)(&(chunk->data[0]) + _int_no_get_3b(&(chunk->payload_size[0])) + ((num - 1) * sizeof(dmime_keyslot_t)));
	default:
		RET_ERROR_PTR(ERR_UNSPEC, "there are no keyslots for this chunk");
	}
}


/*
 * @brief	Destroys dmime message chunk.
 * @param	chunk		Dmime message chunk to be destroyed.
 * @return	void.
*/
void    _dmsg_destroy_message_chunk(dmime_message_chunk_t *chunk) {

	if(!chunk) {
		return;
	}

	_secure_wipe(chunk, sizeof(dmime_message_chunk_state_t) + sizeof(size_t) + chunk->serial_size);
	free(chunk);
}


/*
 * @brief	Allocates memory for and encodes a dmime_message_chunk_t structure with data provided.
 * @param	type		Type of chunk being created. Is necessary to calculate total number of bytes that must be allocated.
 * @param	data		Data that will be encoded into the chunk.
 * @param	insize		Size of data.
 * @param	flags		flags to be set for chunk, only relevant for standard payload chunk types.
 * @return	Pointer to the newly allocated and encoded dmime_message_chunk_t structure.
*/
dmime_message_chunk_t *_dmsg_create_message_chunk(dmime_chunk_type_t type, const unsigned char *data, size_t insize, unsigned char flags) {

	dmime_chunk_key_t *key;
	void *payload;
	dmime_message_chunk_t *result;
	// total_size is the amount of memory needed to be allocated to the dmime_message_chunk_t structure
	// serial_size is the size of the serialized result, corresponds to result->serial_size
	size_t total_size = 0, serial_size = CHUNK_HEADER_SIZE;
	// payload_size needs to be less than or equal to UNSIGNED_MAX_3_BYTE, corresponds to result->payload_size
	// data_size is specific only to the standard payload, corresponds to
	uint32_t payload_size = 0, data_size = 0;
	unsigned char padbyte = 0;
	unsigned int num_keyslots = 0, padlen = 0;

	if(!data || !insize) {
		// Currently we do not support chunks with empty payloads TODO
		RET_ERROR_PTR(ERR_BAD_PARAM, "no data provided for the chunk");
	}

	//check that the input size is not too big
	if(insize > UNSIGNED_MAX_3_BYTE) {
		RET_ERROR_PTR(ERR_UNSPEC, "the input data size is too large");
	}

	//get the chunk type key
	if(!((key = _dmsg_get_chunk_type_key(type))->section)) {
		RET_ERROR_PTR(ERR_UNSPEC, "specified chunk type is invalid");
	}

	//switch statement for payload type to determine the payload size, payload size will be finalized after this
	switch(key->payload) {

	case PAYLOAD_TYPE_SIGNATURE:
		// check that signature length is appropriate
		if(insize != ED25519_SIG_SIZE) {
			RET_ERROR_PTR(ERR_UNSPEC, "provided data does not have correct size to be a signature");
		}
		// payload size will be equal to the input size
		payload_size = insize;
		break;
	case PAYLOAD_TYPE_EPHEMERAL:
		// check that the public encryption key length is appropriate
		if(insize != EC_PUBKEY_SIZE) {
			RET_ERROR_PTR(ERR_UNSPEC, "provided data does not have correct size to be a public encryption key");
		}
		// payload size will be equal to the input size
		payload_size = insize;
		break;
	case PAYLOAD_TYPE_STANDARD:
		// calculate padding length and padding byte according to the specified flag
		if(_dmsg_padlen(insize + 69, flags, &padlen, &padbyte)) {
			RET_ERROR_PTR(ERR_UNSPEC, "could not calculate padding");
		}
		//payload size will be equal to the sum of the following:
		//64 bytes for payload signature, 3 bytes for the length, 1 byte for flags, 1 byte for padding byte, input size, padding size
		payload_size = 69 + insize + padlen;
		//data size is the input size
		data_size = insize;
		break;
	default:
		RET_ERROR_PTR(ERR_UNSPEC, "unsupported payload type");
		break;

	}

	// if the payload size is greater than the largest number that can be represented by 3 bytes, it's too big
	if(payload_size > UNSIGNED_MAX_3_BYTE) {
		RET_ERROR_PTR(ERR_UNSPEC, "chunk size is too large");
	}

	// add the payload size to the serialized size
	serial_size += payload_size;
	// Add the sizes of state and serial_size structure members to total_size
	total_size += sizeof(dmime_message_chunk_state_t) + sizeof(size_t);

	// Use the key to find the number of keyslots for particular chunk_type
	if(key->encrypted) {
		num_keyslots += (key->auth_keyslot + key->orig_keyslot + key->dest_keyslot + key->recp_keyslot);
	}

	// add the length for all the needed keyslots to the serialized size, serialized size is now finalized
	serial_size += (num_keyslots * sizeof(dmime_keyslot_t));
	// add the serialized size to the total size, total size is now finalized
	total_size += serial_size;

	// allocate memory to the message chunk structure
	if(!(result = malloc(total_size))) {
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate memory for message chunk structure");
	}

	//flush it and set the static members, set state to creation as we have not finished encoding the chunk
	memset(result, 0, total_size);
	result->state = MESSAGE_CHUNK_STATE_NONE;
	result->serial_size = serial_size;
	result->type = (unsigned char)type;
	_int_no_put_3b(&(result->payload_size[0]), payload_size);
	result->state = MESSAGE_CHUNK_STATE_CREATION;

	// get chunk payload
	if(!(payload = _dmsg_get_chunk_payload(result))) {
		_dmsg_destroy_message_chunk(result);
		RET_ERROR_PTR(ERR_UNSPEC, "could not retrieve standard chunk");
	}

	//this switch statement will encode the data into the chunk
	switch(key->payload) {

	case PAYLOAD_TYPE_SIGNATURE:
		// copy the data into the payload
		memcpy(payload, data, ED25519_SIG_SIZE);
		break;
	case PAYLOAD_TYPE_EPHEMERAL:
		//copy the data into the payload
		memcpy(payload, data, EC_PUBKEY_SIZE);
		break;
	case PAYLOAD_TYPE_STANDARD:
		//set the data segment 3 byte size
		_int_no_put_3b(&(((dmime_standard_payload_t *)payload)->data_size[0]), data_size);
		//set the flags byte
		((dmime_standard_payload_t *)payload)->flags = flags;
		//set the pad byte
		((dmime_standard_payload_t *)payload)->pad_len = padbyte;
		//copy the data into the payload
		memcpy(&(((dmime_standard_payload_t *)payload)->data[0]), data, data_size);
		//pad the payload
		memset(&(((dmime_standard_payload_t *)payload)->data[data_size]), padbyte, padlen);
		break;
	default:
		_dmsg_destroy_message_chunk(result);
		RET_ERROR_PTR(ERR_UNSPEC, "unsupported payload type");
		break;

	}

	// encoding is complete
	result->state = MESSAGE_CHUNK_STATE_ENCODED;

	return result;
}


/*
 * @brief	Deserializes an encrypted chunk from binary data.
 * @param	in		Pointer to the binary data of an encrypted chunk.
 * @param	insize		Maximum size of provided data (not guaranteed to contain only the chunk specified by the provided pointer).
 * @param	read		Stores number of bytes read for this chunk.
 * @return	Pointer to a Dmime message chunk object in encrypted state, NULL on error.
*/
dmime_message_chunk_t *_dmsg_deserialize_chunk(const unsigned char *in, size_t insize, size_t *read) {

	dmime_chunk_key_t *key;
	dmime_chunk_type_t type;
	dmime_message_chunk_t *result;
	int num_keyslots;
	size_t payload_size, serial_size, chunk_size;

	if(!in || !insize || !read) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	type = (dmime_chunk_type_t)in[0];

	if(!((key = _dmsg_get_chunk_type_key(type))->section)) {
		RET_ERROR_PTR(ERR_UNSPEC, "chunk type is invalid");
	}

	payload_size = _int_no_get_3b((void *)(in + 1));

	num_keyslots = key->auth_keyslot + key->orig_keyslot + key->dest_keyslot + key->recp_keyslot;
	// total number of bytes to be read:
	if((serial_size = CHUNK_HEADER_SIZE + payload_size + num_keyslots * sizeof(dmime_keyslot_t)) > insize) {
		RET_ERROR_PTR(ERR_UNSPEC, "invalid input or chunk size");
	}

	// size of chunk object:
	chunk_size = serial_size + sizeof(dmime_message_chunk_state_t) + sizeof(size_t);

	if(!(result = malloc(chunk_size))) {
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate memory for chunk");
	}

	memset(result, 0, chunk_size);
	result->state = MESSAGE_CHUNK_STATE_CREATION;
	result->serial_size = serial_size;
	memcpy(&(result->type), in, serial_size);
	if(key->encrypted) {
		result->state = MESSAGE_CHUNK_STATE_ENCRYPTED;
	} else {
		result->state = MESSAGE_CHUNK_STATE_ENCODED;
	}
	*read = serial_size;

	return result;
}


/*
 * @brief	Wraps a binary payload in a chunk of specified type. Only the validity of size is verified.
 * @NOTE	DO NOT USE THIS AS A GENERAL CONSTRUCTOR.
 * @param	type		Specified chunk type.
 * @param	payload		Array to binary payload to be wrapped in the message chunk.
 * @param	insize		Length of input payload.
 * @return	An allocated and encoded dmime message chunk.
 */
dmime_message_chunk_t *_dmsg_wrap_chunk_payload(dmime_chunk_type_t type, unsigned char *payload, size_t insize) {

	dmime_chunk_key_t *key;
	dmime_message_chunk_t *result;
	int num_keyslots;
	size_t total_size, serial_size;

	if(!payload || !insize) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!((key = _dmsg_get_chunk_type_key(type))->section)) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not retrieve key for specified chunk type");
	}

	if(key->payload == PAYLOAD_TYPE_EPHEMERAL && insize != EC_PUBKEY_SIZE) {
		RET_ERROR_PTR(ERR_UNSPEC, "invalid ephemeral payload size");
	}

	if(key->payload == PAYLOAD_TYPE_SIGNATURE && insize != ED25519_SIG_SIZE) {
		RET_ERROR_PTR(ERR_UNSPEC, "invalid signature payload size");
	}

	if(key->payload == PAYLOAD_TYPE_STANDARD && (insize % 16)) {
		RET_ERROR_PTR(ERR_UNSPEC, "invalid standard payload size");
	}

	num_keyslots = key->auth_keyslot + key->orig_keyslot + key->dest_keyslot + key->recp_keyslot;
	serial_size = CHUNK_HEADER_SIZE + insize + num_keyslots * sizeof(dmime_keyslot_t);
	total_size = serial_size + sizeof(dmime_message_chunk_state_t) + sizeof(size_t);

	if(!(result = malloc(total_size))) {
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate memory for message chunk");
	}

	memset(result, 0, total_size);
	result->state = MESSAGE_CHUNK_STATE_CREATION;
	result->serial_size = serial_size;
	result->type = type;
	_int_no_put_3b(&(result->payload_size[0]), insize);
	memcpy(&(result->data[0]), payload, insize);

	if(key->payload == PAYLOAD_TYPE_STANDARD) {
		result->state = MESSAGE_CHUNK_STATE_SIGNED;
	} else {
		result->state = MESSAGE_CHUNK_STATE_ENCODED;
	}

	return result;
}

/*
 * @brief	Returns the location of the data segment of the specified chunk and stores its size.
 * NOTE:	For ephemeral and signature payload chunks it is the entire payload, for standard payload chunks it is the data section.
 * @param	chunk		Pointer to a chunk from which the data is copied.
 * @param	outsize		Stores the length of chunk data.
 * @return	Pointer to the chunk data.
 */
unsigned char *_dmsg_get_chunk_data(dmime_message_chunk_t *chunk, size_t *outsize) {

	dmime_chunk_key_t *key;
	size_t size;
	unsigned char *result;
	void *payload;

	if(!chunk || !outsize) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!((key = _dmsg_get_chunk_type_key(chunk->type))->section)) {
		RET_ERROR_PTR(ERR_UNSPEC, "invalid chunk type");
	}

	if(!(payload = _dmsg_get_chunk_payload(chunk))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could retrieve chunk payload");
	}

	switch(key->payload) {

	case PAYLOAD_TYPE_EPHEMERAL:
		result = &(chunk->data[0]);

		if((size = _int_no_get_3b(&(chunk->payload_size[0]))) != EC_PUBKEY_SIZE) {
			RET_ERROR_PTR(ERR_UNSPEC, "the ephemeral chunk contains data of invalid size");
		}

		break;
	case PAYLOAD_TYPE_SIGNATURE:
		result = &(chunk->data[0]);

		if((size = _int_no_get_3b(&(chunk->payload_size[0]))) != ED25519_SIG_SIZE) {
			RET_ERROR_PTR(ERR_UNSPEC, "the signature chunk contains data of invalid size");
		}

		size = _int_no_get_3b(&(chunk->payload_size[0]));
		break;
	case PAYLOAD_TYPE_STANDARD:

		if(chunk->state == MESSAGE_CHUNK_STATE_ENCRYPTED) {
			result = (unsigned char *)payload;
			size = _int_no_get_3b(&(chunk->payload_size[0]));
		} else {
			result = &(((dmime_standard_payload_t *)payload)->data[0]);
			size = _int_no_get_3b(&(((dmime_standard_payload_t *)payload)->data_size[0]));
		}

		break;
	default:
		RET_ERROR_PTR(ERR_UNSPEC, "invalid chunk type");
		break;

	}

	*outsize = size;

	return result;
}


/*
 * @brief	Returns the pointer to the data of the chunk.
 * NOTE:	The size will include the padding.
 * @param	chunk		Pointer to the dmime message chunk the data of which will be retrieved.
 * @param	outsize		The size of the returned buffer.
 * @return	Pointer to the chunk data (does not allocate new memory).
 */
unsigned char *_dmsg_get_chunk_padded_data(dmime_message_chunk_t *chunk, size_t *outsize) {

	dmime_chunk_key_t *key;
	size_t size;
	unsigned char *result;
	void *payload;

	if(!chunk || !outsize) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!((key = _dmsg_get_chunk_type_key(chunk->type))->section)) {
		RET_ERROR_PTR(ERR_UNSPEC, "invalid chunk type");
	}

	if(!(payload = _dmsg_get_chunk_payload(chunk))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not retrieve chunk payload");
	}

	switch(key->payload) {

	case PAYLOAD_TYPE_EPHEMERAL:
	case PAYLOAD_TYPE_SIGNATURE:
		result = &(chunk->data[0]);
		size = _int_no_get_3b(&(chunk->payload_size[0]));
		break;
	case PAYLOAD_TYPE_STANDARD:

		if(chunk->state == MESSAGE_CHUNK_STATE_ENCRYPTED) {
			result = (unsigned char *)payload;
			size = _int_no_get_3b(&(chunk->payload_size[0]));
		} else {
			result = &(((dmime_standard_payload_t *)payload)->data_size[0]);
			size = _int_no_get_3b(&(chunk->payload_size[0])) - ED25519_SIG_SIZE;
		}

		break;
	default:
		RET_ERROR_PTR(ERR_UNSPEC, "invalid chunk type");
		break;
	}

	*outsize = size;

	return result;
}


/*
 * @brief	Returns the pointer to the plaintext signature of a standard payload chunk.
 * NOTE:	Signatures are ED25519_SIG_SIZE
 * @param	chunk		Pointer to the dmime message chunk with standard payload type from which the signature will be retrieved.
 * @return	Pointer to the plaintext signature.
 */
unsigned char *_dmsg_get_chunk_plaintext_sig(dmime_message_chunk_t *chunk) {

	dmime_chunk_key_t *key;
	unsigned char *result;

	if(!chunk) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!((key = _dmsg_get_chunk_type_key(chunk->type))->section)) {
		RET_ERROR_PTR(ERR_UNSPEC, "invalid chunk type");
	}

	if(key->payload != PAYLOAD_TYPE_STANDARD) {
		RET_ERROR_PTR(ERR_UNSPEC, "the chunk type does not have a plaintext signature");
	}

	if(chunk->state > MESSAGE_CHUNK_STATE_SIGNED) {
		RET_ERROR_PTR(ERR_UNSPEC, "the chunk is already encrypted");
	}

	if(!(result = _dmsg_get_chunk_payload(chunk))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not retrieve chunk payload");
	}

	return result;
}

/*
 * @brief	Returns the flags character of a standard payload chunk.
 * @param	chunk		Pointer to a dmime message chunk with standard payload type from which the signature will be retrieved.
 * @return	The flags byte of the chunk or default flags on error.
 */
unsigned char _dmsg_get_chunk_flags(dmime_message_chunk_t *chunk) {

	dmime_chunk_key_t *key;
	dmime_standard_payload_t *payload;

	if(!chunk) {
		return DEFAULT_CHUNK_FLAGS;
	}

	if(!((key = _dmsg_get_chunk_type_key(chunk->type))->section)) {
		return DEFAULT_CHUNK_FLAGS;
	}

	if(key->payload != PAYLOAD_TYPE_STANDARD) {
		return DEFAULT_CHUNK_FLAGS;
	}

	if(chunk->state > MESSAGE_CHUNK_STATE_SIGNED) {
		return DEFAULT_CHUNK_FLAGS;
	}

	if(!(payload = _dmsg_get_chunk_payload(chunk))) {
		return DEFAULT_CHUNK_FLAGS;
	}

	return payload->flags;
}
