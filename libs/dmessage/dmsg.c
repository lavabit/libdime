
#include "dmessage/dmsg.h"

/*
 * @brief	Takes a dmime object and determines the state it is in.
 * @param	object		Dmime object, state of which will be retrieved.
 * @return	The state of dmime object.
 */
dmime_object_state_t _dmsg_init_object_state(dmime_object_t *object) {

	if(!object) {
		RET_ERROR_CUST(DMIME_OBJECT_STATE_NONE, ERR_BAD_PARAM, NULL);
	}

	//TODO more comprehensive state checks/retrieval.
	if(!object->author || !object->signet_author || !object->origin || !object->signet_origin || !object->destination || !object->signet_destination || !object->recipient || !object->signet_recipient) {
		return object->state = DMIME_OBJECT_STATE_INCOMPLETE_ENVELOPE;
	}

	if(!object->common_headers) {
		return object->state = DMIME_OBJECT_STATE_INCOMPLETE_METADATA;
	}

	return object->state = DMIME_OBJECT_STATE_COMPLETE;
}


/*
 * @brief	Retrieves dmime message state.
 * @param	message		Pointer to a dmime message.
 * @return	dmime_message_state_t corresponding to the current state.
 */
dmime_message_state_t _dmsg_get_message_state(const dmime_message_t *message) {

	if(!message) {
		RET_ERROR_CUST(MESSAGE_STATE_NONE, ERR_BAD_PARAM, NULL);
	}
	//TODO Maybe needs a better implementation.
	return message->state;
}


/*
 * @brief	Destroys dmime message object.
 * @param	msg		Pointer to the dmime message to be destroyed.
 * @return	void.
*/
void	_dmsg_destroy_msg(dmime_message_t *msg) {

	int i;

	if(!msg) {
		return;
	}

	if(msg->tracing) {
		free(msg->tracing);
	}

	if(msg->origin) {
		_dmsg_destroy_message_chunk(msg->origin);
	}

	if(msg->destination) {
		_dmsg_destroy_message_chunk(msg->destination);
	}

	if(msg->common_headers) {
		_dmsg_destroy_message_chunk(msg->common_headers);
	}

	if(msg->other_headers) {
		_dmsg_destroy_message_chunk(msg->other_headers);
	}

	i = 0;

	if(msg->display) {

		while(msg->display[i]) {
			_dmsg_destroy_message_chunk(msg->display[i++]);
		}

	}

	free(msg->display);
	i = 0;

	if(msg->attach) {

		while(msg->attach[i]) {
			_dmsg_destroy_message_chunk(msg->attach[i++]);
		}

	}

	free(msg->attach);

	if(msg->author_tree_sig) {
		_dmsg_destroy_message_chunk(msg->author_tree_sig);
	}

	if(msg->author_full_sig) {
		_dmsg_destroy_message_chunk(msg->author_full_sig);
	}

	if(msg->origin_meta_bounce_sig) {
		_dmsg_destroy_message_chunk(msg->origin_meta_bounce_sig);
	}

	if(msg->origin_display_bounce_sig) {
		_dmsg_destroy_message_chunk(msg->origin_display_bounce_sig);
	}

	if(msg->origin_full_sig) {
		_dmsg_destroy_message_chunk(msg->origin_full_sig);
	}

	free(msg);

	return;
}


/*
 * @brief	Takes a dmime object uses it to encode an origin dmime message chunk
 * @param	object		dmime object with information that will be encoded into the origin chunk
 * @return	Pointer to a dmime message origin chunk
*/
dmime_message_chunk_t * _dmsg_encode_origin(dmime_object_t *object) {

	char *author_crypto_signet_b64, *destination_signet_fingerprint_b64;
	dmime_message_chunk_t *result;
	signet_t *crypto_signet;
	stringer_t *data = NULL;

	if(!object) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!object->signet_author || !object->author || !object->signet_destination || !object->destination) {
		RET_ERROR_PTR(ERR_UNSPEC, "the dmime object does not contain necessary information to encode an origin message chunk");
	}

	if(!(crypto_signet = _signet_user_split(object->signet_author))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not split author signet");
	}

	if(!(author_crypto_signet_b64 = _signet_serialize_b64(crypto_signet))) {
		_signet_destroy(crypto_signet);
		RET_ERROR_PTR(ERR_UNSPEC, "could not serialize the split signet into b64 data");
	}

	_signet_destroy(crypto_signet);

	if(!(destination_signet_fingerprint_b64 = _signet_core_fingerprint(object->signet_destination))) {
		free(author_crypto_signet_b64);
	}

	if(!(data = st_merge("nsnnnsnnn", "Author: <", object->author, ">\r\nAuthor-Signet: [", author_crypto_signet_b64, "]\r\nDestination: <", object->destination, ">\r\nDestination-Signet-Fingerprint: [", destination_signet_fingerprint_b64, "]\r\n"))) {
		free(author_crypto_signet_b64);
		free(destination_signet_fingerprint_b64);
		RET_ERROR_PTR(ERR_UNSPEC, "could not merge data");
	}

	free(author_crypto_signet_b64);
	free(destination_signet_fingerprint_b64);

	if(!(result = _dmsg_create_message_chunk(CHUNK_TYPE_ORIGIN, (unsigned char *) st_data_get(data), st_length_get(data), DEFAULT_CHUNK_FLAGS))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not create message chunk");
	}

	st_cleanup(data);

	return result;
}


/*
 * @brief	Takes a dmime object uses it to encode a destination dmime message chunk
 * @param	object		dmime object with information that will be encoded into the destination chunk
 * @return	Pointer to a dmime message destination chunk
*/
dmime_message_chunk_t * _dmsg_encode_destination(dmime_object_t *object) {

	char *recipient_crypto_signet_b64, *origin_signet_fingerprint_b64;
	dmime_message_chunk_t *result;
	signet_t *crypto_signet;
	stringer_t *data;

	if(!object) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!object->signet_recipient || !object->recipient || !object->signet_origin || !object->origin) {
		RET_ERROR_PTR(ERR_UNSPEC, "the dmime object does not contain necessary information to encode an origin message chunk");
	}

	if(!(crypto_signet = _signet_user_split(object->signet_recipient))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not split author signet");
	}

	if(!(recipient_crypto_signet_b64 = _signet_serialize_b64(crypto_signet))) {
		_signet_destroy(crypto_signet);
		RET_ERROR_PTR(ERR_UNSPEC, "could not serialize the split signet into b64 data");
	}

	_signet_destroy(crypto_signet);

	if(!(origin_signet_fingerprint_b64 = _signet_core_fingerprint(object->signet_origin))) {
		free(recipient_crypto_signet_b64);
	}

	if(!(data = st_merge("nsnnnsnnn", "Recipient: <", object->recipient, ">\r\nRecipient-Signet: [", recipient_crypto_signet_b64, "]\r\nOrigin: <", object->origin, ">\r\nOrigin-Signet-Fingerprint: [", origin_signet_fingerprint_b64, "]\r\n"))) {
		free(recipient_crypto_signet_b64);
		free(origin_signet_fingerprint_b64);
		RET_ERROR_PTR(ERR_UNSPEC, "could not merge data");
	}

	free(recipient_crypto_signet_b64);
	free(origin_signet_fingerprint_b64);

	if(!(result = _dmsg_create_message_chunk(CHUNK_TYPE_DESTINATION, (unsigned char *) st_data_get(data), st_length_get(data), DEFAULT_CHUNK_FLAGS))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not create message chunk");
	}

	st_cleanup(data);

	return result;
}


/* 
 * @brief	Takes a dmime object uses it to encode a common metadata dmime message chunk
 * @param	object		dmime object with information that will be encoded into the common headers chunk
 * @return	Pointer to a dmime message common headers chunk
*/
dmime_message_chunk_t * _dmsg_encode_common_headers(dmime_object_t *object) {

	dmime_message_chunk_t *result;

	if(!object) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!(result = _dmsg_create_message_chunk(CHUNK_TYPE_META_COMMON, (unsigned char *) st_data_get(object->common_headers), st_length_get(object->common_headers), DEFAULT_CHUNK_FLAGS))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not create message chunk");
	}

	return result;
}


/*
 * @brief	Takes a dmime object and uses it to encode other_headers metadata dmime message chunk
 * @param	object	dmime object with the other_headers data that will be encoded into the chunk
 * @return	Pointer to a dmime message other headers chunk
*/
dmime_message_chunk_t * _dmsg_encode_other_headers(dmime_object_t *object) {

	dmime_message_chunk_t *result;

	if(!object) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	//TODO right now we have all the non-common headers combined into one string
	
	if(!(result = _dmsg_create_message_chunk(CHUNK_TYPE_META_OTHER, (unsigned char *) st_data_get(object->other_headers), st_length_get(object->other_headers), DEFAULT_CHUNK_FLAGS))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not create message chunk");
	}

	return result;
}


/*
 * @brief	Takes a dmime object and encodes the display chunk into an array of dmime message chunks.
 * @param	object		Pointer to the dmime object containing the display chunk data.
 * @return	Returns a pointer to a null-pointer terminated array of dmime message chunks encoded with the display data.
*/
dmime_message_chunk_t ** _dmsg_encode_display(dmime_object_t *object) {

	dmime_object_chunk_t *first_chunk, *temp;
	dmime_message_chunk_t **result;
	int counter = 0, i, j;

	if(!object) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!(temp = first_chunk = object->display)) {
		RET_ERROR_PTR(ERR_UNSPEC, "no display data in the dmime object");
	}

	while(temp) {
		++counter;
		temp = temp->next;
	}

	temp = first_chunk;

	if(!(result = malloc((counter + 1) * sizeof(dmime_message_chunk_t *)))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate array for chunk pointers");
	}

	memset(result, 0, ((counter + 1) * sizeof(dmime_message_chunk_t *)));

	for(i = 0; i < counter; ++i) {

		if(!(result[i] = _dmsg_create_message_chunk(temp->type, temp->data, temp->data_size, temp->flags))) {

			for(j = 0; j < i; ++j) {
				_dmsg_destroy_message_chunk(result[j]);
			}

			free(result);
			RET_ERROR_PTR(ERR_UNSPEC, "could not encode a display message chunk");
		}

		temp = temp->next;
	}

	return result;
}


/*
 * @brief	Takes a dmime object and encodes the attachment chunk into an array of dmime message chunks.
 * @param	object		Pointer to the dmime object containing the attachment chunk data.
 * @return	Returns a pointer to a null-pointer terminated array of dmime message chunks encoded with the attachment data.
*/
dmime_message_chunk_t ** _dmsg_encode_attach(dmime_object_t *object) {

	dmime_object_chunk_t *first_chunk, *temp;
	dmime_message_chunk_t **result;
	int counter = 0, i, j;

	if(!object) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!(temp = first_chunk = object->attach)) {
		RET_ERROR_PTR(ERR_UNSPEC, "no attachment data in the dmime object");
	}

	while(temp) {
		++counter;
		temp = temp->next;
	}

	temp = first_chunk;

	if(!(result = malloc((counter + 1) * sizeof(dmime_message_chunk_t *)))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate array for chunk pointers");
	}

	memset(result, 0, ((counter + 1) * sizeof(dmime_message_chunk_t *)));

	for(i = 0; i < counter; ++i) {

		if(!(result[i] = _dmsg_create_message_chunk(temp->type, temp->data, temp->data_size, temp->flags))) {

			for(j = 0; j < i; ++j) {
				_dmsg_destroy_message_chunk(result[j]);
			}

			free(result);
			RET_ERROR_PTR(ERR_UNSPEC, "could not encode an attachment message chunk");
		}

		temp = temp->next;
	}

	return result;
}


/*
 * @brief	Takes a dmime object and encodes the envelope, metadata, display and attachment data into a dmime message.
 * @param	object		Pointer to a dmime object containing the envelope, metadata, display and attachment information.
 * @param	message		Pointer to a dmime message into which the information gets encoded.
 * @return	0 on success, anything other than 0 is failure.
*/
int _dmsg_encode_msg_chunks(dmime_object_t *object, dmime_message_t *message) {

	if(!object || !message) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(_dmsg_get_message_state(message) != MESSAGE_STATE_EMPTY) {
		RET_ERROR_INT(ERR_UNSPEC, "message should be empty to be encoded");
	}

	if(!(message->origin = _dmsg_encode_origin(object))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not encode origin chunk");
	}

	if(!(message->destination = _dmsg_encode_destination(object))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not encode destination chunk");
	}

	if(!(message->common_headers = _dmsg_encode_common_headers(object))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not encode common headers chunk");
	}

	if(object->other_headers && !(message->other_headers = _dmsg_encode_other_headers(object))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not encode other headers chunk");
	}

	if(!(message->display = _dmsg_encode_display(object))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not encode display chunks");
	}

	if(object->attach && !(message->attach = _dmsg_encode_attach(object))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not encode attachment chunks");
	}

	message->state = MESSAGE_STATE_ENCODED;

	return 0;
}


/*
 * @brief	Signs a message chunk using the specified private signing key.
 * @param	message		Pointer to a dmime message chunk to be signed.
 * @param	signkey		Author's ed25519 private signing key.
 * @return	0 on success, all other values signify failure.
*/
int _dmsg_sign_chunk(dmime_message_chunk_t *chunk, ED25519_KEY *signkey) {

	dmime_chunk_key_t *key;
	size_t data_size;
	unsigned char *data, *signature;

	if(!chunk || !signkey) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(chunk->state != MESSAGE_CHUNK_STATE_ENCODED) {
		RET_ERROR_INT(ERR_UNSPEC, "message chunk is not encoded");
	}

	if(!(key = _dmsg_get_chunk_type_key((dmime_chunk_type_t) chunk->type))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not retrieve chunk key");
	}

	if(key->payload != PAYLOAD_TYPE_STANDARD) {
		RET_ERROR_INT(ERR_UNSPEC, "only standard payloads can be signed");
	}

	if(!(data = _dmsg_get_chunk_padded_data(chunk, &data_size))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not retrieve chunk padded data");
	}

	if(!(signature = _dmsg_get_chunk_plaintext_sig(chunk))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not retrieve chunk plaintext signature buffer");
	}

	if(_ed25519_sign_data(data, data_size, signkey, signature)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not sign the payload data");
	}

/*
	fprintf(stderr, "type: %u, signature: %u data: %u\n", (unsigned int)chunk->type, _int_no_get_4b(signature), _int_no_get_4b(data));

	if(chunk->type == 4) {

		fprintf(stderr, "type:4 full chunk: ");

		for(i = 0; i < 20; ++i) {
			fprintf(stderr, "%u ", _int_no_get_4b(&(chunk->type) + (4*i)));
		}

		fprintf(stderr, "\n");
	}
*/

	chunk->state = MESSAGE_CHUNK_STATE_SIGNED;

	return 0;
}


/*
 * @brief	Takes a dmime message that has only been encoded and signs every encoded chunk with the provided ed25519 private signing key.
 * @param	message		Pointer to a dmime message, the chunks of which will be signed.
 * @param	signkey		A ed25519 private signing (supposedly the author's).
 * @return	0 on success, anything other than 0 is failure.
*/
int _dmsg_sign_msg_chunks(dmime_message_t *message, ED25519_KEY *signkey) {

	int i = 0;

	if(!message || !signkey) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(_dmsg_get_message_state(message) !=  MESSAGE_STATE_ENCODED) {
		RET_ERROR_INT(ERR_UNSPEC, "you can only sign the chunks of a message that has been encoded");
	}

	if(_dmsg_sign_chunk(message->origin, signkey)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not sign origin chunk");
	}

	if(_dmsg_sign_chunk(message->destination, signkey)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not sign origin chunk");
	}

	if(_dmsg_sign_chunk(message->common_headers, signkey)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not sign origin chunk");
	}

	if(_dmsg_sign_chunk(message->other_headers, signkey)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not sign origin chunk");
	}

	if(message->display) {

		while(message->display[i]) {

			if(_dmsg_sign_chunk(message->display[i], signkey)) {
				RET_ERROR_INT(ERR_UNSPEC, "could not sign display chunk");
			}
	
			++i;
		}

	}

	i = 0;

	if(message->attach) {

		while(message->attach[i]) {

			if(_dmsg_sign_chunk(message->attach[i], signkey)) {
				RET_ERROR_INT(ERR_UNSPEC, "could not sign attachment chunk");
			}

			++i;
		}

	}

	message->state = MESSAGE_STATE_CHUNKS_SIGNED;

	return 0;
}


/*
 * @brief       Uses the signet passed to function and an EC key to create key-encryption-key block via ECDH, with the public key being taken from the signet.
 * @param       privkey         Pointer to an EC_KEY structure containing a private EC key used for the ECDH
 * @param       signet          Pointer to a signet containing the public EC encryption key used for the ECDH
 * @param       kekbuf          key encryption key buffer tha will be set to the resulting 16 byte IV and 32 byte AES256 key
 * @return      0 on success, others on failure.
*/
int _dmsg_set_kek(EC_KEY *privkey, signet_t *signet, dmime_kek_t *kekbuf) {

        EC_KEY *signetkey;

        if(!privkey || !signet || !kekbuf) {
                RET_ERROR_INT(ERR_BAD_PARAM, NULL);
        }

        if(!(signetkey = _signet_get_enckey(signet))){
                RET_ERROR_INT(ERR_UNSPEC, "could not retrieve author public encryption key");
        }

        if(_compute_aes256_kek(signetkey, privkey, (unsigned char *)kekbuf)) {
                _free_ec_key(signetkey);
                RET_ERROR_INT(ERR_UNSPEC, "could not compute aes256 kek and store it in the specified buffer");
        }

        _free_ec_key(signetkey);

        return 0;
}


/*
 * @brief	Populates the set of kek's (key encryption keys).
 * @param	msg		Pointer to the non-serialized dmime message that has had its ephemeral chunk allocated and is linked to all required signets.
 * @param	ephemeral	Pointer to an ephemeral private encryption ec key used to generate the key encryption keys and initialization vectors.
 * @param	kekset		Pointer to the set of key encryption keys to be populated.
 * @result	0 on success, all other values indicate failure.
 */
int _dmsg_derive_kekset(dmime_object_t *object, EC_KEY *ephemeral, dmime_kekset_t *kekset) {

	if(!object || !ephemeral || !kekset) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL); 
	}

	memset((*kekset), 0, sizeof(dmime_kekset_t));

	if(_dmsg_set_kek(ephemeral, object->signet_author, &((*kekset)[id_author]))) {
		_free_ec_key(ephemeral);
		RET_ERROR_INT(ERR_UNSPEC, "could not set author KEK");
	}

	if(_dmsg_set_kek(ephemeral, object->signet_origin, &((*kekset)[id_origin]))) {
		_free_ec_key(ephemeral);
		RET_ERROR_INT(ERR_UNSPEC, "could not set recipient KEK");
	}

	if(_dmsg_set_kek(ephemeral, object->signet_destination, &((*kekset)[id_destination]))) {
		_free_ec_key(ephemeral);
		RET_ERROR_INT(ERR_UNSPEC, "could not set origin KEK");
	}

	if(_dmsg_set_kek(ephemeral, object->signet_recipient, &((*kekset)[id_recipient]))) {
		_free_ec_key(ephemeral);
		RET_ERROR_INT(ERR_UNSPEC, "could not set destination KEK");
	}

	return 0;
}


/*
 * @brief	Encrypts keyslot with the specified AES256 key and initialization vector.
 * @param	keyslot		Pointer to the keyslot to be encrypted.
 * @param	kek		Pointer to the kek used for encrpypting the keyslot.
 * @return	0 on success, all other values indicate failure.
*/
int _dmsg_encrypt_keyslot(dmime_keyslot_t *keyslot, dmime_kek_t *kek) {

        dmime_keyslot_t slot;
        int result, i;

        if (!keyslot || !kek) {
                RET_ERROR_INT(ERR_BAD_PARAM, NULL);
        }

        mm_set(&slot, 0, sizeof(slot));

	for(i = 0; i < 16; ++i) {
		keyslot->iv[i] = keyslot->random[i] ^ keyslot->iv[i];
	}

	        if ((result = _encrypt_aes_256((unsigned char *)&slot, (unsigned char *)keyslot, sizeof(dmime_keyslot_t), kek->key, kek->iv)) < 0) {
                RET_ERROR_INT(ERR_UNSPEC, "error occurred while encrypting chunk data");
        } else if (result != sizeof(slot)) {
                mm_set(&slot,0, sizeof(slot));
                RET_ERROR_INT(ERR_UNSPEC, "chunk keyslot encryption operation did not return expected length");
        }

        // Copy the newly encrypted information over the keyslot and return.
        mm_copy(keyslot, &slot, sizeof(dmime_keyslot_t));
        mm_set(&slot, 0, sizeof(slot));

	return 0;
}


/*
 * @brief	Takes a dmime message chunk and a kekset, generates the AES256 chunk encryption keys for the keyslots, encrypts the message, then encrypts the keyslots with the kekset.
 * @param	chunk		Pointer to the dmime message chunk to be encrypted.
 * @param	keks		Pointer to the kekset for encrypting the key slots.
 * @return	0 on success, all other values indicate failure.
*/
int _dmsg_encrypt_chunk(dmime_message_chunk_t *chunk, dmime_kekset_t *keks) { //TODO There may be some code reuse that could occur here, the function is a bit long

	dmime_chunk_key_t *key;
	dmime_keyslot_t *keyslot, temp;
	int slot_count = 0, res;
	size_t data_size;
	unsigned char *outbuf;

	if(!chunk || !keks) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(!((key = _dmsg_get_chunk_type_key(chunk->type))->section)) {
		RET_ERROR_INT(ERR_UNSPEC, "chunk type is invalid");
	}

	if(!key->encrypted) {
		RET_ERROR_INT(ERR_UNSPEC, "this chunk does not get encrypted");
	}

	if(key->payload == PAYLOAD_TYPE_SIGNATURE && chunk->state != MESSAGE_CHUNK_STATE_ENCODED) {
		RET_ERROR_INT(ERR_UNSPEC, "signature chunk should to be encoded before it can be encrypted");
	}

	if(key->payload == PAYLOAD_TYPE_STANDARD && chunk->state != MESSAGE_CHUNK_STATE_SIGNED) {
		RET_ERROR_INT(ERR_UNSPEC, "standard payload chunk should be signed before it can be encrypted");
	}

	if(!(data_size = _int_no_get_3b(&(chunk->payload_size[0]))) || (data_size % 16)) {
		RET_ERROR_INT(ERR_UNSPEC, "data to be encrypted must not be of size 0 and must be a multiple of 16");
	}

	if(!(outbuf = malloc(data_size))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_INT(ERR_NOMEM, "could not allocate buffer for encrypted data");
	}

	//TODO RNG is used, needs review
	if(_get_random_bytes(&(temp.iv[0]), sizeof(temp.iv))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not generate initialization vector");
	}

	if(_get_random_bytes(&(temp.aes_key[0]), sizeof(temp.aes_key))) {
		_secure_wipe((unsigned char *)&temp, sizeof(temp));
		RET_ERROR_INT(ERR_UNSPEC, "could not generate random key");
	}

	if((res = _encrypt_aes_256(outbuf, &(chunk->data[0]), data_size, temp.aes_key, temp.iv)) < 0) {
		_secure_wipe((unsigned char *)&temp, sizeof(temp));
		RET_ERROR_INT(ERR_UNSPEC, "error encrypting data");
	} else if((size_t)res != data_size) {
		RET_ERROR_INT(ERR_UNSPEC, "encrypted an unexpected number of bytes");
	}

	memcpy(&(chunk->data[0]), outbuf, data_size);
	free(outbuf);
	chunk->state = MESSAGE_CHUNK_STATE_UNKNOWN;

	if(key->auth_keyslot) {
		keyslot = _dmsg_get_chunk_keyslot_by_num(chunk, ++slot_count);

		//TODO RNG used needs review
		if(_get_random_bytes(&(temp.random[0]), sizeof(temp.random))) {
			_secure_wipe((unsigned char *)&temp, sizeof(temp));
			RET_ERROR_INT(ERR_UNSPEC, "could not generate random array");
		}

		memcpy(&(keyslot->random[0]), &(temp.random[0]), sizeof(temp.random));
		memcpy(&(keyslot->iv[0]), &(temp.iv[0]), sizeof(temp.iv));
		memcpy(&(keyslot->aes_key[0]), &(temp.aes_key[0]), sizeof(temp.aes_key));

		if(_dmsg_encrypt_keyslot(keyslot, &((*keks)[id_author]))) {
			_secure_wipe((unsigned char *)&temp, sizeof(temp));
			_secure_wipe((unsigned char *)keyslot, sizeof(keyslot));
			RET_ERROR_INT(ERR_UNSPEC, "could not encrypt keyslot");
		}

	}

	if(key->orig_keyslot) {
		keyslot = _dmsg_get_chunk_keyslot_by_num(chunk, ++slot_count);

		//TODO RNG used needs review
		if(_get_random_bytes(&(temp.random[0]), sizeof(temp.random))) {
			_secure_wipe((unsigned char *)&temp, sizeof(temp));
			RET_ERROR_INT(ERR_UNSPEC, "could not generate random array");
		}

		memcpy(&(keyslot->random[0]), &(temp.random[0]), sizeof(temp.random));
		memcpy(&(keyslot->iv[0]), &(temp.iv[0]), sizeof(temp.iv));
		memcpy(&(keyslot->aes_key[0]), &(temp.aes_key[0]), sizeof(temp.aes_key));

		if(_dmsg_encrypt_keyslot(keyslot, &((*keks)[id_origin]))) {
			_secure_wipe((unsigned char *)&temp, sizeof(temp));
			_secure_wipe((unsigned char *)keyslot, sizeof(keyslot));
			RET_ERROR_INT(ERR_UNSPEC, "could not encrypt keyslot");
		}

	}

	if(key->dest_keyslot) {
		keyslot = _dmsg_get_chunk_keyslot_by_num(chunk, ++slot_count);

		//TODO RNG used needs review
		if(_get_random_bytes(&(temp.random[0]), sizeof(temp.random))) {
			_secure_wipe((unsigned char *)&temp, sizeof(temp));
			RET_ERROR_INT(ERR_UNSPEC, "could not generate random array");
		}

		memcpy(&(keyslot->random[0]), &(temp.random[0]), sizeof(temp.random));
		memcpy(&(keyslot->iv[0]), &(temp.iv[0]), sizeof(temp.iv));
		memcpy(&(keyslot->aes_key[0]), &(temp.aes_key[0]), sizeof(temp.aes_key));

		if(_dmsg_encrypt_keyslot(keyslot, &((*keks)[id_destination]))) {
			_secure_wipe((unsigned char *)&temp, sizeof(temp));
			_secure_wipe((unsigned char *)keyslot, sizeof(keyslot));
			RET_ERROR_INT(ERR_UNSPEC, "could not encrypt keyslot");
		}

	}

	if(key->recp_keyslot) {
		keyslot = _dmsg_get_chunk_keyslot_by_num(chunk, ++slot_count);

		//TODO RNG used needs review
		if(_get_random_bytes(&(temp.random[0]), sizeof(temp.random))) {
			_secure_wipe((unsigned char *)&temp, sizeof(temp));
			RET_ERROR_INT(ERR_UNSPEC, "could not generate random array");
		}

		memcpy(&(keyslot->random[0]), &(temp.random[0]), sizeof(temp.random));
		memcpy(&(keyslot->iv[0]), &(temp.iv[0]), sizeof(temp.iv));
		memcpy(&(keyslot->aes_key[0]), &(temp.aes_key[0]), sizeof(temp.aes_key));

		if(_dmsg_encrypt_keyslot(keyslot, &((*keks)[id_recipient]))) {
			_secure_wipe((unsigned char *)&temp, sizeof(temp));
			_secure_wipe((unsigned char *)keyslot, sizeof(keyslot));
			RET_ERROR_INT(ERR_UNSPEC, "could not encrypt keyslot");
		}

	}

	_secure_wipe((unsigned char *)&temp, sizeof(temp));
	chunk->state = MESSAGE_CHUNK_STATE_ENCRYPTED;

	return 0;
}


/*
 * @brief	Takes a dmime message with chunks that have already been signed and for each chunk: 
 * 		fills the keyslots, encrypts the chunk and then encrypts the keyslots.
 * @param	message		Pointer to the dmime message to be encrypted.
 * @param	keks		Pointer to the set of key-encryption-keys to be used for encrypting keyslots.
 * @return	0 on success, all other values indicate failure.
*/
int _dmsg_encrypt_message(dmime_message_t *message, dmime_kekset_t *keks) {

	int i = 0;

	if(!message || !keks) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(_dmsg_get_message_state(message) != MESSAGE_STATE_CHUNKS_SIGNED) {
		RET_ERROR_INT(ERR_UNSPEC, "the message chunks must be signed before they can be encrypted");
	}

	if(_dmsg_encrypt_chunk(message->origin, keks)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not encrypt origin chunk");
	}

	if(_dmsg_encrypt_chunk(message->destination, keks)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not encrypt destination chunk");
	}

	if(_dmsg_encrypt_chunk(message->common_headers, keks)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not encrypt common headers chunk");
	}

	if(_dmsg_encrypt_chunk(message->other_headers, keks)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not encrypt other headers chunk");
	}

	if(message->display) {

		while(message->display[i]) {
		
			if(_dmsg_encrypt_chunk(message->display[i], keks)) {
				RET_ERROR_INT(ERR_UNSPEC, "could not encrypt display chunks");
			}

			++i;
		}

	}

	i = 0;

	if(message->attach) {
	
		while(message->attach[i]) {
		
			if(_dmsg_encrypt_chunk(message->attach[i], keks)) {
				RET_ERROR_INT(ERR_UNSPEC, "could not encrypt attachment chunks");
			}

			++i;
		}

	}

	message->state = MESSAGE_STATE_ENCRYPTED;

	return 0;
}


/*
 * @brief	Derives the data needed for signing the tree signature.
 * @param	msg		Pointer to the dmime message.
 * @param	outsize		Used to store the size of the result.
 * @return	Array of data that gets signed for the tree signature.
*/  // TODO this is probably too long and can be shortened but not sure how.
unsigned char * _dmsg_tree_sig_data(const dmime_message_t *msg, size_t *outsize) {

	unsigned int i, chunk_count = 0;
	unsigned char *result;

	if(!msg || !outsize) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(_dmsg_get_message_state(msg) < MESSAGE_STATE_ENCRYPTED) {
		RET_ERROR_PTR(ERR_UNSPEC, "the message should be encrypted before it is signed with the tree signature");
	}

	if(msg->ephemeral) {
		++chunk_count;
	}

	if(msg->origin) {
		++chunk_count;
	}

	if(msg->destination) {
		++chunk_count;
	}

	if(msg->common_headers) {
		++chunk_count;
	}

	if(msg->other_headers) {
		++chunk_count;
	}

	i = 0;

	if(msg->display) {
	
		while(msg->display[i]) {
			++chunk_count;
			++i;
		}

	}

	i = 0;

	if(msg->attach) {

		while(msg->attach[i]) {
			++chunk_count;
			++i;
		}

	}

	if(!(result = malloc(chunk_count * SHA_512_SIZE))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate memory for data");
	}

	memset(result, 0, chunk_count * SHA_512_SIZE);
	*outsize = chunk_count * SHA_512_SIZE;
	chunk_count = 0;

	if(msg->ephemeral) {

		if(_compute_sha_hash(512, &(msg->ephemeral->type), msg->ephemeral->serial_size, result + (SHA_512_SIZE * chunk_count))) {
			free(result);
			RET_ERROR_PTR(ERR_UNSPEC, "could not hash ephemeral chunk");
		}

		++chunk_count;
	}
	
	if(msg->origin) {

		if(_compute_sha_hash(512, &(msg->origin->type), msg->origin->serial_size, result + (SHA_512_SIZE * chunk_count))) {
			free(result);
			RET_ERROR_PTR(ERR_UNSPEC, "could not hash origin chunk");
		}

		++chunk_count;
	}

	if(msg->destination) {

		if(_compute_sha_hash(512, &(msg->destination->type), msg->destination->serial_size, result + (SHA_512_SIZE * chunk_count))) {
			free(result);
			RET_ERROR_PTR(ERR_UNSPEC, "could not hash destination chunk");
		}
	}

	if(msg->common_headers) {

		if(_compute_sha_hash(512, &(msg->common_headers->type), msg->common_headers->serial_size, result + (SHA_512_SIZE * chunk_count))) {
			free(result);
			RET_ERROR_PTR(ERR_UNSPEC, "could not hash common headers chunk");
		}

		++chunk_count;
	}

	if(msg->other_headers) {

		if(_compute_sha_hash(512, &(msg->other_headers->type), msg->other_headers->serial_size, result + (SHA_512_SIZE * chunk_count))) {
			free(result);
			RET_ERROR_PTR(ERR_UNSPEC, "could not hash other headers chunk");
		}

		++chunk_count;
	}

	i = 0;

	if(msg->display) {

		while(msg->display[i]) {

			if(_compute_sha_hash(512, &(msg->display[i]->type), msg->display[i]->serial_size, result + (SHA_512_SIZE * chunk_count))) {
				free(result);
				RET_ERROR_PTR(ERR_UNSPEC, "could not hash a display chunk");
			}

			++i;
			++chunk_count;
		}

	}

	if(msg->attach) {

		while(msg->attach[i]) {

			if(_compute_sha_hash(512, &(msg->attach[i]->type), msg->attach[i]->serial_size, result + (SHA_512_SIZE * chunk_count))) {
				free(result);
				RET_ERROR_PTR(ERR_UNSPEC, "could not hash an attachment chunk");
			}

			++i;
			++chunk_count;
		}

	}

	return result;
}


/*
 * @brief	Calculates the serialized size of the specified sections of a dmime message.
 * @param	msg		Dmime message.
 * @param	sections	Sections specified.
 * @return	size, 0 on error.
*/
size_t _dmsg_get_sections_size(const dmime_message_t *msg, unsigned char sections) {

	size_t size = 0, last = 0;
	unsigned int i;

	if(!msg) {
		RET_ERROR_UINT(ERR_BAD_PARAM, NULL);
	}

	if(msg->ephemeral && (CHUNK_SECTION_ENVELOPE & sections)) {
		size += msg->ephemeral->serial_size;
	}

	if(msg->origin && (CHUNK_SECTION_ENVELOPE & sections)) {
		size += msg->origin->serial_size;
	}

	if(msg->destination && (CHUNK_SECTION_ENVELOPE & sections)) {
		size += msg->destination->serial_size;
	}

	if(msg->common_headers && (CHUNK_SECTION_METADATA & sections)) {
		size += msg->common_headers->serial_size;
	}

	if(msg->other_headers && (CHUNK_SECTION_METADATA & sections)) {
		size += msg->other_headers->serial_size;
	}

	i = 0;

	if((CHUNK_SECTION_DISPLAY & sections) && msg->display) {

		while(msg->display[i]) {
			last = size;		// last is used to check for size overflow
			size += msg->display[i++]->serial_size;

			if(last > size) {
				RET_ERROR_UINT(ERR_UNSPEC, "message size is exceeding the maximum size");
			}

		}

	}

	i = 0;

	if((CHUNK_SECTION_ATTACH & sections) && msg->attach) {

		while(msg->attach[i]) {
			last = size;
			size += msg->attach[i++]->serial_size;

			if(last > size) {
				RET_ERROR_UINT(ERR_UNSPEC, "message size is exceeding the maximum size");
			}

		}

	}

	if(msg->author_tree_sig && (_dmsg_get_chunk_type_key(CHUNK_TYPE_SIG_AUTHOR_TREE)->section & sections)) {
		size += msg->author_tree_sig->serial_size;
	}

	if(msg->author_full_sig && (_dmsg_get_chunk_type_key(CHUNK_TYPE_SIG_AUTHOR_FULL)->section & sections)) {
		size += msg->author_full_sig->serial_size;
	}

	if(msg->origin_meta_bounce_sig && (_dmsg_get_chunk_type_key(CHUNK_TYPE_SIG_ORIGIN_META_BOUNCE)->section & sections)) {
		size += msg->origin_meta_bounce_sig->serial_size;
	}

	if(msg->origin_display_bounce_sig && (_dmsg_get_chunk_type_key(CHUNK_TYPE_SIG_ORIGIN_DISPLAY_BOUNCE)->section & sections)) {
		size += msg->origin_display_bounce_sig->serial_size;
	}

	if(msg->origin_full_sig && (_dmsg_get_chunk_type_key(CHUNK_TYPE_SIG_ORIGIN_FULL)->section & sections)) {
		size += msg->origin_full_sig->serial_size;
	}

	return size;
}


/*
 * @brief	Serializes the specified sections of a dmime message (only if encrypted).
 * @param	msg		Dmime message to be serialized.
 * @param	first		The first 
 * @param	outsize		Stores the output size.
 * @return	Pointer to the binary array containing the binary message.
*/
unsigned char * _dmsg_serialize_sections(const dmime_message_t *msg, unsigned char sections, size_t *outsize) {

	size_t total_size;
	unsigned int i, at = 0;
	unsigned char *result;

	if(!msg || !outsize) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(_dmsg_get_message_state(msg) < MESSAGE_STATE_ENCRYPTED) {
		RET_ERROR_PTR(ERR_UNSPEC, "a message should be encrypted before it is signed");
	}

	if(!(total_size = _dmsg_get_sections_size(msg, sections))) {
		RET_ERROR_PTR(ERR_UNSPEC, "the total sections size is 0");
	}

	if(!(result = malloc(total_size))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate memory for serialized message");
	}

	memset(result, 0, total_size);
	*outsize = total_size;

	if(msg->ephemeral && (CHUNK_SECTION_ENVELOPE & sections)) {
		memcpy(result + at, &(msg->ephemeral->type), msg->ephemeral->serial_size);
		at += msg->ephemeral->serial_size;
	}

	if(msg->origin && (CHUNK_SECTION_ENVELOPE & sections)) {
		memcpy(result + at, &(msg->origin->type), msg->origin->serial_size);
		at += msg->origin->serial_size;
	}

	if(msg->destination && (CHUNK_SECTION_ENVELOPE & sections)) {
		memcpy(result + at, &(msg->destination->type), msg->destination->serial_size);
		at += msg->destination->serial_size;
	}

	if(msg->common_headers && (CHUNK_SECTION_METADATA & sections)) {
		memcpy(result + at, &(msg->common_headers->type), msg->common_headers->serial_size);
		at += msg->common_headers->serial_size;
	}

	if(msg->other_headers && (CHUNK_SECTION_METADATA & sections)) {
		memcpy(result + at, &(msg->other_headers->type), msg->other_headers->serial_size);
		at += msg->other_headers->serial_size;
	}

	i = 0;
	
	if((CHUNK_SECTION_DISPLAY & sections) && msg->display) {

		while(msg->display[i]) {
			memcpy(result + at, &(msg->display[i]->type), msg->display[i]->serial_size);
			at += msg->display[i++]->serial_size;
		}

	}
		
	i = 0;

	if((CHUNK_SECTION_ATTACH & sections) && msg->attach) {

		while(msg->attach[i]) {
			memcpy(result + at, &(msg->attach[i]->type), msg->attach[i]->serial_size);
			at += msg->attach[i++]->serial_size;
		}

	}

	if(CHUNK_SECTION_SIG & sections) {

		if(msg->author_tree_sig) {
			memcpy(result + at, &(msg->author_tree_sig->type), msg->author_tree_sig->serial_size);
			at += msg->author_tree_sig->serial_size;
		}

		if(msg->author_full_sig) {
			memcpy(result + at, &(msg->author_full_sig->type), msg->author_full_sig->serial_size);
			at += msg->author_full_sig->serial_size;
		}

		if(msg->origin_meta_bounce_sig) {
			memcpy(result + at, &(msg->origin_meta_bounce_sig->type), msg->origin_meta_bounce_sig->serial_size);
			at += msg->origin_meta_bounce_sig->serial_size;
		}

		if(msg->origin_display_bounce_sig) {
			memcpy(result + at, &(msg->origin_display_bounce_sig->type), msg->origin_display_bounce_sig->serial_size);
			at += msg->origin_display_bounce_sig->serial_size;
		}

		if(msg->origin_full_sig) {
			memcpy(result + at, &(msg->origin_full_sig->type), msg->origin_full_sig->serial_size);
			at += msg->origin_full_sig->serial_size;
		}

	}

	return result;
}


/*
 * @brief	Calculates the serialized size of the specified chunks from the first to last specified chunk types.
 * @param	msg		Dmime message containing the chunks, the total serialized size of which will be calculated in the specified chunk type range.
 * @param	first		Lower bound chunk type the size of which will be calculated.
 * @param	last		Upper bound chunk type the size of which will be calculated. 
 * @return	size, 0 on error.
*/
size_t _dmsg_get_chunks_size(const dmime_message_t *msg, dmime_chunk_type_t first, dmime_chunk_type_t last) {

	size_t size = 0;
	unsigned int i;

	if(!msg) {
		RET_ERROR_UINT(ERR_BAD_PARAM, NULL);
	}

	if(last < first) {
		RET_ERROR_UINT(ERR_UNSPEC, "invalid chunk type bounds");
	}

	if(msg->ephemeral && (first <= CHUNK_TYPE_EPHEMERAL && CHUNK_TYPE_EPHEMERAL <= last)) {
		size += msg->ephemeral->serial_size;
	}

	if(msg->origin && (first <= CHUNK_TYPE_ORIGIN && CHUNK_TYPE_ORIGIN <= last)) {
		size += msg->origin->serial_size;
	}

	if(msg->destination && (first <= CHUNK_TYPE_DESTINATION && CHUNK_TYPE_DESTINATION <= last)) {
		size += msg->destination->serial_size;
	}

	if(msg->common_headers && (first <= CHUNK_TYPE_META_COMMON && CHUNK_TYPE_META_COMMON <= last)) {
		size += msg->common_headers->serial_size;
	}

	if(msg->other_headers && (first <= CHUNK_TYPE_META_OTHER && CHUNK_TYPE_META_OTHER <= last)) {
		size += msg->other_headers->serial_size;
	}

	i = 0;

	if(first <= CHUNK_TYPE_DISPLAY_CONTENT && CHUNK_TYPE_DISPLAY_CONTENT <= last && msg->display) {

		while(msg->display[i]) {
			last = size;		// last is used to check for size overflow
			size += msg->display[i++]->serial_size;

			if(last > size) {
				RET_ERROR_UINT(ERR_UNSPEC, "message size is exceeding the maximum size");
			}

		}

	}

	i = 0;

	if(first <= CHUNK_TYPE_ATTACH_CONTENT && CHUNK_TYPE_ATTACH_CONTENT <= last && msg->attach) {

		while(msg->attach[i]) {
			last = size;
			size += msg->attach[i++]->serial_size;

			if(last > size) {
				RET_ERROR_UINT(ERR_UNSPEC, "message size is exceeding the maximum size");
			}

		}

	}

	if(msg->author_tree_sig && (first <= CHUNK_TYPE_SIG_AUTHOR_TREE && CHUNK_TYPE_SIG_AUTHOR_TREE <= last)) {
		size += msg->author_tree_sig->serial_size;
	}

	if(msg->author_full_sig && (first <= CHUNK_TYPE_SIG_AUTHOR_FULL && CHUNK_TYPE_SIG_AUTHOR_FULL <= last)) {
		size += msg->author_full_sig->serial_size;
	}

	if(msg->origin_meta_bounce_sig && (first <= CHUNK_TYPE_SIG_ORIGIN_META_BOUNCE && CHUNK_TYPE_SIG_ORIGIN_META_BOUNCE <= last)) {
		size += msg->origin_meta_bounce_sig->serial_size;
	}

	if(msg->origin_display_bounce_sig && (first <= CHUNK_TYPE_SIG_ORIGIN_DISPLAY_BOUNCE && CHUNK_TYPE_SIG_ORIGIN_DISPLAY_BOUNCE <= last)) {
		size += msg->origin_display_bounce_sig->serial_size;
	}

	if(msg->origin_full_sig && (first <= CHUNK_TYPE_SIG_ORIGIN_FULL && CHUNK_TYPE_SIG_ORIGIN_FULL <= last)) {
		size += msg->origin_full_sig->serial_size;
	}

	return size;
}

/*
 * @brief	Takes an encrypted dmime message and serializes its chunks sequentially from the first specified to the last.
 * @param	msg		Pointer to the dmime message that will be serialized.
 * @param	first		The first chunk type to be serialized.
 * @param	last 		Last chunk type to be serialized.
 * @param	outsize		Stores the size of the serialized message.
 * @return	Pointer to the serialized message.
*/
unsigned char * _dmsg_serialize_chunks(const dmime_message_t *msg, dmime_chunk_type_t first, dmime_chunk_type_t last, size_t *outsize) {

	size_t total_size;
	unsigned int i, at = 0;
	unsigned char *result;

	if(!msg || !outsize) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(_dmsg_get_message_state(msg) < MESSAGE_STATE_ENCRYPTED) {
		RET_ERROR_PTR(ERR_UNSPEC, "a message should be encrypted before it is serialized");
	}

	if(first > last) {
		RET_ERROR_PTR(ERR_UNSPEC, "The first chunk to be serialized is higher than the last"); 
	}

	if(!(total_size = _dmsg_get_chunks_size(msg, first, last))) {
		RET_ERROR_PTR(ERR_UNSPEC, "the total sections size is 0");
	}

	if(!(result = malloc(total_size))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate memory for serialized message");
	}

	memset(result, 0, total_size);
	*outsize = total_size;

	if(msg->ephemeral && (CHUNK_TYPE_EPHEMERAL <= last && first <= CHUNK_TYPE_EPHEMERAL)) {
		memcpy(result + at, &(msg->ephemeral->type), msg->ephemeral->serial_size);
		at += msg->ephemeral->serial_size;
	}

	if(msg->origin && (CHUNK_TYPE_ORIGIN <= last && first <= CHUNK_TYPE_ORIGIN)) {
		memcpy(result + at, &(msg->origin->type), msg->origin->serial_size);
		at += msg->origin->serial_size;
	}

	if(msg->destination && (CHUNK_TYPE_DESTINATION <= last && first <= CHUNK_TYPE_DESTINATION)) {
		memcpy(result + at, &(msg->destination->type), msg->destination->serial_size);
		at += msg->destination->serial_size;
	}

	if(msg->common_headers && (CHUNK_TYPE_META_COMMON <= last && first <= CHUNK_TYPE_META_COMMON)) {
		memcpy(result + at, &(msg->common_headers->type), msg->common_headers->serial_size);
		at += msg->common_headers->serial_size;
	}

	if(msg->other_headers && (CHUNK_TYPE_META_OTHER <= last && first <= CHUNK_TYPE_META_OTHER)) {
		memcpy(result + at, &(msg->other_headers->type), msg->other_headers->serial_size);
		at += msg->other_headers->serial_size;
	}

	i = 0;
	
	if(CHUNK_TYPE_DISPLAY_CONTENT <= last && first <= CHUNK_TYPE_DISPLAY_CONTENT && msg->display) {

		while(msg->display[i]) {
			memcpy(result + at, &(msg->display[i]->type), msg->display[i]->serial_size);
			at += msg->display[i++]->serial_size;
		}

	}
		
	i = 0;

	if(CHUNK_TYPE_ATTACH_CONTENT <= last && first <= CHUNK_TYPE_ATTACH_CONTENT && msg->attach) {

		while(msg->attach[i]) {
			memcpy(result + at, &(msg->attach[i]->type), msg->attach[i]->serial_size);
			at += msg->attach[i++]->serial_size;
		}

	}

	memset(result + at, 0, ED25519_SIG_SIZE+5);

	if(msg->author_tree_sig && (CHUNK_TYPE_SIG_AUTHOR_TREE <= last && first <= CHUNK_TYPE_SIG_AUTHOR_TREE)) {
		memcpy(result + at, &(msg->author_tree_sig->type), msg->author_tree_sig->serial_size);
		at += msg->author_tree_sig->serial_size;
	}

	if(msg->author_full_sig && (CHUNK_TYPE_SIG_AUTHOR_FULL <= last && first <= CHUNK_TYPE_SIG_AUTHOR_FULL)) {
		memcpy(result + at, &(msg->author_full_sig->type), msg->author_full_sig->serial_size);
		at += msg->author_full_sig->serial_size;
	}

	if(msg->origin_meta_bounce_sig && (CHUNK_TYPE_SIG_ORIGIN_META_BOUNCE <= last && first <= CHUNK_TYPE_SIG_ORIGIN_META_BOUNCE)) {
		memcpy(result + at, &(msg->origin_meta_bounce_sig->type), msg->origin_meta_bounce_sig->serial_size);
		at += msg->origin_meta_bounce_sig->serial_size;
	}

	if(msg->origin_display_bounce_sig && (CHUNK_TYPE_SIG_ORIGIN_DISPLAY_BOUNCE <= last && first <= CHUNK_TYPE_SIG_ORIGIN_DISPLAY_BOUNCE)) {
		memcpy(result + at, &(msg->origin_display_bounce_sig->type), msg->origin_display_bounce_sig->serial_size);
		at += msg->origin_display_bounce_sig->serial_size;
	}

	if(msg->origin_full_sig && (CHUNK_TYPE_SIG_ORIGIN_FULL <= last && first <= CHUNK_TYPE_SIG_ORIGIN_FULL)) {
		memcpy(result + at, &(msg->origin_full_sig->type), msg->origin_full_sig->serial_size);
		at += msg->origin_full_sig->serial_size;
	}

	return result;
}



/*
 * @brief	Takes an encrypted dmime message and adds the two mandatory author signature chunks (tree and full).
 * @param	message		Pointer to the dmime message that will be signed. 
 * @param	signkey		Pointer to the author's ed25519 private signing key that will be used for signatures.
 * @param	keks		Pointer to a set of key encryption keys used to encrypt the keyslots.
 * @return	0 on success, all other return values signify failure.
*/
int _dmsg_add_author_sig_chunks(dmime_message_t *message, ED25519_KEY *signkey, dmime_kekset_t *keks) {

	unsigned char *data, sigbuf[ED25519_SIG_SIZE];
	size_t data_size;

	if(!message || !signkey || !keks) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(_dmsg_get_message_state(message) != MESSAGE_STATE_ENCRYPTED) {
		RET_ERROR_INT(ERR_UNSPEC, "signature chunks can not be added to a message with unencrypted chunks");
	}

	memset(sigbuf, 0, sizeof(sigbuf));

	if(!(data = _dmsg_tree_sig_data(message, &data_size))) {
		RET_ERROR_INT(ERR_UNSPEC, "could retrieve input for the tree signature");
	}

	if(_ed25519_sign_data(data, data_size, signkey, sigbuf)) {
		free(data);
		RET_ERROR_INT(ERR_UNSPEC, "could not sign tree data");
	}

	free(data);

	if(!(message->author_tree_sig = _dmsg_create_message_chunk(CHUNK_TYPE_SIG_AUTHOR_TREE, sigbuf, ED25519_SIG_SIZE, DEFAULT_CHUNK_FLAGS))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not create author tree signature chunk");
	}

	if(_dmsg_encrypt_chunk(message->author_tree_sig, keks)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not encrypt author tree signature chunk");
	}

	if(!(data = _dmsg_serialize_chunks(message, CHUNK_TYPE_EPHEMERAL, CHUNK_TYPE_SIG_AUTHOR_TREE, &data_size))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not serialize dmime message");
	}

	if(_ed25519_sign_data(data, data_size, signkey, sigbuf)) {
		free(data);
		RET_ERROR_INT(ERR_UNSPEC, "could not sign dmime message");
	}

	if(!(message->author_full_sig = _dmsg_create_message_chunk(CHUNK_TYPE_SIG_AUTHOR_FULL, sigbuf, ED25519_SIG_SIZE, DEFAULT_CHUNK_FLAGS))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not not create author full signature chunk");
	}

	if(_dmsg_encrypt_chunk(message->author_full_sig, keks)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not encrypt author full signature chunk");
	}

	message->state = MESSAGE_STATE_AUTHOR_SIGNED;

	return 0;
}


/*
 * @brief	Takes an author signed dmime message and adds the three mandatory origin signature fields where each signature is filled with zeros.
 * @param	message		Pointer to the dmime message that will be signed.
 * @param	keks		Pointer to a set of key encryption keys used to encrypt the keyslots.
 * @return	0 on success, all other values indicate failure.
*/
int _dmsg_add_origin_sig_chunks(dmime_message_t *message, dmime_kekset_t *keks) {

	unsigned char blank_buf[ED25519_SIG_SIZE];

	if(!message || !keks) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(_dmsg_get_message_state(message) != MESSAGE_STATE_AUTHOR_SIGNED) {
		RET_ERROR_INT(ERR_UNSPEC, "in order to add the origin signature chunks the message must already include author's signatures");
	}

	memset(blank_buf, 0, sizeof(blank_buf));
	message->state = MESSAGE_STATE_INCOMPLETE;

	if(!(message->origin_meta_bounce_sig = _dmsg_create_message_chunk(CHUNK_TYPE_SIG_ORIGIN_META_BOUNCE, blank_buf, ED25519_SIG_SIZE, DEFAULT_CHUNK_FLAGS))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not create an origin meta bounce signature chunk");
	}

	if(_dmsg_encrypt_chunk(message->origin_meta_bounce_sig, keks)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not encrypt the origin meta bounce signature chunk");
	}

	if(!(message->origin_display_bounce_sig = _dmsg_create_message_chunk(CHUNK_TYPE_SIG_ORIGIN_DISPLAY_BOUNCE, blank_buf, ED25519_SIG_SIZE, DEFAULT_CHUNK_FLAGS))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not create an origin display bounce signature chunk");
	}

	if(_dmsg_encrypt_chunk(message->origin_display_bounce_sig, keks)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not encrypt the origin display bounce signature chunk");
	}

	if(!(message->origin_full_sig = _dmsg_create_message_chunk(CHUNK_TYPE_SIG_ORIGIN_FULL, blank_buf, ED25519_SIG_SIZE, DEFAULT_CHUNK_FLAGS))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not create an origin full signature chunk");
	}

	if(_dmsg_encrypt_chunk(message->origin_full_sig, keks)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not encrypt the origin full signature chunk");
	}
	
	message->state = MESSAGE_STATE_COMPLETE;

	return 0;
}


/*
 * @brief 	Converts a dmime object to a dmime message, fully encrypting and signing the message !!AS AN AUTHOR!!
 * @param	object		dmime object which contains all the envelope, metadata, display and attachment information.
 * 				As well as pointers to signets of author, origin, destination and recipient.
 * @param	signkey		The author's private ed25519 signing key which will be used.
 * @return	A pointer to a fully signed and encrypted dmime message.
*/
dmime_message_t * _dmsg_object_to_msg(dmime_object_t *object, ED25519_KEY *signkey) {

	EC_KEY *ephemeral;
	dmime_kekset_t kekset;
	dmime_message_t *result;
	size_t ecsize;
	unsigned char * bin_pub;

	if(!object || !signkey) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(_dmsg_init_object_state(object) != DMIME_OBJECT_STATE_COMPLETE) {
		RET_ERROR_PTR(ERR_UNSPEC, "dmime object is not complete");
	}

	if(!(result = malloc(sizeof(dmime_message_t)))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate space for message");
	}

	memset(result, 0, sizeof(dmime_message_t));
	result->state = MESSAGE_STATE_EMPTY;

	if(_dmsg_encode_msg_chunks(object, result)) {
		_dmsg_destroy_msg(result);
		RET_ERROR_PTR(ERR_UNSPEC, "could not encode message chunks");
	}

	if(_dmsg_sign_msg_chunks(result, signkey)) {
		_dmsg_destroy_msg(result);
		RET_ERROR_PTR(ERR_UNSPEC, "could not sign message chunks");
	}

	if(!(ephemeral = _generate_ec_keypair(0))) {
		_dmsg_destroy_msg(result);
		RET_ERROR_PTR(ERR_UNSPEC, "could not generate ephemeral encryption key");
	}

	if(_dmsg_derive_kekset(object, ephemeral, &kekset)) {
		_dmsg_destroy_msg(result);
		_free_ec_key(ephemeral);
		RET_ERROR_PTR(ERR_UNSPEC, "could not derive kekset from signets and ephemeral key");
	}

	if(_dmsg_encrypt_message(result, &kekset)) {
		_secure_wipe(kekset, sizeof(dmime_kekset_t));
		_dmsg_destroy_msg(result);
		_free_ec_key(ephemeral);
		RET_ERROR_PTR(ERR_UNSPEC, "could not encrypt message chunks");
	}

	if(!(bin_pub = _serialize_ec_pubkey(ephemeral, &ecsize))) {
		_secure_wipe(kekset, sizeof(dmime_kekset_t));
		_free_ec_key(ephemeral);
		RET_ERROR_PTR(ERR_UNSPEC, "could not serialize public ephemeral EC key");
	}

	_free_ec_key(ephemeral);

	if(ecsize != EC_PUBKEY_SIZE) {
		_secure_wipe(kekset, sizeof(dmime_kekset_t));
		free(bin_pub);
		RET_ERROR_PTR(ERR_UNSPEC, "serialized public key size did not match expected length");
	}

	if(!(result->ephemeral = _dmsg_create_message_chunk(CHUNK_TYPE_EPHEMERAL, bin_pub, ecsize, DEFAULT_CHUNK_FLAGS))) {
		_secure_wipe(kekset, sizeof(dmime_kekset_t));
		free(bin_pub);
		RET_ERROR_PTR(ERR_UNSPEC, "could not create an ephemeral chunk");
	}
	
	free(bin_pub);

	if(_dmsg_add_author_sig_chunks(result, signkey, &kekset)) {
		_secure_wipe(kekset, sizeof(dmime_kekset_t));
		_dmsg_destroy_msg(result);
		RET_ERROR_PTR(ERR_UNSPEC, "could not add author signatures");
	}

	if(_dmsg_add_origin_sig_chunks(result, &kekset)) {
		_secure_wipe(kekset, sizeof(dmime_kekset_t));
		_dmsg_destroy_msg(result);
		RET_ERROR_PTR(ERR_UNSPEC, "could not add origin sig chunks");
	}

	//TODO crypto information on the stack. Should this have been memlocked?
	_secure_wipe(kekset, sizeof(dmime_kekset_t));

	return result;
}


/*
 * @brief	Converts the specified sections of a dmime message to a complete binary form. The message must be at least signed by author.
 * @param	msg		Dmime message to be converted.
 * @param	sections	Sections to be included.
 * @param	tracing		If set, include tracing, if clear don't include tracing.
 * @param	outsize		Stores the output size of the binary.
*/
unsigned char * _dmsg_msg_to_bin(const dmime_message_t *msg, unsigned char sections, unsigned char tracing, size_t *outsize) {

	size_t trc_size = 0, msg_size, total_size, at = 0;
	unsigned char *result, *ser;

	if(!msg || ! outsize) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(_dmsg_get_message_state(msg) < MESSAGE_STATE_AUTHOR_SIGNED) {
		RET_ERROR_PTR(ERR_UNSPEC, "the message must be at least signed by author in order to be converted to complete binary form");
	}

	if(tracing && msg->tracing) {
		trc_size = _int_no_get_2b(&(msg->tracing->size[0]));
	}

	if(!(ser = _dmsg_serialize_sections(msg, sections, &msg_size))) {
		RET_ERROR_PTR(ERR_NOMEM, "could not serialize message sections");
	}

	total_size =  MESSAGE_HEADER_SIZE + msg_size;

	if(tracing) {
		total_size += TRACING_HEADER_SIZE + trc_size;
	}

	*outsize = total_size;

	if(!(result = malloc(total_size))) {
		PUSH_ERROR_SYSCALL("malloc");
		free(ser);
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate memory for binary message");
	}

	memset(result, 0, total_size);

	if(tracing && msg->tracing) {
		_int_no_put_2b(result, (uint16_t)DIME_MSG_TRACING);
		at += 2;
		memcpy(result + at, (unsigned char *)msg->tracing, trc_size + TRACING_HEADER_SIZE);
		at += trc_size + TRACING_LENGTH_SIZE;
	}

	_int_no_put_2b(result + at, (uint16_t)DIME_ENCRYPTED_MSG);
	at += 2;
	_int_no_put_4b(result + at, (uint32_t)msg_size);
	at += MESSAGE_LENGTH_SIZE;
	memcpy(result + at, ser, msg_size);
	free(ser);

	return result;
}


/*
 * @brief	Deserializes and adds a tracing object to the dmime message from the provided binary input.
 * @param	msg		Dmime message object to which the tracing object will be attached.
 * @param	in		Points to the first length byte of the array containing the binary tracing (points to the first character after the dime magic number for tracing objects).
 * @param	insize		Maximum size of the input array.
 * @return	Number of characters read as the tracing, 0 on error.
 */
size_t _dmsg_deserialize_tracing(dmime_message_t *msg, const unsigned char *in, size_t insize) {

	size_t trc_size;

	if(!msg || !in || !insize) {
		RET_ERROR_UINT(ERR_BAD_PARAM, NULL);
	}

	if(((trc_size = ((size_t)_int_no_get_2b(in) + TRACING_LENGTH_SIZE)) > insize ) || trc_size <= TRACING_LENGTH_SIZE) {
		RET_ERROR_UINT(ERR_UNSPEC, "invalid message tracing length");
	}

	if(!(msg->tracing = malloc(trc_size))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_UINT(ERR_NOMEM, "could not allocate memory for tracing object");
	}

	memset(msg->tracing, 0, trc_size);
	memcpy(msg->tracing, in, trc_size);

	return trc_size;
}


/*
 * @brief	Deserializes binary message input into an array of chunks of a specified section, regardless of chunk order.
 * NOTE:	Should only be used for display and attachment sections, because all other chunks need to maintain correct sequence.
 * @param	in		Pointer to the binary data.
 * @param	insize		Size of the input array.
 * @param	section		The specified section from which the chunks should be deserialized.
 * @param	read		Number of bytes read for all the chunks.
 * @return	A pointer to a NULL-pointer terminated array of display chunk pointers.
*/
dmime_message_chunk_t ** _dmsg_deserialize_section(const unsigned char *in, size_t insize, dmime_chunk_section_t section, size_t *read) {

	dmime_chunk_key_t *key;
	dmime_message_chunk_t **result;
	int i = 0, num_keyslots, atchunk = 0;
	size_t num_chunks = 0, at = 0, serial_size, payload_size;

	if(!in || !insize || !read) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	while(at + CHUNK_HEADER_SIZE < insize && (key = _dmsg_get_chunk_type_key(in[at]))->section == section) {

		num_keyslots = key->auth_keyslot + key->orig_keyslot + key->dest_keyslot + key->recp_keyslot;
		payload_size = _int_no_get_3b(in+1);
		serial_size = CHUNK_HEADER_SIZE + payload_size + num_keyslots * sizeof(dmime_keyslot_t);
		at += serial_size;

		if(serial_size > insize) {
			RET_ERROR_PTR(ERR_UNSPEC, "invalid chunk size");
		}

		at += serial_size;
		++num_chunks;
	}

	if(!(result = malloc(sizeof(dmime_message_chunk_t *) * (num_chunks+1)))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate memory for array of chunks");
	}

	memset(result, 0, sizeof(dmime_message_chunk_t *) * (num_chunks+1));
	at = 0;

	while(at + CHUNK_HEADER_SIZE < insize && (key = _dmsg_get_chunk_type_key(in[at]))->section == section) {

		if(!(result[atchunk] = _dmsg_deserialize_chunk(in+at, insize-at, &serial_size))) {
	
			while(i < atchunk) {
				_dmsg_destroy_message_chunk(result[i++]);
			}

			free(result);
			RET_ERROR_PTR(ERR_UNSPEC, "could not deserialize a message chunk");
		}

		++atchunk;
		at += serial_size;
	}

	*read = at;

	return result;
}


/*
 * @brief	Deserializes and adds a dmime message chunk object to the specified dmime message from the provided binary input.
 * @param	msg		Dmime message object into which the message chunk will be deserialized.
 * @param	in		Pointer to the first byte of the binary message chunk (the first byte should be the chunk type character).
 * @param	insize		Size of the input array.
 * @param	last_type	Pointer to the previous chunk type that was serialized.
 * @return	Number of characters read as the chunk, 0 on error	
*/ //
size_t _dmsg_deserialize_helper(dmime_message_t *msg , const unsigned char *in, size_t insize, dmime_chunk_type_t *last_type) {

	dmime_chunk_key_t *key;
	dmime_chunk_section_t section;
	dmime_chunk_type_t type;
	dmime_message_chunk_t *chunk;
	size_t read = 0;

	if(!msg || !in || !insize || !last_type) {
		RET_ERROR_UINT(ERR_BAD_PARAM, NULL);
	}

	type = (dmime_chunk_type_t) in[0];

	if(type < *last_type) {
		RET_ERROR_UINT(ERR_UNSPEC, "invalid chunk order");
	}

	if(!((key = _dmsg_get_chunk_type_key(type))->section)) {
		RET_ERROR_UINT(ERR_UNSPEC, "chunk type is invalid");
	}

	section = key->section;

	if(section != CHUNK_SECTION_DISPLAY && section != CHUNK_SECTION_ATTACH) {

		if(!(chunk = _dmsg_deserialize_chunk(in, insize, &read))) {
			RET_ERROR_UINT(ERR_UNSPEC, "could not deserialize encrypted chunk");
		}

		switch(type) {
// TODO support for alternate chunks needed
			case CHUNK_TYPE_EPHEMERAL:
				msg->ephemeral = chunk;
				break;
			case CHUNK_TYPE_ORIGIN:
				msg->origin = chunk;
				break;
			case CHUNK_TYPE_DESTINATION:
				msg->destination = chunk;
				break;
			case CHUNK_TYPE_META_COMMON:
				msg->common_headers = chunk;
				break;
			case CHUNK_TYPE_META_OTHER:
				msg->other_headers = chunk;
				break;
			case CHUNK_TYPE_SIG_AUTHOR_TREE:
				msg->author_tree_sig = chunk;
				break;
			case CHUNK_TYPE_SIG_AUTHOR_FULL:
				msg->author_full_sig = chunk;
				break;
			case CHUNK_TYPE_SIG_ORIGIN_META_BOUNCE:
				msg->origin_meta_bounce_sig = chunk;
				break;
			case CHUNK_TYPE_SIG_ORIGIN_DISPLAY_BOUNCE:
				msg->origin_display_bounce_sig = chunk;
				break;
			case CHUNK_TYPE_SIG_ORIGIN_FULL:
				msg->origin_full_sig = chunk;
				break;
			default:
				_dmsg_destroy_message_chunk(chunk);
				RET_ERROR_UINT(ERR_UNSPEC, "invalid chunk type");
				break;

		}

	} else if(section == CHUNK_SECTION_DISPLAY) {

		if(!(msg->display = _dmsg_deserialize_section(in, insize, CHUNK_SECTION_DISPLAY, &read))) {
			RET_ERROR_UINT(ERR_UNSPEC, "could not deserialize display chunks");
		}

	} else {

		if(!(msg->attach = _dmsg_deserialize_section(in, insize, CHUNK_SECTION_ATTACH, &read))) {
			RET_ERROR_UINT(ERR_UNSPEC, "could not deserialize attachment chunks");
		}

	}
		
	return read;
}


/*
 * @brief	Converts a binary message into a dmime message. The message is assumed to be encrypted.
 * @param	in		Pointer to the binary message.
 * @param	insize		Pointer to the binary size.
 * @return	Pointer to a dmime message structure.
*/
dmime_message_t * _dmsg_bin_to_msg(const unsigned char *in, size_t insize) {

	dime_number_t dime_num;
	dmime_chunk_type_t last_type = CHUNK_TYPE_NONE;
	dmime_message_t *result;
	int tracing;
	size_t read = 0, at = 0, msg_size;

	if(!in || !insize) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!(result = malloc(sizeof(dmime_message_t)))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate memory for message structure");
	}

	memset(result, 0, sizeof(dmime_message_t));
	
	if(insize < DIME_NUMBER_SIZE) {
		RET_ERROR_PTR(ERR_UNSPEC, "invalid message size");
	}
	
	if((dime_num = _int_no_get_2b(in + at)) == DIME_MSG_TRACING) {
		tracing = 1;
	} else if(dime_num == DIME_ENCRYPTED_MSG) {
		tracing = 0;
	} else {
		_dmsg_destroy_msg(result);
		RET_ERROR_PTR(ERR_UNSPEC, "invalid DIME magic number for an encrypted message");
	}

	at += DIME_NUMBER_SIZE;

	if(tracing && !(read = _dmsg_deserialize_tracing(result, in + at, insize - at))) {
		_dmsg_destroy_msg(result);
		RET_ERROR_PTR(ERR_UNSPEC, "could not deserialize tracing");
	}

	at += read;

	if(insize < DIME_NUMBER_SIZE + at) {
		_dmsg_destroy_msg(result);
		RET_ERROR_PTR(ERR_UNSPEC, "invalid message size");
	}

	if(tracing && ((dime_num = _int_no_get_2b(in+at)) != DIME_ENCRYPTED_MSG)) {
		_dmsg_destroy_msg(result);
		RET_ERROR_PTR(ERR_UNSPEC, "invalid DIME magic number for an ecnrypted message");
	}

	if(tracing) {
		at += DIME_NUMBER_SIZE;
	}

	if((msg_size = _int_no_get_4b(in+at)) != (insize - at - MESSAGE_LENGTH_SIZE)) {
		_dmsg_destroy_msg(result);
		RET_ERROR_PTR(ERR_UNSPEC, "invalid message size");
	}

	at += 4;

	while(at < insize) {

		if(!(read = _dmsg_deserialize_helper(result, in + at, insize - at, &last_type))) {
			_dmsg_destroy_msg(result);
			RET_ERROR_PTR(ERR_UNSPEC, "could not read chunk data");
		}

		at += read;
	}

	if(at != insize) {
		_dmsg_destroy_msg(result);
		RET_ERROR_PTR(ERR_UNSPEC, "invalid message size");
	}

	if(result->ephemeral && result->origin && result->destination && result->common_headers && 
	   result->author_tree_sig && result->author_full_sig && result->origin_full_sig && 
	   (result->origin_meta_bounce_sig || result->origin_display_bounce_sig)) { 

		result->state = MESSAGE_STATE_COMPLETE;

	} else  {
		result->state = MESSAGE_STATE_INCOMPLETE;
	}

	return result;
}


/*
 * @brief	Calculates the key encryption key for a given private encryption key and dmime message, using the ephemeral key chunk in the message
 * @param	msg		Pointer to the dmime message, which has the ephemeral key chunk to be used.
 * @param	enckey		Private EC encryption key.
 * @param	kek		Pointer to a dmime_kek_t - a key encryption key object that can be used to decrypt the keyslots.
 * @return	Returns 0 on success, all other values indicate failure.
 */
int _dmsg_get_kek(const dmime_message_t *msg, EC_KEY *enckey, dmime_kek_t *kek) {

	dmime_ephemeral_payload_t *payload;
	EC_KEY *ephemeral;

	if(!msg || !enckey || !kek) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(!msg->ephemeral) {
		RET_ERROR_INT(ERR_UNSPEC, "no ephemeral chunk in specified message");
	}

	if(!(payload = _dmsg_get_chunk_payload(msg->ephemeral))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not get ephemeral chunk payload");
	}

	if(!(ephemeral = _deserialize_ec_pubkey(*payload, EC_PUBKEY_SIZE, 0))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not deserialize public ephemeral key");
	}

        if(_compute_aes256_kek(ephemeral, enckey, (unsigned char *)(kek))) {
                _free_ec_key(ephemeral);
                RET_ERROR_INT(ERR_UNSPEC, "could not compute aes256 kek and store it in the specified buffer");
        }

	return 0;
}


int _dmsg_decrypt_keyslot(dmime_keyslot_t *encrypted, dmime_kek_t *kek, dmime_keyslot_t *decrypted) {

	dmime_keyslot_t temp;
	int i, result;

	if(!encrypted || !kek || !decrypted) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if((result = _decrypt_aes_256((unsigned char *)&temp, (unsigned char *)encrypted, sizeof(dmime_keyslot_t), kek->key, kek->iv)) < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "an error occurred while decrypting keyslot");
	} else if(result != sizeof(dmime_keyslot_t)) {
		RET_ERROR_INT(ERR_UNSPEC, "decrypted an unexpected amount of bytes");
	}

	memcpy(decrypted->aes_key, temp.aes_key, AES_256_KEY_SIZE);
	memcpy(decrypted->random, temp.random, 16);

	for(i = 0; i < 16; ++i) {
		decrypted->iv[i] = temp.random[i] ^ temp.iv[i];
	}

	_secure_wipe(&temp, sizeof(dmime_keyslot_t));

	return 0;
}


/*
 * @brief	Decrypts specified chunk as specified actor with specified key encryption key.
 * @param	chunk		Chunk to be decrypted.
 * @param	actor		Actor doing the decryption.
 * @param	kek		Key encryption key of the actor.
 * @return	Pointer to a new chunk with a decrypted payload and empty keyslots. DON'T LEAK!
*/
dmime_message_chunk_t * _dmsg_decrypt_chunk(dmime_message_chunk_t *chunk, dmime_actor_t actor, dmime_kek_t *kek) {

	dmime_chunk_key_t *key;
	dmime_encrypted_payload_t payload;
	dmime_keyslot_t *keyslot_enc, keyslot_dec;
	dmime_message_chunk_t *result;
	int keyslot_num, res;
	size_t payload_size;
	unsigned char *data;

	if(!chunk || !kek) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!(key = _dmsg_get_chunk_type_key(chunk->type))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not retrieve chunk type key");
	}

	if(!key->encrypted) {
		RET_ERROR_PTR(ERR_UNSPEC, "this chunk type does not get encrypted");
	}

	if(chunk->state != MESSAGE_CHUNK_STATE_ENCRYPTED) {
		RET_ERROR_PTR(ERR_UNSPEC, "this chunk is not encrypted");
	}

	switch(actor) {

		case id_author:

			if(!key->auth_keyslot) {
				RET_ERROR_PTR(ERR_UNSPEC, "invalid actor for specified chunk");
			}

			keyslot_num = 1;
			break;
		case id_origin:

			if(!key->orig_keyslot) {
				RET_ERROR_PTR(ERR_UNSPEC, "invalid actor for specified chunk");
			}

			keyslot_num = key->auth_keyslot + key->orig_keyslot;
			break;
		case id_destination:

			if(!key->dest_keyslot) {
				RET_ERROR_PTR(ERR_UNSPEC, "invalid actor for specified chunk");
			}

			keyslot_num = key->auth_keyslot + key->orig_keyslot + key->dest_keyslot;
			break;
		case id_recipient:

			if(!key->recp_keyslot) {
				RET_ERROR_PTR(ERR_UNSPEC, "invalid actor for specified chunk");
			}

			keyslot_num = key->auth_keyslot + key->orig_keyslot + key->dest_keyslot + key->recp_keyslot;
			break;
		default:
			RET_ERROR_PTR(ERR_UNSPEC, "invalid dmime actor");
			break;

	}

	if((payload_size = _int_no_get_3b(chunk->payload_size)) % 16) {
		RET_ERROR_PTR(ERR_UNSPEC, "invalid chunk payload size");
	}

	if(!(payload = (dmime_encrypted_payload_t) _dmsg_get_chunk_payload(chunk))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not retrieve payload");
	}

	if(!(keyslot_enc = _dmsg_get_chunk_keyslot_by_num(chunk, (size_t) keyslot_num))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not retrieve chunk keyslot");
	}

	if(_dmsg_decrypt_keyslot(keyslot_enc, kek, &keyslot_dec)) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not decrypt keyslot");
	}

	if(!(data = malloc(payload_size))) {
		PUSH_ERROR_SYSCALL("malloc");
		_secure_wipe(&keyslot_dec, sizeof(dmime_keyslot_t));
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate memory for decrypted data");
	}

	memset(data, 0, payload_size);

	if((res = _decrypt_aes_256(data, payload, payload_size, keyslot_dec.aes_key, keyslot_dec.iv)) < 0) {
		_secure_wipe(&keyslot_dec, sizeof(dmime_keyslot_t));
		free(data);
		RET_ERROR_PTR(ERR_UNSPEC, "an error occurred while decrypting a chunk payload");
	} else if((size_t)res != payload_size) {
		_secure_wipe(&keyslot_dec, sizeof(dmime_keyslot_t));
		free(data);
		RET_ERROR_PTR(ERR_UNSPEC, "decrypted an unexpected number of bytes");
	}

	_secure_wipe(&keyslot_dec, sizeof(dmime_keyslot_t));
	result = _dmsg_wrap_chunk_payload(chunk->type, data, payload_size);
	free(data);

	if(!result) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not load data into message chunk");
	}

	return result;
}


/*
 * @brief	Destroy dmime object chunk list.
 * @param	list		Poitner to a dmime object chunk list to be destroyed.
 * @return	void.
 */
void _dmsg_destroy_object_chunk_list(dmime_object_chunk_t *list) {

	if(list) {
		_dmsg_destroy_object_chunk_list(list->next);

		if(list->data) {
			_secure_wipe(&(list->data[0]), list->data_size);
			free(list->data);
		}

		free(list);
	}

	return;
}


/*
 * @brief	Destroy a dmime object.
 * @param	object		Pointer to dmime object to be destroyed.
 * @return	void.
 */
void _dmsg_destroy_object(dmime_object_t *object) {

	if(object) {
		st_cleanup(object->author);
		st_cleanup(object->recipient);
		st_cleanup(object->origin);
		st_cleanup(object->destination);
		st_cleanup(object->common_headers);
		st_cleanup(object->other_headers);
		_dmsg_destroy_object_chunk_list(object->display);
		_dmsg_destroy_object_chunk_list(object->attach);
	}

	return;
}


/*
 * @brief	Retrieves author name for the following actors: author, origin, recipient.
 * @param	msg		Dmime message the author of which is retrieved.
 * @param	actor		Who is trying to get the message author.
 * @param	kek		Key encryption key for the specified actor.
 * @return	A newly allocated dmime object containing the envelope ids available to the actor.
 */
dmime_object_t * _dmsg_msg_to_object_envelope(const dmime_message_t *msg, dmime_actor_t actor, dmime_kek_t *kek) {

	dmime_envelope_object_t *parsed;
	dmime_message_chunk_t *decrypted;
	dmime_object_t *result;
	size_t size;
	unsigned char *chunk_data; 

	if(!msg || !kek) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(msg->state != MESSAGE_STATE_COMPLETE) {
		RET_ERROR_PTR(ERR_UNSPEC, "provided dmime message is not complete");
	}

	if(!(result = malloc(sizeof(dmime_object_t)))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate memory for dmime object");
	}

	memset(result, 0, sizeof(dmime_object_t));
	result->state = DMIME_OBJECT_STATE_CREATION;
	result->actor = actor;

	if(actor != id_destination) {

		if(!(decrypted = _dmsg_decrypt_chunk(msg->origin, actor, kek))) {
			_dmsg_destroy_object(result);
			RET_ERROR_PTR(ERR_UNSPEC, "could not decrypt origin chunk");
		}

		if(!(chunk_data = _dmsg_get_chunk_data(decrypted, &size))) {
			_dmsg_destroy_message_chunk(decrypted);
			_dmsg_destroy_object(result);
			RET_ERROR_PTR(ERR_UNSPEC, "could not retrieve chunk data");
		}

		if(!(parsed = _dmsg_parse_envelope(chunk_data, size, CHUNK_TYPE_ORIGIN))) {
			_dmsg_destroy_message_chunk(decrypted);
			_dmsg_destroy_object(result);
			RET_ERROR_PTR(ERR_UNSPEC, "could not parse origin chunk");
		}

		_dmsg_destroy_message_chunk(decrypted);
		result->author = st_dupe(parsed->auth_recp);
		result->destination = st_dupe(parsed->dest_orig);
		_dmsg_destroy_envelope_object(parsed);
	}

	if(actor != id_origin) {

		if(!(decrypted = _dmsg_decrypt_chunk(msg->destination, actor, kek))) {
			_dmsg_destroy_object(result);
			RET_ERROR_PTR(ERR_UNSPEC, "could not decrypt destination chunk");
		}

		if(!(chunk_data = _dmsg_get_chunk_data(decrypted, &size))) {
			_dmsg_destroy_message_chunk(decrypted);
			_dmsg_destroy_object(result);
			RET_ERROR_PTR(ERR_UNSPEC, "could not retrieve chunk data");
		}

		if(!(parsed = _dmsg_parse_envelope(chunk_data, size, CHUNK_TYPE_DESTINATION))) {
			_dmsg_destroy_message_chunk(decrypted);
			_dmsg_destroy_object(result);
			RET_ERROR_PTR(ERR_UNSPEC, "could not parse destination chunk");
		}

		_dmsg_destroy_message_chunk(decrypted);
		result->recipient = st_dupe(parsed->auth_recp);
		result->origin = st_dupe(parsed->dest_orig);
		_dmsg_destroy_envelope_object(parsed);
	}

	result->state = DMIME_OBJECT_STATE_LOADED_ENVELOPE;

	return result;
}


/*
 * @brief	Verify chunk plaintext signature using the author's signet.
 * @param	chunk		Pointer to a dmime message chunk, the plaintext signature of which will be verified.
 * @param	signet		Author's signet used to verify signature.
 * @return	0 if signature is valid, all other values indicate an error or an invalid signature.
 */
int _dmsg_verify_chunk_signature(dmime_message_chunk_t *chunk, signet_t *signet) {

	int result;
	size_t data_size;
	unsigned char *data, *sig;

	if(!chunk || !signet) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(!(sig = _dmsg_get_chunk_plaintext_sig(chunk))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not retrieve plaintext signature from chunk");
	}

	if(!(data = _dmsg_get_chunk_padded_data(chunk, &data_size))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not retrieve chunk padded data");
	}

/*

	fprintf(stderr, "type: %u, signature: %u data: %u\n", (unsigned int)chunk->type, _int_no_get_4b(sig), _int_no_get_4b(data));

	if(chunk->type == 4) {

		fprintf(stderr, "type:4 full chunk: ");

		for(i = 0; i < 20; ++i) {
			fprintf(stderr, "%u ", _int_no_get_4b(&(chunk->type) + (4*i)));
		}

		fprintf(stderr, "\n");
	}
*/

	result = _signet_verify_message_sig(signet, sig, data, data_size); 

	if(result < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "an error occurred while verifying plaintext signature"); 
	} else if(!result) {
		RET_ERROR_INT(ERR_UNSPEC, "the signature was invalid");
	}

	return 0;
}


/*
 * @brief	Decrypts, verifies and loads all contents of the origin chunk into the dmime object.
 * @param	object		Pointer to the dmime object into which the chunk data will be loaded.
 * @param	msg		Pointer to the dmime message containing the origin chunk.
 * @param	kek		The actor's key encryption key.
 * @return	0 on success, anything else indicates failure.
 */ //TODO pull out reusuable code for _dmsg_msg_to_object_destination
int _dmsg_msg_to_object_origin(dmime_object_t *object, const dmime_message_t *msg, dmime_kek_t *kek) {

	char *auth_signet_b64, *dest_fp_b64;
	dmime_actor_t actor;
	dmime_envelope_object_t *parsed;
	dmime_message_chunk_t *decrypted;
	signet_t *auth_split_signet;
	size_t size;
	unsigned char *chunk_data;

	if(!object || !msg || !kek) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if((actor = object->actor) == id_destination) {
		RET_ERROR_INT(ERR_UNSPEC, "the destination can not decrypt origin chunk");
	}

	if(object->state != DMIME_OBJECT_STATE_LOADED_SIGNETS) {
		RET_ERROR_INT(ERR_UNSPEC, "the state of this dmime object does not indicate that the signets have been loaded");
	}

	if(!(auth_split_signet = _signet_user_split(object->signet_author))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not split author signet");
	}

	if(!(auth_signet_b64 = _signet_serialize_b64(auth_split_signet))) {
		_signet_destroy(auth_split_signet);
		RET_ERROR_INT(ERR_UNSPEC, "could not serialize split author signet");
	}

	_signet_destroy(auth_split_signet);

	if(!(dest_fp_b64 = _signet_core_fingerprint(object->signet_destination))) {
		free(auth_signet_b64);
		RET_ERROR_INT(ERR_UNSPEC, "could not take fingerprint of destination signet");
	}

	if(!(decrypted = _dmsg_decrypt_chunk(msg->origin, actor, kek))) {
		free(dest_fp_b64);
		free(auth_signet_b64);
		RET_ERROR_INT(ERR_UNSPEC, "could not decrypt origin chunk");
	}

	if(_dmsg_verify_chunk_signature(decrypted, object->signet_author)) {
		_dmsg_destroy_message_chunk(decrypted);
		free(dest_fp_b64);
		free(auth_signet_b64);
		RET_ERROR_INT(ERR_UNSPEC, "could not verify origin chunk signature");
	}

	if(!(chunk_data = _dmsg_get_chunk_data(decrypted, &size))) {
		_dmsg_destroy_message_chunk(decrypted);
		free(dest_fp_b64);
		free(auth_signet_b64);
		RET_ERROR_INT(ERR_UNSPEC, "could not retrieve origin chunk data");
	}

	if(!(parsed = _dmsg_parse_envelope(chunk_data, size, CHUNK_TYPE_ORIGIN))) {
		_dmsg_destroy_message_chunk(decrypted);
		free(dest_fp_b64);
		free(auth_signet_b64);
		RET_ERROR_INT(ERR_UNSPEC, "could not parse origin chunk");
	}

	_dmsg_destroy_message_chunk(decrypted);

	if(strlen(auth_signet_b64) != st_length_get(parsed->auth_recp_signet) || memcmp(auth_signet_b64, st_data_get(parsed->auth_recp_signet), strlen(auth_signet_b64))) {
		_dmsg_destroy_envelope_object(parsed);
		free(dest_fp_b64);
		free(auth_signet_b64);
		RET_ERROR_INT(ERR_UNSPEC, "the object author signet does not match the message author signet");
	}

	free(auth_signet_b64);

	if(strlen(dest_fp_b64) != st_length_get(parsed->dest_orig_fingerprint) || memcmp(dest_fp_b64, st_data_get(parsed->dest_orig_fingerprint), strlen(dest_fp_b64))) {
		_dmsg_destroy_envelope_object(parsed);
		free(dest_fp_b64);
		RET_ERROR_INT(ERR_UNSPEC, "the object destination signet fingerprint does not match the message destination signet fingerprint");
	}

	free(dest_fp_b64);

	if(st_length_get(object->author) != st_length_get(parsed->auth_recp) || memcmp(st_data_get(object->author), st_data_get(parsed->auth_recp), st_length_get(object->author))) {
		_dmsg_destroy_envelope_object(parsed);
		RET_ERROR_INT(ERR_UNSPEC, "the object author id does not match the message author id");
	}

	if(st_length_get(object->destination) != st_length_get(parsed->dest_orig) || memcmp(st_data_get(object->destination), st_data_get(parsed->dest_orig), st_length_get(object->destination))) {
		_dmsg_destroy_envelope_object(parsed);
		RET_ERROR_INT(ERR_UNSPEC, "the object destination id does not match the message destination id");
	}

	return 0;
}


/*
 * @brief	Decrypts, verifies and loads all contents of the destination chunk into the dmime object.
 * @param	object		Pointer to the dmime object into which the chunk data will be loaded.
 * @param	msg		Pointer to the dmime message containing the destination chunk.
 * @param	kek		The actor's key encryption key.
 * @return	0 on success, anything else indicates failure.
 */
int _dmsg_msg_to_object_destination(dmime_object_t *object, const dmime_message_t *msg, dmime_kek_t *kek) {

	char *recp_signet_b64, *orig_fp_b64;
	dmime_actor_t actor;
	dmime_envelope_object_t *parsed;
	dmime_message_chunk_t *decrypted;
	signet_t *recp_split_signet;
	size_t size;
	unsigned char *chunk_data;

	if(!object || !msg || !kek) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if((actor = object->actor) == id_origin) {
		RET_ERROR_INT(ERR_UNSPEC, "the origin can not decrypt destination chunk");
	}

	if(object->state != DMIME_OBJECT_STATE_LOADED_SIGNETS) {
		RET_ERROR_INT(ERR_UNSPEC, "the state of this dmime object does not indicate that the signets have been loaded");
	}

	if(!(recp_split_signet = _signet_user_split(object->signet_recipient))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not split recipient signet");
	}

	if(!(recp_signet_b64 = _signet_serialize_b64(recp_split_signet))) {
		_signet_destroy(recp_split_signet);
		RET_ERROR_INT(ERR_UNSPEC, "could not serialize split recipient signet");
	}

	_signet_destroy(recp_split_signet);

	if(!(orig_fp_b64 = _signet_core_fingerprint(object->signet_origin))) {
		free(recp_signet_b64);
		RET_ERROR_INT(ERR_UNSPEC, "could not take fingerprint of origin signet");
	}

	if(!(decrypted = _dmsg_decrypt_chunk(msg->destination, actor, kek))) {
		free(orig_fp_b64);
		free(recp_signet_b64);
		RET_ERROR_INT(ERR_UNSPEC, "could not decrypt destination chunk");
	}

	if(actor != id_destination && _dmsg_verify_chunk_signature(decrypted, object->signet_author)) {
		_dmsg_destroy_message_chunk(decrypted);
		free(orig_fp_b64);
		free(recp_signet_b64);
		RET_ERROR_INT(ERR_UNSPEC, "could not verify destination chunk signature");
	}

	if(!(chunk_data = _dmsg_get_chunk_data(decrypted, &size))) {
		_dmsg_destroy_message_chunk(decrypted);
		free(orig_fp_b64);
		free(recp_signet_b64);
		RET_ERROR_INT(ERR_UNSPEC, "could not retrieve destination chunk data");
	}

	if(!(parsed = _dmsg_parse_envelope(chunk_data, size, CHUNK_TYPE_DESTINATION))) {
		_dmsg_destroy_message_chunk(decrypted);
		free(orig_fp_b64);
		free(recp_signet_b64);
		RET_ERROR_INT(ERR_UNSPEC, "could not parse destination chunk");
	}

	_dmsg_destroy_message_chunk(decrypted);

	if(strlen(recp_signet_b64) != st_length_get(parsed->auth_recp_signet) || memcmp(recp_signet_b64, st_data_get(parsed->auth_recp_signet), strlen(recp_signet_b64))) {
		_dmsg_destroy_envelope_object(parsed);
		free(orig_fp_b64);
		free(recp_signet_b64);
		RET_ERROR_INT(ERR_UNSPEC, "the object recipient signet does not match the message recipient signet");
	}

	free(recp_signet_b64);

	if(strlen(orig_fp_b64) != st_length_get(parsed->dest_orig_fingerprint) || memcmp(orig_fp_b64, st_data_get(parsed->dest_orig_fingerprint), strlen(orig_fp_b64))) {
		_dmsg_destroy_envelope_object(parsed);
		free(orig_fp_b64);
		RET_ERROR_INT(ERR_UNSPEC, "the object origin signet fingerprint does not match the message origin signet fingerprint");
	}

	free(orig_fp_b64);

	if(st_length_get(object->recipient) != st_length_get(parsed->auth_recp) || memcmp(st_data_get(object->recipient), st_data_get(parsed->auth_recp), st_length_get(object->recipient))) {
		_dmsg_destroy_envelope_object(parsed);
		RET_ERROR_INT(ERR_UNSPEC, "the object recipient id does not match the message recipient id");
	}

	if(st_length_get(object->origin) != st_length_get(parsed->dest_orig) || memcmp(st_data_get(object->origin), st_data_get(parsed->dest_orig), st_length_get(object->origin))) {
		_dmsg_destroy_envelope_object(parsed);
		RET_ERROR_INT(ERR_UNSPEC, "the object origin id does not match the message origin id");
	}

	return 0;
}


/*
 * @brief	Verify the signatures in author tree and full signature chunks.
 * @param	object		Dmime object containing the ids and signets that the specified actor requires in order to complete message decryption and verification.
 * @param	msg		Dmime message containing the signature chunks to be verified.
 * @param	kek		The current actor's key encryption key.
 * @return	0 on success, all other return values indicate failure.
 */
int _dmsg_verify_author_sig_chunks(dmime_object_t *object, const dmime_message_t *msg, dmime_kek_t *kek) {

	dmime_actor_t actor;
	dmime_message_chunk_t *decrypted;
	int result;
	size_t data_size, sig_size;
	unsigned char *data, *signature;

	if(!object || !msg || !kek) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if((actor = object->actor) == id_destination) {
		RET_ERROR_INT(ERR_UNSPEC, "destination domain can not verify author signatures");
	}

	if(object->state != DMIME_OBJECT_STATE_LOADED_SIGNETS) {
		RET_ERROR_INT(ERR_UNSPEC, "the state of this dmime object does not indicate that the signets have been loaded");
	}

	if(!(data = _dmsg_tree_sig_data(msg, &data_size))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not computer tree sig data");
	}


	if(!(decrypted = _dmsg_decrypt_chunk(msg->author_tree_sig, actor, kek))) {
		free(data);
		RET_ERROR_INT(ERR_UNSPEC, "could not decrypt author tree signature chunk");
	}

	if(!(signature = _dmsg_get_chunk_data(decrypted, &sig_size))) {
		_dmsg_destroy_message_chunk(decrypted);
		free(data);
		RET_ERROR_INT(ERR_UNSPEC, "could not retrieve author tree signature chunk data");
	} else if(sig_size != ED25519_SIG_SIZE) {
		_dmsg_destroy_message_chunk(decrypted);
		free(data);
		RET_ERROR_INT(ERR_UNSPEC, "signature chunk has data of invalid size");
	}

	result =  _signet_verify_message_sig(object->signet_author, signature, data, data_size);
	_dmsg_destroy_message_chunk(decrypted);
	free(data);

	if(result < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "error verifying author tree signature");
	} else if(!result) {
		RET_ERROR_INT(ERR_UNSPEC, "author tree signature is invalid");
	}

	if(!(data = _dmsg_serialize_chunks(msg, CHUNK_TYPE_EPHEMERAL, CHUNK_TYPE_SIG_AUTHOR_TREE, &data_size))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not serialize dmime message");
	}

	if(!(decrypted = _dmsg_decrypt_chunk(msg->author_full_sig, actor, kek))) {
		free(data);
		RET_ERROR_INT(ERR_UNSPEC, "could not decrypt author full signature chunk");
	}

	if(!(signature = _dmsg_get_chunk_data(decrypted, &sig_size))) {
		_dmsg_destroy_message_chunk(decrypted);
		free(data);
		RET_ERROR_INT(ERR_UNSPEC, "could not retrieve author tree signature chunk data");
	} else if(sig_size != ED25519_SIG_SIZE) {
		_dmsg_destroy_message_chunk(decrypted);
		free(data);
		RET_ERROR_INT(ERR_UNSPEC, "signature chunk has data of invalid size");
	}

	result = _signet_verify_message_sig(object->signet_author, signature, data, data_size);
	_dmsg_destroy_message_chunk(decrypted);
	free(data);

	if(result) {
		RET_ERROR_INT(ERR_UNSPEC, "error verifying author full signature");
	} else if(!result) {
		RET_ERROR_INT(ERR_UNSPEC, "author full signature is invalid");
	}

	return 0;
}


/*
 * @brief	Decrypts and verifies the common headers metadata chunk and loads it into the dmime object.
 * @param	object		Dmime object that will have the contents of the common headers chunk loaded into it.
 * @param	msg		Dmime object which contains the common headers chunk to be decrypted and verified.
 * @param	kek		The key encryption key for the current actor.
 * @return	0 on success, all other values indicate failure.
 */
int _dmsg_msg_to_object_common_headers(dmime_object_t *object, const dmime_message_t *msg, dmime_kek_t *kek) {

	dmime_actor_t actor;
	dmime_message_chunk_t *decrypted;
	//int i;
	size_t data_size;
	unsigned char *data;

	if(!object || !msg || !kek) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(((actor = object->actor) == id_origin) || actor == id_destination) {
		RET_ERROR_INT(ERR_UNSPEC, "only the author and recipient have access to the metadata");
	}

	if(object->state != DMIME_OBJECT_STATE_LOADED_SIGNETS) {
		RET_ERROR_INT(ERR_UNSPEC, "the state of this dmime object does not indicate that the actor signets have been loaded");
	}

	if(!(decrypted = _dmsg_decrypt_chunk(object->common_headers, actor, kek))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not decrypt common headers chunk");
	}

	if(_dmsg_verify_chunk_signature(decrypted, object->signet_author)) {
		_dmsg_destroy_message_chunk(decrypted);
		RET_ERROR_INT(ERR_UNSPEC, "the plaintext chunk signature is invalid");
	}

	if(!(data = _dmsg_get_chunk_data(decrypted, &data_size))) {
		_dmsg_destroy_message_chunk(decrypted);
		RET_ERROR_INT(ERR_UNSPEC, "could not retrieve chunk data");
	}
/*//TODO content check
	for(i = 0; i < data_size; ++i) {

		if(!isprint(data[i]) && !isspace(data[i])) {
			_dmsg_destroy_message_chunk(decrypted);
			RET_ERROR_INT(ERR_UNSPEC, "invalid characters in the metadata chunk");
		}

	}
*/	
	object->common_headers = st_import(data, data_size);
	_dmsg_destroy_message_chunk(decrypted);

	return 0;
}


/*
 * @brief	Decrypts and verifies the other headers metadata chunk and loads it into the dmime object.
 * @param	object		Dmime object that will have the contents of the other headers chunk loaded into it.
 * @param	msg		Dmime object which contains the other headers chunk to be decrypted and verified.
 * @param	kek		The key encryption key for the current actor.
 * @return	0 on success, all other values indicate failure.
 */
int _dmsg_msg_to_object_other_headers(dmime_object_t *object, const dmime_message_t *msg, dmime_kek_t *kek) {

	dmime_actor_t actor;
	dmime_message_chunk_t *decrypted;
	//int i;
	size_t data_size;
	unsigned char *data;

	if(!object || !msg || !kek) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(((actor = object->actor) == id_origin) || actor == id_destination) {
		RET_ERROR_INT(ERR_UNSPEC, "only the author and recipient have access to the metadata");
	}

	if(object->state != DMIME_OBJECT_STATE_LOADED_SIGNETS) {
		RET_ERROR_INT(ERR_UNSPEC, "the state of this dmime object does not indicate that the actor signets have been loaded");
	}

	if(!(decrypted = _dmsg_decrypt_chunk(object->other_headers, actor, kek))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not decrypt common headers chunk");
	}

	if(_dmsg_verify_chunk_signature(decrypted, object->signet_author)) {
		_dmsg_destroy_message_chunk(decrypted);
		RET_ERROR_INT(ERR_UNSPEC, "the plaintext chunk signature is invalid");
	}

	if(!(data = _dmsg_get_chunk_data(decrypted, &data_size))) {
		_dmsg_destroy_message_chunk(decrypted);
		RET_ERROR_INT(ERR_UNSPEC, "could not retrieve chunk data");
	}
/*//TODO content check
	for(i = 0; i < data_size; ++i) {

		if(!isprint(data[i]) && !isspace(data[i])) {
			_dmsg_destroy_message_chunk(decrypted);
			RET_ERROR_INT(ERR_UNSPEC, "invalid characters in the metadata chunk");
		}

	}
*/
	object->common_headers = st_import(data, data_size);
	_dmsg_destroy_message_chunk(decrypted);

	return 0;
}


/* @brief	Creates a dmime object chunk with the specified type, data and flags.
 * @param	type		Chunk type.
 * @param	data		Pointer to an array that gets copied into newly allocated memory.
 * @param	data_size	Length of data array.
 * @param	flags		Specified flags for the object chunk.
*/
dmime_object_chunk_t * _dmsg_create_object_chunk(dmime_chunk_type_t type, unsigned char *data, size_t data_size, unsigned char flags) {

	dmime_object_chunk_t *result;

	if(!data || !data_size) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!(result = malloc(sizeof(dmime_object_chunk_t)))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate memory for a dmime object chunk");
	}

	memset(result, 0, sizeof(dmime_object_chunk_t));
	result->type = type;

	if(!(result->data = malloc(data_size))) {
		_dmsg_destroy_object_chunk_list(result);
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate memory for dmime object chunk data");
	}

	memset(result->data, 0, data_size);
	memcpy(result->data, data, data_size);
	result->flags = flags;
	result->data_size = data_size;

	return result;
}


/*
 * @brief	Decrypts and verifies all the available display and attachment chunks and loads them into the dmime object.
 * @param	object		Dmime object that will contain the display and attachment data.
 * @param	msg		An encrypted dmime message from which display and attachment data is taken.
 * @param	kek		The key encryption key for the current actor.
 * @return	0 on success, all other values indicate failure.
*/
int _dmsg_msg_to_object_content(dmime_object_t *object, const dmime_message_t *msg, dmime_kek_t *kek) {

	dmime_actor_t actor;
	dmime_message_chunk_t *decrypted;
	dmime_object_chunk_t *chunk, *last = NULL;
	int i = 0;
	unsigned char *data;
	size_t data_size;

	if(!object || !msg || !kek) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(object->state != DMIME_OBJECT_STATE_LOADED_SIGNETS) {
		RET_ERROR_INT(ERR_UNSPEC, "the state of the object does not indicate that all necessary signets were loaded");
	}

	if(((actor = object->actor) == id_destination) || actor == id_origin) {
		RET_ERROR_INT(ERR_UNSPEC, "origin and destination do not have access to the content chunks");
	}

	if(object->display || object->attach) {
		RET_ERROR_INT(ERR_UNSPEC, "this object already contains data in its content chunks");
	}

	if(msg->display) {

		while(msg->display[i]) {
		
			if(!(decrypted = _dmsg_decrypt_chunk(msg->display[i], actor, kek))) {
				_dmsg_destroy_object_chunk_list(object->display);
				RET_ERROR_INT(ERR_UNSPEC, "could not decrypt display chunk");
			}

			if(_dmsg_verify_chunk_signature(decrypted, object->signet_author)) {
				_dmsg_destroy_object_chunk_list(object->display);
				_dmsg_destroy_message_chunk(decrypted);
				RET_ERROR_INT(ERR_UNSPEC, "could not verify signature chunk");
			}

			if(!(data = _dmsg_get_chunk_data(decrypted, &data_size))) {
				_dmsg_destroy_object_chunk_list(object->display);
				_dmsg_destroy_message_chunk(decrypted);
				RET_ERROR_INT(ERR_UNSPEC, "could not retrieve decrypted display chunk data");
			}

			if(!(chunk = _dmsg_create_object_chunk(decrypted->type, data, data_size, _dmsg_get_chunk_flags(decrypted)))) {
				_dmsg_destroy_object_chunk_list(object->display);
				_dmsg_destroy_message_chunk(decrypted);
				RET_ERROR_INT(ERR_UNSPEC, "could not create an object chunk with the contents from the message chunk");
			}

			_dmsg_destroy_message_chunk(decrypted);

			if(!i) {
				object->display = chunk;
				last = object->display;
			} else if (chunk) {
				last->next = chunk;
				last = chunk;
			}

			++i;
		}

	}

	i = 0;

	if(msg->attach) {
	
		while(msg->attach[i]) {
		
			if(!(decrypted = _dmsg_decrypt_chunk(msg->attach[i], actor, kek))) {
				_dmsg_destroy_object_chunk_list(object->attach);
				_dmsg_destroy_object_chunk_list(object->display);
				RET_ERROR_INT(ERR_UNSPEC, "could not decrypt display chunk");
			}

			if(_dmsg_verify_chunk_signature(decrypted, object->signet_author)) {
				_dmsg_destroy_object_chunk_list(object->attach);
				_dmsg_destroy_object_chunk_list(object->display);
				_dmsg_destroy_message_chunk(decrypted);
				RET_ERROR_INT(ERR_UNSPEC, "could not verify signature chunk");
			}

			if(!(data = _dmsg_get_chunk_data(decrypted, &data_size))) {
				_dmsg_destroy_object_chunk_list(object->attach);
				_dmsg_destroy_object_chunk_list(object->display);
				_dmsg_destroy_message_chunk(decrypted);
				RET_ERROR_INT(ERR_UNSPEC, "could not retrieve decrypted display chunk data");
			}

			if(!(chunk = _dmsg_create_object_chunk(decrypted->type, data, data_size, _dmsg_get_chunk_flags(decrypted)))) {
				_dmsg_destroy_object_chunk_list(object->attach);
				_dmsg_destroy_object_chunk_list(object->display);
				_dmsg_destroy_message_chunk(decrypted);
				RET_ERROR_INT(ERR_UNSPEC, "could not create an object chunk with the contents from the message chunk");
			}

			_dmsg_destroy_message_chunk(decrypted);

			if(!i) {
				object->attach = chunk;
				last = object->display;
			} else if (chunk) {
				chunk->next = chunk;
				last = chunk;
			}

			++i;
		}

	}

	return 0;
}


/*
 * @brief	Decrypts, verifies and extracts all the information available to the author from the message.
 * @param	object		Dmime object into which the information is extracted, it must already contain the ids and signets of all the actors available to the author.
 * @param	msg		Dmime message to be decrypted.
 * @param	enckey		Author's private encryption EC key.
 * @return	0 on success, all other output values indicate failure.
*/
int _dmsg_msg_to_object_as_auth(dmime_object_t *obj, const dmime_message_t *msg, dmime_kek_t * kek) {

	if(!obj || !msg || !kek) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(!msg->state != MESSAGE_STATE_COMPLETE) {
		RET_ERROR_INT(ERR_UNSPEC, "the specified dmime message is not complete");
	}

	if(obj->actor != id_author) {
		RET_ERROR_INT(ERR_UNSPEC, "the dmime object specifies actor other than author");
	}

	if(obj->state < DMIME_OBJECT_STATE_LOADED_ENVELOPE || !(obj->author && obj->signet_author) || !(obj->origin && obj->signet_origin) || !(obj->destination && obj->signet_destination) || !(obj->recipient && obj->signet_recipient)) {
		RET_ERROR_INT(ERR_UNSPEC, "not all necessary signets were retrieved to decrypt the message");
	}

	obj->state = DMIME_OBJECT_STATE_LOADED_SIGNETS;

	if(_dmsg_msg_to_object_origin(obj, msg, kek)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not load origin chunk contents");
	}

	if(_dmsg_msg_to_object_destination(obj, msg, kek)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not load destination chunk contents");
	}

	// TODO this needs to be changed for when not the entire message was downloaded. Author/Recipient needs to be able to request the combined hashes of all the chunks from their domain to verify the tree signature, but the full author signature can't always be verified.
	// TODO Technically author/recipients should only have to verify the tree signature.
	if(_dmsg_verify_author_sig_chunks(obj, msg, kek)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not verify author signature chunks");
	} 

/*	// TODO This has similar issue as above. technically these signatures are only for the destination to verify UNLESS it's a bounce and then the appropriate bounce signature needs to be verified by the recipient. How do we know if it's a bounce?!
	if(_dmsg_verify_origin_sig_chunks(obj, msg, kek)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not verify author signature chunks");
	}
*/
	if(_dmsg_msg_to_object_common_headers(obj, msg, kek)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not load common headers chunk contents");
	}

	if(_dmsg_msg_to_object_other_headers(obj, msg, kek)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not load common headers chunk contents");
	}

	if(_dmsg_msg_to_object_content(obj, msg, kek)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not load mesage content");
	}

	obj->state = DMIME_OBJECT_STATE_COMPLETE;

	return 0;
}


/*
 * @brief	Decrypts, verifies and extracts all the information available to the origin from the message.
 * @param	object		Dmime object into which the information is extracted, it must already contain the ids and signets of all the actors available to the origin.
 * @param	msg		Dmime message to be decrypted.
 * @param	enckey		Origin's private encryption EC key.
 * @return	0 on success, all other output values indicate failure.
*/
int _dmsg_msg_to_object_as_orig(dmime_object_t *obj, const dmime_message_t *msg, dmime_kek_t * kek) {

	if(!obj || !msg || !kek) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(msg->state != MESSAGE_STATE_COMPLETE) {
		RET_ERROR_INT(ERR_UNSPEC, "the specified dmime message is not complete");
	}

	if(obj->actor != id_origin) {
		RET_ERROR_INT(ERR_UNSPEC, "the dmime object specifies actor other than origin");
	}

	if(obj->state < DMIME_OBJECT_STATE_LOADED_ENVELOPE || !(obj->author && obj->signet_author) || !(obj->origin && obj->signet_origin) || !(obj->destination && obj->signet_destination)) {
		RET_ERROR_INT(ERR_UNSPEC, "not all necessary signets were retrieved to decrypt the message");
	}

	obj->state = DMIME_OBJECT_STATE_LOADED_SIGNETS;

	if(_dmsg_msg_to_object_origin(obj, msg, kek)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not load origin chunk contents");
	}

	// TODO this needs to be changed for when not the entire message was downloaded. Author/Recipient needs to be able to request the combined hashes of all the chunks from their domain to verify the tree signature, but the full author signature can't always be verified.
	// TODO Technically author/recipients should only have to verify the tree signature.
	if(_dmsg_verify_author_sig_chunks(obj, msg, kek)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not verify author signature chunks");
	} 

	obj->state = DMIME_OBJECT_STATE_COMPLETE;

	return 0;
}


/*
 * @brief	Signs the encrypted, author signed dmime message with the origin signatures. The origin signature chunks must already exist in order for the signing to occur.
 * @param	msg		Dmime message that will be signed by the origin.
 * @param	bounce_flags	Flags indicating bounce signatures that the origin will sign.
 * @param	kek		Origin's key encryption key.
 * @param	signkey		Origin's private signing key that will be used to sign the message. The public part of this key must be included in the origin signet either as the pok or one of the soks with the message signing flag.
 * @return	0 on success, anything else indicates failure.
 */ //TODO some code reusability is possible with a subroutine.
int _dmsg_sign_origin_sig_chunks(dmime_message_t *msg, unsigned char bounce_flags, dmime_kek_t *kek, ED25519_KEY *signkey) {

	dmime_keyslot_t *keyslot_enc, keyslot_dec;
	ed25519_signature sig;
	int res;
	size_t data_size, chunk_data_size;
	unsigned char *data, *chunk_data;

	if(!msg || !kek) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(!msg->origin_full_sig) {
		RET_ERROR_INT(ERR_UNSPEC, "the message does not have a chunk for origin full signature");
	}

	if(msg->origin_meta_bounce_sig) {

		if(bounce_flags & META_BOUNCE) {

			if(!(data = _dmsg_serialize_sections(msg, (CHUNK_SECTION_ENVELOPE | CHUNK_SECTION_METADATA), &data_size))) {
				RET_ERROR_INT(ERR_UNSPEC, "could not serialize message for bounce metadata signature");
			}

			res = _ed25519_sign_data(data, data_size, signkey, sig);
			free(data);

			if(res) {
				RET_ERROR_INT(ERR_UNSPEC, "could not sign data with origin's message signing key");
			}

			if(!(chunk_data = _dmsg_get_chunk_data(msg->origin_meta_bounce_sig, &chunk_data_size)) || (chunk_data_size != ED25519_SIG_SIZE)) {
				_secure_wipe(sig, sizeof(ed25519_signature));
				RET_ERROR_INT(ERR_UNSPEC, "could not locate chunk data segment");
			}

			if(!(keyslot_enc = _dmsg_get_chunk_keyslot_by_num(msg->origin_meta_bounce_sig, id_origin + 1))) {
				_secure_wipe(sig, sizeof(ed25519_signature));
				RET_ERROR_INT(ERR_UNSPEC, "can not retrieve origin meta bounce chunk keyslot");
			}

			if(_dmsg_decrypt_keyslot(keyslot_enc, kek, &keyslot_dec)) {
				_secure_wipe(sig, sizeof(ed25519_signature));
				RET_ERROR_INT(ERR_UNSPEC, "can not decrypt keyslot");
			}

        		if ((res = _encrypt_aes_256(chunk_data, (unsigned char *)sig, ED25519_SIG_SIZE, keyslot_dec.aes_key, keyslot_dec.iv)) < 0) {
				_secure_wipe(&keyslot_dec, sizeof(dmime_keyslot_t));
				_secure_wipe(sig, sizeof(ed25519_signature));
       				RET_ERROR_INT(ERR_UNSPEC, "error occurred while encrypting chunk data");
       		 	} else if (res != ED25519_SIG_SIZE) {
				_secure_wipe(&keyslot_dec, sizeof(dmime_keyslot_t));
				_secure_wipe(sig, sizeof(ed25519_signature));
       	        		mm_set(chunk_data, 0, ED25519_SIG_SIZE);
       				RET_ERROR_INT(ERR_UNSPEC, "chunk data encryption operation did not return expected length");
	        	}

			_secure_wipe(&keyslot_dec, sizeof(dmime_keyslot_t));
			_secure_wipe(sig, sizeof(ed25519_signature));
		} else {
			_dmsg_destroy_message_chunk(msg->origin_meta_bounce_sig);
			msg->origin_meta_bounce_sig = NULL;
		}

	}

	if(msg->origin_display_bounce_sig && (bounce_flags & DISPLAY_BOUNCE)) {

		if(bounce_flags & DISPLAY_BOUNCE) {

			if(!(data = _dmsg_serialize_sections(msg, (CHUNK_SECTION_ENVELOPE | CHUNK_SECTION_METADATA | CHUNK_SECTION_DISPLAY), &data_size))) {
				RET_ERROR_INT(ERR_UNSPEC, "could not serialize message for bounce display signature");
			}

			res = _ed25519_sign_data(data, data_size, signkey, sig);
			free(data);

			if(res) {
				RET_ERROR_INT(ERR_UNSPEC, "could not sign data with origin's message signing key");
			}

			if(!(chunk_data = _dmsg_get_chunk_data(msg->origin_display_bounce_sig, &chunk_data_size)) || (chunk_data_size != ED25519_SIG_SIZE)) {
				_secure_wipe(sig, sizeof(ed25519_signature));
				RET_ERROR_INT(ERR_UNSPEC, "could not locate chunk data segment");
			}

			if(!(keyslot_enc = _dmsg_get_chunk_keyslot_by_num(msg->origin_display_bounce_sig, id_origin + 1))) {
				_secure_wipe(sig, sizeof(ed25519_signature));
				RET_ERROR_INT(ERR_UNSPEC, "can not retrieve origin display bounce chunk keyslot");
			}

			if(_dmsg_decrypt_keyslot(keyslot_enc, kek, &keyslot_dec)) {
				_secure_wipe(sig, sizeof(ed25519_signature));
				RET_ERROR_INT(ERR_UNSPEC, "can not decrypt keyslot");
			}

	        	if ((res = _encrypt_aes_256(chunk_data, (unsigned char *)sig, ED25519_SIG_SIZE, keyslot_dec.aes_key, keyslot_dec.iv)) < 0) {
				_secure_wipe(&keyslot_dec, sizeof(dmime_keyslot_t));
				_secure_wipe(sig, sizeof(ed25519_signature));
       				RET_ERROR_INT(ERR_UNSPEC, "error occurred while encrypting chunk data");
        		} else if (res != ED25519_SIG_SIZE) {
				_secure_wipe(&keyslot_dec, sizeof(dmime_keyslot_t));
				_secure_wipe(sig, sizeof(ed25519_signature));
               			mm_set(chunk_data, 0, ED25519_SIG_SIZE);
                		RET_ERROR_INT(ERR_UNSPEC, "chunk data encryption operation did not return expected length");
        		}

			_secure_wipe(&keyslot_dec, sizeof(dmime_keyslot_t));
			_secure_wipe(sig, sizeof(ed25519_signature));
		} else {
			_dmsg_destroy_message_chunk(msg->origin_display_bounce_sig);
			msg->origin_display_bounce_sig = NULL;
		}

	}

	if(!(data = _dmsg_serialize_chunks(msg, CHUNK_TYPE_EPHEMERAL, CHUNK_TYPE_SIG_ORIGIN_DISPLAY_BOUNCE, &data_size))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not serialize dmime message");
	}

	res = _ed25519_sign_data(data, data_size, signkey, sig);
	free(data);

	if(res) {
		RET_ERROR_INT(ERR_UNSPEC, "could not sign data with origin's message signing key");
	}

	if(!(chunk_data = _dmsg_get_chunk_data(msg->origin_full_sig, &chunk_data_size)) || (chunk_data_size != ED25519_SIG_SIZE)) {
		_secure_wipe(sig, sizeof(ed25519_signature));
		RET_ERROR_INT(ERR_UNSPEC, "could not retrieve chunk data segment");
	}

	if(!(keyslot_enc = _dmsg_get_chunk_keyslot_by_num(msg->origin_full_sig, id_origin + 1))) {
		_secure_wipe(sig, sizeof(ed25519_signature));
		RET_ERROR_INT(ERR_UNSPEC, "can not retrieve origin full signature chunk keyslot");
	}

	if(_dmsg_decrypt_keyslot(keyslot_enc, kek, &keyslot_dec)) {
		_secure_wipe(sig, sizeof(ed25519_signature));
		RET_ERROR_INT(ERR_UNSPEC, "can not decrypt keyslot");
	}

       	if ((res = _encrypt_aes_256(chunk_data, (unsigned char *)sig, ED25519_SIG_SIZE, keyslot_dec.aes_key, keyslot_dec.iv)) < 0) {
		_secure_wipe(&keyslot_dec, sizeof(dmime_keyslot_t));
		_secure_wipe(sig, sizeof(ed25519_signature));
               	RET_ERROR_INT(ERR_UNSPEC, "error occurred while encrypting chunk data");
       	} else if (res != ED25519_SIG_SIZE) {
		_secure_wipe(&keyslot_dec, sizeof(dmime_keyslot_t));
		_secure_wipe(sig, sizeof(ed25519_signature));
       		mm_set(chunk_data, 0, ED25519_SIG_SIZE);
               	RET_ERROR_INT(ERR_UNSPEC, "chunk data encryption operation did not return expected length");
       	}

	_secure_wipe(&keyslot_dec, sizeof(dmime_keyslot_t));
	_secure_wipe(sig, sizeof(ed25519_signature));

	return 0;
}


/*
 * @brief	Verify the signatures in origin bounce and full signature chunks.
 * @param	object		Dmime object containing the ids and signets that the specified actor requires in order to complete message decryption and verification.
 * @param	msg		Dmime message containing the signature chunks to be verified.
 * @param	kek		The current actor's key encryption key.
 * @return	0 on success, all other return values indicate failure.
 */ 
int _dmsg_verify_origin_sig_chunks(dmime_object_t *object, const dmime_message_t *msg, dmime_kek_t *kek) {

	ED25519_KEY *signkey;
	dmime_actor_t actor;
	dmime_message_chunk_t *decrypted;
	int result;
	size_t data_size, sig_size;
	unsigned char *data, *signature;

	if(!object || !msg || !kek) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(object->state != DMIME_OBJECT_STATE_LOADED_SIGNETS) {
		RET_ERROR_INT(ERR_UNSPEC, "the state of this dmime object does not indicate that the signets have been loaded");
	}

	actor = object->actor;

	if(!(signkey = _signet_get_signkey(object->signet_origin))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not retrieve author signing key");
	}

	if(msg->origin_meta_bounce_sig) {

		if(!(data = _dmsg_serialize_sections(msg, (CHUNK_SECTION_ENVELOPE | CHUNK_SECTION_METADATA), &data_size))) {
			free_ed25519_key(signkey);
			RET_ERROR_INT(ERR_UNSPEC, "could not serialize envelope and metadata message chunks");
		}

		if(!(decrypted = _dmsg_decrypt_chunk(msg->origin_meta_bounce_sig, actor, kek))) {
			free(data);
			_free_ed25519_key(signkey);
			RET_ERROR_INT(ERR_UNSPEC, "could not decrypt origin meta bounce chunk");
		}

		if(!(signature = _dmsg_get_chunk_data(decrypted, &sig_size)) || (sig_size != ED25519_SIG_SIZE)) {
			_dmsg_destroy_message_chunk(decrypted);
			free(data);
			_free_ed25519_key(signkey);
			RET_ERROR_INT(ERR_UNSPEC, "could not retrieve meta bounce chunk data");
		}

		result = _ed25519_verify_sig(data, data_size, signkey, signature);
		_dmsg_destroy_message_chunk(decrypted);
		free(data);

		if(result) {
			_free_ed25519_key(signkey);
			RET_ERROR_INT(ERR_UNSPEC, "the origin meta bounce signature could not be validated successfully");
		}

	}

	if(msg->origin_display_bounce_sig) {

		if(!(data = _dmsg_serialize_sections(msg, (CHUNK_SECTION_ENVELOPE | CHUNK_SECTION_METADATA | CHUNK_SECTION_DISPLAY), &data_size))) {
			free_ed25519_key(signkey);
			RET_ERROR_INT(ERR_UNSPEC, "could not serialize envelope metadata and display message chunks");
		}

		if(!(decrypted = _dmsg_decrypt_chunk(msg->origin_display_bounce_sig, actor, kek))) {
			free(data);
			_free_ed25519_key(signkey);
			RET_ERROR_INT(ERR_UNSPEC, "could not decrypt origin display bounce chunk");
		}

		if(!(signature = _dmsg_get_chunk_data(decrypted, &sig_size)) || (sig_size != ED25519_SIG_SIZE)) {
			_dmsg_destroy_message_chunk(decrypted);
			free(data);
			_free_ed25519_key(signkey);
			RET_ERROR_INT(ERR_UNSPEC, "could not retrieve dispaly bounce chunk data");
		}

		result = _ed25519_verify_sig(data, data_size, signkey, signature);
		_dmsg_destroy_message_chunk(decrypted);
		free(data);

		if(result) {
			_free_ed25519_key(signkey);
			RET_ERROR_INT(ERR_UNSPEC, "the origin display bounce signature could not be validated successfully");
		}

	}

	if(!(data = _dmsg_serialize_chunks(msg, CHUNK_TYPE_EPHEMERAL, CHUNK_TYPE_SIG_ORIGIN_DISPLAY_BOUNCE, &data_size))) {
		_free_ed25519_key(signkey);
		RET_ERROR_INT(ERR_UNSPEC, "could not serialize the dmime message");
	}

	if(!(decrypted = _dmsg_decrypt_chunk(msg->origin_full_sig, actor, kek))) {
		free(data);
		_free_ed25519_key(signkey);
		RET_ERROR_INT(ERR_UNSPEC, "could not decrypt chunk");
	}

	if(!(signature = _dmsg_get_chunk_data(decrypted, &sig_size)) || (sig_size != ED25519_SIG_SIZE)) {
		_dmsg_destroy_message_chunk(decrypted);
		free(data);
		_free_ed25519_key(signkey);
		RET_ERROR_INT(ERR_UNSPEC, "could not retrieve origin full sig chunk data");
	}

	result = _ed25519_verify_sig(data, data_size, signkey, signature);
	_dmsg_destroy_message_chunk(decrypted);
	free(data);
	_free_ed25519_key(signkey);

	if(result) {
		RET_ERROR_INT(ERR_UNSPEC, "the origin full signature was not validated successfully");
	}

	return 0;
}


/*
 * @brief	Decrypts, verifies and extracts all the information available to the destination from the message.
 * @param	object		Dmime object into which the information is extracted, it must already contain the ids and signets of all the actors available to the destination.
 * @param	msg		Dmime message to be decrypted.
 * @param	enckey		Destination's private encryption EC key.
 * @return	0 on success, all other output values indicate failure.
*/
int _dmsg_msg_to_object_as_dest(dmime_object_t *obj, const dmime_message_t *msg, dmime_kek_t * kek) {

	if(!obj || !msg || !kek) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(!msg->state != MESSAGE_STATE_COMPLETE) {
		RET_ERROR_INT(ERR_UNSPEC, "the specified dmime message is not complete");
	}

	if(obj->actor != id_destination) {
		RET_ERROR_INT(ERR_UNSPEC, "the dmime object specifies actor other than destination");
	}

	if(obj->state < DMIME_OBJECT_STATE_LOADED_ENVELOPE || !(obj->recipient && obj->signet_recipient) || !(obj->origin && obj->signet_origin) || !(obj->destination && obj->signet_destination)) {
		RET_ERROR_INT(ERR_UNSPEC, "not all necessary signets were retrieved to decrypt the message");
	}

	obj->state = DMIME_OBJECT_STATE_LOADED_SIGNETS;

	if(_dmsg_msg_to_object_destination(obj, msg, kek)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not load destination chunk contents");
	}

	// TODO this needs to be changed for when not the entire message was downloaded. Author/Recipient needs to be able to request the combined hashes of all the chunks from their domain to verify the tree signature, but the full author signature can't always be verified.
	// TODO Technically author/recipients should only have to verify the tree signature.
	if(_dmsg_verify_author_sig_chunks(obj, msg, kek)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not verify author signature chunks");
	}
 
	if(_dmsg_verify_origin_sig_chunks(obj, msg, kek)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not verify origin signature chunks");
	} 

	obj->state = DMIME_OBJECT_STATE_COMPLETE;

	return 0;
}


/*
 * @brief	Decrypts, verifies and extracts all the information available to the recipient from the message.
 * @param	object		Dmime object into which the information is extracted, it must already contain the ids and signets of all the actors available to the recipient.
 * @param	msg		Dmime message to be decrypted.
 * @param	enckey		Recipient's private encryption EC key.
 * @return	0 on success, all other output values indicate failure.
*/
int _dmsg_msg_to_object_as_recp(dmime_object_t *obj, const dmime_message_t *msg, dmime_kek_t * kek) {

	if(!obj || !msg || !kek) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(!msg->state != MESSAGE_STATE_COMPLETE) {
		RET_ERROR_INT(ERR_UNSPEC, "the specified dmime message is not complete");
	}

	if(obj->actor != id_recipient) {
		RET_ERROR_INT(ERR_UNSPEC, "the dmime object specifies actor other than recipient");
	}

	if(obj->state < DMIME_OBJECT_STATE_LOADED_ENVELOPE || !(obj->author && obj->signet_author) || !(obj->origin && obj->signet_origin) || !(obj->destination && obj->signet_destination) || !(obj->recipient && obj->signet_recipient)) {
		RET_ERROR_INT(ERR_UNSPEC, "not all necessary signets were retrieved to decrypt the message");
	}

	obj->state = DMIME_OBJECT_STATE_LOADED_SIGNETS;

	if(_dmsg_msg_to_object_origin(obj, msg, kek)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not load origin chunk contents");
	}

	if(_dmsg_msg_to_object_destination(obj, msg, kek)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not load destination chunk contents");
	}

	// TODO this needs to be changed for when not the entire message was downloaded. Author/Recipient needs to be able to request the combined hashes of all the chunks from their domain to verify the tree signature, but the full author signature can't always be verified.
	// TODO Technically author/recipients should only have to verify the tree signature.
	if(_dmsg_verify_author_sig_chunks(obj, msg, kek)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not verify recipient signature chunks");
	} 

	// TODO This has similar issue as above. technically these signatures are only for the destination to verify UNLESS it's a bounce and then the appropriate bounce signature needs to be verified by the recipient. How do we know if it's a bounce?!
	// TODO UPDATE: bounces will have a different magic number, we need to add a discriminator to dmime_message_t structure.
	if(_dmsg_verify_origin_sig_chunks(obj, msg, kek)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not verify recipient signature chunks");
	}

	if(_dmsg_msg_to_object_common_headers(obj, msg, kek)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not load common headers chunk contents");
	}

	if(_dmsg_msg_to_object_other_headers(obj, msg, kek)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not load common headers chunk contents");
	}

	if(_dmsg_msg_to_object_content(obj, msg, kek)) {
		RET_ERROR_INT(ERR_UNSPEC, "could not load mesage content");
	}

	obj->state = DMIME_OBJECT_STATE_COMPLETE;

	return 0;
}


/*
 * @brief	Dumps the contents of the dmime object.
 * @param	object		Dmime object to be dumped.
 * @return	0 on success, all other values indicate failure.
*/
int _dmsg_dump_object(dmime_object_t *object) {

	dmime_object_chunk_t *display;
	int i = 1;

	if(!object) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	printf("Message Viewer: %s\n", _dmsg_actor_to_string(object->actor));
	printf("Message State : %s\n", _dmsg_object_state_to_string(object->state));
	
	if((object->actor != id_destination) && object->author) {
		printf("Message Auth  : %.*s\n", (int)st_length_get(object->author), (char *)st_data_get(object->author));
	}

	if((object->actor != id_origin) && object->origin) {
		printf("Message Orig  : %.*s\n", (int)st_length_get(object->origin), (char *)st_data_get(object->origin));
	}

	if((object->actor != id_destination) && object->destination) {
		printf("Message Dest  : %.*s\n", (int)st_length_get(object->destination), (char *)st_data_get(object->destination));
	}

	if((object->actor != id_origin) && object->recipient) {
		printf("Message Recp  : %.*s\n", (int)st_length_get(object->recipient), (char *)st_data_get(object->recipient));
	}

	if((object->actor == id_author) || (object->actor == id_recipient)) {
		printf("Common Headers:\n %.*s\n", (int)st_length_get(object->common_headers), (char *)st_data_get(object->common_headers));
		printf("Other Headers :\n %.*s\n", (int)st_length_get(object->other_headers), (char *)st_data_get(object->other_headers));
		display = object->display;

		while(display) {
			printf("Display %d     :\n %.*s\n", i, (int)display->data_size, display->data);
			++i;
			display = display->next;
		}

	}

	return 0;
}




//      	    { .required .unique .encrypted .sequential .section, .payload, .auth_keyslot, .orig_keyslot, .dest_keyslot, .recp_keyslot, .name, .description }
#define CKEY_EMPTY  { 0,        0,      0,         0,          0,        0,        0,             0,             0,             0,             NULL,  NULL        }
// TODO add display_multi, display_alt, attach_multi, attach_alt chunks
dmime_chunk_key_t dmime_chunk_keys[DMIME_CHUNK_TYPE_MAX] = {
//      { .required, .unique, .encrypted, .sequential, .section,               .payload,               .auth_keyslot, .orig_keyslot, .dest_keyslot, .recp_keyslot, .name,                                      .description }
/*0*/// { 0,         0,       0,          1,           CHUNK_SECTION_TRACING,  PAYLOAD_TYPE_TRACING    0,             0,             0,             0,             "Tracing",                                  NULL},   tracing is no longer a chunk
/*0*/   CKEY_EMPTY, CKEY_EMPTY,
/*2*/   { 1,         0,       0,          1,           CHUNK_SECTION_ENVELOPE, PAYLOAD_TYPE_EPHEMERAL, 0,             0,             0,             0,             "Ephemeral",                                NULL},
/*3*/   { 0,         0,       1,          1,           CHUNK_SECTION_ENVELOPE, PAYLOAD_TYPE_STANDARD,  1,             0,             0,             1,             "Alternate",                                NULL},
/*4*/   { 1,         0,       1,          1,           CHUNK_SECTION_ENVELOPE, PAYLOAD_TYPE_STANDARD,  1,             1,             0,             1,             "Origin",                                   NULL},
/*5*/   { 1,         0,       1,          1,           CHUNK_SECTION_ENVELOPE, PAYLOAD_TYPE_STANDARD,  1,             0,             1,             1,             "Destination",                              NULL},
/*6*/   CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY,
/*10*/  CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*20*/  CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*30*/  CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY,
/*33*/  { 1,         0,       1,          1,           CHUNK_SECTION_METADATA, PAYLOAD_TYPE_STANDARD,  1,             0,             0,             1,             "Common",                                   NULL},
/*34*/  { 0,         0,       1,          1,           CHUNK_SECTION_METADATA, PAYLOAD_TYPE_STANDARD,  1,             0,             0,             1,             "Headers",                                  NULL},
/*35*/  CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY,
/*40*/  CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*50*/  CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*60*/  CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*67*/  { 0,         1,       1,          0,           CHUNK_SECTION_DISPLAY,  PAYLOAD_TYPE_STANDARD,  1,             0,             0,             1,             "Display-Content",                          NULL},
/*68*/  CKEY_EMPTY, CKEY_EMPTY, 
/*70*/  CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*80*/  CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*90*/  CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*100*/ CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*110*/ CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*120*/ CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*130*/ CKEY_EMPTY,
/*131*/ { 0,         1,       1,          0,           CHUNK_SECTION_ATTACH,   PAYLOAD_TYPE_STANDARD,  1,             0,             0,             1,             "Attachments-Contetn",                      NULL},
/*132*/ CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*140*/ CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*150*/ CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*160*/ CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*170*/ CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*180*/ CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*190*/ CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*200*/ CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*210*/ CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*220*/ CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*225*/ { 1,         0,       1,          1,           CHUNK_SECTION_SIG,      PAYLOAD_TYPE_SIGNATURE, 1,             1,             0,             1,             "Author-Tree-Signature",                    NULL},
/*226*/ { 1,         0,       1,          1,           CHUNK_SECTION_SIG,      PAYLOAD_TYPE_SIGNATURE, 1,             1,             0,             1,             "Author-Signature",                         NULL},
/*227*/ CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*230*/ CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*240*/ CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, 
/*248*/ { 0,         0,       1,          1,           CHUNK_SECTION_SIG,      PAYLOAD_TYPE_SIGNATURE, 1,             1,             1,             1,             "Organizational-Metadata-Bounce-Signature", NULL},
/*249*/ { 0,         0,       1,          1,           CHUNK_SECTION_SIG,      PAYLOAD_TYPE_SIGNATURE, 1,             1,             1,             1,             "Organizational-Display-Bounce-Signature",  NULL},
/*250*/ CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY, CKEY_EMPTY,
/*255*/ { 1,         0,       1,          1,           CHUNK_SECTION_SIG,      PAYLOAD_TYPE_SIGNATURE, 1,             1,             1,             1,             "Organizational-Signature",                 NULL}
};

