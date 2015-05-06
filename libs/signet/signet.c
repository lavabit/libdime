#include "signet/signet.h"
#include "signet/keys.h"



/* cache callback functions TODO: move this to resolver */
void *                  _deserialize_signet_cb(void *data, size_t len);
void *                  _serialize_signet_cb(void *record, size_t *outlen);
void                    _destroy_signet_cb(void *record);
void                    _dump_signet_cb(FILE *fp, void *record, int brief);


/* PRIVATE FUNCTIONS */

static int                     sgnt_create_defined_field(signet_t *signet, unsigned char fid, size_t data_size, const unsigned char *data);
static int                     sgnt_create_field_at(signet_t *signet, unsigned int offset, size_t field_size, const unsigned char *field_data);
static signet_field_t *        sgnt_create_field_list(const signet_t *signet, unsigned char fid);
static signet_field_t *        sgnt_create_field_node(const signet_t *signet, uint32_t offset, signet_field_key_t *key);
static signet_t *              sgnt_create_signet(signet_type_t type);
static signet_t *              sgnt_create_signet_w_keys(signet_type_t type, const char *keysfile);
static int                     sgnt_create_sok(signet_t *signet, ED25519_KEY *key, unsigned char format, unsigned char perm);
static int                     sgnt_create_undefined_field(signet_t *signet, size_t name_size, const unsigned char *name, size_t data_size, const unsigned char *data);
static void                    sgnt_destroy_field_list(signet_field_t *field);
static signet_field_t *        sgnt_destroy_field_node(signet_field_t *field);
static void                    sgnt_destroy_signet(signet_t *signet);
static int                     sgnt_dump_fid(FILE *fp, const signet_t *signet, unsigned int fid);
static int                     sgnt_dump_field(FILE *fp, const signet_field_t *field);
static void                    sgnt_dump_signet(FILE *fp, signet_t *signet);
static EC_KEY *                sgnt_fetch_enckey(const signet_t *signet);
static unsigned char *         sgnt_fetch_fid_num(const signet_t *signet, unsigned char fid, unsigned int num, size_t *data_size);
static ED25519_KEY **          sgnt_fetch_msg_signkeys(const signet_t *signet);
static ED25519_KEY *           sgnt_fetch_signkey(const signet_t *signet);
static ED25519_KEY **          sgnt_fetch_signkey_by_perm(const signet_t *signet, unsigned char perm);
static ED25519_KEY **          sgnt_fetch_signet_signkeys(const signet_t *signet);
static ED25519_KEY **          sgnt_fetch_software_signkeys(const signet_t *signet);
static ED25519_KEY *           sgnt_fetch_sok_num(const signet_t *signet, unsigned int num);
static ED25519_KEY **          sgnt_fetch_tls_signkeys(const signet_t *signet);
static unsigned char *         sgnt_fetch_undefined_field(const signet_t *signet, size_t name_size, const unsigned char *name, size_t *data_size);
static int                     sgnt_fid_exists(const signet_t *signet, unsigned char fid);
static int                     sgnt_fid_get_count(const signet_t *signet, unsigned char fid);
/* CURRENTLY UNUSED
static int                     sgnt_fid_get_size(const signet_t *signet, unsigned char fid);
*/
static signet_t *              sgnt_file_to_signet(const char *filename);
static int                     sgnt_file_create(signet_t *signet, const char *filename);
static char *                  sgnt_fingerprint_crypto(const signet_t *signet);
static char *                  sgnt_fingerprint_full(const signet_t *signet);
static char *                  sgnt_fingerprint_id(const signet_t *signet);
static char *                  sgnt_fingerprint_ssr(const signet_t *signet);
static char *                  sgnt_fingerprint_upto_fid(const signet_t *signet, unsigned char fid);
static int                     sgnt_remove_fid_num(signet_t *signet, unsigned char fid, int num);
static int                     sgnt_remove_field_at(signet_t *signet, unsigned int offset, size_t field_size);
static int                     sgnt_remove_undefined_field(signet_t *signet, size_t name_size, const unsigned char *name);
static signet_t *              sgnt_serial_b64_to_signet(const char *b64_in);
static int                     sgnt_serial_check_length(const unsigned char *in, uint32_t slen);
/* CURRENTLY UNUSED
static unsigned char *         sgnt_serial_from_fid(const signet_t *signet, unsigned char fid, size_t *fid_size);
*/
static unsigned char *         sgnt_serial_from_signet(signet_t *signet, uint32_t *serial_size);
static unsigned char *         sgnt_serial_from_signkey(ED25519_KEY *key, unsigned char format, size_t *key_size);
static unsigned char *         sgnt_serial_from_upto_fid(const signet_t *signet, unsigned char fid, size_t *data_size);
static int                     sgnt_serial_get_field_size(const signet_field_t *field);
static int                     sgnt_serial_get_size(const signet_t *signet);
static int                     sgnt_serial_index(signet_t *signet);
static char *                  sgnt_serial_signet_to_b64(signet_t *signet);
static signet_t *              sgnt_serial_to_signet(const unsigned char *in, size_t len);
static ED25519_KEY *           sgnt_serial_to_signkey(const unsigned char *serial_key, size_t key_size);
static int                     sgnt_set_defined_field(signet_t *signet, unsigned char fid, size_t data_size, const unsigned char *data);
static int                     sgnt_set_id_field(signet_t *signet, size_t id_size, const unsigned char *id);
static int                     sgnt_set_signkey(signet_t *signet, ED25519_KEY *key, unsigned char format);
static int                     sgnt_sign_coc_sig(signet_t *signet, ED25519_KEY *key);
static int                     sgnt_sign_crypto_sig(signet_t *signet, ED25519_KEY *key);
static int                     sgnt_sign_field(signet_t *signet, unsigned char signet_fid, ED25519_KEY *key);
static int                     sgnt_sign_full_sig(signet_t *signet, ED25519_KEY *key);
static int                     sgnt_sign_id_sig(signet_t *signet, ED25519_KEY *key);
static int                     sgnt_sign_ssr_sig(signet_t *signet, ED25519_KEY *key);
static signet_t *              sgnt_split_crypto(const signet_t *signet);
static signet_t *              sgnt_split_full(const signet_t *signet);
static signet_type_t           sgnt_type_get(const signet_t *signet);
static int                     sgnt_type_set(signet_t *signet, signet_type_t type);
static signet_state_t          sgnt_validate_all(const signet_t *signet, const signet_t *previous, const signet_t *orgsig, const unsigned char **dime_pok);
static int                     sgnt_validate_pok(const signet_t *signet, const unsigned char **dime_pok);
static int                     sgnt_validate_required_upto_fid(const signet_t *signet, signet_field_key_t *keys, unsigned char fid);
static int                     sgnt_validate_sig_field(const signet_t *signet, unsigned char sigfid, const unsigned char *key);
static int                     sgnt_validate_sig_field_key(const signet_t *signet, unsigned char sigfid, ED25519_KEY *key);
static int                     sgnt_validate_sig_field_multikey(const signet_t *signet, unsigned char sig_fid, ED25519_KEY **keys);
static signet_state_t          sgnt_validate_structure(const signet_t *signet);
static int                     sgnt_verify_message_sig(const signet_t *signet, ed25519_signature sig, const unsigned char *buf, size_t buf_len);  /* TODO verify function for each type of signatures (message, signet, TLS certificate, software)*/


/**
 * @brief	Returns	a new signet_t structure.
 * @param	type	signet type user org or sss (SIGNET_TYPE_USER, SIGNET_TYPE_ORG or SIGNET_TYPE_SSR)
 * @return	A pointer to a newly allocated signet_t structure type, NULL if failure.
 * @free_using{sgnt_destroy_signet}
*/
static signet_t *sgnt_create_signet(signet_type_t type) {

	signet_t *signet;

	if(type != SIGNET_TYPE_ORG && type != SIGNET_TYPE_USER && type != SIGNET_TYPE_SSR) {
		RET_ERROR_PTR(ERR_BAD_PARAM, "invalid signet type");
	}

	if(!(signet = malloc(sizeof(signet_t)))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate space for new signet");
	}

	memset(signet, 0, sizeof(signet_t));
	signet->type = type;

	return signet;
}


/**
 * @brief	Takes a binary signet input buffer and its length. Checks for signet size inconsistencies.
 * @param	in	binary signet buffer
 * @param	slen	length of in
 * @return	0 if the checks passed, -1 if at least one failed.
*/
static int sgnt_serial_check_length(const unsigned char *in, uint32_t slen) {

	uint32_t signet_length;

	if (!in || (slen < SIGNET_HEADER_SIZE)) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	signet_length = _int_no_get_3b(in + 2);

	if ((slen - SIGNET_HEADER_SIZE) != signet_length) {
		RET_ERROR_INT(ERR_UNSPEC, "input length did not match signet");
	}

	return 0;
}


/**
 * @brief	Parses the fields of a signet object and assigns the offsets to the byte following the field id byte of the first instance of a field type to signet-fields[]
 * @param	signet	A pointer to a signet_t object to be parsed.
 * @return	0 if parsing finished successfully, -1 if it failed.
*/
static int sgnt_serial_index(signet_t *signet) {

	uint32_t field_size, name_size;
	unsigned int at = 0;
	signet_field_key_t key, *keys;

	if (!signet) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	switch(sgnt_type_get(signet)) {

	case SIGNET_TYPE_ORG:
		keys = signet_org_field_keys;
		break;
	case SIGNET_TYPE_USER:
		keys = signet_user_field_keys;
		break;
	case SIGNET_TYPE_SSR:
		keys = signet_ssr_field_keys;
		break;
	default:
		RET_ERROR_INT(ERR_UNSPEC, "incorrect signet type");
		break;

	}

	for(int i = 0; i < SIGNET_FID_MAX + 1; ++i) {

		if(at == signet->size) {
			break;
		}

		if(at > signet->size) {
			RET_ERROR_INT(ERR_UNSPEC, "invalid signet size");
		}

		if(!keys[i].name) {

			if(i == signet->data[at]) {
				RET_ERROR_INT(ERR_UNSPEC, "a field in this signet file is disallowed by the current version");
			}

			signet->fields[i] = 0;
			continue;
		}

		if(keys[i].name) {
			key = keys[i];

			if(i > signet->data[at]) {
				RET_ERROR_INT(ERR_UNSPEC, "signet fields are not in numerical order or a unique field appears more than once");
			}

			if(i < signet->data[at]) {
				signet->fields[i] = 0;
				continue;
			}

			if(i == signet->data[at]) {

				if(at + 1 >= signet->size) {
					RET_ERROR_INT(ERR_UNSPEC, "signet size error");
				}

				signet->fields[i] = (at + 1);

				while(at < signet->size && i == signet->data[at]) {
					++at;
					field_size = 0;

					if(key.bytes_name_size) {

						if(at + 1 >= signet->size) {
							RET_ERROR_INT(ERR_UNSPEC, "signet size error");
						}

						name_size = (unsigned char)signet->data[at++];

						if(at + name_size >= signet->size) {
							RET_ERROR_INT(ERR_UNSPEC, "signet size error");
						}

						at += name_size;
					}

					if (key.bytes_data_size && (at + key.bytes_data_size >= signet->size)) {
						RET_ERROR_INT(ERR_UNSPEC, "signet size error");
					}

					if(key.bytes_data_size == 0) {
						field_size = key.data_size;
					} else if(key.bytes_data_size == 1) {
						field_size = (unsigned char)signet->data[at];
					} else if(key.bytes_data_size == 2) {
						field_size = _int_no_get_2b(signet->data + at);
					} else if(key.bytes_data_size == 3) {
						field_size = _int_no_get_3b(signet->data + at);
					}

					at += key.bytes_data_size;

					if(at + field_size > signet->size) {
						RET_ERROR_INT(ERR_UNSPEC, "signet size error");
					}

					at += field_size;

					if(key.unique) {
						break;
					}

				}

			}

		}

	}

	return 0;
}


/**
 * @brief	Retrieves the length of all fields in the signet with the specified field id in serial form.
 * @param	signet	Pointer to the target signet.
 * @param	fid	The target field id.
 * @return	The length of the serialized fields, returns -1 on errors and on non-existing fields.
 *              NOTE: int overflow should not occur because field size and signet size are bounded well below 2^31 bits.
*/
/* CURRENT UNUSED
static int sgnt_fid_get_size(const signet_t *signet, unsigned char fid) {

	int res;
	size_t start, end;

	if(!signet) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if((res = sgnt_fid_exists(signet, fid)) < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "error searching for field in signet");
	} else if(!res) {
		RET_ERROR_INT(ERR_UNSPEC, "specified field does not exist");
	}

	start = signet->fields[fid] - 1;
	end = signet->size;

	for(int i = fid + 1; i <= SIGNET_FID_MAX; ++i) {

		if((res = sgnt_fid_exists(signet, i))) {

			if(res < 0) {
				RET_ERROR_INT(ERR_UNSPEC, "error searching for field in signet");
			}

			end = signet->fields[i] - 1;
			break;
		}
	}

	if(end < start) {
		RET_ERROR_INT(ERR_UNSPEC, "signet is corrupted");
	}

	return end - start;
}
*/

/**
 * @brief	Calculates the size of the target signet when serialized.
 * @param	signet	Pointer to the target signet.
 * @return	The size of signet when serialized, if no signet was passed returns -1.
 *              NOTE: int overflow should not occur signet size s bounded well below 2^31 bits.
*/
static int sgnt_serial_get_size(const signet_t *signet) {

	if(!signet) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	return signet->size + SIGNET_HEADER_SIZE;
}


/**
 * @brief	Compares the POK in the signet to an array of POKs from the dime record
 * @param	signet		Pointer to the target signet.
 * @param	dime_pok	A NULL pointer terminated array of pointers to POKs from the dime record.
 * @return	The index + 1 number of the POK from dime_pok that matches the signet POK. If an error occurs returns -1. If no POKs match returns 0.
 *              NOTE: Could int overflow if more than 2^31 elements are passed in the dime_pok array.
*/
static int sgnt_validate_pok(const signet_t *signet, const unsigned char **dime_pok) {

	ED25519_KEY *signet_pok;
	int i = 0, res;

	if(!signet || !dime_pok) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(sgnt_type_get(signet) != SIGNET_TYPE_ORG) {
		RET_ERROR_INT(ERR_BAD_PARAM, "signet must be org signet");
	}

	if((res = sgnt_fid_exists(signet, SIGNET_ORG_POK)) < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "error searching for field in signet");
	} else if(!res) {
		RET_ERROR_INT(ERR_UNSPEC, "signet was missing Primary-Org-Key field");
	}

	if(!(signet_pok = sgnt_fetch_signkey(signet))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not retrieve signet signing key");
	}

	while(dime_pok[i]) {

		if(!(memcmp(dime_pok[i], (unsigned char *)signet_pok->public_key, ED25519_KEY_SIZE))) {
			_free_ed25519_key(signet_pok);
			return i + 1;
		}

		++i;
	}

	_free_ed25519_key(signet_pok);

	return 0;
}


/**
 * @brief	Checks for the existence of all required fields with field ids less than the specified field id.
 * @param	signet	Pointer to the target signet.
 * @param	keys	Array of structure that describe field types
 * @param	fid	The field upto and including which the signet checks whether all the required fields are present.
 * @return	1 if all required fields were present, 0 if at least one is missing. -1 if an error occurred.
*/
static int sgnt_validate_required_upto_fid(const signet_t *signet, signet_field_key_t *keys, unsigned char fid) {

	int res;

	if(!signet || !keys) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	for(int i = fid - 1; i >= 0; --i) {

		if(keys[i].required && (((res = sgnt_fid_exists(signet, i))) <= 0)) {

			if(res < 0) {
				RET_ERROR_INT(ERR_UNSPEC, "error searching for field in signet");
			}

			return 0;
		}
	}

	return 1;
}


/**
 * @brief	Verifies a field specified by a field id in the target signet by using multiple keys.
 * @param	signet	Pointer to the target signet.
 * @param	sig_fid	Field id of the field which contains the signature intended for verification.
 * @param	keys	A NULL pointer terminated array of ed25519 public key objects which are used to verify the signet signature.
 * @return	1 if one of the keys was able to verify the signature. 0 if none were able to verify. -1 if error.
*/
static int sgnt_validate_sig_field_multikey(const signet_t *signet, unsigned char sig_fid, ED25519_KEY **keys) {

	int i = 0, res = 0;

	if(!signet || !keys) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	while(keys[i]) {

		if((res = sgnt_validate_sig_field_key(signet, sig_fid, keys[i])) < 0) {
			RET_ERROR_INT(ERR_UNSPEC, "error during signet signature field verification");
		} else if(res) {
			return 1;
		}

		++i;
	}

	return 0;
}


/**
 * @brief	Perform SHA512 fingerprint on all the fields up to the specified field.
 * @param	signet	Pointer to the target signet.
 * @param	fid	Field id upto and including which the signet should be fingerprinted.
 * @return	NULL terminated string to the SHA512 base64 encoded unpadded fingerprint. NULL on error.
*/
static char *sgnt_fingerprint_upto_fid(const signet_t *signet, unsigned char fid) {

	char *b64_fingerprint;
	unsigned char *data, hash[SHA_512_SIZE];
	size_t data_size;

	if(!signet) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	memset(hash, 0, SHA_512_SIZE);

	if(!(data = sgnt_serial_from_upto_fid(signet, fid, &data_size))) {
		RET_ERROR_PTR(ERR_UNSPEC, "no signet data to fingerprint");
	}

	if(_compute_sha_hash(512, data, data_size, hash) < 0) {
		free(data);
		RET_ERROR_PTR(ERR_UNSPEC, "could not compute SHA-512 hash of full signet data");
	}

	free(data);

	if(!(b64_fingerprint = _b64encode_nopad(hash, SHA_512_SIZE))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not base-64 encode full signet fingerprint");
	}

	return b64_fingerprint;
}


/* signet_field_t creators, destructors and related functions*/

/**
 * @brief	Creates a chain of signet_field_t structures for all fields in the provided signet with the specified field id. The fields are in a linked list, preserving the order in which they are in the signet.
 * @param	signet	Pointer to the target signet.
 * @param	fid	Field id that specifies the target fields.
 * @return	Pointer to the first signet_field_t structure in the created linked list. Null if error occurred.
*/
static signet_field_t *sgnt_create_field_list(const signet_t *signet, unsigned char fid) {

	int res;
	uint32_t offset;
	signet_field_t *field;
	signet_field_t *temp;
	signet_field_key_t *key;

	if(!signet) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if((res = sgnt_fid_exists(signet, fid)) < 0) {
		RET_ERROR_PTR(ERR_UNSPEC, "error searching for field in signet");
	} else if(!res) {
		RET_ERROR_PTR(ERR_UNSPEC, "specified field data does not exist");
	}

	offset = signet->fields[fid] - 1;

	switch(sgnt_type_get(signet)) {

	case SIGNET_TYPE_ORG:
		key = &(signet_org_field_keys[fid]);
		break;
	case SIGNET_TYPE_USER:
		key = &(signet_user_field_keys[fid]);
		break;
	case SIGNET_TYPE_SSR:
		key = &(signet_ssr_field_keys[fid]);
		break;
	default:
		RET_ERROR_PTR(ERR_UNSPEC, "invalid signet type");
		break;
	}

	if(!key->name) {
		RET_ERROR_PTR(ERR_UNSPEC, "signet field id does not support creation");
	}

	if(!(field = sgnt_create_field_node(signet, offset, key))) {
		RET_ERROR_PTR(ERR_UNSPEC, "error creating signet field");
	}

	offset = field->data_offset + field->data_size;
	temp = field;

	while(offset < signet->size && signet->data[offset] == fid) {

		if(!(temp->next = sgnt_create_field_node(signet, offset, key))) {
			sgnt_destroy_field_list(field);
			RET_ERROR_PTR(ERR_UNSPEC, "error creating signet field");
		}

		temp = temp->next;
		offset = temp->data_offset + temp->data_size;
	}

	return field;
}


/**
 * @brief	Creates signet_field_t type structure from the data in the signet at the specified offset. Explicit call creates an unchained structure.
 * @param	signet	Pointer to the signet that contains the field that is having a signet_field_t indexing structure created for it.
 * @param	offset	The offset at which the field physically begins in the signet->data array.
 * @param	key	Pointer to the field id specific key that contains information on the format of the field data.
 * @return	Pointer to the created field structure, NULL on failure.
*/
static signet_field_t *sgnt_create_field_node(const signet_t *signet, uint32_t offset, signet_field_key_t *key) {

	uint32_t at = offset;
	signet_field_t *field;

	if (!signet) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if((at + 1) >= signet->size) {
		RET_ERROR_PTR(ERR_UNSPEC, "offset exceeded signet size");
	}

	if (!(field = malloc(sizeof(signet_field_t)))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, NULL);
	}

	memset(field, 0, sizeof(signet_field_t));
	field->signet = signet;
	field->key = key;
	field->id_offset = at++;

	if(key->bytes_name_size) {
		field->name_size = signet->data[at++];
		field->name_offset = at++;
		at = field->name_offset + field->name_size;

		if(at >= signet->size) {
			sgnt_destroy_field_node(field);
			RET_ERROR_PTR(ERR_UNSPEC, "offset exceeded signet size");
		}
	}

	switch(key->bytes_data_size) {

	case 0:
		field->data_size = key->data_size;
		break;
	case 1:
		field->data_size = (uint32_t)signet->data[at];
		break;
	case 2:
		if(at + 1 >= signet->size) {
			sgnt_destroy_field_node(field);
			RET_ERROR_PTR(ERR_UNSPEC, "buffer overflow in signet");
		}

		field->data_size = _int_no_get_2b(signet->data + at);
		break;
	case 3:
		if(at + 2 >= signet->size) {
			sgnt_destroy_field_node(field);
			RET_ERROR_PTR(ERR_UNSPEC, "buffer overflow in signet");
		}

		field->data_size = _int_no_get_3b(signet->data + at);
		break;

	}

	at += key->bytes_data_size;
	field->data_offset = at;

	if(at + field->data_size - 1 >= signet->size) {
		sgnt_destroy_field_node(field);
		RET_ERROR_PTR(ERR_UNSPEC, "buffer overflow in signet operation");
	}

	field->next = NULL;

	return field;
}


/**
 * @brief	Destroys a chain of signet_field_t structures starting with provided structure, does not effect the linked signet_t structure.
 * @param	field	Pointer to the first signet_field_t in the linked list to be deleted.
*/
static void sgnt_destroy_field_list(signet_field_t *field) {

	signet_field_t *temp = field;

	if(!field) {
		return;
	}

	while(temp) {
		temp = sgnt_destroy_field_node(temp);
	}

}


/**
 * @brief	Destroys signet_field_t type structure.
 * @param	field	Pointer to the signet_field_t to be destroyed.
 * @return	Pointer to the signet_field_t that was the destroyed structure was linked to, NULL if the destroyed structure was the last/only structure in the linked list, or error.
*/
static signet_field_t *sgnt_destroy_field_node(signet_field_t *field) {

	signet_field_t *next;

	if(!field) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	next = field->next;
	free(field);
	return next;
}


/**
 * @brief	Dumps the field indexed by the specified signet_field_t. Mainly called by _signet_fid_dump(...), may be poorly formatted for an explicit single-field dump.
 * @param	fp	Dump target stream.
 * @param	field	Pointer to signet_field_t structure that indexes a signet field to be dumped.
 * @return	0 on success -1 on failure.
*/

static int sgnt_dump_field(FILE *fp, const signet_field_t *field) {

	char *name, *data = NULL;
	const char *png_name = "PNG file", *nbuf;

	if(!fp || !field) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	fprintf(fp, "--- %-*d ", 3, field->signet->data[field->id_offset]);

	if(!(field->key->bytes_name_size)) {

		if(!(name = malloc(strlen(field->key->name) + 1))) {
			PUSH_ERROR_SYSCALL("malloc");
			RET_ERROR_INT(ERR_NOMEM, NULL);
		}

		memset(name, 0, strlen(field->key->name) + 1);
		memcpy(name, field->key->name, strlen(field->key->name));
	} else {

		if(!(name = malloc(field->name_size + 1))) {
			PUSH_ERROR_SYSCALL("malloc");
			RET_ERROR_INT(ERR_NOMEM, NULL);
		}

		memset(name, 0, field->name_size + 1);
		memcpy(name, field->signet->data + field->name_offset, field->name_size);
	}

	switch(field->key->data_type) {

	case UNICODE:                                                                   // TODO Unicode currently same as ASCII

		if(!(data = malloc(field->data_size + 1))) {
			PUSH_ERROR_SYSCALL("malloc");
			free(name);
			RET_ERROR_INT(ERR_NOMEM, NULL);
		}

		memset(data, 0, field->data_size + 1);
		memcpy(data, field->signet->data + field->data_offset, field->data_size);
		break;
	case HEX:                                                                       // TODO
	case B64:

		if(!(data = _b64encode_nopad(field->signet->data + field->data_offset, (size_t)field->data_size))) {
			free(name);
			RET_ERROR_INT(ERR_UNSPEC, "could not base64-encode signet field data");
		}

		break;
	case PNG:

		if(!(data = strdup(png_name))) {
			PUSH_ERROR_SYSCALL("strdup");
			free(name);
			RET_ERROR_INT(ERR_NOMEM, NULL);
		}

		break;

	}

	if (!strlen(name)) {
		nbuf = "----------------";
	} else {
		nbuf = name;
	}

	fprintf(fp, "%-26.26s -> %-90.90s%s\n", nbuf, data ? data : "(null)", data && strlen(data) > 90 ? "..." : "");
	free(name);
	free(data);

	return 0;
}


/**
 * @brief       Retrieves the total length of a serialized field specified by a signet_field_t structure.
 * @param	field	Pointer to the signet_field_t structure that indexes the field, the size of which is retrieved.
 * @return	Length of the serialized field. -1 if error.
 *              NOTE: int overflow should not occur because field size and signet size are bounded well below 2^31 bits.
*/

static int sgnt_serial_get_field_size(const signet_field_t *field) {

	int field_size = 1;

	if(!field) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
		return 0;
	}

	if(field->key->bytes_name_size) {
		field_size += (int)(1 + field->name_size);
	}

	field_size += (field->key->bytes_data_size + field->data_size);

	return field_size;
}


/* signet field data retrieval functions */

/**
 * @brief	Dumps all fields with specified field id.
 * @param	fp	Dump target stream.
 * @param	signet	Pointer to signet from which fields are dumped.
 * @param	fid	Field id that specifies which fields are dumped.
 * @return	0 on success, -1 on failure.
*/
static int sgnt_dump_fid(FILE *fp, const signet_t *signet, unsigned int fid) {

	signet_field_t *field, *temp;

	if(!fp || !signet) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(!(field = sgnt_create_field_list(signet, fid))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not create signet field for data dump");
	}

	temp = field;

	while(temp) {

		if(sgnt_dump_field(fp, temp) < 0) {
			sgnt_destroy_field_list(field);
			RET_ERROR_INT(ERR_UNSPEC, "could not dump field");
		}

		temp = temp->next;
	}

	sgnt_destroy_field_list(field);

	return 0;
}


/**
 * @brief	Retrieves the serialized representation of all fields with the specified field id in the signet.
 * @param	signet	Pointer to the target signet.
 * @param	fid	Specified field id.
 * @param	out_len	Pointer to the length of returned array.
 * @return	Array containing serialized fields with the specified field id, NULL if an error occurs. Caller is responsible for freeing memory after use.
*/
/* CURRENTLY UNUSED
static unsigned char *sgnt_serial_from_fid(const signet_t *signet, unsigned char fid, size_t *fid_size) {

	int res;
	unsigned char *data;

	if(!signet || !fid_size) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if((res = sgnt_fid_exists(signet, fid)) < 0) {
		RET_ERROR_PTR(ERR_UNSPEC, "error searching for field in signet");
	} else if(!res) {
		RET_ERROR_PTR(ERR_UNSPEC, "defined field does not exist");
	}

	if ((res = sgnt_fid_get_size(signet, fid)) < 0) {
		RET_ERROR_PTR_FMT(ERR_UNSPEC, "error retrieving size of field %u", fid);
	}

	if(!(data = malloc(*fid_size))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, NULL);
	}

	memset(data, 0, res);
	memcpy(data, &(signet->data[signet->fields[fid] - 1]), res);
	*fid_size = res;

	return data;
}
*/

/**
 * @brief	Allocates memory for and serializes all fields from field id = 0 upto and including the specified field id.
 * @param	signet		Pointer to target signet.
 * @param	fid		Specified field.
 * @param	data_size	Pointer to the length of the returned array.
 * @return	Allocated array of serialized fields, NULL on failure or if the signet was empty.
*/
static unsigned char *sgnt_serial_from_upto_fid(const signet_t *signet, unsigned char fid, size_t *data_size) {

	unsigned char *data;

	if(!signet || !data_size) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	*data_size = signet->size;

	for(int i = fid + 1; i <= SIGNET_FID_MAX; ++i) {

		if(signet->fields[i]) {
			*data_size = signet->fields[i] - 1;
			break;
		}
	}

	if(!(*data_size)) {
		return NULL;
	}

	if(!(data = malloc(*data_size))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, NULL);
	}

	memset(data, 0, *data_size);
	memcpy(data, signet->data, *data_size);

	return data;
}


/* signet content modification and related functions */

/**
 * @brief	Helper function which removes a substring of length field_size from the target signet at offset.
 * @param	signet		Pointer to target signet.
 * @param	offset		Offset at which the field intended for removal begins in the target signet.
 * @param	field_size	Size of field to be removed.
 * @return	0 on success, -1 on failure.
*/
static int sgnt_remove_field_at(signet_t *signet, unsigned int offset, size_t data_size) {

	size_t signet_size;

	if(!signet) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(signet->size < offset + data_size) {
		RET_ERROR_INT(ERR_UNSPEC, "signet field position exceeded signet size");
	}

	if (!(signet_size = signet->size - data_size)) {
		signet->size = 0;
		free(signet->data);
		signet->data = NULL;
		return 0;
	}

	if(offset + data_size != signet->size) {
		memmove(signet->data + offset, signet->data + offset + data_size, signet->size - offset - data_size);
	}

	if(!(signet->data = realloc(signet->data, signet_size))) {
		PUSH_ERROR_SYSCALL("realloc");
		signet->size = 0;
		RET_ERROR_INT(ERR_NOMEM, NULL);
	}

	signet->size = signet_size;

	return 0;
}


/**
 * @brief	Helper function which inserts an array of field data into the signet data array.
 * @param	signet		Pointer to target signet.
 * @param	offset		Offset at which the field data must be inserted.
 * @param	field_size	Size of field data to be inserted.
 * @param	field_data	Field data to be inserted into the signet.
 * @return	0 on success, -1 on failure.
*/

static int sgnt_create_field_at(signet_t *signet, unsigned int offset, size_t field_size, const unsigned char *field_data) {

	uint32_t signet_size;

	if(!signet || !offset || (offset + field_size) > UNSIGNED_MAX_3_BYTE || !field_size || !field_data) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	signet_size = signet->size + field_size;

	if(!(signet->data = realloc(signet->data, signet_size))) {
		PUSH_ERROR_SYSCALL("realloc");
		signet->size = 0;
		RET_ERROR_INT(ERR_NOMEM, NULL);
	}

	memset(signet->data + signet->size, 0, field_size);

	if(offset != (size_t)signet->size) {
		memmove(signet->data + offset + field_size, signet->data + offset, signet->size - offset);
	}

	signet->size = signet_size + field_size;
	memcpy(signet->data + offset, field_data, field_size);

	return 0;
}


/**
 * @brief	Uses specified ED25519 key to sign the target signet.
 *              The signature is placed into the field specified by the signet_fid and the signature is taken of all the fields that come before signet_fid.
 * @param	signet	Pointer to the target signet to be signed.
 * @param	signet_fid	Target field which will hold the signature, it also specifies which fields are to be signed (all the fields that come before it.)
 * @param	key	ed25519 key object containing the private key, which is used for signing.
 * @return	0 if signing was successful, otherwise -1.
*/
static int sgnt_sign_field(signet_t *signet, unsigned char signet_fid, ED25519_KEY *key) {

	int res;
	size_t data_size;
	unsigned char *data;
	ed25519_signature sig;
	signet_field_key_t *keys;

	if(!signet || !key) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	switch(sgnt_type_get(signet)) {

	case SIGNET_TYPE_ORG:
		keys = signet_org_field_keys;
		break;
	case SIGNET_TYPE_USER:
		keys = signet_user_field_keys;
		break;
	case SIGNET_TYPE_SSR:
		keys = signet_ssr_field_keys;
		break;
	default:
		RET_ERROR_INT(ERR_UNSPEC, "invalid signet type");
		break;

	}

	if((sgnt_validate_required_upto_fid(signet, keys, signet_fid)) <= 0) {
		RET_ERROR_INT(ERR_UNSPEC, "required fields for signet signing were missing");
	}

	if(!(data = sgnt_serial_from_upto_fid(signet, signet_fid - 1, &data_size))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not get signet data for signature");
	}

	if(_ed25519_sign_data(data, data_size, key, sig) < 0) {
		free(data);
		RET_ERROR_INT(ERR_UNSPEC, "could not sign signet data");
	}

	free(data);

	while((res = sgnt_fid_exists(signet, signet_fid))) {

		if(res < 0) {
			RET_ERROR_INT(ERR_UNSPEC, "error searching for field in signet");
		}

		if(sgnt_remove_fid_num(signet, signet_fid, 1) < 0) {
			RET_ERROR_INT(ERR_UNSPEC, "could not remove signature field from signet");
		}
	}

	if ((res = sgnt_set_defined_field(signet, signet_fid, ED25519_SIG_SIZE, (const unsigned char *)sig)) < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "could not add signature field to signet");
	}

	return res;
}


/* Cache callback functions */

/**
 * @brief	Deserializes signet from a void pointer.
 * @param	data	Pointer to serial signet data.
 * @param	len	Length of serial signet data.
 * @return	Void pointer to a signet_t structure.
*/
void *_deserialize_signet_cb(void *data, size_t len) {

	signet_t *result;

	if(!data || !len) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!(result = sgnt_serial_to_signet(data, len))) {
		RET_ERROR_PTR(ERR_UNSPEC, NULL);
	}

	return result;
}


/**
 * @brief	Serializes a signet_t structure into a binary string.
 * @param	record	Void pointer to a signet_t structure to be serialized.
 * @param	outlen	Pointer to the length of the returned string.
 * @return	Pointer to a serialized signet.
*/
void *_serialize_signet_cb(void *record, size_t *outlen) {

	unsigned char *serial;
	void *result;
	uint32_t ssize;

	if(!record || !outlen) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!(serial = sgnt_serial_from_signet(record, &ssize))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not serialize signet");
	}

	if(!(result = malloc(ssize))) {
		PUSH_ERROR_SYSCALL("malloc");
		free(serial);
		RET_ERROR_PTR(ERR_NOMEM, NULL);
	}

	*outlen = ssize;
	memcpy(result, serial, ssize);
	free(serial);

	return result;
}


/**
 * @brief	Dumps a signet from a signet_t structure.
 * @param	fp	File descriptor that specifies the output destination.
 * @param	record	Void pointer to a signet_t structure.
 * @param	brief	TODO
*/
void _dump_signet_cb(FILE *fp, void *record, int brief) {

	signet_t *sig = (signet_t *)record;

	if (!fp || !sig) {
		return;
	}

	if (brief) {
		fprintf(fp, "*** hashed ***");
		return;
	}

	sgnt_dump_signet(fp, sig);

}


/**
 * @brief	Destroys a signet_t structure.
 * @param	record	Void pointer to a signet_t structure to be destroyed.
*/
void _destroy_signet_cb(void *record) {

	sgnt_destroy_signet(record);

}

/* Create new signet and load signet from file */

/**
 * @brief	Creates a signet structure with public signing and encyption keys. Also creates a keys file in which the private keys are stored.
 * @param	type		Signet type, org, user or ssr (SIGNET_TYPE_ORG, SIGNET_TYPE_USER or SIGNET_TYPE_SSR).
 * @param	keysfile	Null terminated string containing the name of the keyfile to be created.
 * @return	Pointer to the newly created and allocated signet_t structure or NULL on error.
 * @free_using{sgnt_destroy_signet}
*/
static signet_t *sgnt_create_signet_w_keys(signet_type_t type, const char *keysfile) {

	size_t enc_key_size, f_len;
	unsigned char sign_fid, enc_fid, *ser_enc_pubkey;
	EC_KEY *enc_key;
	ED25519_KEY *sign_key;
	keys_type_t keys_type;
	signet_t *signet;

	if(!keysfile) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if (!(f_len = strlen(keysfile))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not write data to empty file path");
	}

	switch(type) {

	case SIGNET_TYPE_ORG:
		sign_fid = SIGNET_ORG_POK;
		enc_fid = SIGNET_ORG_ENC_KEY;
		keys_type = KEYS_TYPE_ORG;
		break;
	case SIGNET_TYPE_USER:
		sign_fid = SIGNET_USER_SIGN_KEY;
		enc_fid = SIGNET_USER_ENC_KEY;
		keys_type = KEYS_TYPE_USER;
		break;
	case SIGNET_TYPE_SSR:
		sign_fid = SIGNET_SSR_SIGN_KEY;
		enc_fid = SIGNET_SSR_ENC_KEY;
		keys_type = KEYS_TYPE_USER;
		break;
	default:
		RET_ERROR_PTR(ERR_BAD_PARAM, "invalid signet type");
		break;

	}

	if(!(sign_key = _generate_ed25519_keypair())) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not generate ed25519 key pair");
	}

	if(!(enc_key = _generate_ec_keypair(0))) {
		_free_ed25519_key(sign_key);
		RET_ERROR_PTR(ERR_UNSPEC, "could not generate elliptic curve key pair");
	}

	if(dime_keys_file_create(keys_type, sign_key, enc_key, keysfile) < 0) {
		_free_ed25519_key(sign_key);
		RET_ERROR_PTR(ERR_UNSPEC, "could not write private keys to file");
	}

	if(!(ser_enc_pubkey = _serialize_ec_pubkey(enc_key, &enc_key_size))) {
		_free_ed25519_key(sign_key);
		_free_ec_key(enc_key);
		RET_ERROR_PTR(ERR_UNSPEC, "could not serialize elliptic curve public key");
	}

	_free_ec_key(enc_key);

	if(!(signet = sgnt_create_signet(type))) {
		_free_ed25519_key(sign_key);
		free(ser_enc_pubkey);
		RET_ERROR_PTR(ERR_UNSPEC, "could not create signet object");
	}

	if(sgnt_set_signkey(signet, sign_key, SIGNKEY_DEFAULT_FORMAT) < 0) {
		sgnt_destroy_signet(signet);
		_free_ed25519_key(sign_key);
		free(ser_enc_pubkey);
		RET_ERROR_PTR(ERR_UNSPEC, "could not add signing key field to signet");
	}

	_free_ed25519_key(sign_key);
//TODO replace with sgnt_set_enckey
	if(sgnt_create_defined_field(signet, enc_fid, enc_key_size, ser_enc_pubkey) < 0) {
		free(ser_enc_pubkey);
		sgnt_destroy_signet(signet);
		RET_ERROR_PTR(ERR_UNSPEC, "could not add encryption key field to signet");
	}

	free(ser_enc_pubkey);

	return signet;
}


/* Loading signet from and saving to file */

/**
 * @brief	Loads signet_t structure from a PEM formatted file specified by filename.
 * @param	filename	Null terminated string containing the filename of the file containing the signet.
 * @return	Pointer to a newly created signet_t structure loaded from the file, NULL on failure.
 * @free_using{sgnt_destroy_signet}
*/
static signet_t *sgnt_file_to_signet(const char *filename) {

	char *b64_signet = NULL;
	signet_t *signet;

	if(!filename) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!(b64_signet = _read_pem_data(filename, SIGNET_PEM_TAG, 1))) {
		RET_ERROR_PTR_FMT(ERR_UNSPEC, "could not load signet from file: %s", filename);
	}

	if(!(signet = sgnt_serial_b64_to_signet(b64_signet))) {
		free(b64_signet);
		RET_ERROR_PTR(ERR_UNSPEC, "could not deserialize signet from base64 encoded data");
	}

	free(b64_signet);

	return signet;
}


/**
 * @brief	Stores a signet from the signet_t structure in a PEM formatted file specified by the filename.
 * @param	signet		Pointer to the signet_t structure containing the signet.
 * @param	filename	Null terminated string containing the desired filename for the signet.
 * @return	0 on success, -1 on failure.
*/
static int sgnt_file_create(signet_t *signet, const char *filename) {

	char *armored;

	if(!signet || !filename) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(!(armored = sgnt_serial_signet_to_b64(signet))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not serialize armored signet");
	}

	if(_write_pem_data(armored, SIGNET_PEM_TAG, filename) < 0) {
		free(armored);
		RET_ERROR_INT(ERR_UNSPEC, "could not write signet to PEM file");
	}

	free(armored);

	return 0;
}


/* Initializing and destroying signets*/

/**
 * @brief	Returns a new signet_t structure that gets deserialized from a data buffer
 * @param	in	data buffer that should contain the binary form of a signet
 * @param	in_len	length of data buffer
 * @return	A pointer to a newly allocated signet_t structure type, NULL on failure.
 * @free_using{sgnt_destroy_signet}
 */
static signet_t *sgnt_serial_to_signet(const unsigned char *in, size_t in_len) {

	size_t data_size = 0;
	dime_number_t magic_num;
	signet_t *signet;
	signet_type_t type;

	if(!in || !in_len) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(sgnt_serial_check_length(in, in_len) < 0) {
		RET_ERROR_PTR(ERR_UNSPEC, "supplied buffer length was too small for signet input");
	}

	magic_num = (dime_number_t)_int_no_get_2b((void *)in);

	switch(magic_num) {

	case DIME_ORG_SIGNET:
		type = SIGNET_TYPE_ORG;
		break;
	case DIME_USER_SIGNET:
		type = SIGNET_TYPE_USER;
		break;
	case DIME_SSR:
		type = SIGNET_TYPE_SSR;
		break;
	default:
		RET_ERROR_PTR(ERR_UNSPEC, "input buffer is not a signet");
		break;

	}

	if(!(signet = sgnt_create_signet(type))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not create new signet");
	}

	data_size = (size_t)_int_no_get_3b(in + 2);

	if(!(signet->data = malloc(data_size))) {
		PUSH_ERROR_SYSCALL("malloc");
		sgnt_destroy_signet(signet);
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate memory for signet data");
	}

	memset(signet->data, 0, data_size);
	memcpy(signet->data, in + SIGNET_HEADER_SIZE, data_size);
	signet->size = (uint32_t)data_size;

	if(sgnt_serial_index(signet) < 0) {
		sgnt_destroy_signet(signet);
		RET_ERROR_PTR(ERR_UNSPEC, "could not parse input buffer into signet");
	}

	return signet;
}


/**
 * @brief	Deserializes a b64 signet into a signet structure.
 * @param	b64_in	Null terminated array of b64 signet data.
 * @return	Pointer to newly allocated signet structure, NULL if failure.
 * @free_using{sgnt_destroy_signet}
*/
static signet_t *sgnt_serial_b64_to_signet(const char *b64_in) {

	unsigned char *in;
	size_t size = 0;
	signet_t *signet;

	if (!b64_in) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if (!(in = _b64decode(b64_in, strlen(b64_in), &size))) {
		RET_ERROR_PTR(ERR_UNSPEC, "base64 decoding of armored signet failed");
	}

	if (!(signet = sgnt_serial_to_signet(in, size))) {
		free(in);
		RET_ERROR_PTR(ERR_UNSPEC, "unable to initialize signet from data");
	}

	free(in);

	return signet;
}


/**
 * @brief	Destroys a signet and frees the memory.
 * @param	signet	Pointer to signet to be destroyed.
*/
static void sgnt_destroy_signet(signet_t *signet) {

	if(!signet) {
		return;
	}

	if(signet->data) {
		free(signet->data);
	}

	free(signet);

}


/* Serializing signet into binary and b64 */

/**
 * @brief	Serializes a signet structure into binary data.
 * @param	signet		Pointer to the target signet.
 * @param	serial_size	Pointer to the value that stores the length of the array returned.
 * @return	Signet serialized into binary data. Null on error.
 * @free_using{free}
*/
static unsigned char *sgnt_serial_from_signet(signet_t *signet, uint32_t *serial_size) {

	unsigned char *serial;
	dime_number_t number;

	if(!signet || !serial_size) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	switch(sgnt_type_get(signet)) {

	case SIGNET_TYPE_ORG:
		number = DIME_ORG_SIGNET;
		break;
	case SIGNET_TYPE_USER:
		number = DIME_USER_SIGNET;
		break;
	case SIGNET_TYPE_SSR:
		number = DIME_SSR;
		break;
	default:
		RET_ERROR_PTR(ERR_UNSPEC, "invalid signet type");
		break;

	}

	*serial_size = signet->size + SIGNET_HEADER_SIZE;

	if(!(serial = malloc(*serial_size))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, NULL);
	}

	memset(serial, 0, *serial_size);
	_int_no_put_2b(serial, (uint16_t)number);
	_int_no_put_3b(serial + 2, signet->size);
	memcpy(serial + SIGNET_HEADER_SIZE, signet->data, signet->size);

	return serial;
}


/**
 * @brief	Serializes a signet structure into b64 data.
 * @param	signet		Pointer to the target signet.
 * @return	Signet serialized into b64 data. Null on error.
 * @free_using{free}
*/
static char *sgnt_serial_signet_to_b64(signet_t *signet) {

	unsigned char *serial;
	uint32_t serial_size = 0;
	char *base64;

	if (!signet) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!(serial = sgnt_serial_from_signet(signet, &serial_size))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not serialize signet");
	}

	base64 = _b64encode(serial, (size_t)serial_size);
	free(serial);

	if(!base64) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not base64 encode serialized signet");
	}

	return base64;
}


/* Dump signet */

/**
 * @brief	Dumps signet into the specified file descriptor.
 * @param	fp	File descriptor the signet is dumped to.
 * @param	signet	Pointer to the signet_t structure to be dumped.
*/
static void sgnt_dump_signet(FILE *fp, signet_t *signet) {

	const char *type;
	int res;
	unsigned int version = SIGNET_VER_NO;
	signet_type_t signet_type;

	if(!signet || !fp) {
		return;
	}

	signet_type = sgnt_type_get(signet);

	switch(signet_type) {

	case SIGNET_TYPE_ORG:
		type = "organizational";
		break;
	case SIGNET_TYPE_USER:
		type = "user";
		break;
	case SIGNET_TYPE_SSR:
		type = "SSR";
		break;
	default:
		fprintf(fp, "--- Unrecognized signet type (%u) could not be dumped.\n", signet_type);

		if (get_last_error()) {
			dump_error_stack();
			_clear_error_stack();
		}

		return;
		break;

	}

	fprintf(fp, "--- version: %d, size = %d, signet type = %s\n", version, signet->size + 4, type);

	for(int i = 0; i < SIGNET_FID_MAX + 1; ++i) {

		if((res = sgnt_fid_exists(signet, i)) < 0) {
			fprintf(fp, "Error: field existence check failed.\n");
			dump_error_stack();
			_clear_error_stack();
			return;
		} else if(!res) {
			continue;
		}

		if(sgnt_dump_fid(fp, signet, i) < 0) {
			_clear_error_stack();
			return;
		}

		if(i == SIGNET_USER_CRYPTO_SIG && signet_type == SIGNET_TYPE_USER) {
			fprintf(fp, "%-34s    %s\n", "------- End user crypto. portion", "------------------------------------------------------------------------------------------");
		}

		if((i == SIGNET_USER_FULL_SIG && signet_type == SIGNET_TYPE_USER) || (i == SIGNET_ORG_FULL_SIG && signet_type == SIGNET_TYPE_ORG)) {
			fprintf(fp, "%-34s    %s\n", "------- End core signet portion", "------------------------------------------------------------------------------------------");
		}
	}

}


/* Retrieving signet states */

/**
 * @brief	Retrieves the number of fields with the specified field id.
 * @param	signet	Pointer to the target signet.
 * @param	fid	The target field id.
 * @return	The number of fields with specified field id. On various errors returns -1.
 *              NOTE: int overflow should not occur because of field size lower and signet size upper bounds.
*/
static int sgnt_fid_get_count(const signet_t *signet, unsigned char fid) {

	int count = 0, res;
	signet_field_t *field, *temp;

	if(!signet) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if((res = sgnt_fid_exists(signet, fid)) < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "error searching for field in signet");
	} else if(!res) {
		return count;
	}

	if(!(field = sgnt_create_field_list(signet, fid))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not create signet field object");
	}

	temp = field;

	while(temp) {
		temp = (signet_field_t *)temp->next;
		++count;
	}

	sgnt_destroy_field_list(field);

	return count;
}


/**
 * @brief	Checks for presence of field with specified id in the signet
 * @param	signet	The signet to be checked
 * @param	fid	Specified field id
 * @return	1 if such a field exists, 0 if it does not exist, -1 if error.
*/
static int sgnt_fid_exists(const signet_t *signet, unsigned char fid) {

	if(!signet) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	return (signet->fields[fid] ? 1 : 0);
}


/**
 * @brief	Checks the state of the specified signet, performing all non-cryptographic checks.
 * @param	signet	Pointer to the target signet.
 * @return	Signet state, SS_UNKNOWN on failure.
*/
static signet_state_t sgnt_validate_structure(const signet_t *signet) {

	int res;
	unsigned char full_sig, id_sig, crypto_sig;
	signet_field_key_t *keys;
	signet_field_t *field;
	signet_type_t type;

	if (!signet) {
		RET_ERROR_CUST(SS_UNKNOWN, ERR_BAD_PARAM, NULL);
	}

	/* check legal signet type */
	type = sgnt_type_get(signet);

	switch(type) {

	case SIGNET_TYPE_ORG:
		keys = signet_org_field_keys;
		crypto_sig = SIGNET_ORG_CRYPTO_SIG;
		id_sig = SIGNET_ORG_ID_SIG;
		full_sig = SIGNET_ORG_FULL_SIG;
		break;
	case SIGNET_TYPE_USER:
		keys = signet_user_field_keys;
		crypto_sig = SIGNET_USER_CRYPTO_SIG;
		id_sig = SIGNET_USER_ID_SIG;
		full_sig = SIGNET_USER_FULL_SIG;
		break;
	case SIGNET_TYPE_SSR:
		keys = signet_ssr_field_keys;
		full_sig = 0;
		id_sig = 0;
		crypto_sig = 0;
		break;
	default:
		RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "invalid signet type");
		break;

	}

	/* check against presence of illegal fields and presence of multiple unique fields
	Also, check field format */

	for(int i = 0; i < SIGNET_FID_MAX + 1; ++i) {

		if((res = sgnt_fid_exists(signet, i))) {

			if(res < 0) {
				RET_ERROR_UINT(ERR_UNSPEC, "could not determine existence of specified field in signet");
			}

			if(!keys[i].name) {
				return SS_MALFORMED;
			}

			if(!(field = sgnt_create_field_list(signet, i))) {
				return SS_MALFORMED;
			}

			if(keys[i].unique && field->next) {
				sgnt_destroy_field_list(field);
				return SS_MALFORMED;
			}

			sgnt_destroy_field_list(field);
		}
	}

	/* check to avoid signet exceeding maximum size */
	if(sgnt_serial_get_size(signet) > SIGNET_MAX_SIZE) {
		RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "signet size exceeds maximum size");
	}

	/* Check signatures and required fields to determine the signet state*/
	if(type == SIGNET_TYPE_USER || type == SIGNET_TYPE_ORG) {

		if((res = sgnt_fid_exists(signet, id_sig))) {

			if(res < 0) {
				RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "error searching for identifiable signature field in signet");
			}

			if((res = sgnt_validate_required_upto_fid(signet, keys, id_sig)) < 0) {
				RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "could not determine existence of required field");
			} else if (res) {
				return SS_ID;
			} else {
				return SS_INCOMPLETE;
			}
		}

		if((res = sgnt_fid_exists(signet, full_sig))) {

			if(res < 0) {
				RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "error searching for full signature field in signet");
			}

			if((res = sgnt_validate_required_upto_fid(signet, keys, full_sig)) < 0) {
				RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "could not determine existence of required field");
			} else if (res) {
				return SS_FULL;
			} else {
				return SS_INCOMPLETE;
			}
		}

		if((res = sgnt_fid_exists(signet, crypto_sig))) {

			if(res < 0) {
				RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "error searching for crypto signature field in signet");
			}

			if((res = sgnt_validate_required_upto_fid(signet, keys, crypto_sig)) < 0) {
				RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "could not determine existence of required fields");
			} else if(res) {
				return SS_CRYPTO;
			} else {
				return SS_INCOMPLETE;
			}
		}
	}

	if(type == SIGNET_TYPE_SSR) {

		if((res = sgnt_fid_exists(signet, SIGNET_USER_SSR_SIG))) {

			if(res < 0) {
				RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "error searching for ssr signature field in signet");
			}

			if((res = sgnt_validate_required_upto_fid(signet, keys, SIGNET_USER_SSR_SIG)) < 0) {
				RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "could not determine existence of required fields");
			} else if (res) {
				return SS_SSR;
			} else {
				return SS_INCOMPLETE;
			}
		}
	}

	return SS_INCOMPLETE;
}


/**
 * @brief	Retrieves the signet type, org or user (SIGNET_TYPE_ORG or SIGNET_TYPE_USER)
 * @param	signet	Pointer to the target signet.
 * @return	A signet_type_t enum type with the signet type, SIGNET_TYPE_ERROR on failure.
*/
static signet_type_t sgnt_type_get(const signet_t *signet) {

	if (!signet) {
		RET_ERROR_CUST(SIGNET_TYPE_ERROR, ERR_BAD_PARAM, NULL);
	}

	return (signet_type_t)signet->type;
}


/* Retrieving field data */

/**
 * @brief	Fetches the binary data value of the field specified by field id and the number at which it appears in the signet amongst fields with the same field id (1, 2, ...).
 * @param	signet	Pointer to the target signet.
 * @param	fid	Specified field id.
 * @param	num	Specified field number based on the order in which it appears in the signet.
 * @param	out_len	Pointer to the length of returned array.
 * @return	Array containing the binary data of the specified field, NULL if an error occurs. Caller is responsible for freeing memory.
*/
static unsigned char *sgnt_fetch_fid_num(const signet_t *signet, unsigned char fid, uint32_t num, size_t *out_len) {

	int res;
	unsigned char *data;
	signet_field_t *field, *temp;

	if(!signet || !out_len) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if((res = sgnt_fid_exists(signet, fid)) < 0) {
		RET_ERROR_PTR(ERR_UNSPEC, "error searching for field in signet");
	} else if (!res) {
		RET_ERROR_PTR(ERR_UNSPEC, "specified field does not exist");
	}

	if(!(field = sgnt_create_field_list(signet, fid))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not create signet field");
	}

	temp = field;

	for(uint32_t i = 1; i < num; ++i) {
		temp = temp->next;

		if(!temp) {
			sgnt_destroy_field_list(field);
			RET_ERROR_PTR(ERR_UNSPEC, "signet field index exceeded number of present field elements");
		}
	}

	if(!(data = malloc(temp->data_size))) {
		PUSH_ERROR_SYSCALL("malloc");
		sgnt_destroy_field_list(field);
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate space for signet data");
	}

	*out_len = temp->data_size;
	memset(data, 0, *out_len);
	memcpy(data, &(signet->data[temp->data_offset]), *out_len);
	sgnt_destroy_field_list(field);

	return data;
}


/**
 * @brief	Fetches the first undefined field with the specified field name.
 * @param	signet		Pointer to the target signet.
 * @param	name_size	Length of the passed array containing the length of the target field name.
 * @param	name		Array containing the name of the desired undefined field.
 * @param	data_size       Pointer to the size of the array that gets returned by the function.
 * @return	The array containing the data from the specified field or NULL in case of failure such as if the field was not found.
*/
static unsigned char *sgnt_fetch_undefined_field(const signet_t *signet, size_t name_size, const unsigned char *name, size_t *data_size) {

	int res;
	unsigned char undef_id, *data;
	signet_field_t *field, *temp;

	if(!signet || !name || !data_size) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	switch(sgnt_type_get(signet)) {

	case SIGNET_TYPE_ORG:
		undef_id = SIGNET_ORG_UNDEFINED;
		break;
	case SIGNET_TYPE_USER:
		undef_id = SIGNET_USER_UNDEFINED;
		break;
	default:
		RET_ERROR_PTR(ERR_UNSPEC, "signet type does not support undefined fields");
		break;

	}

	if((res = sgnt_fid_exists(signet, undef_id)) < 0) {
		RET_ERROR_PTR(ERR_UNSPEC, "error finding undefined fields in signet");
	} else if(!res) {
		RET_ERROR_PTR(ERR_UNSPEC, "no undefined fields exist in signet");
	}

	if(!(field = sgnt_create_field_list(signet, undef_id))) {
		RET_ERROR_PTR(ERR_UNSPEC, "failed to create signet field object");
	}

	temp = field;

	while(temp) {

		if(temp->name_size == name_size) {

			if(!memcmp(temp->signet->data + temp->name_offset, name, name_size)) {

				if(!(data = malloc(temp->data_size))) {
					PUSH_ERROR_SYSCALL("malloc");
					sgnt_destroy_field_list(field);
					RET_ERROR_PTR(ERR_NOMEM, "could not allocate memory for signet field data");
				}

				memset(data, 0, temp->data_size);
				memcpy(data, &(signet->data[temp->data_offset]), temp->data_size);
				*data_size = temp->data_size;
				sgnt_destroy_field_list(field);

				return data;
			}
		}

		temp = (signet_field_t *)temp->next;
	}

	sgnt_destroy_field_list(field);

	RET_ERROR_PTR(ERR_UNSPEC, "could not find undefined field with requested name");
}


/**
 * @brief	Converts a signing key from a signet serial format to a ed25519 public signing key object.
 * @param	serial_key	Ed25519 signing key in a signet serial format.
 * @param	key_size	Serial size.
 * @return	ED25519_KEY object.
 * @free_using{free_ed25519_key}
*/
static ED25519_KEY *sgnt_serial_to_signkey(const unsigned char *serial_key, size_t key_size) {

	ED25519_KEY *key;

	if(!serial_key || !key_size) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	switch(serial_key[0]) {

	case SIGNKEY_DEFAULT_FORMAT:

		if(key_size != ED25519_KEY_SIZE + 1) {
			PUSH_ERROR(ERR_UNSPEC, "invalid signet signing key size or format");
			key = NULL;
			break;
		}

		key = _deserialize_ed25519_pubkey(serial_key + 1);
		break;
	default:
		key = NULL;
		PUSH_ERROR(ERR_UNSPEC, "unsupported format specifier for signing key");
		break;

	}

	if(!key) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not convert signet serial format key to object");
	}

	return key;
}

/**brief	Converts a public signing key object to a signet specified format.
 * @param	key		Ed25519 signing key object.
 * @param	format		Format specifier.
 * @param	key_size	Output serial size.
 * @return	Serial data of the provided signing key in specified format.
 * @free_using{free}
*/
static unsigned char *sgnt_serial_from_signkey(ED25519_KEY *key, unsigned char format, size_t *key_size) {

	unsigned char *serial_key;
	size_t serial_size;

	switch(format) {

	case SIGNKEY_DEFAULT_FORMAT:
		serial_size = ED25519_KEY_SIZE + 1;

		if(!(serial_key = malloc(serial_size))) {
			PUSH_ERROR_SYSCALL("malloc");
			RET_ERROR_PTR(ERR_NOMEM, "could not allocate memory for serialized signing key");
		}

		serial_key[0] = format;
		memcpy(serial_key + 1, key->public_key, ED25519_KEY_SIZE);
		break;
	default:
		RET_ERROR_PTR(ERR_UNSPEC, "unsupported signing key format specifer");
		
	}

	*key_size = serial_size;

	return serial_key;
}


/**
 * @brief	Retrieves the public signing key from the signet, if the signet is an org signet only retrieves the POK.
 * @param	signet	Pointer to the target signet.
 * @return	Pointer to the target ed25519 public key.
 * @free_using{free_ed25519_key}
*/
static ED25519_KEY *sgnt_fetch_signkey(const signet_t *signet) {

	size_t key_size;
	unsigned char fid, *serial_key;
	ED25519_KEY *key;

	if(!signet) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	switch(sgnt_type_get(signet)) {

	case SIGNET_TYPE_ORG:
		fid = SIGNET_ORG_POK;
		break;
	case SIGNET_TYPE_USER:
		fid = SIGNET_USER_SIGN_KEY;
		break;
	case SIGNET_TYPE_SSR:
		fid = SIGNET_SSR_SIGN_KEY;
		break;
	default:
		RET_ERROR_PTR(ERR_UNSPEC, "invalid signet type");
		break;

	}

	if(!(serial_key = sgnt_fetch_fid_num(signet, fid, 1, &key_size))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not retrieve signing key");
	}

	key = sgnt_serial_to_signkey(serial_key, key_size);
	free(serial_key);

	if(!key) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not deserialize signet signing key");
	}

	return key;
}


/**
 * @brief	Retrieves the public encryption key from the signet, if the signet is a user signet only retrieves the main encryption key (not alternate).
 * @param	signet	Pointer to the target signet.
 * @return	Pointer to the target encryption public key.
 * @free_using{free_ec_key}
*/
static EC_KEY *sgnt_fetch_enckey(const signet_t *signet) {

	size_t key_size;
	unsigned char fid, *serial_key;
	EC_KEY *key;

	if(!signet) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	switch(sgnt_type_get(signet)) {

	case SIGNET_TYPE_ORG:
		fid = SIGNET_ORG_ENC_KEY;
		break;
	case SIGNET_TYPE_USER:
		fid = SIGNET_USER_ENC_KEY;
		break;
	case SIGNET_TYPE_SSR:
		fid = SIGNET_SSR_ENC_KEY;
		break;
	default:
		RET_ERROR_PTR(ERR_UNSPEC, "invalid signet type");
		break;

	}

	if(!(serial_key = sgnt_fetch_fid_num(signet, fid, 1, &key_size))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not retrieve signing key");
	}

	if(!(key = _deserialize_ec_pubkey(serial_key, key_size, 0))) {
		free(serial_key);
		RET_ERROR_PTR(ERR_UNSPEC, "could not deserialize signing key");
	}

	free(serial_key);

	return key;
}

/**
 * @brief	Retrieves all signing keys from an ORG signet that have a specific set of permissions
 * @param	signet	Pointer to target organizational signet.
 * @param	perm	Permissions by which the keys are filtered.
 * @return	A NULL pointer terminated array of ed25519 public signing key objects.
 * @NOTE	Always returns at least POK.
 * @free_using{free_ed25519_key_chain}
*/
static ED25519_KEY **sgnt_fetch_signkey_by_perm(const signet_t *signet, unsigned char perm) {

	int res;
	ED25519_KEY **keys;
	signet_field_t *field, *list;
	size_t buflen, list_count = 1, key_count = 1;
	unsigned int num_keys = 1;

	if(!signet) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(sgnt_type_get(signet) != SIGNET_TYPE_ORG) {
		RET_ERROR_PTR(ERR_UNSPEC, "target must an organizational signet");
	}

	if(sgnt_validate_structure(signet) < SS_CRYPTO) {
		RET_ERROR_PTR(ERR_UNSPEC, "signet structure is not valid for signing key retrieval");
	}

	if((res = sgnt_fid_exists(signet, SIGNET_ORG_SOK))) {

		if(res < 0) {
			RET_ERROR_PTR(ERR_UNSPEC, "error checking for existence of SOKs in signet");
		}

		if(!(field = list = sgnt_create_field_list(signet, SIGNET_ORG_SOK))) {
			RET_ERROR_PTR(ERR_UNSPEC, "error creating field list of signet SOKs");
		}

		while(field) {

			if(!(signet->data[field->data_offset] ^ perm)) {
				++num_keys;
			}

			field = (signet_field_t *)field->next;
		}
		
	}

	buflen = sizeof(ED25519_KEY *) * (num_keys + 1);

	if(!(keys = malloc(buflen))) {
		PUSH_ERROR_SYSCALL("malloc");
		sgnt_destroy_field_list(list);
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate memory for array of keys");
	}

	memset(keys, 0, buflen);
	field = list;

	if(!(keys[0] = sgnt_fetch_signkey(signet))) {
		_free_ed25519_key_chain(keys);
		sgnt_destroy_field_list(list);
		RET_ERROR_PTR(ERR_UNSPEC, "could not fetch signet signing key");
	}

	while(field) {

		if(!(signet->data[field->data_offset] ^ perm)) {

			if(!(keys[key_count] = sgnt_fetch_sok_num(signet, list_count))) {
				_free_ed25519_key_chain(keys);
				sgnt_destroy_field_list(list);
				RET_ERROR_PTR(ERR_UNSPEC, "could not fetch signet sok");
			}

			++key_count;
		}

		++list_count;
		field = (signet_field_t *)field->next;
	}

	if(list) {
		sgnt_destroy_field_list(list);
	}

	return keys;
}


/**
 * @brief	Retrieves all the signing keys from an org signet that can be used to sign a message.
 * @param	signet	Pointer to target organizational signet.
 * @return	A NULL pointer terminated array of ed25519 public signing key objects.
 * @NOTE	Always returns at least POK.
 * @free_using{free_ed25519_key_chain}
*/
static ED25519_KEY **sgnt_fetch_msg_signkeys(const signet_t *signet) {

	ED25519_KEY **res;

	if(!signet) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!(res = sgnt_fetch_signkey_by_perm(signet, SIGNET_SOK_MSG))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not fetch list of message signing keys");
	}

	return res;
}


/**
 * @brief	Retrieves all the signing keys from an org signet that can be used to sign a signet.
 * @param	signet	Pointer to target organizational signet.
 * @return	A NULL pointer terminated array of ed25519 public signing key objects.
 * @NOTE	Always returns at least POK.
 * @free_using{free_ed25519_key_chain}
*/
static ED25519_KEY **sgnt_fetch_signet_signkeys(const signet_t *signet) {

	ED25519_KEY **res;

	if(!signet) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!(res = sgnt_fetch_signkey_by_perm(signet, SIGNET_SOK_SIGNET))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not fetch list of message signing keys");
	}

	return res;
}


/**
 * @brief	Retrieves all the signing keys from an org signet that can be used to sign a TLS certificate.
 * @param	signet	Pointer to target organizational signet.
 * @return	A NULL pointer terminated array of ed25519 public signing key objects.
 * @NOTE	Always returns at least POK.
 * @free_using{free_ed25519_key_chain}
*/
static ED25519_KEY **sgnt_fetch_tls_signkeys(const signet_t *signet) {

	ED25519_KEY **res;

	if(!signet) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!(res = sgnt_fetch_signkey_by_perm(signet, SIGNET_SOK_TLS))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not fetch list of message signing keys");
	}

	return res;
}


/**
 * @brief	Retrieves all the signing keys from an org signet that can be used to sign software.
 * @param	signet	Pointer to target organizational signet.
 * @return	A NULL pointer terminated array of ed25519 public signing key objects.
 * @NOTE	Always returns at least POK.
 * @free_using{free_ed25519_key_chain}
*/
static ED25519_KEY **sgnt_fetch_software_signkeys(const signet_t *signet) {

	ED25519_KEY **res;

	if(!signet) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(!(res = sgnt_fetch_signkey_by_perm(signet, SIGNET_SOK_SOFTWARE))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not fetch list of message signing keys");
	}

	return res;
}


/**
 * @brief	Fetch the secondary organizational signing key from the signet by number (starting at 1)
 * @param	signet	Pointer to the target organizational signet.
 * @param	num	The sok number to be fetched.
 * @return	Retrieved ED25519 key.
 * @free_using{free_ed25519_key}
*/
static ED25519_KEY *sgnt_fetch_sok_num(const signet_t *signet, unsigned int num) {

	ED25519_KEY *key;
	size_t key_size;
	unsigned char *serial_key;

	if(!signet || !num) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(sgnt_type_get(signet) != SIGNET_TYPE_ORG) {
		RET_ERROR_PTR(ERR_UNSPEC, "only organizational signets can have SOKs");
	}

	if((unsigned int)sgnt_fid_get_count(signet, SIGNET_ORG_SOK) < num) {
		RET_ERROR_PTR(ERR_UNSPEC, "there are less SOKs than the specified number");
	}

	if(!(serial_key = sgnt_fetch_fid_num(signet, SIGNET_ORG_SOK, 1, &key_size))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not retrieve signing key");
	}

	key = sgnt_serial_to_signkey(serial_key + 1, key_size - 1);
	free(serial_key);

	if(!key) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not deserialize signet signing key");
	}

	return key;
}


/* Modifying the signet */

/**
 * @brief	Adds a field to the target field.
 * @param	signet		Pointer to the target signet.
 * @param	fid		Field id of the field to be added.
 * @param	data_size	Size of the array containing the field data.
 * @param	data		Field data.
 * @return	0 on success, -1 on failure.
*/
static int sgnt_create_defined_field(signet_t *signet, unsigned char fid, size_t data_size, const unsigned char *data) {

	int res;
	size_t at = 0, field_size = 1;
	signet_field_key_t *keys;
	uint32_t maxsize = 0;
	unsigned char *field_data;
	unsigned int offset;

	if(!signet || (!data && data_size) || (data && !data_size)) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	switch(sgnt_type_get(signet)) {

	case SIGNET_TYPE_ORG:
		keys = signet_org_field_keys;

		if(fid == SIGNET_ORG_UNDEFINED) {
			RET_ERROR_INT(ERR_UNSPEC, "incorrect function for undefined field creation");
		}

		break;
	case SIGNET_TYPE_USER:
		keys = signet_user_field_keys;

		if(fid == SIGNET_USER_UNDEFINED) {
			RET_ERROR_INT(ERR_UNSPEC, "incorrect function for undefined field creation");
		}

		break;
	case SIGNET_TYPE_SSR:
		keys = signet_ssr_field_keys;
		break;
	default:
		RET_ERROR_INT(ERR_UNSPEC, "invalid signet type");
		break;

	}

	switch(keys[fid].bytes_data_size) {

	case 0:

		if(data_size != keys[fid].data_size) {
			RET_ERROR_INT(ERR_BAD_PARAM, "signet field data size did not match required field data size");
		}

		field_size += keys[fid].data_size;
		break;
	case 1:
		maxsize = UNSIGNED_MAX_1_BYTE;
		break;
	case 2:
		maxsize = UNSIGNED_MAX_2_BYTE;
		break;
	case 3:
		maxsize = UNSIGNED_MAX_3_BYTE;
		break;
	default:
		RET_ERROR_INT(ERR_UNSPEC, "inalid signet field data size");
		break;

	}

	if (maxsize) {

		if (data_size > maxsize) {
			RET_ERROR_INT(ERR_BAD_PARAM, "the specified data size is too large for the field type");
		}

		field_size += keys[fid].bytes_data_size + data_size;
	}

	if(!(field_data = malloc(field_size))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_INT(ERR_NOMEM, NULL);
	}

	memset(field_data, 0, field_size);
	field_data[at++] = fid;

	switch(keys[fid].bytes_data_size) {

	case 1:
		field_data[at] = (unsigned char)data_size;
		break;
	case 2:
		_int_no_put_2b(field_data + at, (uint16_t)data_size);
		break;
	case 3:
		_int_no_put_3b(field_data + at, (uint32_t)data_size);
		break;
	default:
		break;

	}

	at += keys[fid].bytes_data_size;
	if (data != NULL) {
		memcpy(field_data + at, data, data_size);
	}

	offset = (unsigned int)signet->size;

	for(int i = fid + 1; i < SIGNET_FID_MAX; ++i) {

		if((res = sgnt_fid_exists(signet, i))) {

			if(res < 0) {
				RET_ERROR_INT(ERR_UNSPEC, "error searching for field in signet");
			}

			offset = (unsigned int)signet->fields[i] - 1;
			break;
		}
	}

	res = sgnt_create_field_at(signet, offset, field_size, (const unsigned char *)field_data);
	free(field_data);

	if(res) {
		RET_ERROR_INT(ERR_UNSPEC, "error inserting field data into signet");
	}

	if((res = sgnt_fid_exists(signet, fid)) < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "error searching for field in signet");
	} else if(!res) {
		signet->fields[fid] = offset + 1;
	}

	for(int i = fid + 1; i <= SIGNET_FID_MAX; ++i) {

		if((res = sgnt_fid_exists(signet, i))) {

			if(res < 0) {
				RET_ERROR_INT(ERR_UNSPEC, "error searching for field in signet");
			}

			signet->fields[i] += field_size;
		}
	}

	return 0;
}


/**
 * @brief	Adds a SOK (Secondary Organizational Signing Key) to an organizational signet.
 * @param	signet		Pointer to the target org signet.
 * @param	key		ED25519 key to be added as a SOK to the signet.
 * @param	format		Format specifier byte dictating the format.
 * @param	perm		Permissions for the usage of the SOK.
 * @return	0 on success, -1 on failure.
*/
static int sgnt_create_sok(signet_t *signet, ED25519_KEY *key, unsigned char format, unsigned char perm) {

	int res;
	unsigned char *serial_key;
	size_t serial_size;

	if(!signet || !key) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(sgnt_type_get(signet) != SIGNET_TYPE_ORG) {
		RET_ERROR_INT(ERR_UNSPEC, "only organizational signets have a secondary organizational key field type");
	}

	if(!(serial_key = sgnt_serial_from_signkey(key, format, &serial_size))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not serialize ed25519 public key to specified signet format");
	}

	if(!(serial_key = realloc(serial_key, serial_size + 1))) {
		PUSH_ERROR_SYSCALL("realloc");
		RET_ERROR_INT(ERR_NOMEM, "could not reallocate memory for signet serial SOK representation");
	}

	memmove(serial_key, serial_key+1, serial_size);
	serial_key[0] = perm;
	++serial_size;
	res = sgnt_create_defined_field(signet, SIGNET_ORG_SOK, serial_size, serial_key);
	free(serial_key);

	if(res) {
		RET_ERROR_INT(ERR_UNSPEC, "could not add SOK to signet");
	}

	return 0;
}


/**
 * @brief	Adds an undefined field to signet with specified name and data.
 * @param	signet		Pointer to the target signet to which the field is added.
 * @param	name_size	Size of field name.
 * @param	name		Pointer to  field name.
 * @param	data_size	Size of field data.
 * @param	data		Pointer to field data.
 * @return	0 on success, -1 on failure.
*/
static int sgnt_create_undefined_field(signet_t *signet, size_t name_size, const unsigned char *name, size_t data_size, const unsigned char *data) {

	int res;
	size_t at = 0, field_size = 1;
	signet_field_key_t *keys;
	unsigned char *field_data, fid;
	unsigned int offset;

	if(!signet || (!data && data_size) || (data && !data_size) || !name || !name_size) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	switch(sgnt_type_get(signet)) {

	case SIGNET_TYPE_ORG:
		fid = SIGNET_ORG_UNDEFINED;
		keys = signet_org_field_keys;
		break;
	case SIGNET_TYPE_USER:
		fid = SIGNET_USER_UNDEFINED;
		keys = signet_user_field_keys;
		break;
	case SIGNET_TYPE_SSR:
		RET_ERROR_INT(ERR_UNSPEC, "signet signing request has no allowed undefined fields");
		break;
	default:
		RET_ERROR_INT(ERR_UNSPEC, "invalid signet type");
		break;

	}

	if(name_size > UNSIGNED_MAX_1_BYTE || data_size > UNSIGNED_MAX_2_BYTE) {
		RET_ERROR_INT(ERR_UNSPEC, "invalid name or data size for undefined field");
	}

	field_size += 1 + name_size + 2 + data_size;

	if(!(field_data = malloc(field_size))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_INT(ERR_NOMEM, NULL);
	}

	memset(field_data, 0, field_size);
	field_data[at++] = fid;
	field_data[at++] = (unsigned char)name_size;
	memcpy(field_data + at, name, name_size);
	at += name_size;
	_int_no_put_2b(field_data + at, (uint16_t) data_size);
	at += 2;
	memcpy(field_data + at, data, data_size);

	offset = (unsigned int)signet->size;

	for(int i = fid + 1; i < SIGNET_FID_MAX; ++i) {

		if((res = sgnt_fid_exists(signet, i))) {

			if(res < 0) {
				RET_ERROR_INT(ERR_UNSPEC, "error searching for field in signet");
			}

			offset = (unsigned int)signet->fields[i] - 1;
			break;
		}
	}

	res = sgnt_create_field_at(signet, offset, field_size, (const unsigned char *)field_data);
	free(field_data);

	if(res) {
		RET_ERROR_INT(ERR_UNSPEC, "error inserting field data into signet");
	}

	if((res = sgnt_fid_exists(signet, fid)) < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "error searching for field in signet");
	} else if(!res) {
		signet->fields[fid] = offset + 1;
	}

	for(int i = fid + 1; i <= SIGNET_FID_MAX; ++i) {

		if((res = sgnt_fid_exists(signet, i))) {

			if(res < 0) {
				RET_ERROR_INT(ERR_UNSPEC, "error searching for field in signet");
			}

			signet->fields[i] += field_size;
		}
	}

	return 0;
}


/**
 * @brief	Removes the field specified by a field id and the number in which it appears in the target signet amongst fields with the same field id from the target signet.
 * @param	signet	Pointer to the target signet.
 * @param	fid	Field id of the field to be removed.
 * @param	num	The number in which the field to be removed appears amongst other fields with the same field id in the target signet, (1, 2, ...).
 * @return	Number of fields with specified id on success, -1 on failure.
*/
static int sgnt_remove_fid_num(signet_t *signet, unsigned char fid, int num) {

	int num_fields, res;
	int field_size;
	unsigned int offset;
	signet_field_t *field, *temp;

	if(!signet) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if((res = sgnt_fid_exists(signet, fid)) < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "error searching for field in signet");
	} else if(!res) {
		RET_ERROR_INT(ERR_UNSPEC, "field not found in signet");
	}

	if((num_fields = sgnt_fid_get_count(signet, fid)) < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "could not calculate signet field count with specified field id");
	}

	if(num_fields < num) {
		RET_ERROR_INT(ERR_UNSPEC, "signet field index exceeds field count");
	}

	if(!(field = sgnt_create_field_list(signet, fid))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not retrieve fields from signet");
	}

	temp = field;

	for(int i = 1; i < num; ++i) {

		if(!temp) {
			sgnt_destroy_field_list(field);
			RET_ERROR_INT(ERR_UNSPEC, "signet field index does not exist");
		}

		temp = (signet_field_t *)temp->next;
	}

	offset = temp->id_offset;

	if((field_size = sgnt_serial_get_field_size((const signet_field_t *)temp)) < 0) {
		sgnt_destroy_field_list(field);
		RET_ERROR_INT(ERR_UNSPEC, "could not calculate signet field size");
	}

	sgnt_destroy_field_list(field);

	if(num_fields == 1) {
		signet->fields[fid] = 0;
	}

	for(int i = fid + 1; i <= SIGNET_FID_MAX; ++i) {

		if((res = sgnt_fid_exists(signet, i))) {

			if(res < 0) {
				RET_ERROR_INT(ERR_UNSPEC, "error searching for field in signet");
			}

			signet->fields[i] -= field_size;
		}
	}

	if(sgnt_remove_field_at(signet, offset, field_size) < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "could not remove specified field from signet");
	}

	return 0;
}


/**
 * @brief	Removes an undefined field from the target signet by name.
 * @param	signet		Pointer to the target signet.
 * @param	name_size	Size of field name.
 * @param	name		Name of the field to be removed.
 * @return	0 on success, -1 on failure.
*/
static int sgnt_remove_undefined_field(signet_t *signet, size_t name_size, const unsigned char *name) {

	int num_fields, res;
	size_t field_size;
	unsigned char fid;
	unsigned int offset;
	signet_field_t *field, *temp;

	if(!signet) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	switch(sgnt_type_get(signet)) {

	case SIGNET_TYPE_ORG:
		fid = SIGNET_ORG_UNDEFINED;
		break;
	case SIGNET_TYPE_USER:
		fid = SIGNET_USER_UNDEFINED;
		break;
	default:
		RET_ERROR_INT(ERR_UNSPEC, "invalid signet type");
		break;

	}

	if((res = sgnt_fid_exists(signet, fid)) < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "error searching for field in signet");
	} else if(!res) {
		RET_ERROR_INT(ERR_UNSPEC, "field id not found in signet");
	}

	if((num_fields = sgnt_fid_get_count(signet, fid)) < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "could not calculate field count for signet");
	}

	if(!(field = sgnt_create_field_list(signet, fid))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not retrieve signet fields with specified field id");
	}

	temp = field;

	while(temp) {

		if(temp->name_size == (unsigned char)name_size) {

			if(memcmp(temp->signet->data + temp->name_offset, name, name_size) == 0) {
				offset = temp->id_offset;
				field_size = sgnt_serial_get_field_size((const signet_field_t *)temp);
				break;
			}
		}
	}

	sgnt_destroy_field_list(field);

	if(num_fields == 1) {
		signet->fields[fid] = 0;
	}

	for(int i = fid + 1; i <= SIGNET_FID_MAX; ++i) {

		if((res = sgnt_fid_exists(signet, i))) {

			if(res < 0) {
				RET_ERROR_INT(ERR_UNSPEC, "error searching for field in signet");
			}

			signet->fields[i] -= field_size;
		}
	}

	if(sgnt_remove_field_at(signet, offset, field_size) < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "could not remove specified field from signet");
	}

	return 0;
}


/**
 * @brief	Replaces all fields in the target signet with the specified field id with a new field specified by the parameters.
 * @param	signet		Pointer to the target signet_t structure.
 * @param	fid			Field id which specifies the fields to be replaced with the new field.
 * @param	data_size	Size of field data array.
 * @param	data		Array contaning field data.
 * @return	0 on success, -1 on failure.
*/
static int sgnt_set_defined_field(signet_t *signet, unsigned char fid, size_t data_size, const unsigned char *data) {

	int result;

	if(!signet) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	while((result = sgnt_fid_exists(signet, fid))) {

		if(result < 0) {
			RET_ERROR_INT(ERR_UNSPEC, "error searching for field in signet");
		}

		if(sgnt_remove_fid_num(signet, fid, 1) < 0) {
			RET_ERROR_INT(ERR_UNSPEC, "could not remove old signet field value");
		}
	}

	if(sgnt_create_defined_field(signet, fid, data_size, data) < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "could not add field to signet");
	}

	return 0;
}


/**
 * @brief	Sets the ID of the signet to the specified NULL terminated string.
 * @param	signet	Pointer to the target signet.
 * @param	id_size	Size of signet id.
 * @param	id		Signet id.
 * @return	0 on success, -1 on failure.
*/
static int sgnt_set_id_field(signet_t *signet, size_t id_size, const unsigned char *id) {

	int result;
	unsigned char fid;

	if(!signet || !id || !id_size) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	switch(sgnt_type_get(signet)) {

	case SIGNET_TYPE_ORG:
		fid = SIGNET_ORG_ID;
		break;
	case SIGNET_TYPE_USER:
		fid = SIGNET_USER_ID;
		break;
	case SIGNET_TYPE_SSR:
		RET_ERROR_INT(ERR_UNSPEC, "SSR does not have an id field");
		break;
	default:
		RET_ERROR_INT(ERR_UNSPEC, "invalid signet type");
		break;

	}

	if((result = sgnt_set_defined_field(signet, fid, id_size, id)) < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "could not set signet id field");
	}

	return 0;
}


/**
 * @brief	Sets the signing key (pok - primary signing key in case of an org signet).
 * @param	signet	Pointer to the target signet.
 * @param	key	Public signing key to be set as the signing key of the signet.
 * @param	format	Format specifier byte, dictating the format.
 * @return	0 on success, -1 on failure.
*/
static int sgnt_set_signkey(signet_t *signet, ED25519_KEY *key, unsigned char format) {

	int res;
	unsigned char *serial_key, fid;
	size_t serial_size;

	if(!signet || !key) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	switch(sgnt_type_get(signet)) {

	case SIGNET_TYPE_ORG:
		fid = SIGNET_ORG_POK;
		break;
	case SIGNET_TYPE_USER:
		fid = SIGNET_USER_SIGN_KEY;
		break;
	case SIGNET_TYPE_SSR:
		fid = SIGNET_SSR_SIGN_KEY;
		break;
	default:
		RET_ERROR_INT(ERR_UNSPEC, "invalid signet type");

	}

	if(!(serial_key = sgnt_serial_from_signkey(key, format, &serial_size))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not serialize provided public ed25519 key to signet format");
	}

	res = sgnt_set_defined_field(signet, fid, serial_size, serial_key);
	free(serial_key);

	if(res) {
		RET_ERROR_INT(ERR_UNSPEC, "could not set signet signing key");
	}

	return 0;
}


/**
 * @brief	Sets the target signet to a specified type.
 * @param	signet	Pointer to the target signet.
 * @param	type	Specified signet type.
 * @return	0 on success, -1 on error.
*/
static int sgnt_type_set(signet_t *signet, signet_type_t type) {

	if(!signet) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	} else if(type != SIGNET_TYPE_ORG && type != SIGNET_TYPE_USER && type != SIGNET_TYPE_SSR) {
		RET_ERROR_INT(ERR_BAD_PARAM, "unsupported signet type");
	}

	signet->type = type;

	return 0;
}


/* signet splits */

// TODO: some code reuse possibilities with _signet_core_split() and _signet_user_split()

/**
 * @brief	Creates a copy of the target signet with the ID field and the FULL signature stripped off.
 * @param	signet	Pointer to the target signet.
 * @return	Pointer to a stripped signet on success, NULL on failure.
 * @free_using{sgnt_destroy_signet}
*/
static signet_t *sgnt_split_full(const signet_t *signet) {

	unsigned char fid, *data = NULL, *split;
	size_t data_size, split_size;
	dime_number_t number;
	signet_t *split_signet;

	if(!signet) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	switch(sgnt_type_get(signet)) {

	case SIGNET_TYPE_ORG:
		fid = SIGNET_ORG_FULL_SIG;
		number = DIME_ORG_SIGNET;
		break;
	case SIGNET_TYPE_USER:
		fid = SIGNET_USER_FULL_SIG;
		number = DIME_USER_SIGNET;
		break;
	default:
		RET_ERROR_PTR(ERR_UNSPEC, "unsupported signet type");
		break;

	}

	if(!(data = sgnt_serial_from_upto_fid(signet, fid, &data_size))) {

		if(get_last_error()) {
			RET_ERROR_PTR(ERR_UNSPEC, "could not serialize specified signet fields");
		}

	}

	split_size = data_size + SIGNET_HEADER_SIZE;

	if(!(split = malloc(split_size))) {
		PUSH_ERROR_SYSCALL("malloc");

		if (data) {
			free(data);
		}

		RET_ERROR_PTR(ERR_NOMEM, NULL);
	}

	memset(split, 0, split_size);
	_int_no_put_2b(split, (uint16_t)number);
	_int_no_put_3b(split + 2, (uint32_t)data_size);

	if(data) {
		memcpy(split + SIGNET_HEADER_SIZE, data, data_size);
		free(data);
	}

	if(!(split_signet = sgnt_serial_to_signet(split, split_size))) {
		free(split);
		RET_ERROR_PTR(ERR_UNSPEC, "could not deserialize split signet");
	}

	free(split);

	return split_signet;
}


/**
 * @brief	Creates a copy of the target user signet with all fields beyond the INITIAL signature stripped off.
 * @param	signet	Pointer to the target signet.
 * @return	Pointer to a stripped signet on success, NULL on failure.
 * @free_using{sgnt_destroy_signet}
*/
static signet_t *sgnt_split_crypto(const signet_t *signet) {

	unsigned char *data = NULL, *split;
	size_t data_size, split_size;
	dime_number_t number = DIME_USER_SIGNET;
	signet_t *split_signet;

	if(!signet) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(sgnt_type_get(signet) != SIGNET_TYPE_USER) {
		RET_ERROR_PTR(ERR_UNSPEC, "invalid signet type");
	}

	if(!(data = sgnt_serial_from_upto_fid(signet, SIGNET_USER_CRYPTO_SIG, &data_size))) {

		if(get_last_error()) {
			RET_ERROR_PTR(ERR_UNSPEC, "could not serialize specified signet fields");
		}

	}

	split_size = data_size + SIGNET_HEADER_SIZE;

	if(!(split = malloc(split_size))) {
		PUSH_ERROR_SYSCALL("malloc");

		if (data) {
			free(data);
		}

		RET_ERROR_PTR(ERR_NOMEM, NULL);
	}

	memset(split, 0, split_size);
	_int_no_put_2b(split, (uint16_t)number);
	_int_no_put_3b(split + 2, (uint32_t)data_size);

	if(data) {
		memcpy(split + SIGNET_HEADER_SIZE, data, data_size);
		free(data);
	}

	if(!(split_signet = sgnt_serial_to_signet(split, split_size))) {
		free(split);
		RET_ERROR_PTR(ERR_UNSPEC, "could not deserialize split signet");
	}

	free(split);

	return split_signet;
}


/* Signet Fingerprints */

/**
 * @brief	Takes a SHA512 fingerprint of the entire user or org signet.
 * @param	signet	Pointer to the target signet.
 * @return	Allocated NULL terminated buffer to a base64 encoded unpadded fingerprint. Null on failure;
 * @free_using{free}
*/
static char *sgnt_fingerprint_id(const signet_t *signet) {

	char *b64_fingerprint;

	if(!signet) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if(sgnt_type_get(signet) == SIGNET_TYPE_SSR) {
		RET_ERROR_PTR(ERR_UNSPEC, "unsupported signet type");
	}

	if(!(b64_fingerprint = sgnt_fingerprint_upto_fid(signet, SIGNET_FID_MAX))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not base-64 encode full signet fingerprint");
	}

	return b64_fingerprint;
}


/**
 * @brief	Takes a SHA512 fingerprint of the user or org signet with the ID and FULL signature fields stripped off.
 * @note	To take an SSR fingerprint, use the signet_ssr_fingerprint() function.
 * @param	signet	Pointer to the target signet.
 * @return	Allocated NULL terminated buffer to a base64 encoded unpadded fingerprint. Null on failure.
 * @free_using{free}
*/
static char *sgnt_fingerprint_full(const signet_t *signet) {

	char *b64_fingerprint;
	unsigned char fid;

	if(!signet) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	switch(sgnt_type_get(signet)) {

	case SIGNET_TYPE_ORG:
		fid = SIGNET_ORG_FULL_SIG;
		break;
	case SIGNET_TYPE_USER:
		fid = SIGNET_USER_FULL_SIG;
		break;
	default:
		RET_ERROR_PTR(ERR_UNSPEC, "unsupported signet type");
		break;

	}

	if(!(b64_fingerprint = sgnt_fingerprint_upto_fid(signet, fid))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not base-64 encode full signet fingerprint");
	}

	return b64_fingerprint;
}


/**
 * @brief	Takes a SHA512 fingerprint of a signet with all fields after the cryptographic signature field stripped off.
 * @note	To take an SSR fingerprint, use the signet_ssr_fingerprint() function.
 * @param	signet	Pointer to the target signet.
 * @return	Allocated NULL terminated string to a base64 encoded unpadded fingerprint. Null on error.
 * @free_using{free}
*/
static char *sgnt_fingerprint_crypto(const signet_t *signet) {

	char *b64_fingerprint;
	unsigned char fid;

	if(!signet) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	switch(sgnt_type_get(signet)) {

	case SIGNET_TYPE_ORG:
		fid = SIGNET_ORG_CRYPTO_SIG;
		break;
	case SIGNET_TYPE_USER:
		fid = SIGNET_USER_CRYPTO_SIG;
	default:
		RET_ERROR_PTR(ERR_UNSPEC, "unsupported signet type for cryptographic fingerprint");

	}

	if(!(b64_fingerprint = sgnt_fingerprint_upto_fid(signet, fid))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not base-64 encode full signet fingerprint");
	}

	return b64_fingerprint;
}


/**
 * @brief	Takes a SHA512 fingerprint of a user signet or an ssr with all fields after the SSR signature stripped off.
 * @param	signet	Pointer to the target signet.
 * @return	Allocated NULL terminated buffer to a base64 encoded unpadded fingerprint.
 * @free_using{free}
*/
static char *sgnt_fingerprint_ssr(const signet_t *signet) {

	char *b64_fingerprint;
	signet_type_t type;

	if(!signet) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	if ((type = sgnt_type_get(signet)) == SIGNET_TYPE_ERROR) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not determine signet type");
	} else if(type != SIGNET_TYPE_USER && type != SIGNET_TYPE_SSR) {
		RET_ERROR_PTR(ERR_UNSPEC, "invalid signet type");
	}

	if(!(b64_fingerprint = sgnt_fingerprint_upto_fid(signet, SIGNET_USER_SSR_SIG))) {
		RET_ERROR_PTR(ERR_UNSPEC, "could not base-64 encode full signet fingerprint");
	}

	return b64_fingerprint;
}


/* Signet verification */

/**
 * @brief	Verifies a user signet, org signet or ssr for syntax, context and cryptographic validity. Does NOT perform chain of custody validation.
 * @param	signet		Pointer to the target signet_t structure.
 * @param	orgsig		Pointer to the org signet associated with the target signet IF the target signet is a user signet.
 *                              If target signet is not a user signet, orgsig should be passed as NULL.
 * @param	previous	Pointer to the previous user signet, which will be used validate the chain of custody signature, if such is available.
 * @param	dime_pok	A NULL terminated array of pointers to ed25519 POKs from the dime record associated with the target signet if the target signet is an org signet.
 *                              If the target signet is not an org signet dime_pok should be passed as NULL;
 * @return	Signet state as a signet_state_t enum type. SS_UNKNOWN on error.
*/
static signet_state_t  sgnt_validate_all(const signet_t *signet, const signet_t *previous, const signet_t *orgsig, const unsigned char **dime_pok) {

	ED25519_KEY **org_keys, *user_key, *prev_key;
	int res, res2, res3, pok_num;
	const char *errmsg = NULL;
	signet_state_t signet_state, result = SS_ID;
	signet_type_t type;

	if(!signet) {
		RET_ERROR_CUST(SS_UNKNOWN, ERR_BAD_PARAM, NULL);
	}

	signet_state = sgnt_validate_structure(signet);

	if(signet_state <= SS_INVALID) {
		return signet_state;
	}

	type = sgnt_type_get(signet);

	if(type == SIGNET_TYPE_SSR) {

		if(!(user_key = sgnt_fetch_signkey(signet))) {
			RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "could not retrieve signing key");
		}

		res = sgnt_validate_sig_field_key(signet, SIGNET_SSR_SSR_SIG, user_key);
		_free_ed25519_key(user_key);

		if(res < 0) {
			RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "error during signature field validation");
		} else if(!res) {
			return SS_INVALID;
		}

		if((res = sgnt_fid_exists(signet, SIGNET_SSR_COC_SIG))) {

			if(res < 0) {
				RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "error while checking existence of coc signature");
			}

			if(!previous) {
				return SS_BROKEN_COC;
			} else {

				if(!(prev_key = sgnt_fetch_signkey(previous))) {
					RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "error while retrieving signet signing key");
				}

				res = sgnt_validate_sig_field_key(signet, SIGNET_USER_SSR_SIG, prev_key); 
				_free_ed25519_key(prev_key);

				if(res < 0) {
					RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "error during signature field validation");
				} else if(!res) {
					return SS_BROKEN_COC;
				}
			}
		} else if(!res && previous) {
			return SS_BROKEN_COC;
		}

		return SS_SSR;
	} else if(type == SIGNET_TYPE_ORG) {

		if(!dime_pok) {
			RET_ERROR_CUST(SS_UNKNOWN, ERR_BAD_PARAM, NULL);
		}

		if(signet_state <= SS_SSR) {
			RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "invalid state for organizational signet");
		}

		if((pok_num = sgnt_validate_pok(signet, dime_pok)) < 0) {
			RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "error matching signet POK with DIME management record");
		}

		if(!pok_num) {
			RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "no DIME record POKs match the signet signing key");
		}

		pok_num -= 1;

		if((res = sgnt_validate_sig_field(signet, SIGNET_ORG_CRYPTO_SIG, dime_pok[pok_num])) == 1) {

			if(signet_state == SS_CRYPTO) {
				result = SS_CRYPTO;
			} else if((res2 = sgnt_validate_sig_field(signet, SIGNET_ORG_FULL_SIG, dime_pok[pok_num])) == 1) {

				if(signet_state == SS_FULL) {
					result = SS_FULL;
				} else if((res3 = sgnt_validate_sig_field(signet, SIGNET_ORG_ID_SIG, dime_pok[pok_num])) < 0) {
					result = SS_UNKNOWN;
					errmsg = "encountered error during id signature field validation";
				} else if(!res3) {
					result = SS_INVALID;
				}

			} else if(res2 < 0) {
				result = SS_UNKNOWN;
				errmsg = "encountered error during full signature field validation";
			} else {
				result = SS_INVALID;
			}

		} else if(res < 0) {
			result = SS_UNKNOWN;
			errmsg = "encountered error during crypto signature field validation";
		} else {
			result = SS_INVALID;
		}

	} else if(type == SIGNET_TYPE_USER) {

		if(!orgsig) {
			RET_ERROR_CUST(SS_UNKNOWN, ERR_BAD_PARAM, NULL);
		}

		if(signet_state <= SS_SSR) {
			RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "invalid state for user signet");
		}

		if(sgnt_type_get(orgsig) != SIGNET_TYPE_ORG) {
			RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "the signet passed to verify the user signet was not an org signet");
		}

		if(!(org_keys = sgnt_fetch_signet_signkeys(orgsig))) {
			RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "could not retrieve signing keys from organizational signet");
		}

		if((res = sgnt_validate_sig_field_multikey(signet, SIGNET_USER_CRYPTO_SIG, org_keys)) == 1) {

			if(signet_state == SS_CRYPTO) {
				result = SS_CRYPTO;
			} else if((res2 = sgnt_validate_sig_field_multikey(signet, SIGNET_USER_FULL_SIG, org_keys)) == 1) {

				if(signet_state == SS_FULL) {
					result = SS_FULL;
				} else if ((res3 = sgnt_validate_sig_field_multikey(signet, SIGNET_USER_ID_SIG, org_keys)) < 0) {
					result = SS_UNKNOWN;
					errmsg = "encountered error during id signature field validation";
				} else if(!res3) {
					result = SS_INVALID;
				}

			} else if (res2 < 0) {
				result = SS_UNKNOWN;
				errmsg = "encountered error during full signature field validation";
			} else {
				result = SS_INVALID;
			}

		} else if (res < 0) {
			result = SS_UNKNOWN;
			errmsg = "encountered error during crypto signature field validation";
		} else {
			result = SS_INVALID;
		}

		_free_ed25519_key_chain(org_keys);

		if(result >= SS_CRYPTO && (res = sgnt_fid_exists(signet, SIGNET_USER_COC_SIG))) {

			if(res < 0) {
				RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "error while checking existence of coc signature");
			}

			if(!previous || sgnt_type_get(previous) != SIGNET_TYPE_USER) {
				return SS_BROKEN_COC;
			} else {

				if(!(prev_key = sgnt_fetch_signkey(previous))) {
					RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "error while retrieving previous signet public signing key");
				}

				res = sgnt_validate_sig_field_key(signet, SIGNET_USER_COC_SIG, prev_key); 
				free(prev_key);

				if(res < 0) {
					RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "encountered error during chain of custody signature field validation");
				} else if(!res) {
					return SS_BROKEN_COC;
				}
			}
		} else if(!res && previous) {
			return SS_BROKEN_COC;
		}

	} else {
		RET_ERROR_CUST(SS_UNKNOWN, ERR_UNSPEC, "invalid signet type");
	}

	if(result == SS_UNKNOWN) {
		RET_ERROR_CUST(result, ERR_UNSPEC, errmsg);
	}

	return result;
}


/**
 * @brief	Verifies a specified signet signature using the key passed to the function. Assumes that both key and signature are ed25519.
 * @param	signet	Pointer to the target signet.
 * @param	sig_fid	The field id of the field which contains the signature intended for verification.
 * @param	key	Array containing the public ed25519 signing key used to verify the signature.
 * @return	1 if signature verification was successful, 0 if verification failed. -1 if error occurred.
*/
static int sgnt_validate_sig_field(const signet_t *signet, unsigned char sig_fid, const unsigned char *key) {

	int res;
	ED25519_KEY *pub_key;

	if(!signet || !key) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(!(pub_key = _deserialize_ed25519_pubkey(key))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not deserialize user signing key");
	}

	res = sgnt_validate_sig_field_key(signet, sig_fid, pub_key);
	_free_ed25519_key(pub_key);

	if(res < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "error verifying signet signature field");
	}

	return res;
}


/**
 * @brief	Verifies a specified signet signature using the ed25519 key structure passed to the function.
 * @param	signet	Pointer to the target signet.
 * @param	sig_fid	The field id of the field which contains the signature intended for verification.
 * @param	key	Array containing the public ed25519 signing key used to verify the signature.
 * @return	1 if signature verification was successful, 0 if verification failed. -1 if error occurred.
*/
static int sgnt_validate_sig_field_key(const signet_t *signet, unsigned char sig_fid, ED25519_KEY *key) {

	int res;
	size_t data_size, signet_size;
	unsigned char *sig, *data;
	ed25519_signature ed_sig;

	if(!signet || !key) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(!(data = sgnt_serial_from_upto_fid(signet, sig_fid - 1, &data_size))) {
		RET_ERROR_INT(ERR_UNSPEC, "could not get signet fields for signature operation");
	}

	if(!(sig = sgnt_fetch_fid_num(signet, sig_fid, 1, &signet_size))) {
		free(data);
		RET_ERROR_INT(ERR_UNSPEC, "could not retrieve user signet signature field");
	}

	memcpy(&(ed_sig[0]), sig, signet_size);

	res = _ed25519_verify_sig(data, data_size, key, sig);
	free(data);
	free(sig);

	if(res < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "error encountered in signet signature verification");
	}

	return res;
}


/**
 * @brief	Uses a signet's signing keys to verify a signature.
 * @param	signet	Pointer to the signet.
 * @param	sig	ed25519 signature buffer to be verified.
 * @param	buf	Data buffer over which the signature was taken.
 * @param	buf_len	Length of data buffer.
 * @return	1 on successful verification, 0 if the signature was invalid, -1 if an error occurred.
*/
static int sgnt_verify_message_sig(const signet_t *signet, ed25519_signature sig, const unsigned char *buf, size_t buf_len) {

	int res, result = 0;
	ED25519_KEY **keys = NULL;
	ED25519_KEY *key = NULL;
	signet_type_t sigtype;

	if(!signet || !sig || !buf || !buf_len) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if ((sigtype = sgnt_type_get(signet)) == SIGNET_TYPE_SSR) {
		RET_ERROR_INT(ERR_UNSPEC, "SSR cannot be used for user message signature verification");
	} else if (sigtype == SIGNET_TYPE_USER) {

		if(!(key = sgnt_fetch_signkey(signet))) {
			RET_ERROR_INT(ERR_UNSPEC, "error retrieving signing key from signet");
		}

		res = _ed25519_verify_sig(buf, buf_len, key, sig);
		_free_ed25519_key(key);

		if(res < 0) {
			RET_ERROR_INT(ERR_UNSPEC, "error occurred while verifying signature");
		}

		return res;
	} else if (sigtype != SIGNET_TYPE_ORG) {
		RET_ERROR_INT(ERR_UNSPEC, "invalid signet type");
	}

	if(!(keys = sgnt_fetch_msg_signkeys(signet))) {
		RET_ERROR_INT(ERR_UNSPEC, "error retrieving msg signing keys from signet");
	}

	for(size_t i = 0; keys[i]; ++i) {

		if((res = _ed25519_verify_sig(buf, buf_len, keys[i], sig)) < 0) {
			PUSH_ERROR(ERR_UNSPEC, "error occurred during signature verification");
			result = -1;
			break;
		}

		if(res) {
			result = 1;
			break;
		}
	}

	_free_ed25519_key_chain(keys);

	if (result < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "error occurred while verifying signature");
	}

	return result;
}


/* Signet Builder Sign */

/**
 * @brief	Checks for the presence of all required fields that come before the FULL signature and signs the entire target signet using the specified key.
 * @param	signet	Pointer to the target signet_t structure.
 * @param	key	Specified ed25519 key used for signing.
 * @return	0 on success, -1 on failure.
*/
static int sgnt_sign_id_sig(signet_t *signet, ED25519_KEY *key) {

	unsigned char fid;

	if(!signet || !key) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	switch(sgnt_type_get(signet)) {

	case SIGNET_TYPE_ORG:
		fid = SIGNET_ORG_ID_SIG;
		break;
	case SIGNET_TYPE_USER:
		fid = SIGNET_USER_ID_SIG;
		break;
	default:
		RET_ERROR_INT(ERR_UNSPEC, "unsupported signet type");
		break;

	}

	if((sgnt_sign_field(signet, fid, key)) < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "could not take full signet signature");
	}

	return 0;
}


/**
 * @brief	Checks for the presence of all required fields that come before the CORE signature and signs all the fields that come before the CORE signature field
 * @param	signet	Pointer to the target signet_t structure.
 * @param	key	Specified ed25519 key used for signing.
 * @return	0 on success, -1 on failure.
*/
static int sgnt_sign_full_sig(signet_t *signet, ED25519_KEY *key) {

	unsigned char fid;

	if(!signet || !key) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	switch(sgnt_type_get(signet)) {

	case SIGNET_TYPE_ORG:
		fid = SIGNET_ORG_FULL_SIG;
		break;
	case SIGNET_TYPE_USER:
		fid = SIGNET_USER_FULL_SIG;
		break;
	default:
		RET_ERROR_INT(ERR_UNSPEC, "unsupported signet type");
		break;

	}

	if((sgnt_sign_field(signet, fid, key)) < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "could not sign signet");
	}

	return 0;
}


/**
 * @brief	Signs an incomplete user signet with the INITIAL signature after checking for the presence of all previous required fields.
 * @param	signet	Pointer to the target signet_t structure.
 * @param	key	Specified ed25519 key used for signing.
 * @return	0 on success, -1 on failure.
*/
static int sgnt_sign_crypto_sig(signet_t *signet, ED25519_KEY *key) {

	signet_type_t type;
	unsigned char fid;

	if(!signet || !key) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	switch(type = sgnt_type_get(signet)) {

	case SIGNET_TYPE_ORG:
		fid = SIGNET_ORG_CRYPTO_SIG;
		break;
	case SIGNET_TYPE_SSR:
		fid = SIGNET_USER_CRYPTO_SIG;

		if(sgnt_type_set(signet, SIGNET_TYPE_USER) < 0) {
			RET_ERROR_INT(ERR_UNSPEC, "could not change signet type to user from ssr");
		}

		break;
	default:
		RET_ERROR_INT(ERR_UNSPEC, "invalid signet type for crypto signature");

	}

	if((sgnt_sign_field(signet, fid, key)) < 0) {

		if(sgnt_type_set(signet, SIGNET_TYPE_SSR) < 0) {
			RET_ERROR_INT(ERR_UNSPEC, "could not change signet type from user back to ssr after signing failed");
		}

		RET_ERROR_INT(ERR_UNSPEC, "error encountered in signet signing operation");
	}

	return 0;
}


/**
 * @brief	Checks for the presence of all required fields that come before the SSR signature field and adds the SSR signature.
 * @param	signet	Pointer to the target signet_t structure.
 * @param	key	Specified ed25519 key used for signing.
 * @return	0 on success, -1 on failure.
*/
static int sgnt_sign_ssr_sig(signet_t *signet, ED25519_KEY *key) {

	if(!signet || !key) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(sgnt_type_get(signet) != SIGNET_TYPE_SSR) {
		RET_ERROR_INT(ERR_UNSPEC, "invalid signet type");
	}

	if((sgnt_sign_field(signet, SIGNET_SSR_SSR_SIG, key)) < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "error encountered in signet signing operation");
	}

	return 0;
}


/**
 * @brief	Checks for the presence of all required fields that come before the chain of custody signature field and adds the SSR signature.
 * @param	signet	Pointer to the target signet_t structure.
 * @param	key	Specified ed25519 key used for signing.
 * @return	0 on success, -1 on failure.
*/
static int sgnt_sign_coc_sig(signet_t *signet, ED25519_KEY *key) {

	if(!signet || !key) {
		RET_ERROR_INT(ERR_BAD_PARAM, NULL);
	}

	if(sgnt_type_get(signet) != SIGNET_TYPE_SSR) {
		RET_ERROR_INT(ERR_UNSPEC, "invalid signet type");
	}

	if((sgnt_sign_field(signet, SIGNET_SSR_COC_SIG, key)) < 0) {
		RET_ERROR_INT(ERR_UNSPEC, "error encountered in signet signing operation");
	}

	return 0;
}


/* PUBLIC FUNCTIONS */


int dime_sgnt_create_defined_field(signet_t *signet, unsigned char fid, size_t data_size, const unsigned char *data) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_create_defined_field, signet, fid, data_size, data);
}

signet_t *dime_sgnt_create_signet(signet_type_t type) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_create_signet, type);
}

signet_t *dime_sgnt_create_signet_w_keys(signet_type_t type, const char *keysfile) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_create_signet_w_keys, type, keysfile);
}

int dime_sgnt_create_sok(signet_t *signet, ED25519_KEY *key, unsigned char format, unsigned char perm) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_create_sok, signet, key, format, perm);
}

int dime_sgnt_create_undefined_field(signet_t *signet, size_t name_size, const unsigned char *name, size_t data_size, const unsigned char *data) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_create_undefined_field, signet, name_size, name, data_size, data);
}

void dime_sgnt_destroy_signet(signet_t *signet) {
	PUBLIC_FUNCTION_IMPLEMENT_VOID(sgnt_destroy_signet, signet);
}

void dime_sgnt_dump_signet(FILE *fp, signet_t *signet) {
	PUBLIC_FUNCTION_IMPLEMENT_VOID(sgnt_dump_signet, fp, signet);
}

EC_KEY *dime_sgnt_fetch_enckey(const signet_t *signet) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_fetch_enckey, signet);
}

unsigned char *dime_sgnt_fetch_fid_num(const signet_t *signet, unsigned char fid, unsigned int num, size_t *data_size) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_fetch_fid_num, signet, fid, num, data_size);
}

ED25519_KEY **dime_sgnt_fetch_msg_signkeys(const signet_t *signet) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_fetch_msg_signkeys, signet);
}

ED25519_KEY *dime_sgnt_fetch_signkey(const signet_t *signet) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_fetch_signkey, signet);
}

ED25519_KEY **dime_sgnt_fetch_signet_signkeys(const signet_t *signet) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_fetch_signet_signkeys, signet);
}

ED25519_KEY **          dime_sgnt_fetch_software_signkeys(const signet_t *signet) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_fetch_software_signkeys, signet);
}

ED25519_KEY *dime_sgnt_fetch_sok_num(const signet_t *signet, unsigned int num) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_fetch_sok_num, signet, num);
}

ED25519_KEY **          dime_sgnt_fetch_tls_signkeys(const signet_t *signet) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_fetch_tls_signkeys, signet);
}

unsigned char *dime_sgnt_fetch_undefined_field(const signet_t *signet, size_t name_size, const unsigned char *name, size_t *data_size) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_fetch_undefined_field, signet, name_size, name, data_size);
}

signet_t *dime_sgnt_file_to_signet(const char *filename) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_file_to_signet, filename);
}

int dime_sgnt_file_create(signet_t *signet, const char *filename) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_file_create, signet, filename);
}

int dime_sgnt_fid_exists(const signet_t *signet, unsigned char fid) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_fid_exists, signet, fid);
}

int dime_sgnt_fid_get_count(const signet_t *signet, unsigned char fid) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_fid_get_count, signet, fid);
}

char *dime_sgnt_fingerprint_crypto(const signet_t *signet) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_fingerprint_crypto, signet);
}

char *dime_sgnt_fingerprint_full(const signet_t *signet) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_fingerprint_full, signet);
}

char *dime_sgnt_fingerprint_id(const signet_t *signet) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_fingerprint_id, signet);
}

char *dime_sgnt_fingerprint_ssr(const signet_t *signet) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_fingerprint_ssr, signet);
}

int dime_sgnt_remove_fid_num(signet_t *signet, unsigned char fid, int num) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_remove_fid_num, signet, fid, num);
}

int dime_sgnt_remove_undefined_field(signet_t *signet, size_t name_size, const unsigned char *name) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_remove_undefined_field, signet, name_size, name);
}

signet_t *dime_sgnt_serial_b64_to_signet(const char *b64_in) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_serial_b64_to_signet, b64_in);
}

char *dime_sgnt_serial_signet_to_b64(signet_t *signet) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_serial_signet_to_b64, signet);
}

signet_t *dime_sgnt_serial_to_signet(const unsigned char *in, size_t len) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_serial_to_signet, in, len);
}

unsigned char *dime_sgnt_serial_from_signet(signet_t *signet, uint32_t *serial_size) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_serial_from_signet, signet, serial_size);
}

int dime_sgnt_set_defined_field(signet_t *signet, unsigned char fid, size_t data_size, const unsigned char *data) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_set_defined_field, signet, fid, data_size, data);
}

int dime_sgnt_set_id_field(signet_t *signet, size_t id_size, const unsigned char *id) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_set_id_field, signet, id_size, id);
}

int dime_sgnt_sign_coc_sig(signet_t *signet, ED25519_KEY *key) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_sign_coc_sig, signet, key);
}

int dime_sgnt_sign_crypto_sig(signet_t *signet, ED25519_KEY *key) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_sign_crypto_sig, signet, key);
}

int dime_sgnt_sign_full_sig(signet_t *signet, ED25519_KEY *key) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_sign_full_sig, signet, key);
}

int dime_sgnt_sign_id_sig(signet_t *signet, ED25519_KEY *key) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_sign_id_sig, signet, key);
}

int dime_sgnt_sign_ssr_sig(signet_t *signet, ED25519_KEY *key) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_sign_ssr_sig, signet, key);
}

signet_t *dime_sgnt_split_crypto(const signet_t *signet) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_split_crypto, signet);
}

signet_t *dime_sgnt_split_full(const signet_t *signet) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_split_full, signet);
}

signet_type_t dime_sgnt_type_get(const signet_t *signet) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_type_get, signet);
}

int dime_sgnt_type_set(signet_t *signet, signet_type_t type) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_type_set, signet, type);
}

signet_state_t dime_sgnt_validate_all(const signet_t *signet, const signet_t *previous, const signet_t *orgsig, const unsigned char **dime_pok) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_validate_all, signet, previous, orgsig, dime_pok);
}

int dime_sgnt_verify_message_sig(const signet_t *signet, ed25519_signature sig, const unsigned char *buf, size_t buf_len) {
	PUBLIC_FUNCTION_IMPLEMENT(sgnt_verify_message_sig, signet, sig, buf, buf_len);
}

