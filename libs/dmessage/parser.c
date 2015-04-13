#include "dmessage/dmime.h"
#include "dmessage/dmsg.h"

/*
 * @brief	Destroys a dmime_common_headers_t structure.
 * @param	obj		Headers to be destroyed.
 * @return	void.
 */
void _dmsg_destroy_common_headers(dmime_common_headers_t obj) {

	if(!obj) {
		return;
	}

	for(unsigned int i = 0; i < 6; ++i) {

		if(obj[i]) {
			_secure_wipe(st_data_get(obj[i]), st_length_get(obj[i]));
			st_cleanup(obj[i]);
		}

	}

	free(obj);
}


/*
 * @brief	Formats the dmime_common_headers_t into a single array for the common headers chunk.
 * @param	obj		The headers to be formatted.
 * @param	outsize	Stores the size of the output array.
 * @return	Returns the array of ASCII characters (not terminated by '\0') as pointer to unsigned char.
 */
unsigned char * _dmsg_format_common_headers(dmime_common_headers_t obj, size_t *outsize) {

	size_t size = 0, at = 0;
	unsigned char *result;

	if(!obj || !outsize) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	for(unsigned int i = 0; i < 6; ++i) {

		if(!obj[i] && dmime_header_keys[i+1].required) {
			RET_ERROR_PTR(ERR_UNSPEC, "a required common header field is missing");
		}

		size += dmime_header_keys[i+1].label_length + st_length_get(obj[i]) + 2;
	}

	if(!(result = malloc(size))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate memory for common headers data");
	}

	memset(result, 0, size);

	for(unsigned int i = 0; i < 6; ++i) {

		if(obj[i]) {
			memcpy(result+at, (unsigned char *)dmime_header_keys[i+1].label, dmime_header_keys[i+1].label_length);
			at += dmime_header_keys[i+1].label_length;
			memcpy(result+at, st_data_get(obj[i]), st_length_get(obj[i]));
			at += st_length_get(obj[i]);
			result[at++] = (unsigned char)'\r';
			result[at++] = (unsigned char)'\n';
		}

	}

	*outsize = size;

	return result;
}


/*
 * @brief	Reads the first bytes of the input array and determines the next header type.
 * @param	in		Input buffer.
 * @param	insize	Size of input buffer.
 * @return	Common header type.
 */
dmime_header_type_t _dmsg_parse_next_header(unsigned char *in, size_t insize) {

	if(!in || !insize) {
		RET_ERROR_CUST(HEADER_TYPE_NONE, ERR_BAD_PARAM, NULL);
	}

	if(insize < dmime_header_keys[HEADER_TYPE_TO].label_length) {
		RET_ERROR_CUST(HEADER_TYPE_NONE, ERR_UNSPEC, "invalid header syntax");
	}

	if(!memcmp(in, (unsigned char *)dmime_header_keys[HEADER_TYPE_TO].label, dmime_header_keys[HEADER_TYPE_TO].label_length)) {
		return HEADER_TYPE_TO;
	}

	if(!memcmp(in, (unsigned char *)dmime_header_keys[HEADER_TYPE_CC].label, dmime_header_keys[HEADER_TYPE_CC].label_length)) {
		return HEADER_TYPE_CC;
	}

	if(insize < dmime_header_keys[HEADER_TYPE_FROM].label_length) {
		RET_ERROR_CUST(HEADER_TYPE_NONE, ERR_UNSPEC, "invalid header syntax");
	}

	if(!memcmp(in, (unsigned char *)dmime_header_keys[HEADER_TYPE_FROM].label, dmime_header_keys[HEADER_TYPE_FROM].label_length)) {
		return HEADER_TYPE_FROM;
	}

	if(!memcmp(in, (unsigned char *)dmime_header_keys[HEADER_TYPE_DATE].label, dmime_header_keys[HEADER_TYPE_DATE].label_length)) {
		return HEADER_TYPE_DATE;
	}

	if(insize < dmime_header_keys[HEADER_TYPE_SUBJECT].label_length) {
		RET_ERROR_CUST(HEADER_TYPE_NONE, ERR_UNSPEC, "invalid header syntax");
	}

	if(!memcmp(in, (unsigned char *)dmime_header_keys[HEADER_TYPE_SUBJECT].label, dmime_header_keys[HEADER_TYPE_SUBJECT].label_length)) {
		return HEADER_TYPE_SUBJECT;
	}

	if(insize < dmime_header_keys[HEADER_TYPE_ORGANIZATION].label_length) {
		RET_ERROR_CUST(HEADER_TYPE_NONE, ERR_UNSPEC, "invalid header syntax");
	}

	if(!memcmp(in, (unsigned char *)dmime_header_keys[HEADER_TYPE_ORGANIZATION].label, dmime_header_keys[HEADER_TYPE_ORGANIZATION].label_length)) {
		return HEADER_TYPE_ORGANIZATION;
	}

	return HEADER_TYPE_ORGANIZATION;
}

/*
 * @brief	Parses the passed array of bytes into dmime_common_headers_t.
 * @param	in		Input buffer.
 * @param	insize	Input buffer size.
 * @return	A dmime_common_headers_t array of stringers containing parsed header info.
 */
dmime_common_headers_t _dmsg_parse_common_headers(unsigned char *in, size_t insize) {

	dmime_header_type_t type;
	size_t at = 0, head_size;
	dmime_common_headers_t result;

	if(!in || !insize) {
		RET_ERROR_CUST(0, ERR_BAD_PARAM, NULL);
	}

	if(!(result = malloc(6 * sizeof(stringer_t *)))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_CUST(0, ERR_NOMEM, "could not allocate memory for parsed common headers");
	}

	memset(result, 0, 6*sizeof(stringer_t *));

	while(at < insize) {

		if(!(type = _dmsg_parse_next_header(in + at, insize - at))) {
			_dmsg_destroy_common_headers(result);
			RET_ERROR_CUST(0, ERR_UNSPEC, "headers buffer contained an invalid header type");
		}

		if(result[type - 1]) {
			_dmsg_destroy_common_headers(result);
			RET_ERROR_CUST(0, ERR_UNSPEC, "headers buffer contains duplicate fields");
		}

		at += dmime_header_keys[type].label_length;
		head_size = 0;

		while((at + head_size + 1) < insize && in[at + head_size] != '\r' && in[at + head_size + 1] != '\n' ) {
			++head_size;
		}

		if((at + head_size + 1) > insize || ((at + head_size + 1) == insize && in[at + head_size + 1] != '\n')) {
			_dmsg_destroy_common_headers(result);
			RET_ERROR_CUST(0, ERR_UNSPEC, "invalid header syntax");
		}

		result[type - 1] = st_import(in+at, head_size);
		at += head_size + 2;
	}

	return result;
}


/*
 * @brief	Destroys a dmime_envelop_object_t structure.
 * @param	obj		Pointer to the object to be destroyed.
 * @return	void.
 */
void _dmsg_destroy_envelope_object(dmime_envelope_object_t *obj) {

	if(!obj) {
		return;
	}

	if(obj->auth_recp) {
		_secure_wipe(st_data_get(obj->auth_recp), st_length_get(obj->auth_recp));
		st_cleanup(obj->auth_recp);
	}

	if(obj->auth_recp_signet) {
		_secure_wipe(st_data_get(obj->auth_recp_signet), st_length_get(obj->auth_recp_signet));
		st_cleanup(obj->auth_recp_signet);
	}

	if(obj->dest_orig) {
		_secure_wipe(st_data_get(obj->dest_orig), st_length_get(obj->dest_orig));
		st_cleanup(obj->dest_orig);
	}

	if(obj->dest_orig_fingerprint) {
		_secure_wipe(st_data_get(obj->dest_orig_fingerprint), st_length_get(obj->dest_orig_fingerprint));
		st_cleanup(obj->dest_orig_fingerprint);
	}

	free(obj);

	return;
}



/*
 * @brief	Parses a binary buffer from a dmime message into a dmime origin object.
 * @param	in		Binary origin array.
 * @param	insize		Size of input array.
 * @param	
 * @return	Pointer to a parsed dmime object or NULL on error.
*/ //TODO Could be shortened with a sub-routine
dmime_envelope_object_t * _dmsg_parse_envelope(const unsigned char *in, size_t insize, dmime_chunk_type_t type) {

	dmime_envelope_object_t *result;
	const char *authrecp, *authrecp_signet, *destorig, *destorig_fp, *end1 = ">\r\n", *end2 = "]\r\n";
	unsigned char *start;
	size_t string_size = 0, at = 0;

	if(!in || !insize) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	switch(type) {

		case CHUNK_TYPE_ORIGIN:
			authrecp = "Author: <";
			authrecp_signet = "Author-Signet: [";
			destorig = "Destination: <";
			destorig_fp = "Destination-Signet-Fingerprint: [";
			break;
		case CHUNK_TYPE_DESTINATION:
			authrecp = "Recipient: <";
			authrecp_signet = "Recipient-Signet: [";
			destorig = "Origin: <";
			destorig_fp = "Origin-Signet-Fingerprint: [";
			break;
		default:
			RET_ERROR_PTR(ERR_UNSPEC, "invalid envelope chunk type specified");
			break;

	}

	if(!(result = malloc(sizeof(dmime_envelope_object_t)))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate memory for origin object");
	}

	memset(result, 0, sizeof(dmime_envelope_object_t));

	if(insize <= strlen(authrecp) || in != (unsigned char *)strstr((char *)in, authrecp)) {
		_dmsg_destroy_envelope_object(result);
		RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
	}

	at += strlen(authrecp);
	start = (unsigned char *)(in + at);

	while(at < insize && in[at] != '>') {

		if(!isprint(in[at])) {
			_dmsg_destroy_envelope_object(result);
			RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
		}

		++at;
	}

	string_size = in + at - start;

	if(!(result->auth_recp = st_import(start, string_size))) {
		_dmsg_destroy_envelope_object(result);
		RET_ERROR_PTR(ERR_UNSPEC, "could not import stringer");
	}

	if(in+at != (unsigned char *)strstr((char *)in+at, end1)) {
		_dmsg_destroy_envelope_object(result);
		RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
	}

	at += strlen(end1);

	if(insize - at <= strlen(authrecp_signet) || in + at != (unsigned char *)strstr((char *)in, authrecp_signet)) {
		_dmsg_destroy_envelope_object(result);
		RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
	}

	at += strlen(authrecp_signet);
	start = (unsigned char *)(in + at);

	while(at < insize && in[at] != ']') {

		if(!isprint(in[at])) {
			_dmsg_destroy_envelope_object(result);
			RET_ERROR_PTR(ERR_UNSPEC, "invalid envelope origin buffer passed to parser");
		}

		++at;
	}

	string_size = in + at - start;

	if(!(result->auth_recp_signet = st_import(start, string_size))) {
		_dmsg_destroy_envelope_object(result);
		RET_ERROR_PTR(ERR_UNSPEC, "could not import stringer");
	}

	if(in+at != (unsigned char *)strstr((char *)in+at, end2)) {
		_dmsg_destroy_envelope_object(result);
		RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
	}

	at += strlen(end2);

	if(insize - at <= strlen(destorig) || in + at != (unsigned char *)strstr((char *)in, destorig)) {
		_dmsg_destroy_envelope_object(result);
		RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
	}

	at += strlen(destorig);
	start = (unsigned char *)(in + at);

	while(at < insize && in[at] != '>') {

		if(!isprint(in[at])) {
			_dmsg_destroy_envelope_object(result);
			RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
		}

		++at;
	}

	string_size = in + at - start;

	if(!(result->dest_orig = st_import(start, string_size))) {
		_dmsg_destroy_envelope_object(result);
		RET_ERROR_PTR(ERR_UNSPEC, "could not import stringer");
	}

	if(in+at != (unsigned char *)strstr((char *)in+at, end1)) {
		_dmsg_destroy_envelope_object(result);
		RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
	}

	at += strlen(end1);

	if(insize - at <= strlen(destorig_fp) || in + at != (unsigned char *)strstr((char *)in, destorig_fp)) {
		_dmsg_destroy_envelope_object(result);
		RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
	}

	at += strlen(destorig_fp);
	start = (unsigned char *)(in + at);

	while(at < insize && in[at] != ']') {

		if(!isprint(in[at])) {
			_dmsg_destroy_envelope_object(result);
			RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
		}

		++at;
	}

	string_size = in + at - start;

	if(!(result->dest_orig_fingerprint = st_import(start, string_size))) {
		_dmsg_destroy_envelope_object(result);
		RET_ERROR_PTR(ERR_UNSPEC, "could not import stringer");
	}

	if(in+at != (unsigned char *)strstr((char *)in + at, end2)) {
		_dmsg_destroy_envelope_object(result);
		RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
	}

	return result;
}


/*
 * @brief	Returns a string from dmime_actor_t.
 * @param	actor		Actor value.
 * @return	String containing human readable actor.
*/
const char * _dmsg_actor_to_string(dmime_actor_t actor) {

	switch(actor) {

		case id_author:
			return "Author";
		case id_origin:
			return "Origin";
		case id_destination:
			return "Destination";
		case id_recipient:
			return "Recipient";
		default:
			return "Invalid dmime actor";

	}

}


/*
 * @brief	Returns a string from dmime_object_state_t.
 * @param	state		Object state value.
 * @return	String containing human readable dmime object state.
*/
const char * _dmsg_object_state_to_string(dmime_object_state_t state) {

	switch(state) {

		case DMIME_OBJECT_STATE_NONE:
			return "None";
		case DMIME_OBJECT_STATE_CREATION:
			return "Creation";
		case DMIME_OBJECT_STATE_LOADED_ENVELOPE:
			return "Loaded Envelope";
		case DMIME_OBJECT_STATE_LOADED_SIGNETS:
			return "Loaded Signets";
		case DMIME_OBJECT_STATE_INCOMPLETE_ENVELOPE:
			return "Incomplete Envelope";
		case DMIME_OBJECT_STATE_INCOMPLETE_METADATA:
			return "Incomplete Metadata";
		case DMIME_OBJECT_STATE_COMPLETE:
			return "Complete";
		default:
			return "Unknown";

	}

}


dmime_header_key_t dmime_header_keys[7] = {
	{0, NULL, 0},
	{1, "Date: ", 6},
	{1, "To: ", 4},
	{0, "CC: ", 4},
	{1, "From: ", 6},
	{0, "Organization: ", 14},
	{1, "Subject: ", 9}
};
