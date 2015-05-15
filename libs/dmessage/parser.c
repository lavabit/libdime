#include "dmessage/parser.h"

static void                        prsr_envelope_destroy(dmime_envelope_object_t *obj);
static dmime_envelope_object_t *   prsr_envelope_parse(const unsigned char *in, size_t insize, dmime_chunk_type_t type);
static dmime_common_headers_t *    prsr_headers_create(void);
static void                        prsr_headers_destroy(dmime_common_headers_t *obj);
static unsigned char *             prsr_headers_format(dmime_common_headers_t *obj, size_t *outsize);
static dmime_header_type_t         prsr_headers_get_type(unsigned char *in, size_t insize);
static dmime_common_headers_t *    prsr_headers_parse(unsigned char *in, size_t insize);

/* PRIVATE FUNCTIONS */

/**
 * @brief	Allocates memory for an empty dmime_common_headers_t type.
 * @return	dmime_common_headers_t structure.
 * @free_using{prsr_headers_destroy}
*/
static dmime_common_headers_t *prsr_headers_create(void) {

	dmime_common_headers_t *result;

	if(!(result = malloc(sizeof(dmime_common_headers_t)))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate memory for parsed common headers");
	}

	memset(result, 0, sizeof(dmime_common_headers_t));

	return result;
}


/**
 * @brief	Destroys a dmime_common_headers_t structure.
 * @param	obj		Headers to be destroyed.
 */
static void prsr_headers_destroy(dmime_common_headers_t *obj) {

	if(!obj) {
		return;
	}

	for(unsigned int i = 0; i < DMIME_NUM_COMMON_HEADERS; ++i) {

		if(obj->headers[i]) {
			_secure_wipe(st_data_get(obj->headers[i]), st_length_get(obj->headers[i]));
			st_cleanup(obj->headers[i]);
		}

	}

	free(obj);
}


/**
 * @brief	Formats the dmime_common_headers_t into a single array for the common headers chunk.
 * @param	obj		The headers to be formatted.
 * @param	outsize	Stores the size of the output array.
 * @return	Returns the array of ASCII characters (not terminated by '\0') as pointer to unsigned char.
 * @free_using{free}
 */
static unsigned char *prsr_headers_format(dmime_common_headers_t *obj, size_t *outsize) {

	size_t size = 0, at = 0;
	unsigned char *result;

	if(!obj || !outsize) {
		RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
	}

	for(unsigned int i = 0; i < DMIME_NUM_COMMON_HEADERS; ++i) {

		if(!obj->headers[i] && dmime_header_keys[i].required) {
			RET_ERROR_PTR(ERR_UNSPEC, "a required common header field is missing");
		}

		if(dmime_header_keys[i].label && obj->headers[i]) {
			size += dmime_header_keys[i].label_length + st_length_get(obj->headers[i]) + 2;
		}
	}

	if(!(result = malloc(size))) {
		PUSH_ERROR_SYSCALL("malloc");
		RET_ERROR_PTR(ERR_NOMEM, "could not allocate memory for common headers data");
	}

	memset(result, 0, size);

	for(unsigned int i = 0; i < DMIME_NUM_COMMON_HEADERS; ++i) {

		if(obj->headers[i] && dmime_header_keys[i].label) {
			memcpy(result + at, (unsigned char *)dmime_header_keys[i].label, dmime_header_keys[i].label_length);
			at += dmime_header_keys[i].label_length;
			memcpy(result + at, st_data_get(obj->headers[i]), st_length_get(obj->headers[i]));
			at += st_length_get(obj->headers[i]);
			result[at++] = (unsigned char)'\r';
			result[at++] = (unsigned char)'\n';
		}

	}

	*outsize = size;

	return result;
}


/**
 * @brief	Reads the first bytes of the input array and determines the next header type.
 * @param	in		Input buffer.
 * @param	insize	Size of input buffer.
 * @return	Common header type.
 */
static dmime_header_type_t prsr_headers_get_type(unsigned char *in, size_t insize) {

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

	return HEADER_TYPE_NONE;
}

/**
 * @brief	Parses the passed array of bytes into dmime_common_headers_t.
 * @param	in		Input buffer.
 * @param	insize	Input buffer size.
 * @return	A dmime_common_headers_t array of stringers containing parsed header info.
 * @free_using{prsr_headers_destroy}
 */
static dmime_common_headers_t *prsr_headers_parse(unsigned char *in, size_t insize) {

	dmime_header_type_t type;
	size_t at = 0, head_size;
	dmime_common_headers_t *result;

	if(!in || !insize) {
		RET_ERROR_CUST(0, ERR_BAD_PARAM, NULL);
	}

	if(!(result = prsr_headers_create())) {
		RET_ERROR_CUST(0, ERR_UNSPEC, "error creating a new dmime_common_headers_t object");
	}

	while(at < insize) {

		if((type = prsr_headers_get_type(in + at, insize - at)) == HEADER_TYPE_NONE) {
			prsr_headers_destroy(result);
			RET_ERROR_CUST(0, ERR_UNSPEC, "headers	 buffer contained an invalid header type");
		}

		if(result->headers[type]) {
			prsr_headers_destroy(result);
			RET_ERROR_CUST(0, ERR_UNSPEC, "headers buffer contains duplicate fields");
		}

		at += dmime_header_keys[type].label_length;
		head_size = 0;

		while((at + head_size + 1) < insize && in[at + head_size] != '\r' && in[at + head_size + 1] != '\n') {
			++head_size;
		}

		if((at + head_size + 1) > insize || ((at + head_size + 1) == insize && in[at + head_size + 1] != '\n')) {
			prsr_headers_destroy(result);
			RET_ERROR_CUST(0, ERR_UNSPEC, "invalid header syntax");
		}

		result->headers[type] = st_import(in + at, head_size);
		at += head_size + 2;
	}

	return result;
}


/**
 * @brief	Destroys a dmime_envelop_object_t structure.
 * @param	obj		Pointer to the object to be destroyed.
 */
static void prsr_envelope_destroy(dmime_envelope_object_t *obj) {

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

}



/**
 * @brief	Parses a binary buffer from a dmime message into a dmime origin object.
 * @param	in		Binary origin array.
 * @param	insize		Size of input array.
 * @param	type		Type of the chunk.
 * @return	Pointer to a parsed dmime object or NULL on error.
 * @free_using{prsr_envelope_destroy}
*/
static dmime_envelope_object_t *prsr_envelope_parse(const unsigned char *in, size_t insize, dmime_chunk_type_t type) {

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
		prsr_envelope_destroy(result);
		RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
	}

	at += strlen(authrecp);
	start = (unsigned char *)(in + at);

	while(at < insize && in[at] != '>') {

		if(!isprint(in[at])) {
			prsr_envelope_destroy(result);
			RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
		}

		++at;
	}

	string_size = in + at - start;

	if(!(result->auth_recp = st_import(start, string_size))) {
		prsr_envelope_destroy(result);
		RET_ERROR_PTR(ERR_UNSPEC, "could not import stringer");
	}

	if(in + at != (unsigned char *)strstr((char *)in + at, end1)) {
		prsr_envelope_destroy(result);
		RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
	}

	at += strlen(end1);

	if(insize - at <= strlen(authrecp_signet) || in + at != (unsigned char *)strstr((char *)in, authrecp_signet)) {
		prsr_envelope_destroy(result);
		RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
	}

	at += strlen(authrecp_signet);
	start = (unsigned char *)(in + at);

	while(at < insize && in[at] != ']') {

		if(!isprint(in[at])) {
			prsr_envelope_destroy(result);
			RET_ERROR_PTR(ERR_UNSPEC, "invalid envelope origin buffer passed to parser");
		}

		++at;
	}

	string_size = in + at - start;

	if(!(result->auth_recp_signet = st_import(start, string_size))) {
		prsr_envelope_destroy(result);
		RET_ERROR_PTR(ERR_UNSPEC, "could not import stringer");
	}

	if(in + at != (unsigned char *)strstr((char *)in + at, end2)) {
		prsr_envelope_destroy(result);
		RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
	}

	at += strlen(end2);

	if(insize - at <= strlen(destorig) || in + at != (unsigned char *)strstr((char *)in, destorig)) {
		prsr_envelope_destroy(result);
		RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
	}

	at += strlen(destorig);
	start = (unsigned char *)(in + at);

	while(at < insize && in[at] != '>') {

		if(!isprint(in[at])) {
			prsr_envelope_destroy(result);
			RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
		}

		++at;
	}

	string_size = in + at - start;

	if(!(result->dest_orig = st_import(start, string_size))) {
		prsr_envelope_destroy(result);
		RET_ERROR_PTR(ERR_UNSPEC, "could not import stringer");
	}

	if(in + at != (unsigned char *)strstr((char *)in + at, end1)) {
		prsr_envelope_destroy(result);
		RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
	}

	at += strlen(end1);

	if(insize - at <= strlen(destorig_fp) || in + at != (unsigned char *)strstr((char *)in, destorig_fp)) {
		prsr_envelope_destroy(result);
		RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
	}

	at += strlen(destorig_fp);
	start = (unsigned char *)(in + at);

	while(at < insize && in[at] != ']') {

		if(!isprint(in[at])) {
			prsr_envelope_destroy(result);
			RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
		}

		++at;
	}

	string_size = in + at - start;

	if(!(result->dest_orig_fingerprint = st_import(start, string_size))) {
		prsr_envelope_destroy(result);
		RET_ERROR_PTR(ERR_UNSPEC, "could not import stringer");
	}

	if(in + at != (unsigned char *)strstr((char *)in + at, end2)) {
		prsr_envelope_destroy(result);
		RET_ERROR_PTR(ERR_UNSPEC, "invalid input buffer passed to envelope parser");
	}

	return result;
}


dmime_header_key_t dmime_header_keys[DMIME_NUM_COMMON_HEADERS] = {
	{1, "Date: ", 6},
	{1, "To: ", 4},
	{0, "CC: ", 4},
	{1, "From: ", 6},
	{0, "Organization: ", 14},
	{1, "Subject: ", 9},
	{0, NULL, 0}
};


/* PUBLIC FUNCTIONS */

void                        dime_prsr_envelope_destroy(dmime_envelope_object_t *obj) {
	PUBLIC_FUNCTION_IMPLEMENT_VOID(prsr_envelope_destroy, obj);
}

dmime_envelope_object_t *   dime_prsr_envelope_parse(const unsigned char *in, size_t insize, dmime_chunk_type_t type) {
	PUBLIC_FUNCTION_IMPLEMENT(prsr_envelope_parse, in, insize, type);
}

dmime_common_headers_t *    dime_prsr_headers_create(void) {
	PUBLIC_FUNCTION_IMPLEMENT(prsr_headers_create);
}

void                        dime_prsr_headers_destroy(dmime_common_headers_t *obj) {
	PUBLIC_FUNCTION_IMPLEMENT_VOID(prsr_headers_destroy, obj);
}

unsigned char *             dime_prsr_headers_format(dmime_common_headers_t *obj, size_t *outsize) {
	PUBLIC_FUNCTION_IMPLEMENT(prsr_headers_format, obj, outsize);
}

dmime_common_headers_t *    dime_prsr_headers_parse(unsigned char *in, size_t insize) {
	PUBLIC_FUNCTION_IMPLEMENT(prsr_headers_parse, in, insize);
}
