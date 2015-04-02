#include "dmessage/dmime.h"





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
	char *authrecp, *authrecp_signet, *destorig, *destorig_fp, *end1 = ">\r\n", *end2 = "]\r\n";
	int at = 0;
	unsigned char *start;
	size_t string_size = 0;

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
char * _dmsg_actor_to_string(dmime_actor_t actor) {

	switch(actor) {

		case id_author:
			return "Author";
			break;
		case id_origin:
			return "Origin";
			break;
		case id_destination:
			return "Destination";
			break;
		case id_recipient:
			return "Recipient";
			break;
		default:
			return "Invalid dmime actor";
			break;

	}

}


/*
 * @brief	Returns a string from dmime_object_state_t.
 * @param	state		Object state value.
 * @return	String containing human readable dmime object state.
*/
char * _dmsg_object_state_to_string(dmime_object_state_t state) {

	switch(state) {

		case DMIME_OBJECT_STATE_NONE:
			return "None";
			break;
		case DMIME_OBJECT_STATE_CREATION:
			return "Creation";
			break;
		case DMIME_OBJECT_STATE_LOADED_ENVELOPE:
			return "Loaded Envelope";
			break;
		case DMIME_OBJECT_STATE_LOADED_SIGNETS:
			return "Loaded Signets";
			break;
		case DMIME_OBJECT_STATE_INCOMPLETE_ENVELOPE:
			return "Incomplete Envelope";
			break;
		case DMIME_OBJECT_STATE_INCOMPLETE_METADATA:
			return "Incomplete Metadata";
			break;
		case DMIME_OBJECT_STATE_COMPLETE:
			return "Complete";
			break;
		default:
			return "Unknown";
			break;

	}

}
