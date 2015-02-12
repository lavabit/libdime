/*
 * signet.h
 *
 *  Created on: Sep 11, 2014
 *      Author: iv
*/

#ifndef SIGNET_H
#define SIGNET_H

#include "signet/keys.h"


/*PUBLIC FUNCTIONS*/

/* Create a new signet and keysfile */
PUBLIC_FUNC_DECL(signet_t *, 	   signet_new_keysfile,		signet_type_t type, 	 char *keysfile);	

/* Loading signet from and saving to file */
PUBLIC_FUNC_DECL(signet_t *,	   signet_from_file,		const char *filename);
PUBLIC_FUNC_DECL(int,		   signet_to_file,		signet_t *signet, 	 const char *filename);

/* Initializing and destroying signet*/
PUBLIC_FUNC_DECL(signet_t *, 	   signet_deserialize,		const unsigned char *in, size_t len);
PUBLIC_FUNC_DECL(signet_t *, 	   signet_deserialize_b64,	const char *b64_in);

PUBLIC_FUNC_DECL(void, 	       	   signet_destroy,		signet_t* signet);						

/* Serializing signet into binary and b64 */
PUBLIC_FUNC_DECL(unsigned char *,  signet_serialize,		signet_t *signet, 	 uint32_t *serial_size);			
PUBLIC_FUNC_DECL(char *, 	   signet_serialize_b64,	signet_t *signet);				

/* Dumps signet into the file descriptor */
PUBLIC_FUNC_DECL(void, 		   signet_dump,			FILE *fp, 		 signet_t* signet);

/* Signet state retrieval */
PUBLIC_FUNC_DECL(int, 		   signet_get_count_fid,	const signet_t *signet, unsigned char fid);
PUBLIC_FUNC_DECL(int,		   signet_fid_exists,		const signet_t *signet, unsigned char fid);
PUBLIC_FUNC_DECL(signet_state_t,   signet_get_state,		const signet_t *signet);
PUBLIC_FUNC_DECL(signet_type_t,	   signet_get_type,		const signet_t *signet);

/* Retrieving field data */
PUBLIC_FUNC_DECL(unsigned char *,  signet_fetch_fid_num,	const signet_t *signet, unsigned char fid, 	unsigned int num,          size_t *data_size);
PUBLIC_FUNC_DECL(unsigned char *,  signet_fetch_undef_name,	const signet_t *signet, size_t name_len,        const unsigned char *name, size_t *data_size);
PUBLIC_FUNC_DECL(ED25519_KEY *,	   signet_get_signkey,		const signet_t *signet);
PUBLIC_FUNC_DECL(unsigned char **, signet_get_msg_sign_keys,	const signet_t *signet);
PUBLIC_FUNC_DECL(unsigned char **, signet_get_signet_sign_keys,	const signet_t *signet);

/* Modifying the signet */
PUBLIC_FUNC_DECL(int,	     	   signet_add_field,		signet_t *signet, 	  unsigned char fid, 	size_t name_size, const unsigned char *name, size_t data_size, const unsigned char *data, unsigned char flags);
PUBLIC_FUNC_DECL(int,		   signet_add_field_string,	signet_t *signet,	  unsigned char fid, 	const char *name, const char *data, 	     unsigned char flags);
PUBLIC_FUNC_DECL(int,		   signet_remove_fid_num,	signet_t *signet, 	  unsigned char fid,  	int num);
PUBLIC_FUNC_DECL(int,		   signet_remove_undef_name,	signet_t *signet, 	  size_t name_len,      const unsigned char *name);
PUBLIC_FUNC_DECL(int,		   signet_set_field,		signet_t *signet, 	  unsigned char fid, 	const char *name, const char *data, unsigned char flags);
PUBLIC_FUNC_DECL(int,		   signet_set_id,		signet_t *signet,	  const char *id);
PUBLIC_FUNC_DECL(int,		   signet_set_type, 		signet_t *signet,	  signet_type_t type);

/* Signet Splits */
PUBLIC_FUNC_DECL(signet_t *,	   signet_core_split,		const signet_t *signet);
PUBLIC_FUNC_DECL(signet_t *,	   signet_user_split,		const signet_t *signet);

/* Signet Fingerprints */
PUBLIC_FUNC_DECL(char *, 	   signet_full_fingerprint,	const signet_t *signet);
PUBLIC_FUNC_DECL(char *, 	   signet_core_fingerprint,	const signet_t *signet);

PUBLIC_FUNC_DECL(char *, 	   signet_user_fingerprint,	const signet_t *signet);

PUBLIC_FUNC_DECL(char *, 	   signet_ssr_fingerprint,	const signet_t *signet);

/* Signet verification */
PUBLIC_FUNC_DECL(signet_state_t,   signet_full_verify,		const signet_t *signet, const signet_t *orgsig, const unsigned char ** dime_pok);
PUBLIC_FUNC_DECL(int,		   signet_verify_signature,	const signet_t *signet, unsigned char sig_fid,  const unsigned char *key);
PUBLIC_FUNC_DECL(int,		   signet_verify_signature_key, const signet_t *signet, unsigned char sig_fid,  ED25519_KEY *key);
PUBLIC_FUNC_DECL(int,		   signet_verify_message_sig,	const signet_t *signet, ed25519_signature sig,  const unsigned char *buf, size_t buf_len);

/* Signet sign */
PUBLIC_FUNC_DECL(int,		   signet_sign_full_sig,	signet_t *signet, 	ED25519_KEY *key);
PUBLIC_FUNC_DECL(int,		   signet_sign_core_sig,	signet_t *signet, 	ED25519_KEY *key);

PUBLIC_FUNC_DECL(int,		   signet_sign_initial_sig,	signet_t *signet, 	ED25519_KEY *key);
PUBLIC_FUNC_DECL(int,		   signet_sign_ssr_sig,		signet_t *signet, 	ED25519_KEY *key);
PUBLIC_FUNC_DECL(int,		   signet_sign_coc_sig,		signet_t *signet,	ED25519_KEY *key);


/* ---------------------------------------------------------------------------------------------------------------------- */
/*PRIVATE METHODS*/

/* signet creation related functions */
signet_t * 		_signet_create(signet_type_t type);

int			_signet_check_length(const unsigned char *in, uint32_t slen);
int			_signet_parse_fields(signet_t* signet);

/* signet state and size retrieval */
int	 		_signet_fid_size(const signet_t *signet, unsigned char fid);
int			_signet_get_serial_size(const signet_t *signet);
int 			_signet_pok_compare(const signet_t *signet, const unsigned char ** dime_pok);
int			_signet_upto_fid_check_required(const signet_t *signet, signet_field_key_t *keys, unsigned char fid);
int			_signet_verify_signature_multikey(const signet_t *signet, unsigned char sig_fid, const unsigned char ** keys);
char *			_signet_upto_fid_fingerprint(const signet_t *signet, unsigned char fid);

/* signet_field_t creators, destructors and related functions*/
signet_field_t *	_signet_fid_create(const signet_t *signet, unsigned char fid);
signet_field_t *	_signet_field_create(const signet_t *signet, uint32_t offset, signet_field_key_t *key);

void 			_signet_fid_destroy(signet_field_t *field);
signet_field_t *	_signet_field_destroy(signet_field_t *field);

int			_signet_field_dump(FILE *fp, const signet_field_t *field);
int 			_signet_field_size(const signet_field_t *field);

/* signet data and field data retrieval functions */
int			_signet_fid_dump(FILE *fp, const signet_t *signet, unsigned int fid);
unsigned char *		_signet_fid_get(const signet_t *signet, unsigned char fid, size_t *out_len);
unsigned char * 	_signet_upto_fid_serialize(const signet_t* signet, unsigned char fid, size_t *data_size);

/* signet content modification and related functions */
int			_signet_remove_field_at(signet_t *signet, unsigned int offset, size_t field_size);
int			_signet_sign_fid(signet_t *signet, unsigned char signet_fid, ED25519_KEY *key);

/* cache callback functions */
void *			_deserialize_signet_cb(void *data, size_t len);
void * 			_serialize_signet_cb(void *record, size_t *outlen);
void 			_destroy_signet_cb(void *record);
void 			_dump_signet_cb(FILE *fp, void *record, int brief);
/* ------------------------------------------------------------------------------------------------------------------------ */
#endif
