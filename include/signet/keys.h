#ifndef KEYS_H
#define KEYS_H

#include <signet/general.h>

/* PUBLIC FUNCTIONS */

PUBLIC_FUNC_DECL(int,		  keys_to_file,	        keys_type_t,	 	       ED25519_KEY *sign_key, EC_KEY *enc_key, const char *filename);

PUBLIC_FUNC_DECL(int, 		  keys_add_sok_to_file, ED25519_KEY *sok, 	       const char *filename);

PUBLIC_FUNC_DECL(unsigned char *, keys_get_binary,	const char *filename, 	       size_t *len);

PUBLIC_FUNC_DECL(keys_type_t,	  keys_get_type,	const unsigned char *bin_keys, size_t len);

PUBLIC_FUNC_DECL(ED25519_KEY *,   keys_fetch_sign_key,  const unsigned char *bin_keys, size_t len);

PUBLIC_FUNC_DECL(ED25519_KEY *,   keys_file_fetch_sign_key,  const char *filename);

PUBLIC_FUNC_DECL(EC_KEY *,	  keys_fetch_enc_key,   const unsigned char *bin_keys, size_t len);

PUBLIC_FUNC_DECL(EC_KEY *,	  keys_file_fetch_enc_key,   const char *filename);


/* PRIVATE FUNCTIONS */

int	_keys_check_length(const unsigned char * in, size_t in_len);
#endif
