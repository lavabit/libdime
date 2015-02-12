#include "signet/keys.h"

int keys_to_file(keys_type_t type, ED25519_KEY *sign_key, EC_KEY *enc_key, const char *filename) {
	PUBLIC_FUNC_IMPL(keys_to_file, type, sign_key, enc_key, filename);
}

/*int keys_add_sok_to_file(ED25519_KEY *sok, const char *filename) {
	PUBLIC_FUNC_IMPL(keys_add_sok_to_file, sok, filename);
}*/

unsigned char * keys_get_binary(const char *filename, size_t *len) {
	PUBLIC_FUNC_IMPL(keys_get_binary, filename, len);
}

keys_type_t keys_get_type(const unsigned char *bin_keys, size_t len) {
	PUBLIC_FUNC_IMPL(keys_get_type,	bin_keys, len);
}

ED25519_KEY * keys_fetch_sign_key(const unsigned char *bin_keys, size_t len) {
	PUBLIC_FUNC_IMPL(keys_fetch_sign_key,  bin_keys, len);
}

ED25519_KEY * keys_file_fetch_sign_key(const char *filename) {
	PUBLIC_FUNC_IMPL(keys_file_fetch_sign_key, filename);
}

EC_KEY * keys_fetch_enc_key(const unsigned char *bin_keys, size_t len) {
	PUBLIC_FUNC_IMPL(keys_fetch_enc_key, bin_keys, len);
}

EC_KEY * keys_file_fetch_enc_key(const char *filename) {
	PUBLIC_FUNC_IMPL(keys_file_fetch_enc_key, filename);
}
