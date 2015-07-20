#include <unistd.h>
#include "signet/keys.h"
#include "checks.h"

START_TEST(check_keys_file_handling)
{

	const char *filename_u = "keys_user.keys", *filename_o = "keys_org.keys", *filename_w = "keys_wrong.keys";
	EC_KEY *enckey, *enckey2;
	ED25519_KEY *signkey, *signkey2;
	int res;
	size_t enc1_size, enc2_size;
	unsigned char *ser_enc1, *ser_enc2;

	_crypto_init();

	enckey = _generate_ec_keypair(0);
	signkey = _generate_ed25519_keypair();

	ser_enc1 = _serialize_ec_privkey(enckey, &enc1_size);

/* testing user keys file */
	res = dime_keys_file_create(KEYS_TYPE_USER, signkey, enckey, filename_u);
	ck_assert_msg(res == 0, "Failure creating user keys file\n.");

	signkey2 = dime_keys_signkey_fetch(filename_u);
	ck_assert_msg(signkey2 != NULL, "Failure fetching signing key.\n");


	res = memcmp(signkey->private_key, signkey2->private_key, ED25519_KEY_SIZE);
	ck_assert_msg(res == 0, "Corruption of signing key data.\n");

	_free_ed25519_key(signkey2);

	enckey2 = dime_keys_enckey_fetch(filename_u);
	ck_assert_msg(enckey2 != NULL, "Failure fetching encryption key.\n");

	ser_enc2 = _serialize_ec_privkey(enckey2, &enc2_size);
	_free_ec_key(enckey2);
	ck_assert_msg(enc1_size == enc2_size, "Corruption of serialized encryption key size.\n");

	res = memcmp(ser_enc1, ser_enc2, enc1_size);
	ck_assert_msg(res == 0, "Corruption of encryption key data.\n");

	free(ser_enc2);

/* testing organizational keys file */
	res = dime_keys_file_create(KEYS_TYPE_ORG, signkey, enckey, filename_o);
	ck_assert_msg(res == 0, "Failure to create organizational keys file\n.");

	signkey2 = dime_keys_signkey_fetch(filename_o);
	ck_assert_msg(signkey2 != NULL, "Failure to fetch signing key.\n");

	res = memcmp(signkey->private_key, signkey2->private_key, ED25519_KEY_SIZE);
	ck_assert_msg(res == 0, "Corruption of signing key data.\n");

	_free_ed25519_key(signkey2);

	enckey2 = dime_keys_enckey_fetch(filename_o);
	ck_assert_msg(enckey2 != NULL, "Failure to fetch encryption key.\n");

	ser_enc2 = _serialize_ec_privkey(enckey2, &enc2_size);
	ck_assert_msg(enc1_size == enc2_size, "Corruption of serialized encryption key size.\n");

	res = memcmp(ser_enc1, ser_enc2, enc1_size);
	ck_assert_msg(res == 0, "Corruption of encryption key data.\n");

	_free_ec_key(enckey2);
	free(ser_enc1);
	free(ser_enc2);

/* testing invalid keys file types */
	res = dime_keys_file_create(KEYS_TYPE_ERROR, signkey, enckey, filename_w);
	ck_assert_msg(res != 0, "Failure to trigger error creating keys file type KEYS_TYPE_ERROR.\n");

	ck_assert_msg(access(filename_w, F_OK) == -1, "Unintended creation of keys file with invalid type.\n");

	res = dime_keys_file_create(4, signkey, enckey, filename_w);
	ck_assert_msg(res != 0, "Failure to trigger error creating keys file type 4.\n");

	ck_assert_msg(access(filename_w, F_OK) == -1, "Unintended creation of keys file with invalid type.\n");

	_free_ed25519_key(signkey);
	_free_ec_key(enckey);

	fprintf(stderr, "Keys file I/O check complete.\n");
}
END_TEST


Suite *suite_check_keys(void) {

	Suite *s = suite_create("\nKeys");
	suite_add_test(s, "check keys file I/O", check_keys_file_handling);
	return s;
}
