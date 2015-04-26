#include <signet/signet.h>
#include "checks.h"

START_TEST(check_signet_modification)
{
	const char *phone1 = "1SOMENUMBER", *phone2 = "15124123529", *name1 = "check undef", *data1 = "undef data", *name2 = "check name", *data2 = "check check";
	size_t data_size;
	unsigned char *data;
	signet_t *signet;

	ck_assert_msg((signet = _signet_create(SIGNET_TYPE_ORG)) != NULL, "could not create signet.\n");

	ck_assert_msg(!(_signet_add_field_string(signet, SIGNET_ORG_UNDEFINED, name1, data1, 0)), "could not add undefined field.\n");

	ck_assert_msg((_signet_fid_exists(signet, SIGNET_ORG_UNDEFINED)) == 1, "could not find added undefined field.\n");

	ck_assert_msg((data = _signet_fetch_undef_name(signet, strlen(name1), (unsigned char *)name1, &data_size)) != NULL, "could not retrieve undefined field.\n");

	ck_assert_msg(!(memcmp(data, (unsigned char *)data1, data_size)), "undefined field was corrupted.\n");

	free(data);

	ck_assert_msg(!(_signet_add_field_string(signet, SIGNET_ORG_UNDEFINED, name2, data2, 0)), "could not add undefined field.\n");

	ck_assert_msg((data = _signet_fetch_undef_name(signet, strlen(name2), (unsigned char *)name2, &data_size)) != NULL, "could not retrieve undefined field.\n");

	ck_assert_msg(!(memcmp(data, (unsigned char *)data2, data_size)), "undefined field was corrupted.\n");

	free(data);

	ck_assert_msg(!(_signet_remove_undef_name(signet, strlen(name1), (unsigned char *)name1)), "could not remove undefined field by name.\n");

	ck_assert_msg((data = _signet_fetch_undef_name(signet, strlen(name2), (unsigned char *)name2, &data_size)) != NULL, "could not retrieve undefined field.\n");

	ck_assert_msg(!(memcmp(data, (unsigned char *)data2, data_size)), "undefined field was corrupted by the deletion of the previous field.\n");

	free(data);

	ck_assert_msg(!(_signet_add_field_string(signet, SIGNET_ORG_PHONE, NULL, phone1, 0)), "could not add phone field.\n");

	ck_assert_msg(_signet_fid_exists(signet, SIGNET_ORG_PHONE) == 1, "could not find added field.\n");

	ck_assert_msg((data = _signet_fetch_fid_num(signet, SIGNET_ORG_PHONE, 1, &data_size)) != NULL, "could not retrieve phone field.\n");

	ck_assert_msg(!(memcmp(data, (unsigned char *)phone1, data_size)), "field was corrupted.\n");

	free(data);

	ck_assert_msg(!(_signet_add_field_string(signet, SIGNET_ORG_PHONE, NULL, phone2, 0)), "could not add phone field.\n");

	ck_assert_msg((data = _signet_fetch_fid_num(signet, SIGNET_ORG_PHONE, 2, &data_size)) != NULL, "could not retrieve phone field.\n");

	ck_assert_msg(!(memcmp(data, (unsigned char *)phone2, data_size)), "field was corrupted.\n");

	free(data);

	ck_assert_msg(!(_signet_remove_fid_num(signet, SIGNET_ORG_PHONE, 1)), "could not remove field.\n");

	ck_assert_msg((data = _signet_fetch_fid_num(signet, SIGNET_ORG_PHONE, 1, &data_size)) != NULL, "could not retrieve phone field after previous field was deleted.\n");

	ck_assert_msg(!(memcmp(data, (unsigned char *)phone2, data_size)), "field was corrupted by the deletion of the previous field.\n");

	free(data);
	_signet_destroy(signet);
}
END_TEST

#if 0
static void signet_dump(const signet_t *signet) {

	fprintf(stderr, "signet size: %d\nsignet data: ", signet->size);
	for(size_t i = 0; i < signet->size; ++i) {
		fprintf(stderr, "%d ", signet->data[i]);
	}
	fprintf(stderr, "\nfield indexes: ");
	for(size_t i = 0; i <= SIGNET_FID_MAX; ++i) {
		fprintf(stderr, "%d ", signet->fields[i]);
	}
	fprintf(stderr, "\n");
}
#endif

START_TEST(check_signet_parsing)
{
	char *b64_sigone, *b64_sigtwo;
	const char *filename = "check.signet";
	uint32_t len;
	unsigned char *ser_sigone, *ser_sigtwo;
	signet_t *sigone, *sigtwo;

	sigone = _signet_create(SIGNET_TYPE_ORG);
	_signet_add_field_string(sigone, SIGNET_ORG_NAME, NULL, "some name", 0);
	_signet_add_field_string(sigone, SIGNET_ORG_PHONE, NULL, "phonenum1", 0);
	_signet_add_field_string(sigone, SIGNET_ORG_PHONE, NULL, "someotherphone", 0);
	_signet_add_field_string(sigone, SIGNET_ORG_UNDEFINED, "field name", "some field", 0);
	_signet_add_field_string(sigone, SIGNET_ORG_UNDEFINED, "check name", "check field", 0);
	_signet_add_field_string(sigone, SIGNET_ORG_UNDEFINED, "last field", "check check", 0);

	ck_assert_msg((ser_sigone = _signet_serialize(sigone, &len)) != NULL, "could not serialize signet to binary.\n");

	ck_assert_msg((sigtwo = _signet_deserialize(ser_sigone, len)) != NULL, "could not deserialize signet from binary.\n");

	ck_assert_msg((ser_sigtwo = _signet_serialize(sigtwo, &len)) != NULL, "could not serialize signet to binary the second time.\n");

	ck_assert_msg(!(memcmp(ser_sigone, ser_sigtwo, len)), "the signet got corrupted during serialization and deserialization.\n");

	free(ser_sigone);
	free(ser_sigtwo);
	_signet_destroy(sigtwo);

	ck_assert_msg((b64_sigone = _signet_serialize_b64(sigone)) != NULL, "could not serialize signet to base64.\n");

	ck_assert_msg((sigtwo = _signet_deserialize_b64(b64_sigone)) != NULL, "could not deserialize signet from base64.\n");

	ck_assert_msg((b64_sigtwo = _signet_serialize_b64(sigtwo)) != NULL, "could not serialize signet to base64 the second time.\n");

	ck_assert_msg(!(strcmp(b64_sigone, b64_sigtwo)), "the signet got corrupted during serialization and deserialization to and from b64.\n");

	free(b64_sigtwo);
	_signet_destroy(sigtwo);

	ck_assert_msg(!(_signet_to_file(sigone, filename)), "could not write signet to file.\n");

	ck_assert_msg((sigtwo = _signet_from_file(filename)) != NULL, "could not read signet from file.\n");

	ck_assert_msg(!(_signet_to_file(sigtwo, filename)), "could not write signet to file the second time.\n");

	ck_assert_msg((b64_sigtwo = _read_pem_data(filename, "SIGNET", 1)) != NULL, "could not read data from file.\n");

	ck_assert_msg(!(strcmp(b64_sigone, b64_sigtwo)), "the signet got corrupted after being written to and read from file.\n");

	free(b64_sigone);
	free(b64_sigtwo);
	_signet_destroy(sigtwo);
	_signet_destroy(sigone);
}
END_TEST

START_TEST(check_signet_signing)
{
	const char *org_keys = "check_org.keys", *user_keys = "check_user.keys", *newuser_keys = "check_newuser.keys";
	unsigned char **org_signet_sign_keys;
	ED25519_KEY *orgkey, *userkey, *userpubkey;
	signet_t *org_signet, *user_signet, *newuser_signet;
	EC_KEY *eckey;

	_crypto_init();
//create org signet and keys file
	ck_assert_msg((org_signet = _signet_new_keysfile(SIGNET_TYPE_ORG, org_keys)) != NULL, "could not create new signet with keys.\n");
//retrieve public encryption key
	ck_assert_msg((eckey = _signet_get_enckey(org_signet)) != NULL, "could not retreive public encryption key from signet.\n");
	_free_ec_key(eckey);
//retrieve private encryption key
	ck_assert_msg((eckey = _keys_file_fetch_enc_key(org_keys)) != NULL, "could not fetch private encryption key.\n");
	_free_ec_key(eckey);
//retrieve org private signing key
	ck_assert_msg((orgkey = _keys_file_fetch_sign_key(org_keys)) != NULL, "could not fetch ed25519 signing key.\n");
//sign org core signature
	ck_assert_msg(!(_signet_sign_core_sig(org_signet, orgkey)), "could not sign org signet core.\n");
//retrieve the list of all org signet-signing keys
	ck_assert_msg((org_signet_sign_keys = _signet_get_signet_sign_keys(org_signet)) != NULL, "could not retrieve signing keys.\n");
//verify that the org core signet is valid
	ck_assert_msg(_signet_full_verify(org_signet, NULL, (const unsigned char **)org_signet_sign_keys) == SS_CORE, "could not verify core org signet.\n");
//set a signet id (domain) to the org signet
	ck_assert_msg(!(_signet_set_id(org_signet, "test.com")), "could not set org signet id.\n");
//sign org signet full signature
	ck_assert_msg(!(_signet_sign_full_sig(org_signet, orgkey)), "could not sign full org signet.\n");
//verify that the org signet is a valid full signet
	ck_assert_msg(_signet_full_verify(org_signet, NULL, (const unsigned char **)org_signet_sign_keys) == SS_FULL, "could not verify full org signet.\n");
//create ssr signet and user keys file
	ck_assert_msg((user_signet = _signet_new_keysfile(SIGNET_TYPE_SSR, user_keys)) != NULL, "could not create a new ssr with keys.\n");
//retrieve user private signing key
	ck_assert_msg((userkey = keys_file_fetch_sign_key(user_keys)) != NULL, "could not fetch ed25519 signing key.\n");
//sign the ssr signature with user keys
	ck_assert_msg(!(_signet_sign_ssr_sig(user_signet, userkey)), "could not sign ssr with user signing key.\n");
//verify that the signet is a valid ssr
	ck_assert_msg(_signet_full_verify(user_signet, NULL, NULL) == SS_SSR, "could not verify ssr.\n");
//sign ssr with org signing key
	ck_assert_msg(!(_signet_sign_initial_sig(user_signet, orgkey)), "could not perform initial signature on ssr.\n");
//verify that the signet is now a valid user core signet
	ck_assert_msg(_signet_full_verify(user_signet, org_signet, NULL) == SS_USER_CORE, "could not verify user core signet.\n");
//sign the core signature with org key
	ck_assert_msg(!(_signet_sign_core_sig(user_signet, orgkey)), "could not sign user signet core.\n");
//verify that the user signet is now a valid core signet
	ck_assert_msg(_signet_full_verify(user_signet, org_signet, NULL) == SS_CORE, "could not verify user core signet.\n");
//set user signet id (address)
	ck_assert_msg(!(_signet_set_id(user_signet, "user@test.com")), "could not set user signet id.\n");
//sign the full signature on the user signet
	ck_assert_msg(!(_signet_sign_full_sig(user_signet, orgkey)), "could not sign full user signet.\n");
//verify that the user signet is a valid full signet
	ck_assert_msg(_signet_full_verify(user_signet, org_signet, NULL) == SS_FULL, "could not verify full user signet.\n");
//create new ssr and keys file
	ck_assert_msg((newuser_signet = signet_new_keysfile(SIGNET_TYPE_SSR, newuser_keys)) != NULL, "could not create new ssr with keys.\n");
//sign the new ssr with a chain of custody signature using the user's old signing key
	ck_assert_msg(!(_signet_sign_coc_sig(newuser_signet, userkey)), "could not sign chain of custody signature.\n");
//get user's old public signing key from user's old signet
	ck_assert_msg((userpubkey = _signet_get_signkey(user_signet)) != NULL, "could not retrieve public signing key from the old user signet.\n");
//verify that the chain of custody signature on the new ssr is valid
	ck_assert_msg(_signet_verify_signature_key(newuser_signet, SIGNET_SSR_COC_SIG, userpubkey) == 1, "could not verify new user signet chain of custody signature.\n");

	_free_ed25519_key(userpubkey);
	_free_ed25519_key(userkey);
//retrieve user's new private signing key
	ck_assert_msg((userkey = _keys_file_fetch_sign_key(newuser_keys)) != NULL, "could not retrieve new user signet signing key from file.\n");
//perform all the signatures on teh new ssr
	_signet_sign_ssr_sig(newuser_signet, userkey);
	_signet_sign_initial_sig(newuser_signet, orgkey);
	_signet_sign_core_sig(newuser_signet, orgkey);
	_signet_set_id(newuser_signet, "user@test.com");
	_signet_sign_full_sig(newuser_signet, orgkey);
//confirm that the new signet is now a valid full signet
	ck_assert_msg(_signet_full_verify(newuser_signet, org_signet, NULL) == SS_FULL, "could not verify new user signet as full signet.\n");

	for (size_t i = 0; org_signet_sign_keys[i]; i++) {
		free(org_signet_sign_keys[i]);
	}

	free(org_signet_sign_keys);
	_free_ed25519_key(orgkey);
	_free_ed25519_key(userkey);
	_signet_destroy(newuser_signet);
	_signet_destroy(user_signet);
	_signet_destroy(org_signet);
}
END_TEST

Suite *suite_check_signet(void) {

	Suite *s = suite_create("signet");
	suite_add_test(s, "check signet creation and field modification", check_signet_modification);
	suite_add_test(s, "check signet parsing, serialization, deserialization", check_signet_parsing);
	suite_add_test(s, "check signet signing and verification", check_signet_signing);
	return s;
}
