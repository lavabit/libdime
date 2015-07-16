#include <unistd.h>
#include "signet/keys.h"
#include "signet/signet.h"
#include "checks.h"

START_TEST(check_signet_creation)
{
	signet_t *signet;
	signet_type_t type;

	signet = dime_sgnt_create_signet(SIGNET_TYPE_ORG);
	ck_assert_msg(signet != NULL, "Failureto create organizational signet.\n");

	type = dime_sgnt_type_get(signet);
	ck_assert_msg(type == SIGNET_TYPE_ORG, "Corrupted signet type.\n");

	dime_sgnt_destroy_signet(signet);

	signet = dime_sgnt_create_signet(SIGNET_TYPE_USER);
	ck_assert_msg(signet != NULL, "Failure to create user signet.\n");

	type = dime_sgnt_type_get(signet);
	ck_assert_msg(type == SIGNET_TYPE_USER, "Corrupted signet type.\n");

	dime_sgnt_destroy_signet(signet);

	signet = dime_sgnt_create_signet(SIGNET_TYPE_SSR);
	ck_assert_msg(signet != NULL, "Failure to create SSR.\n");

	type = dime_sgnt_type_get(signet);
	ck_assert_msg(type == SIGNET_TYPE_SSR, "Corrupted signet type.\n");

	dime_sgnt_destroy_signet(signet);

	signet = dime_sgnt_create_signet(SIGNET_TYPE_ERROR);
	ck_assert_msg(signet == NULL, "Unintended creation of signet with invalid type SIGNET_TYPE_ERROR");

	signet = dime_sgnt_create_signet(52);
	ck_assert_msg(signet == NULL, "Unintended creation of signet with invalid type 52");

	fprintf(stderr, "Signet creation check completed.\n");
}
END_TEST

START_TEST(check_signet_keys_pairing)
{
	const char *filename_u = "keys_user.keys", *filename_o = "keys_org.keys",
			*filename_s = "keys_ssr.keys", *filename_w = "keys_wrong.keys",
			*to_sign = "AbcDEFghijKLMNOpqrstuVWXYZ";
	EC_KEY *priv_enckey, *pub_enckey;
	ED25519_KEY *priv_signkey, *pub_signkey;
	ed25519_signature sigbuf;
	int res = 0;
	signet_t *signet;
	signet_type_t type;
	size_t enc1_size, enc2_size;
	unsigned char *enc1_pub, *enc2_pub;

	_crypto_init();

/* creating user signet with keys */
	signet = dime_sgnt_create_signet_w_keys(SIGNET_TYPE_USER, filename_u);
	ck_assert_msg(signet != NULL, "Failure to create user signet.\n");

	type = dime_sgnt_type_get(signet);
	ck_assert_msg(type == SIGNET_TYPE_USER, "Corrupted signet type.\n");

	priv_signkey = dime_keys_fetch_sign_key(filename_u);
	ck_assert_msg(priv_signkey != NULL, "Failure to fetch private signing key from file.\n");

	res = _ed25519_sign_data((const unsigned char *)to_sign, strlen(to_sign), priv_signkey, sigbuf);
	ck_assert_msg(res == 0, "Failure to sign data buffer.\n");

	pub_signkey = dime_sgnt_fetch_signkey(signet);
	ck_assert_msg(pub_signkey != NULL, "Failure to fetch public signing key from signet.\n");

	res = _ed25519_verify_sig((const unsigned char *)to_sign, strlen(to_sign), pub_signkey, sigbuf);
	ck_assert_msg(res = 1, "Failure to verify signature");

	priv_enckey = dime_keys_fetch_enc_key(filename_u);
	ck_assert_msg(priv_enckey != NULL, "Failure to fetch private encryption key from file.\n");

	enc1_pub = _serialize_ec_pubkey(priv_enckey, &enc1_size);
	ck_assert_msg(enc1_pub != NULL, "Failure to serialize public portion of the private encryption key.\n");

	pub_enckey = dime_sgnt_fetch_enckey(signet);
	ck_assert_msg(pub_enckey != NULL, "Failure to fetch public encryption key from signet.\n");

	enc2_pub = _serialize_ec_pubkey(pub_enckey, &enc2_size);
	ck_assert_msg(enc1_size == enc2_size, "Corrupted public encryption key size.\n");
	ck_assert_msg(memcmp(enc1_pub, enc2_pub, enc1_size) == 0, "Corrupted public encryption key data.\n");

	_free_ed25519_key(priv_signkey);
	_free_ed25519_key(pub_signkey);
	_free_ec_key(pub_enckey);
	_free_ec_key(priv_enckey);
	free(enc1_pub);
	free(enc2_pub);
	dime_sgnt_destroy_signet(signet);

/* creating organizational signet with keys */
	signet = dime_sgnt_create_signet_w_keys(SIGNET_TYPE_ORG, filename_o);
	ck_assert_msg(signet != NULL, "Failure to create organizational signet.\n");

	type = dime_sgnt_type_get(signet);
	ck_assert_msg(type == SIGNET_TYPE_ORG, "Corrupted signet type.\n");

	priv_signkey = dime_keys_fetch_sign_key(filename_o);
	ck_assert_msg(priv_signkey != NULL, "Failure to fetch private signing key from file.\n");

	res = _ed25519_sign_data((const unsigned char *)to_sign, strlen(to_sign), priv_signkey, sigbuf);
	ck_assert_msg(res == 0, "Failure to sign data buffer.\n");

	pub_signkey = dime_sgnt_fetch_signkey(signet);
	ck_assert_msg(pub_signkey != NULL, "Failure to fetch public signing key from signet.\n");

	res = _ed25519_verify_sig((const unsigned char *)to_sign, strlen(to_sign), pub_signkey, sigbuf);
	ck_assert_msg(res = 1, "Failure to verify signature");

	priv_enckey = dime_keys_fetch_enc_key(filename_o);
	ck_assert_msg(priv_enckey != NULL, "Failure to fetch private encryption key from file.\n");

	enc1_pub = _serialize_ec_pubkey(priv_enckey, &enc1_size);
	ck_assert_msg(enc1_pub != NULL, "Failure to serialize public portion of the private encryption key.\n");

	pub_enckey = dime_sgnt_fetch_enckey(signet);
	ck_assert_msg(pub_enckey != NULL, "Failure to fetch public encryption key from signet.\n");

	enc2_pub = _serialize_ec_pubkey(pub_enckey, &enc2_size);
	ck_assert_msg(enc1_size == enc2_size, "Corrupted public encryption key size.\n");
	ck_assert_msg(memcmp(enc1_pub, enc2_pub, enc1_size) == 0, "Corrupted public encryption key data.\n");

	_free_ed25519_key(priv_signkey);
	_free_ed25519_key(pub_signkey);
	_free_ec_key(priv_enckey);
	_free_ec_key(pub_enckey);
	free(enc1_pub);
	free(enc2_pub);
	dime_sgnt_destroy_signet(signet);

/* creating ssr signet with keys */
	signet = dime_sgnt_create_signet_w_keys(SIGNET_TYPE_SSR, filename_s);
	ck_assert_msg(signet != NULL, "Failure to create SSR.\n");

	type = dime_sgnt_type_get(signet);
	ck_assert_msg(type == SIGNET_TYPE_SSR, "Corrupted signet type.\n");

	priv_signkey = dime_keys_fetch_sign_key(filename_s);
	ck_assert_msg(priv_signkey != NULL, "Failure to fetch private signing key from file.\n");

	res = _ed25519_sign_data((const unsigned char *)to_sign, strlen(to_sign), priv_signkey, sigbuf);
	ck_assert_msg(res == 0, "Failure to sign data buffer.\n");

	pub_signkey = dime_sgnt_fetch_signkey(signet);
	ck_assert_msg(pub_signkey != NULL, "Failure to fetch public signing key from signet.\n");

	res = _ed25519_verify_sig((const unsigned char *)to_sign, strlen(to_sign), pub_signkey, sigbuf);
	ck_assert_msg(res = 1, "Failure to verify signature");

	priv_enckey = dime_keys_fetch_enc_key(filename_s);
	ck_assert_msg(priv_enckey != NULL, "Failure to fetch private encryption key from file.\n");

	enc1_pub = _serialize_ec_pubkey(priv_enckey, &enc1_size);
	ck_assert_msg(enc1_pub != NULL, "Failure to serialize public portion of the private encryption key.\n");

	pub_enckey = dime_sgnt_fetch_enckey(signet);
	ck_assert_msg(pub_enckey != NULL, "Failure to fetch public encryption key from signet.\n");

	enc2_pub = _serialize_ec_pubkey(pub_enckey, &enc2_size);
	ck_assert_msg(enc1_size == enc2_size, "Corrupted public encryption key size.\n");
	ck_assert_msg(memcmp(enc1_pub, enc2_pub, enc1_size) == 0, "Corrupted public encryption key data.\n");

	_free_ed25519_key(priv_signkey);
	_free_ed25519_key(pub_signkey);
	_free_ec_key(priv_enckey);
	_free_ec_key(pub_enckey);
	free(enc1_pub);
	free(enc2_pub);
	dime_sgnt_destroy_signet(signet);

/*creating invalid signet types*/
	signet = dime_sgnt_create_signet_w_keys(SIGNET_TYPE_ERROR, filename_w);
	ck_assert_msg(signet == NULL, "Unintended creation of signet with invalid type SIGNET_TYPE_ERROR.\n");
	ck_assert_msg(access(filename_w, F_OK) == -1, "Unintended creation of keys file for signet with invalid type SIGNET_TYPE_ERROR.\n");

	signet = dime_sgnt_create_signet_w_keys(31, filename_w);
	ck_assert_msg(signet == NULL, "Unintended creation of signet with invalid type 31.\n");
	ck_assert_msg(access(filename_w, F_OK) == -1, "Unintended creation of keys file for signet with invalid type 31.\n");

	fprintf(stderr, "Signet file keypair check completed.\n");
}
END_TEST

START_TEST(check_signet_modification)
{
	const char *phone1 = "1SOMENUMBER", *phone2 = "15124123529",
			*name1 = "check undef", *data1 = "undef data",
			*name2 = "check name", *data2 = "check check";
	int res;
	signet_t *signet;
	size_t data_size;
	unsigned char *data;

	signet = dime_sgnt_create_signet(SIGNET_TYPE_ORG);
	ck_assert_msg(signet != NULL, "Failure to create signet.\n");

	res = dime_sgnt_create_undefined_field(signet, strlen(name1), (const unsigned char *)name1, strlen(data1), (const unsigned char *)data1);
	ck_assert_msg(res == 0, "Failure to create undefined field.\n");

	res = dime_sgnt_fid_exists(signet, SIGNET_ORG_UNDEFINED);
	ck_assert_msg(res == 1, "Failure to confirm existence of undefined field.\n");

	data = dime_sgnt_fetch_undefined_field(signet, strlen(name1), (const unsigned char *)name1, &data_size);
	ck_assert_msg(data != NULL, "Failure to fetch undefined field.\n");
	ck_assert_msg(data_size == strlen(data1), "Corrupted undefined field size.\n");
	ck_assert_msg(memcmp(data, (unsigned char *)data1, data_size) == 0, "Corrupted undefined field data.\n");

	free(data);

	res = dime_sgnt_create_undefined_field(signet, strlen(name2), (const unsigned char *)name2, strlen(data2), (const unsigned char *)data2);
	ck_assert_msg(res == 0, "Failure to create undefined field.\n");

	data = dime_sgnt_fetch_undefined_field(signet, strlen(name2), (const unsigned char*)name2, &data_size);
	ck_assert_msg(data != NULL, "Failure to fetch undefined field.\n");
	ck_assert_msg(data_size == strlen(data2), "Corrupted undefined field size.\n");
	ck_assert_msg(memcmp(data, (unsigned char *)data2, data_size) == 0, "Corrupted undefined field data.\n");

	free(data);

	res = dime_sgnt_remove_undefined_field(signet, strlen(name1), (const unsigned char *)name1);
	ck_assert_msg(res == 0, "Failure to remove undefined field.\n");

	data = dime_sgnt_fetch_undefined_field(signet, strlen(name1), (const unsigned char *)name1, &data_size);
	ck_assert_msg(data == NULL, "Unintended existence of undefined field after removal.\n");

	data = dime_sgnt_fetch_undefined_field(signet, strlen(name2), (const unsigned char *)name2, &data_size);
	ck_assert_msg(data != NULL, "Failure to fetch undefined field.\n");
	ck_assert_msg(data_size == strlen(data2), "Corrupted undefined field size.\n");
	ck_assert_msg(memcmp(data, (unsigned char *)data2, data_size) == 0, "Corrupted undefined field data.\n");

	free(data);

	res = dime_sgnt_create_defined_field(signet, SIGNET_ORG_PHONE, strlen(phone1), (const unsigned char *)phone1);
	ck_assert_msg(res == 0, "Failure to create phone number field.\n");

	res = dime_sgnt_fid_exists(signet, SIGNET_ORG_PHONE);
	ck_assert_msg(res == 1, "Failure to confirm existence of phone number field.\n");

	data = dime_sgnt_fetch_fid_num(signet, SIGNET_ORG_PHONE, 1, &data_size);
	ck_assert_msg(data != NULL, "Failure to fetch phone number field");
	ck_assert_msg(data_size == strlen(phone1), "Corrupted phone number field size.\n");
	ck_assert_msg(memcmp(data, (unsigned char *)phone1, data_size) == 0, "Corrupted phone number field data.\n");

	free(data);

	res = dime_sgnt_create_defined_field(signet, SIGNET_ORG_PHONE, strlen(phone2), (const unsigned char *)phone2);
	ck_assert_msg(res == 0, "Failure to create phone number field.\n");

	data = dime_sgnt_fetch_fid_num(signet, SIGNET_ORG_PHONE, 2, &data_size);
	ck_assert_msg(data != NULL, "Failure to fetch phone number field.\n");
	ck_assert_msg(data_size == strlen(phone2), "Corrupted phone number field size.\n");
	ck_assert_msg(memcmp(data, (unsigned char *)phone2, data_size) == 0, "Corrupted phone number field data.\n");

	free(data);

	res = dime_sgnt_remove_fid_num(signet, SIGNET_ORG_PHONE, 1);
	ck_assert_msg(res == 0, "Failure to remove phone number field.\n");

	data = dime_sgnt_fetch_fid_num(signet, SIGNET_ORG_PHONE, 1, &data_size);
	ck_assert_msg(data != NULL, "Failure to fetch phone number field.\n");
	ck_assert_msg(data_size == strlen(phone2), "Corrupted phone number field size.\n");
	ck_assert_msg(memcmp(data, (unsigned char *)phone2, data_size) == 0, "Corrupted phone number field data.\n");

	free(data);
	dime_sgnt_destroy_signet(signet);

	fprintf(stderr, "Signet modification check complete.\n");
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
	const char *filename = "check.signet", *name = "some name", 
		*phone1 = "phonenum1", *phone2 = "someotherphone", 
		*name1 = "field name", *name2 = "other field name", 
		*name3 = "last name of field", *data1 = "some field", 
		*data2 = "check fields", *data3 = "check check check";
	int res;
	signet_t *sigone, *sigtwo;
	uint32_t len;
	unsigned char *ser_sigone, *ser_sigtwo;

	sigone = dime_sgnt_create_signet(SIGNET_TYPE_ORG);
	dime_sgnt_create_defined_field(sigone, SIGNET_ORG_NAME, strlen(name), (const unsigned char *)name);
	dime_sgnt_create_defined_field(sigone, SIGNET_ORG_PHONE, strlen(phone1), (const unsigned char *)phone1);
	dime_sgnt_create_defined_field(sigone, SIGNET_ORG_PHONE, strlen(phone2), (const unsigned char *)phone2);
	dime_sgnt_create_undefined_field(sigone, strlen(name1), (const unsigned char *)name1, strlen(data1), (const unsigned char *)data1);
	dime_sgnt_create_undefined_field(sigone, strlen(name2), (const unsigned char *)name2, strlen(data2), (const unsigned char *)data2);
	dime_sgnt_create_undefined_field(sigone, strlen(name3), (const unsigned char *)name3, strlen(data3), (const unsigned char *)data3);

	ser_sigone = dime_sgnt_serial_from_signet(sigone, &len);
	ck_assert_msg(ser_sigone != NULL, "Failure to serialize signet.\n");

	sigtwo = dime_sgnt_serial_to_signet(ser_sigone, len);
	ck_assert_msg(sigtwo != NULL, "Failure to deserialize signet.\n");

	ser_sigtwo = dime_sgnt_serial_from_signet(sigtwo, &len);
	ck_assert_msg(ser_sigtwo != NULL, "Failure to re-serialized the signet.\n");
	ck_assert_msg(memcmp(ser_sigone, ser_sigtwo, len) == 0, "Corrupted serialized signet data.\n");

	free(ser_sigone);
	free(ser_sigtwo);
	dime_sgnt_destroy_signet(sigtwo);

	b64_sigone = dime_sgnt_serial_signet_to_b64(sigone);
	ck_assert_msg(b64_sigone != NULL, "Failure to convert signet to base64 encoded string.\n");

	sigtwo = dime_sgnt_serial_b64_to_signet(b64_sigone);
	ck_assert_msg(sigtwo != NULL, "Failure to convert base64 string to signet.\n");

	b64_sigtwo = dime_sgnt_serial_signet_to_b64(sigtwo);
	ck_assert_msg(b64_sigtwo != NULL, "Failure to re-convert signet to base64 encoded string.\n");
	ck_assert_msg(strcmp(b64_sigone, b64_sigtwo) == 0, "Corrupted base64 string signet data.\n");

	free(b64_sigtwo);
	dime_sgnt_destroy_signet(sigtwo);

	res = dime_sgnt_file_create(sigone, filename);
	ck_assert_msg(res == 0, "Failure to write signet to file.\n");

	sigtwo = dime_sgnt_file_to_signet(filename);
	ck_assert_msg(sigtwo != NULL, "Failure to read signet from file.\n");

	res = dime_sgnt_file_create(sigtwo, filename);
	ck_assert_msg(res == 0, "Failure to re-write signet to file.\n");

	b64_sigtwo = _read_pem_data(filename, SIGNET_PEM_TAG, 1);
	ck_assert_msg(b64_sigtwo != NULL, "Failure to read b64 string from signet file.\n");
	ck_assert_msg(strcmp(b64_sigone, b64_sigtwo) == 0, "Corrupted signet file data.\n");

	free(b64_sigone);
	free(b64_sigtwo);
	dime_sgnt_destroy_signet(sigtwo);
	dime_sgnt_destroy_signet(sigone);

	fprintf(stderr, "Signet parsing check complete.\n");
}
END_TEST

START_TEST(check_signet_validation)
{
	const char *org_keys = "check_org.keys", *user_keys = "check_user.keys", *newuser_keys = "check_newuser.keys";
	ED25519_KEY *orgkey, *userkey, **keys_obj;
	int res;
	signet_state_t state;
	signet_t *org_signet, *user_signet, *newuser_signet;
	unsigned char **org_signet_sign_keys;
	size_t keysnum = 1;

	_crypto_init();
//create org signet and keys file
	org_signet = dime_sgnt_create_signet_w_keys(SIGNET_TYPE_ORG, org_keys);
	ck_assert_msg(org_signet != NULL, "Failure to create signet with keys file.\n");
//retrieve org private signing key
	orgkey = dime_keys_fetch_sign_key(org_keys);
	//ck_assert_msg(orgkey != NULL, "Failure to fetch private signing key from keys file.\n");
//sign org cryptographic signet signature
	res = dime_sgnt_sign_crypto_sig(org_signet, orgkey);
	//ck_assert_msg(res == 0, "Failure to create organizational cryptographic signet signature.\n");
//retrieve the list of all org signet-signing keys (note we're using this instead of retrieving the list of POKs from the dime record just to have a list of keys, 1 of which will be valid.)
	keys_obj = dime_sgnt_fetch_signet_signkeys(org_signet);
	res = dime_sgnt_sign_crypto_sig(org_signet, orgkey);
	ck_assert_msg(keys_obj != NULL, "Failure to retrieve organizational signet signing keys.\n");
//convert ed25519 pointer chain to serialized ed25519 public key pointer chain

	for(size_t i = 0; keys_obj[i]; ++i) {
		++keysnum;
	}

	org_signet_sign_keys = malloc(sizeof(unsigned char *) * keysnum);
	memset(org_signet_sign_keys, 0, sizeof(unsigned char *) * keysnum);

	for(size_t i = 0; keys_obj[i]; ++i) {

		org_signet_sign_keys[i] = malloc(ED25519_KEY_SIZE);
		memcpy(org_signet_sign_keys[i], keys_obj[i]->public_key, ED25519_KEY_SIZE);
	}
//verify that the org crypto signet is valid
	state = dime_sgnt_validate_all(org_signet, NULL, NULL, (const unsigned char **)org_signet_sign_keys);
	ck_assert_msg(state  == SS_CRYPTO, "Failure to correctly validate organizational signet as a cryptographic signet.\n");
//sign org full signet signature
	res = dime_sgnt_sign_full_sig(org_signet, orgkey);
	ck_assert_msg(res == 0, "Failure to create organizational full signet signature.\n");
//verify that the org full signet is valid
	state = dime_sgnt_validate_all(org_signet, NULL, NULL, (const unsigned char **)org_signet_sign_keys);
	ck_assert_msg(state  == SS_FULL, "Failure to correctly validate organizational signet as a full signet.\n");
//set organizational signet id
	res = dime_sgnt_set_id_field(org_signet, strlen("test_org_signet"), (const unsigned char *)"test_org_signet");	
	ck_assert_msg(res == 0, "Failure to set organizational signet id.\n");
//sign identified signet signature
	res = dime_sgnt_sign_id_sig(org_signet, orgkey);
	ck_assert_msg(res == 0, "Failure to create organizational identifiable signet signature field.\n");
//verify that the org signet is a valid identifiable signet
	state = dime_sgnt_validate_all(org_signet, NULL, NULL, (const unsigned char **)org_signet_sign_keys);
	ck_assert_msg(state  == SS_ID, "Failure to correctly validate organizational signet as an identifiable signet.\n");
//create ssr signet and user keys file
	user_signet = dime_sgnt_create_signet_w_keys(SIGNET_TYPE_SSR, user_keys);
	ck_assert_msg(user_signet != NULL, "Failure to create ssr with keys file.\n");
//retrieve user private signing key
	userkey = dime_keys_fetch_sign_key(user_keys);
	ck_assert_msg(userkey != NULL, "Failure to fetch user's private signing key from keys file.\n");
//sign the ssr signature with user keys
	res = dime_sgnt_sign_ssr_sig(user_signet, userkey);
	ck_assert_msg(res == 0, "Failure to sign ssr with the user's private signing key.\n");
//verify that the signet is a valid ssr
	state = dime_sgnt_validate_all(user_signet, NULL, NULL, NULL);
	ck_assert_msg(state  == SS_SSR, "Failure to correctly validate ssr.\n");
//sign ssr with org signing key
	res = dime_sgnt_sign_crypto_sig(user_signet, orgkey);
	ck_assert_msg(res == 0, "Failure to sign ssr into a user cryptographic signet using organizational private signing key.\n");
//verify that the signet is now a valid user core signet
	state = dime_sgnt_validate_all(user_signet, NULL, org_signet, NULL);
	ck_assert_msg(state  == SS_CRYPTO, "Failure to correctly validate user cryptographic signet.\n");
//sign the full signature with org key
	res = dime_sgnt_sign_full_sig(user_signet, orgkey);
	ck_assert_msg(res == 0, "Failure to sign user signet with the full signet signature.\n");
//verify that the user signet is now a valid core signet
	state = dime_sgnt_validate_all(user_signet, NULL, org_signet, NULL);
	ck_assert_msg(state  == SS_FULL, "Failure to correctly validate user full signet.\n");
//set user signet id (address)
	res = dime_sgnt_set_id_field(user_signet, strlen("user@test.org"), (const unsigned char *)"user@test.org");	
	ck_assert_msg(res == 0, "Failure to set user signet id.\n");
//sign the user signature with the identifiable signet signature 
	res = dime_sgnt_sign_id_sig(user_signet, orgkey);
	ck_assert_msg(res == 0, "Failure to sign user signet with the identifiable signet signature.\n");
//verify that the user signet is a valid full signet
	state = dime_sgnt_validate_all(user_signet, NULL, org_signet, NULL);
	ck_assert_msg(state  == SS_ID, "Failure to correctly validate user identifiable signet.\n");
//create new ssr and keys file
	newuser_signet = dime_sgnt_create_signet_w_keys(SIGNET_TYPE_SSR, newuser_keys);
	ck_assert_msg(newuser_signet != NULL, "Failure to create ssr with keys file.\n");
//sign the new ssr with a chain of custody signature using the user's old signing key
	res = dime_sgnt_sign_coc_sig(newuser_signet, userkey);
	ck_assert_msg(res == 0, "Failure to create the chain of custody signature.\n");

	_free_ed25519_key(userkey);

//retrieve user's new private signing key
	userkey = dime_keys_fetch_sign_key(newuser_keys);
	ck_assert_msg(userkey != NULL, "Failure to retrieve user's new private signing key.\n");
//perform all the signatures on the new ssr (adding an address as the id is required for the identifiable signet signature.
	dime_sgnt_sign_ssr_sig(newuser_signet, userkey);
	dime_sgnt_sign_crypto_sig(newuser_signet, orgkey);
	dime_sgnt_sign_full_sig(newuser_signet, orgkey);
	dime_sgnt_set_id_field(newuser_signet, strlen("user@test.com"), (const unsigned char *)"user@test.com");
	dime_sgnt_sign_id_sig(newuser_signet, orgkey);
//Confirm that without using the previous signet to verify the chain of custody, the signet validation returns broken chain of custody
	state = dime_sgnt_validate_all(newuser_signet, NULL, org_signet, NULL);
	ck_assert_msg(state == SS_BROKEN_COC, "Failure to invalidate signet due to no parent signet being provided to validate chain of custody signature.\n");
//Config that by using the previous signet to verify chain of custody, the new user signet is validate as identifiable signet. 
//TODO it may be necessary to test intermediate states with presence of chain of custody also
	state = dime_sgnt_validate_all(newuser_signet, user_signet, org_signet, NULL);
	ck_assert_msg(state == SS_ID, "Failure to validate an identifiable signet with a chain of custody signature.\n");

	_ptr_chain_free(org_signet_sign_keys);
	_free_ed25519_key_chain(keys_obj);
	_free_ed25519_key(orgkey);
	_free_ed25519_key(userkey);
	dime_sgnt_destroy_signet(newuser_signet);
	dime_sgnt_destroy_signet(user_signet);
	dime_sgnt_destroy_signet(org_signet);

	fprintf(stderr, "Signet signing and validation check complete.\n");
}
END_TEST

START_TEST(check_signet_sok)
{

	ED25519_KEY *sok, *sok_from_signet;
	int res;
	signet_t *signet;

	_crypto_init();

	signet = dime_sgnt_create_signet(SIGNET_TYPE_USER);
	ck_assert_msg(signet != NULL, "Failure to create user signet.\n");

	sok = generate_ed25519_keypair();
	ck_assert_msg(sok != NULL, "Failure to generate ed25519 key pair.\n");

	res = dime_sgnt_create_sok(signet, sok, (unsigned char) SIGNKEY_DEFAULT_FORMAT, (SIGNET_SOK_SIGNET | SIGNET_SOK_MSG | SIGNET_SOK_TLS | SIGNET_SOK_SOFTWARE) );
	ck_assert_msg(res == -1, "Error cause by inserting a SOK inside a user signet.\n");

	dime_sgnt_destroy_signet(signet);

	signet = dime_sgnt_create_signet(SIGNET_TYPE_ORG);
	ck_assert_msg(signet != NULL, "Failure to create organizational signet.\n");

	res = dime_sgnt_create_sok(signet, sok, 214, (SIGNET_SOK_SIGNET | SIGNET_SOK_MSG) );
	ck_assert_msg(res == -1, "Error caused by inserting a SOK with an invalid format.\n");

	res = dime_sgnt_create_sok(signet, sok, (unsigned char) SIGNKEY_DEFAULT_FORMAT, (SIGNET_SOK_SIGNET | SIGNET_SOK_MSG | SIGNET_SOK_TLS | SIGNET_SOK_SOFTWARE) );
	ck_assert_msg(res == 0, "Failure to add a SOK field to signet.\n");

	sok_from_signet = dime_sgnt_fetch_sok_num(signet, 1);
	ck_assert_msg(sok_from_signet != NULL, "Failure to fetch SOK from signet.\n");

	res = memcmp(sok->public_key, sok_from_signet->public_key, ED25519_KEY_SIZE);
	ck_assert_msg(res == 0, "SOK was corrupted during inserting and fetching into and from the signet.\n");

	free_ed25519_key(sok_from_signet);
	dime_sgnt_destroy_signet(signet);

	fprintf(stderr, "Signet SOK check complete.\n");
}
END_TEST
/*
START_TEST(check_signet_multi_signkey)
{

	signet_t *signet;
	ED25519_

}
END_TEST
*/
Suite *suite_check_signet(void) {

	Suite *s = suite_create("signet");
	suite_add_test(s, "check signet creation", check_signet_creation);
	suite_add_test(s, "check signet and keys file pair cryptography", check_signet_keys_pairing);
	suite_add_test(s, "check signet creation and field modification", check_signet_modification);
	suite_add_test(s, "check signet parsing, serialization, deserialization", check_signet_parsing);
	suite_add_test(s, "check signet signing and validation", check_signet_validation);
	suite_add_test(s, "check signet sok creation", check_signet_sok);
	return s;
}
