#include <unistd.h>
#include "common/misc.h"
#include "signet/sgnt_keys.h"
#include "signet/sgnt_signet.h"
#include "checks.h"

START_TEST(check_signet_creation)
{
	signet_t *signet;
	signet_type_t type;

	signet = dime_sgnt_signet_create(SIGNET_TYPE_ORG);
	ck_assert_msg(signet != NULL, "Failureto create organizational signet.\n");

	type = dime_sgnt_type_get(signet);
	ck_assert_msg(type == SIGNET_TYPE_ORG, "Corrupted signet type.\n");

	dime_sgnt_signet_destroy(signet);

	signet = dime_sgnt_signet_create(SIGNET_TYPE_USER);
	ck_assert_msg(signet != NULL, "Failure to create user signet.\n");

	type = dime_sgnt_type_get(signet);
	ck_assert_msg(type == SIGNET_TYPE_USER, "Corrupted signet type.\n");

	dime_sgnt_signet_destroy(signet);

	signet = dime_sgnt_signet_create(SIGNET_TYPE_SSR);
	ck_assert_msg(signet != NULL, "Failure to create SSR.\n");

	type = dime_sgnt_type_get(signet);
	ck_assert_msg(type == SIGNET_TYPE_SSR, "Corrupted signet type.\n");

	dime_sgnt_signet_destroy(signet);

	signet = dime_sgnt_signet_create(SIGNET_TYPE_ERROR);
	ck_assert_msg(signet == NULL, "Unintended creation of signet with invalid type SIGNET_TYPE_ERROR");

	signet = dime_sgnt_signet_create(52);
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
	signet = dime_sgnt_signet_create_w_keys(SIGNET_TYPE_USER, filename_u);
	ck_assert_msg(signet != NULL, "Failure to create user signet.\n");

	type = dime_sgnt_type_get(signet);
	ck_assert_msg(type == SIGNET_TYPE_USER, "Corrupted signet type.\n");

	priv_signkey = dime_keys_signkey_fetch(filename_u);
	ck_assert_msg(priv_signkey != NULL, "Failure to fetch private signing key from file.\n");

	res = _ed25519_sign_data((const unsigned char *)to_sign, strlen(to_sign), priv_signkey, sigbuf);
	ck_assert_msg(res == 0, "Failure to sign data buffer.\n");

	pub_signkey = dime_sgnt_signkey_fetch(signet);
	ck_assert_msg(pub_signkey != NULL, "Failure to fetch public signing key from signet.\n");

	res = _ed25519_verify_sig((const unsigned char *)to_sign, strlen(to_sign), pub_signkey, sigbuf);
	ck_assert_msg(res = 1, "Failure to verify signature");

	priv_enckey = dime_keys_enckey_fetch(filename_u);
	ck_assert_msg(priv_enckey != NULL, "Failure to fetch private encryption key from file.\n");

	enc1_pub = _serialize_ec_pubkey(priv_enckey, &enc1_size);
	ck_assert_msg(enc1_pub != NULL, "Failure to serialize public portion of the private encryption key.\n");

	pub_enckey = dime_sgnt_enckey_fetch(signet);
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
	dime_sgnt_signet_destroy(signet);

/* creating organizational signet with keys */
	signet = dime_sgnt_signet_create_w_keys(SIGNET_TYPE_ORG, filename_o);
	ck_assert_msg(signet != NULL, "Failure to create organizational signet.\n");

	type = dime_sgnt_type_get(signet);
	ck_assert_msg(type == SIGNET_TYPE_ORG, "Corrupted signet type.\n");

	priv_signkey = dime_keys_signkey_fetch(filename_o);
	ck_assert_msg(priv_signkey != NULL, "Failure to fetch private signing key from file.\n");

	res = _ed25519_sign_data((const unsigned char *)to_sign, strlen(to_sign), priv_signkey, sigbuf);
	ck_assert_msg(res == 0, "Failure to sign data buffer.\n");

	pub_signkey = dime_sgnt_signkey_fetch(signet);
	ck_assert_msg(pub_signkey != NULL, "Failure to fetch public signing key from signet.\n");

	res = _ed25519_verify_sig((const unsigned char *)to_sign, strlen(to_sign), pub_signkey, sigbuf);
	ck_assert_msg(res = 1, "Failure to verify signature");

	priv_enckey = dime_keys_enckey_fetch(filename_o);
	ck_assert_msg(priv_enckey != NULL, "Failure to fetch private encryption key from file.\n");

	enc1_pub = _serialize_ec_pubkey(priv_enckey, &enc1_size);
	ck_assert_msg(enc1_pub != NULL, "Failure to serialize public portion of the private encryption key.\n");

	pub_enckey = dime_sgnt_enckey_fetch(signet);
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
	dime_sgnt_signet_destroy(signet);

/* creating ssr signet with keys */
	signet = dime_sgnt_signet_create_w_keys(SIGNET_TYPE_SSR, filename_s);
	ck_assert_msg(signet != NULL, "Failure to create SSR.\n");

	type = dime_sgnt_type_get(signet);
	ck_assert_msg(type == SIGNET_TYPE_SSR, "Corrupted signet type.\n");

	priv_signkey = dime_keys_signkey_fetch(filename_s);
	ck_assert_msg(priv_signkey != NULL, "Failure to fetch private signing key from file.\n");

	res = _ed25519_sign_data((const unsigned char *)to_sign, strlen(to_sign), priv_signkey, sigbuf);
	ck_assert_msg(res == 0, "Failure to sign data buffer.\n");

	pub_signkey = dime_sgnt_signkey_fetch(signet);
	ck_assert_msg(pub_signkey != NULL, "Failure to fetch public signing key from signet.\n");

	res = _ed25519_verify_sig((const unsigned char *)to_sign, strlen(to_sign), pub_signkey, sigbuf);
	ck_assert_msg(res = 1, "Failure to verify signature");

	priv_enckey = dime_keys_enckey_fetch(filename_s);
	ck_assert_msg(priv_enckey != NULL, "Failure to fetch private encryption key from file.\n");

	enc1_pub = _serialize_ec_pubkey(priv_enckey, &enc1_size);
	ck_assert_msg(enc1_pub != NULL, "Failure to serialize public portion of the private encryption key.\n");

	pub_enckey = dime_sgnt_enckey_fetch(signet);
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
	dime_sgnt_signet_destroy(signet);

/*creating invalid signet types*/
	signet = dime_sgnt_signet_create_w_keys(SIGNET_TYPE_ERROR, filename_w);
	ck_assert_msg(signet == NULL, "Unintended creation of signet with invalid type SIGNET_TYPE_ERROR.\n");
	ck_assert_msg(access(filename_w, F_OK) == -1, "Unintended creation of keys file for signet with invalid type SIGNET_TYPE_ERROR.\n");

	signet = dime_sgnt_signet_create_w_keys(31, filename_w);
	ck_assert_msg(signet == NULL, "Unintended creation of signet with invalid type 31.\n");
	ck_assert_msg(access(filename_w, F_OK) == -1, "Unintended creation of keys file for signet with invalid type 31.\n");

	fprintf(stderr, "Signet file keypair check completed.\n");
}
END_TEST

START_TEST(check_signet_modification)
{
	const char *phone1 = "1SOMENUMBER", *phone2 = "15124123529",
		*name1 = "check undef", *data1 = "undef data",
		*name2 = "check name", *data2 = "check check", *id = "thisid";
	char *idout;
	int res, count;
	signet_t *signet;
	size_t data_size;
	unsigned char *data;

	signet = dime_sgnt_signet_create(SIGNET_TYPE_ORG);
	ck_assert_msg(signet != NULL, "Failure to create signet.\n");

	res = dime_sgnt_field_undefined_create(signet, strlen(name1), (const unsigned char *)name1, strlen(data1), (const unsigned char *)data1);
	ck_assert_msg(res == 0, "Failure to create undefined field.\n");

	res = dime_sgnt_fid_exists(signet, SIGNET_ORG_UNDEFINED);
	ck_assert_msg(res == 1, "Failure to confirm existence of undefined field.\n");

	count = dime_sgnt_fid_count_get(signet, SIGNET_ORG_UNDEFINED);
	ck_assert_msg(count == 1, "Failure to count number of undefined fields.\n");

	data = dime_sgnt_field_undefined_fetch(signet, strlen(name1), (const unsigned char *)name1, &data_size);
	ck_assert_msg(data != NULL, "Failure to fetch undefined field.\n");
	ck_assert_msg(data_size == strlen(data1), "Corrupted undefined field size.\n");
	ck_assert_msg(memcmp(data, (unsigned char *)data1, data_size) == 0, "Corrupted undefined field data.\n");

	free(data);

	res = dime_sgnt_field_undefined_create(signet, strlen(name2), (const unsigned char *)name2, strlen(data2), (const unsigned char *)data2);
	ck_assert_msg(res == 0, "Failure to create undefined field.\n");

	count = dime_sgnt_fid_count_get(signet, SIGNET_ORG_UNDEFINED);
	ck_assert_msg(count == 2, "Failure to count number of undefined fields.\n");

	data = dime_sgnt_field_undefined_fetch(signet, strlen(name2), (const unsigned char*)name2, &data_size);
	ck_assert_msg(data != NULL, "Failure to fetch undefined field.\n");
	ck_assert_msg(data_size == strlen(data2), "Corrupted undefined field size.\n");
	ck_assert_msg(memcmp(data, (unsigned char *)data2, data_size) == 0, "Corrupted undefined field data.\n");

	free(data);

	res = dime_sgnt_id_set(signet, strlen(id), (unsigned char const *)id);
	ck_assert_msg(data == 0, "Failed to set id of signet.\n");

	idout = dime_sgnt_id_fetch(signet);
	ck_assert_msg(idout != NULL, "Failed o retrieve id of signet.\n");

	res = (strlen(idout) == strlen(id));
	ck_assert_msg(res == 0, "Setting and retrieving signet id corrupted its size.\n");

	res = memcmp(idout, id, strlen(id));
	ck_assert_msg(res == 0, "Setting and retrieving signet id corrupted its data.\n");

	res = dime_sgnt_field_undefined_remove(signet, strlen(name1), (const unsigned char *)name1);
	ck_assert_msg(res == 0, "Failure to remove undefined field.\n");

	count = dime_sgnt_fid_count_get(signet, SIGNET_ORG_UNDEFINED);
	ck_assert_msg(count == 1, "Failure to count number of undefined fields.\n");

	data = dime_sgnt_field_undefined_fetch(signet, strlen(name1), (const unsigned char *)name1, &data_size);
	ck_assert_msg(data == NULL, "Unintended existence of undefined field after removal.\n");

	data = dime_sgnt_field_undefined_fetch(signet, strlen(name2), (const unsigned char *)name2, &data_size);
	ck_assert_msg(data != NULL, "Failure to fetch undefined field.\n");
	ck_assert_msg(data_size == strlen(data2), "Corrupted undefined field size.\n");
	ck_assert_msg(memcmp(data, (unsigned char *)data2, data_size) == 0, "Corrupted undefined field data.\n");

	free(data);

	res = dime_sgnt_field_defined_set(signet, SIGNET_ORG_PHONE, strlen(phone1), (const unsigned char *)phone1);
	ck_assert_msg(res == 0, "Failure to create phone number field.\n");

	res = dime_sgnt_fid_exists(signet, SIGNET_ORG_PHONE);
	ck_assert_msg(res == 1, "Failure to confirm existence of phone number field.\n");

	count = dime_sgnt_fid_count_get(signet, SIGNET_ORG_PHONE);
	ck_assert_msg(count == 1, "Failure to count number of org phone fields.\n");

	data = dime_sgnt_fid_num_fetch(signet, SIGNET_ORG_PHONE, 1, &data_size);
	ck_assert_msg(data != NULL, "Failure to fetch phone number field");
	ck_assert_msg(data_size == strlen(phone1), "Corrupted phone number field size.\n");
	ck_assert_msg(memcmp(data, (unsigned char *)phone1, data_size) == 0, "Corrupted phone number field data.\n");

	free(data);

	res = dime_sgnt_field_defined_create(signet, SIGNET_ORG_PHONE, strlen(phone2), (const unsigned char *)phone2);
	ck_assert_msg(res == 0, "Failure to create phone number field.\n");

	count = dime_sgnt_fid_count_get(signet, SIGNET_ORG_PHONE);
	ck_assert_msg(count == 2, "Failure to count number of org phone fields.\n");

	data = dime_sgnt_fid_num_fetch(signet, SIGNET_ORG_PHONE, 2, &data_size);
	ck_assert_msg(data != NULL, "Failure to fetch phone number field.\n");
	ck_assert_msg(data_size == strlen(phone2), "Corrupted phone number field size.\n");
	ck_assert_msg(memcmp(data, (unsigned char *)phone2, data_size) == 0, "Corrupted phone number field data.\n");

	free(data);

	res = dime_sgnt_fid_num_remove(signet, SIGNET_ORG_PHONE, 1);
	ck_assert_msg(res == 0, "Failure to remove phone number field.\n");

	data = dime_sgnt_fid_num_fetch(signet, SIGNET_ORG_PHONE, 1, &data_size);
	ck_assert_msg(data != NULL, "Failure to fetch phone number field.\n");
	ck_assert_msg(data_size == strlen(phone2), "Corrupted phone number field size.\n");
	ck_assert_msg(memcmp(data, (unsigned char *)phone2, data_size) == 0, "Corrupted phone number field data.\n");

	free(data);
	dime_sgnt_signet_destroy(signet);

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

	sigone = dime_sgnt_signet_create(SIGNET_TYPE_ORG);
	dime_sgnt_field_defined_create(sigone, SIGNET_ORG_NAME, strlen(name), (const unsigned char *)name);
	dime_sgnt_field_defined_create(sigone, SIGNET_ORG_PHONE, strlen(phone1), (const unsigned char *)phone1);
	dime_sgnt_field_defined_create(sigone, SIGNET_ORG_PHONE, strlen(phone2), (const unsigned char *)phone2);
	dime_sgnt_field_undefined_create(sigone, strlen(name1), (const unsigned char *)name1, strlen(data1), (const unsigned char *)data1);
	dime_sgnt_field_undefined_create(sigone, strlen(name2), (const unsigned char *)name2, strlen(data2), (const unsigned char *)data2);
	dime_sgnt_field_undefined_create(sigone, strlen(name3), (const unsigned char *)name3, strlen(data3), (const unsigned char *)data3);

	ser_sigone = dime_sgnt_signet_binary_serialize(sigone, &len);
	ck_assert_msg(ser_sigone != NULL, "Failure to serialize signet.\n");

	sigtwo = dime_sgnt_signet_binary_deserialize(ser_sigone, len);
	ck_assert_msg(sigtwo != NULL, "Failure to deserialize signet.\n");

	ser_sigtwo = dime_sgnt_signet_binary_serialize(sigtwo, &len);
	ck_assert_msg(ser_sigtwo != NULL, "Failure to re-serialized the signet.\n");
	ck_assert_msg(memcmp(ser_sigone, ser_sigtwo, len) == 0, "Corrupted serialized signet data.\n");

	free(ser_sigone);
	free(ser_sigtwo);
	dime_sgnt_signet_destroy(sigtwo);

	b64_sigone = dime_sgnt_signet_b64_serialize(sigone);
	ck_assert_msg(b64_sigone != NULL, "Failure to convert signet to base64 encoded string.\n");

	sigtwo = dime_sgnt_signet_b64_deserialize(b64_sigone);
	ck_assert_msg(sigtwo != NULL, "Failure to convert base64 string to signet.\n");

	b64_sigtwo = dime_sgnt_signet_b64_serialize(sigtwo);
	ck_assert_msg(b64_sigtwo != NULL, "Failure to re-convert signet to base64 encoded string.\n");
	ck_assert_msg(strcmp(b64_sigone, b64_sigtwo) == 0, "Corrupted base64 string signet data.\n");

	free(b64_sigtwo);
	dime_sgnt_signet_destroy(sigtwo);

	res = dime_sgnt_file_create(sigone, filename);
	ck_assert_msg(res == 0, "Failure to write signet to file.\n");

	sigtwo = dime_sgnt_signet_load(filename);
	ck_assert_msg(sigtwo != NULL, "Failure to read signet from file.\n");

	res = dime_sgnt_file_create(sigtwo, filename);
	ck_assert_msg(res == 0, "Failure to re-write signet to file.\n");

	b64_sigtwo = _read_pem_data(filename, SIGNET_PEM_TAG, 1);
	ck_assert_msg(b64_sigtwo != NULL, "Failure to read b64 string from signet file.\n");
	ck_assert_msg(strcmp(b64_sigone, b64_sigtwo) == 0, "Corrupted signet file data.\n");

	free(b64_sigone);
	free(b64_sigtwo);
	dime_sgnt_signet_destroy(sigtwo);
	dime_sgnt_signet_destroy(sigone);

	fprintf(stderr, "Signet parsing check complete.\n");
}
END_TEST

START_TEST(check_signet_validation)
{
	const char *org_keys = "check_org.keys", *user_keys = "check_user.keys", *newuser_keys = "check_newuser.keys";
	ED25519_KEY *orgkey, *userkey, **keys_obj;
	int res;
	signet_state_t state;
	signet_t *org_signet, *user_signet, *newuser_signet, *split, *split2;
	unsigned char **org_signet_sign_keys;
	size_t keysnum = 1;

	_crypto_init();
//create org signet and keys file
	org_signet = dime_sgnt_signet_create_w_keys(SIGNET_TYPE_ORG, org_keys);
	ck_assert_msg(org_signet != NULL, "Failure to create signet with keys file.\n");
//retrieve org private signing key
	orgkey = dime_keys_signkey_fetch(org_keys);
	//ck_assert_msg(orgkey != NULL, "Failure to fetch private signing key from keys file.\n");
//sign org cryptographic signet signature
	res = dime_sgnt_sig_crypto_sign(org_signet, orgkey);
	//ck_assert_msg(res == 0, "Failure to create organizational cryptographic signet signature.\n");
//retrieve the list of all org signet-signing keys (note we're using this instead of retrieving the list of POKs from the dime record just to have a list of keys, 1 of which will be valid.)
	keys_obj = dime_sgnt_signkeys_signet_fetch(org_signet);
	res = dime_sgnt_sig_crypto_sign(org_signet, orgkey);
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
	ck_assert_msg(state == SS_CRYPTO, "Failure to correctly validate organizational signet as a cryptographic signet.\n");
//sign org full signet signature
	res = dime_sgnt_sig_full_sign(org_signet, orgkey);
	ck_assert_msg(res == 0, "Failure to create organizational full signet signature.\n");
//verify that the org full signet is valid
	state = dime_sgnt_validate_all(org_signet, NULL, NULL, (const unsigned char **)org_signet_sign_keys);
	ck_assert_msg(state == SS_FULL, "Failure to correctly validate organizational signet as a full signet.\n");
//set organizational signet id
	res = dime_sgnt_id_set(org_signet, strlen("test_org_signet"), (const unsigned char *)"test_org_signet");
	ck_assert_msg(res == 0, "Failure to set organizational signet id.\n");
//sign identified signet signature
	res = dime_sgnt_sig_id_sign(org_signet, orgkey);
	ck_assert_msg(res == 0, "Failure to create organizational identifiable signet signature field.\n");
//verify that the org signet is a valid identifiable signet
	state = dime_sgnt_validate_all(org_signet, NULL, NULL, (const unsigned char **)org_signet_sign_keys);
	ck_assert_msg(state == SS_ID, "Failure to correctly validate organizational signet as an identifiable signet.\n");
//create ssr signet and user keys file
	user_signet = dime_sgnt_signet_create_w_keys(SIGNET_TYPE_SSR, user_keys);
	ck_assert_msg(user_signet != NULL, "Failure to create ssr with keys file.\n");
//retrieve user private signing key
	userkey = dime_keys_signkey_fetch(user_keys);
	ck_assert_msg(userkey != NULL, "Failure to fetch user's private signing key from keys file.\n");
//sign the ssr signature with user keys
	res = dime_sgnt_sig_ssr_sign(user_signet, userkey);
	ck_assert_msg(res == 0, "Failure to sign ssr with the user's private signing key.\n");
//verify that the signet is a valid ssr
	state = dime_sgnt_validate_all(user_signet, NULL, NULL, NULL);
	ck_assert_msg(state == SS_SSR, "Failure to correctly validate ssr.\n");
//sign ssr with org signing key
	res = dime_sgnt_sig_crypto_sign(user_signet, orgkey);
	ck_assert_msg(res == 0, "Failure to sign ssr into a user cryptographic signet using organizational private signing key.\n");
//verify that the signet is now a valid user core signet
	state = dime_sgnt_validate_all(user_signet, NULL, org_signet, NULL);
	ck_assert_msg(state == SS_CRYPTO, "Failure to correctly validate user cryptographic signet.\n");
//sign the full signature with org key
	res = dime_sgnt_sig_full_sign(user_signet, orgkey);
	ck_assert_msg(res == 0, "Failure to sign user signet with the full signet signature.\n");
//verify that the user signet is now a valid core signet
	state = dime_sgnt_validate_all(user_signet, NULL, org_signet, NULL);
	ck_assert_msg(state == SS_FULL, "Failure to correctly validate user full signet.\n");
//set user signet id (address)
	res = dime_sgnt_id_set(user_signet, strlen("user@test.org"), (const unsigned char *)"user@test.org");
	ck_assert_msg(res == 0, "Failure to set user signet id.\n");
//sign the user signature with the identifiable signet signature
	res = dime_sgnt_sig_id_sign(user_signet, orgkey);
	ck_assert_msg(res == 0, "Failure to sign user signet with the identifiable signet signature.\n");
//verify that the user signet is a valid full signet
	state = dime_sgnt_validate_all(user_signet, NULL, org_signet, NULL);
	ck_assert_msg(state == SS_ID, "Failure to correctly validate user identifiable signet.\n");
//create new ssr and keys file
	newuser_signet = dime_sgnt_signet_create_w_keys(SIGNET_TYPE_SSR, newuser_keys);
	ck_assert_msg(newuser_signet != NULL, "Failure to create ssr with keys file.\n");
//sign the new ssr with a chain of custody signature using the user's old signing key
	res = dime_sgnt_sig_coc_sign(newuser_signet, userkey);
	ck_assert_msg(res == 0, "Failure to create the chain of custody signature.\n");

	_free_ed25519_key(userkey);

//retrieve user's new private signing key
	userkey = dime_keys_signkey_fetch(newuser_keys);
	ck_assert_msg(userkey != NULL, "Failure to retrieve user's new private signing key.\n");
//perform all the signatures on the new ssr (adding an address as the id is required for the identifiable signet signature.
	dime_sgnt_sig_ssr_sign(newuser_signet, userkey);
	dime_sgnt_sig_crypto_sign(newuser_signet, orgkey);
	dime_sgnt_sig_full_sign(newuser_signet, orgkey);
	dime_sgnt_id_set(newuser_signet, strlen("user@test.com"), (const unsigned char *)"user@test.com");
	dime_sgnt_sig_id_sign(newuser_signet, orgkey);
//Confirm that without using the previous signet to verify the chain of custody, the signet validation returns broken chain of custody
	state = dime_sgnt_validate_all(newuser_signet, NULL, org_signet, NULL);
	ck_assert_msg(state == SS_BROKEN_COC, "Failure to invalidate signet due to no parent signet being provided to validate chain of custody signature.\n");
//Config that by using the previous signet to verify chain of custody, the new user signet is validate as identifiable signet.
//TODO it may be necessary to test intermediate states with presence of chain of custody also
	state = dime_sgnt_validate_all(newuser_signet, user_signet, org_signet, NULL);
	ck_assert_msg(state == SS_ID, "Failure to validate an identifiable signet with a chain of custody signature.\n");

//Now, lets test splitting.
	split = dime_sgnt_signet_full_split(newuser_signet);
	ck_assert_msg(split != NULL, "Failed to split identifiable user signet into a full user signet.\n");

	dime_sgnt_signet_destroy(newuser_signet);

	state = dime_sgnt_validate_all(split, user_signet, org_signet, NULL);
	ck_assert_msg(state == SS_FULL, "Failure to validate full user signet with chain of custody.\n");

	split2 = dime_sgnt_signet_crypto_split(split);
	ck_assert_msg(split2 != NULL, "Failed to split full user signet into a cryptographic user signet.\n");

	dime_sgnt_signet_destroy(split);

	state = dime_sgnt_validate_all(split2, user_signet, org_signet, NULL);
	ck_assert_msg(state = SS_CRYPTO, "Failure to validate cryptographic user signet with chain of custody.\n");

	dime_sgnt_signet_destroy(split2);

	_ptr_chain_free(org_signet_sign_keys);
	_free_ed25519_key_chain(keys_obj);
	_free_ed25519_key(orgkey);
	_free_ed25519_key(userkey);
	dime_sgnt_signet_destroy(user_signet);
	dime_sgnt_signet_destroy(org_signet);

	fprintf(stderr, "Signet signing and validation check complete.\n");
}
END_TEST

START_TEST(check_signet_sok)
{

	ED25519_KEY *sok, *sok_from_signet;
	int res;
	signet_t *signet;

	_crypto_init();

	signet = dime_sgnt_signet_create(SIGNET_TYPE_USER);
	ck_assert_msg(signet != NULL, "Failure to create user signet.\n");

	sok = generate_ed25519_keypair();
	ck_assert_msg(sok != NULL, "Failure to generate ed25519 key pair.\n");

	res = dime_sgnt_sok_create(signet, sok, (unsigned char) SIGNKEY_DEFAULT_FORMAT, (SIGNET_SOK_SIGNET | SIGNET_SOK_MSG | SIGNET_SOK_TLS | SIGNET_SOK_SOFTWARE) );
	ck_assert_msg(res == -1, "Error cause by inserting a SOK inside a user signet.\n");

	dime_sgnt_signet_destroy(signet);

	signet = dime_sgnt_signet_create(SIGNET_TYPE_ORG);
	ck_assert_msg(signet != NULL, "Failure to create organizational signet.\n");

	res = dime_sgnt_sok_create(signet, sok, 214, (SIGNET_SOK_SIGNET | SIGNET_SOK_MSG) );
	ck_assert_msg(res == -1, "Error caused by inserting a SOK with an invalid format.\n");

	res = dime_sgnt_sok_create(signet, sok, (unsigned char) SIGNKEY_DEFAULT_FORMAT, (SIGNET_SOK_SIGNET | SIGNET_SOK_MSG | SIGNET_SOK_TLS | SIGNET_SOK_SOFTWARE) );
	ck_assert_msg(res == 0, "Failure to add a SOK field to signet.\n");

	sok_from_signet = dime_sgnt_sok_num_fetch(signet, 1);
	ck_assert_msg(sok_from_signet != NULL, "Failure to fetch SOK from signet.\n");

	res = memcmp(sok->public_key, sok_from_signet->public_key, ED25519_KEY_SIZE);
	ck_assert_msg(res == 0, "SOK was corrupted during inserting and fetching into and from the signet.\n");

	free_ed25519_key(sok_from_signet);
	dime_sgnt_signet_destroy(signet);

	fprintf(stderr, "Signet SOK check complete.\n");
}
END_TEST

START_TEST(check_signet_multi_signkey)
{

	EC_KEY *eckey;
	ED25519_KEY *keys[5], **fetched;
	int res;
	signet_t *signet;

	_crypto_init();

	for(int i = 0; i < 5; ++i) {
		keys[i] = generate_ed25519_keypair();
	}

	eckey = generate_ec_keypair(0);

	signet = dime_sgnt_signet_create(SIGNET_TYPE_ORG);
	ck_assert_msg(signet != NULL, "Failed to create organizational signet.\n");

	res = dime_sgnt_signkey_set(signet, keys[0], SIGNKEY_DEFAULT_FORMAT);
	ck_assert_msg(res == 0, "Failed to set signet POK.\n");

	res += dime_sgnt_sok_create(signet, keys[1], SIGNKEY_DEFAULT_FORMAT, SIGNET_SOK_SIGNET);
	ck_assert_msg(res == 0, "Failed to create SOK 1.\n");

	res += dime_sgnt_sok_create(signet, keys[2], SIGNKEY_DEFAULT_FORMAT, SIGNET_SOK_MSG);
	ck_assert_msg(res == 0, "Failed to create SOK 2.\n");

	res += dime_sgnt_sok_create(signet, keys[3], SIGNKEY_DEFAULT_FORMAT, SIGNET_SOK_TLS);
	ck_assert_msg(res == 0, "Failed to create SOK 3.\n");

	res += dime_sgnt_sok_create(signet, keys[4], SIGNKEY_DEFAULT_FORMAT, SIGNET_SOK_SOFTWARE);
	ck_assert_msg(res == 0, "Failed to create SOK 4.\n");

	res = dime_sgnt_enckey_set(signet, eckey, 0);
	ck_assert_msg(res == 0, "Failed to set signet encryption key.\n");

	free_ec_key(eckey);

	res = dime_sgnt_sig_crypto_sign(signet, keys[0]);
	ck_assert_msg(res == 0, "Failed to sign organizational signet with its private POK.\n");

	fetched = dime_sgnt_signkeys_signet_fetch(signet);
	ck_assert_msg( (fetched != NULL), "Failed to fetch signing keys.\n");
	ck_assert_msg( (fetched[0] != NULL), "Failed to fetch signing keys.\n");
	ck_assert_msg( (fetched[1] != NULL), "Failed to fetch signing keys.\n");
	ck_assert_msg( (fetched[2] == NULL), "Failed to fetch signing keys.\n");

	res = memcmp(fetched[0]->public_key, keys[0]->public_key, ED25519_KEY_SIZE);
	ck_assert_msg(res == 0, "POK was corrupted.\n");
	
	res = memcmp(fetched[1]->public_key, keys[1]->public_key, ED25519_KEY_SIZE);
	ck_assert_msg(res == 0, "SOK 1 was corrupted.\n");

	free_ed25519_key_chain(fetched);
	fetched = NULL;
	fetched = dime_sgnt_signkeys_msg_fetch(signet);
	ck_assert_msg( (fetched != NULL) && 
                       (fetched[0] != NULL) && 
                       (fetched[1] != NULL) && 
                       (fetched[2] == NULL), "Failed to fetch signing keys.\n");
	res = memcmp(fetched[0]->public_key, keys[0]->public_key, ED25519_KEY_SIZE);
	ck_assert_msg(res == 0, "POK was corrupted.\n");

	res = memcmp(fetched[1]->public_key, keys[2]->public_key, ED25519_KEY_SIZE);
	ck_assert_msg(res == 0, "SOK 2 was corrupted.\n");

	free_ed25519_key_chain(fetched);
	fetched = NULL;

	fetched = dime_sgnt_signkeys_tls_fetch(signet);
	ck_assert_msg( (fetched != NULL) && 
                       (fetched[0] != NULL) && 
                       (fetched[1] != NULL) && 
                       (fetched[2] == NULL), "Failed to fetch signing keys.\n");

	res = memcmp(fetched[0]->public_key, keys[0]->public_key, ED25519_KEY_SIZE);
	ck_assert_msg(res == 0, "POK was corrupted.\n");
	
	res = memcmp(fetched[1]->public_key, keys[3]->public_key, ED25519_KEY_SIZE);
	ck_assert_msg(res == 0, "SOK 3 was corrupted.\n");
	
	free_ed25519_key_chain(fetched);
	fetched = NULL;

	fetched = dime_sgnt_signkeys_software_fetch(signet);
	ck_assert_msg( (fetched != NULL) && 
                       (fetched[0] != NULL) && 
                       (fetched[1] != NULL) && 
                       (fetched[2] == NULL), "Failed to fetch signing keys.\n");

	res = memcmp(fetched[0]->public_key, keys[0]->public_key, ED25519_KEY_SIZE);
	ck_assert_msg(res == 0, "POK was corrupted.\n");
	
	res = memcmp(fetched[1]->public_key, keys[4]->public_key, ED25519_KEY_SIZE);
	ck_assert_msg(res == 0, "SOK 4 was corrupted.\n");
	
	free_ed25519_key_chain(fetched);
	fetched = NULL;

	for(int i = 0; i < 5; ++i) {
		free_ed25519_key(keys[i]);
	}

	dime_sgnt_signet_destroy(signet);

	fprintf(stderr, "Signet selective signing key multi-fetching check complete.\n");
}
END_TEST

START_TEST(check_signet_fingerprint)
{
	char *fp1, *fp2;
	int res;
	signet_t *signet;

	_crypto_init();

	signet = dime_sgnt_signet_create_w_keys(SIGNET_TYPE_USER, "fp_test.keys");
	ck_assert_msg(signet != NULL, "Failed to create signet with keys.\n");

	fp1 = dime_sgnt_fingerprint_ssr(signet);
	ck_assert_msg(signet != NULL, "Failed to fingerprint signet.\n");

	fp2 = dime_sgnt_fingerprint_ssr(signet);
	ck_assert_msg(signet != NULL, "Failed to fingerprint signet.\n");

	ck_assert_msg(strlen(fp1) == strlen(fp2), "Inconsistent fingerprinting.\n");

	res = memcmp(fp1, fp2, strlen(fp1));
	ck_assert_msg(res == 0, "Inconsistent fingerprinting.\n");

	free(fp2);

	fp2 = dime_sgnt_fingerprint_crypto(signet);
	ck_assert_msg(signet != NULL, "Failed to fingerprint signet.\n");

	ck_assert_msg(strlen(fp1) == strlen(fp2), "Inconsistent fingerprinting.\n");

	res = memcmp(fp1, fp2, strlen(fp1));
	ck_assert_msg(res == 0, "Inconsistent fingerprinting.\n");
	
	free(fp2);

	fp2 = dime_sgnt_fingerprint_full(signet);
	ck_assert_msg(signet != NULL, "Failed to fingerprint signet.\n");

	ck_assert_msg(strlen(fp1) == strlen(fp2), "Inconsistent fingerprinting.\n");

	res = memcmp(fp1, fp2, strlen(fp1));
	ck_assert_msg(res == 0, "Inconsistent fingerprinting.\n");
	
	free(fp2);

	fp2 = dime_sgnt_fingerprint_id(signet);
	ck_assert_msg(signet != NULL, "Failed to fingerprint signet.\n");

	ck_assert_msg(strlen(fp1) == strlen(fp2), "Inconsistent fingerprinting.\n");

	res = memcmp(fp1, fp2, strlen(fp1));
	ck_assert_msg(res == 0, "Inconsistent fingerprinting.\n");
	
	free(fp2);

	res = dime_sgnt_id_set(signet, 7, (const unsigned char *)"some id");
	ck_assert_msg(res == 0, "Failed to set signet id.\n");

	fp2 = dime_sgnt_fingerprint_id(signet);
	ck_assert_msg(signet != NULL, "Failed to fingerprint signet.\n");

	ck_assert_msg(strlen(fp1) == strlen(fp2), "Inconsistent fingerprinting.\n");

	res = memcmp(fp1, fp2, strlen(fp1));
	ck_assert_msg(res != 0, "Either a sha512 hash collision occurred or fingerprinting is broken.\n");
	
	free(fp2);
	free(fp1);
	dime_sgnt_signet_destroy(signet);
	
	fprintf(stderr, "Signet fingerprinting check complete.\n");
}
END_TEST

START_TEST(check_signet_signature_verification)
{
	char *fp;
	const char *org_keys = "check_org.keys";
	unsigned char signature[ED25519_SIG_SIZE];
	ED25519_KEY *orgkey;
	int res;
	signet_t *org_signet;

	_crypto_init();

	org_signet = dime_sgnt_signet_create_w_keys(SIGNET_TYPE_ORG, org_keys);
	ck_assert_msg(org_signet != NULL, "Failure to create signet with keys file.\n");

	orgkey = dime_keys_signkey_fetch(org_keys);
	ck_assert_msg(orgkey != NULL, "Failure to fetch private signing key from keys file.\n");

	res = dime_sgnt_sig_crypto_sign(org_signet, orgkey);
	ck_assert_msg(res == 0, "Failure to create organizational cryptographic signet signature.\n");

	fp = dime_sgnt_fingerprint_crypto(org_signet);
	ck_assert_msg(fp != NULL, "Failed to fingerprint organiational signet.\n");

	res = ed25519_sign_data((const unsigned char *)fp, strlen(fp), orgkey, signature);
	ck_assert_msg(res == 0, "Failed to provided data with ed25519 key.\n");

	res = dime_sgnt_msg_sig_verify(org_signet, signature, (const unsigned char *)fp, strlen(fp));
	ck_assert_msg(res == 1, "Failed to verify signature using signet.\n");

	fprintf(stderr, "Signet signature verification check complete.\n");
}
END_TEST

Suite *suite_check_signet(void) {

	Suite *s = suite_create("\nSignet");
	suite_add_test(s, "check signet creation", check_signet_creation);
	suite_add_test(s, "check signet and keys file pair cryptography", check_signet_keys_pairing);
	suite_add_test(s, "check signet creation and field modification", check_signet_modification);
	suite_add_test(s, "check signet parsing, serialization, deserialization", check_signet_parsing);
	suite_add_test(s, "check signet signing and validation", check_signet_validation);
	suite_add_test(s, "check signet sok creation", check_signet_sok);
	suite_add_test(s, "check signet selective signing key fetching", check_signet_multi_signkey);
	suite_add_test(s, "check signet fingerprinting", check_signet_fingerprint);
	suite_add_test(s, "check signet signature verification", check_signet_signature_verification);
	return s;
}
