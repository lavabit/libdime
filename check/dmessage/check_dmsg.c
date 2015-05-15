#include "signet/keys.h"
#include "signet/signet.h"
#include "dmessage/dmime.h"
#include "dmessage/parser.h"
#include "dmessage/dmsg.h"
#include "checks.h"

/**
 * Demonstrates how a message travels from the author to the recipient.
 */
START_TEST(test_message_encryption)
{
	EC_KEY *auth_enckey, *orig_enckey, *dest_enckey, *recp_enckey;
	ED25519_KEY *auth_signkey, *orig_signkey, *dest_signkey, *recp_signkey;
	const char *auth = "ivan@darkmail.info", *orig = "darkmail.info", *dest = "lavabit.com", *recp = "ryan@lavabit.com";
	const char *auth_keys = "auth.keys", *orig_keys = "orig.keys", *dest_keys = "dest.keys", *recp_keys = "recp.keys";
	const char *common_date = "12 minutes ago";
	const char *common_to = "Ryan <ryan@lavabit.com>";
	const char *common_from = "Ivan <ivan@darkmail.info>";
	const char *common_subject = "Mr.Watson - Come here - I want to see you";
	const char *common_organization = "Lavabit";
	const char *other_headers = "SECRET METADATA\r\n";
	const char *display = "This is a test\r\nCan you read this?\r\n";
	dmime_kek_t orig_kek, dest_kek, recp_kek;
	dmime_message_t *message;
	dmime_object_t *draft, *at_orig, *at_dest, *at_recp;
	signet_t *signet_auth, *signet_orig, *signet_dest, *signet_recp;
	size_t from_auth_size, from_orig_size, from_dest_size;
	unsigned char *from_auth_bin, *from_orig_bin, *from_dest_bin;

	ck_assert_dime_noerror();
	_crypto_init();
	ck_assert_dime_noerror();

	memset(&orig_kek, 0, sizeof(dmime_kek_t));
	memset(&dest_kek, 0, sizeof(dmime_kek_t));
	memset(&recp_kek, 0, sizeof(dmime_kek_t));


	//create domain signets
	signet_orig = dime_sgnt_create_signet_w_keys(SIGNET_TYPE_ORG, orig_keys);
	signet_dest = dime_sgnt_create_signet_w_keys(SIGNET_TYPE_ORG, dest_keys);
	ck_assert_dime_noerror();

	//create user signet signing requests
	signet_auth = dime_sgnt_create_signet_w_keys(SIGNET_TYPE_SSR, auth_keys);
	signet_recp = dime_sgnt_create_signet_w_keys(SIGNET_TYPE_SSR, recp_keys);
	ck_assert_dime_noerror();

	// retrieve all signing and encryption private keys ahead of time
	orig_enckey = dime_keys_fetch_enc_key(orig_keys);
	dest_enckey = dime_keys_fetch_enc_key(dest_keys);
	auth_enckey = dime_keys_fetch_enc_key(auth_keys);
	recp_enckey = dime_keys_fetch_enc_key(recp_keys);
	ck_assert_dime_noerror();

	orig_signkey = dime_keys_fetch_sign_key(orig_keys);
	dest_signkey = dime_keys_fetch_sign_key(dest_keys);
	auth_signkey = dime_keys_fetch_sign_key(auth_keys);
	recp_signkey = dime_keys_fetch_sign_key(recp_keys);
	ck_assert_dime_noerror();

	// sign domain signets with cryptographic signet signature
	dime_sgnt_sign_crypto_sig(signet_orig, orig_signkey);
	dime_sgnt_sign_crypto_sig(signet_dest, dest_signkey);
	ck_assert_dime_noerror();

	// sign domain signets with full signet signature
	dime_sgnt_sign_full_sig(signet_orig, orig_signkey);
	dime_sgnt_sign_full_sig(signet_dest, dest_signkey);
	ck_assert_dime_noerror();

	//add domain ids to domain signets
	dime_sgnt_set_id_field(signet_orig, strlen(orig), (const unsigned char *)orig);
	dime_sgnt_set_id_field(signet_dest, strlen(dest), (const unsigned char *)dest);
	ck_assert_dime_noerror();

	//add final domain signet signature
	dime_sgnt_sign_id_sig(signet_orig, orig_signkey);
	dime_sgnt_sign_id_sig(signet_dest, dest_signkey);
	ck_assert_dime_noerror();

	//sign user ssr's with user user keys
	dime_sgnt_sign_ssr_sig(signet_auth, auth_signkey);
	dime_sgnt_sign_ssr_sig(signet_recp, recp_signkey);
	ck_assert_dime_noerror();

	//sign user ssr's with corresponding domain keys
	dime_sgnt_sign_crypto_sig(signet_auth, orig_signkey);
	dime_sgnt_sign_crypto_sig(signet_recp, dest_signkey);
	ck_assert_dime_noerror();

	//sign user signets with corresponding domain keys
	dime_sgnt_sign_full_sig(signet_auth, orig_signkey);
	dime_sgnt_sign_full_sig(signet_recp, dest_signkey);
	ck_assert_dime_noerror();

	//set user signet id's
	dime_sgnt_set_id_field(signet_auth, strlen(auth), (const unsigned char *)auth);
	dime_sgnt_set_id_field(signet_recp, strlen(recp), (const unsigned char *)recp);
	ck_assert_dime_noerror();

	//add final user signet signature with corresponding domain keys
	dime_sgnt_sign_id_sig(signet_auth, orig_signkey);
	dime_sgnt_sign_id_sig(signet_recp, dest_signkey);
	ck_assert_dime_noerror();


	//create object as a draft
	draft = malloc(sizeof(dmime_object_t));
	memset(draft, 0, sizeof(dmime_object_t));

	draft->common_headers = dime_prsr_headers_create();

	draft->actor = id_author;
	draft->author = st_import(auth, strlen(auth));
	draft->recipient = st_import(recp, strlen(recp));
	draft->origin = st_import(orig, strlen(orig));
	draft->destination = st_import(dest, strlen(dest));
	draft->signet_author = signet_auth;
	draft->signet_origin = signet_orig;
	draft->signet_destination = signet_dest;
	draft->signet_recipient = signet_recp;
	draft->common_headers->headers[HEADER_TYPE_DATE] = st_import(common_date, strlen(common_date));
	draft->common_headers->headers[HEADER_TYPE_FROM] = st_import(common_from, strlen(common_from));
	draft->common_headers->headers[HEADER_TYPE_ORGANIZATION] = st_import(common_organization, strlen(common_organization));
	draft->common_headers->headers[HEADER_TYPE_SUBJECT] = st_import(common_subject, strlen(common_subject));
	draft->common_headers->headers[HEADER_TYPE_TO] = st_import(common_to, strlen(common_to));
	draft->other_headers = st_import(other_headers, strlen(other_headers));
	draft->display = dime_dmsg_create_object_chunk(CHUNK_TYPE_DISPLAY_CONTENT, (unsigned char *)display, strlen(display), DEFAULT_CHUNK_FLAGS);
	ck_assert_dime_noerror();

	fprintf(stderr, "---BEGIN DRAFT---\n");
	fprintf(stderr, "---END DRAFT---\n");
	ck_assert_dime_noerror();

	// turn object into message by encrypting and serialize
	message = dime_dmsg_encrypt_message(draft, auth_signkey);
	from_auth_bin = dime_dmsg_serial_from_message(message, 0xFF, 0, &from_auth_size);
	ck_assert_dime_noerror();

	//destroy message and deserialize it again from the serialized form as if it was received over wire by the origin
	dime_dmsg_destroy_message(message);
	message = dime_dmsg_serial_to_message(from_auth_bin, from_auth_size);
	ck_assert_dime_noerror();

	//decrypt message as origin
	dime_dmsg_kek_derive_in(message, orig_enckey, &orig_kek);
	ck_assert_dime_noerror();

	at_orig = dime_dmsg_decrypt_envelope(message, id_origin, &orig_kek);
	ck_assert_dime_noerror();
	at_orig->signet_author = signet_auth;
	at_orig->signet_destination = signet_dest;
	at_orig->origin = st_import(orig, strlen(orig));
	at_orig->signet_origin = signet_orig;
	dime_dmsg_decrypt_message_as_orig(at_orig, message, &orig_kek);
	ck_assert_dime_noerror();

	fprintf(stderr, "---BEGIN AT-ORIG---\n");
	fprintf(stderr, "---END AT-ORIG---\n");

	//Add origin signatures and serialize the message again
	dime_dmsg_sign_origin_sig_chunks(message, (META_BOUNCE | DISPLAY_BOUNCE), &orig_kek, orig_signkey);
	from_orig_bin = dime_dmsg_serial_from_message(message, 0xFF, 0, &from_orig_size);
	ck_assert_dime_noerror();

	//destroy message and deserialize it again from the serialized form as if it was received over wire by the destination
	dime_dmsg_destroy_message(message);
	message = dime_dmsg_serial_to_message(from_orig_bin, from_orig_size);
	ck_assert_dime_noerror();

	//decrypt message as destination
	dime_dmsg_kek_derive_in(message, dest_enckey, &dest_kek);
	at_dest = dime_dmsg_decrypt_envelope(message, id_destination, &dest_kek);
	ck_assert_dime_noerror();
	at_dest->signet_origin = signet_orig;
	at_dest->signet_recipient = signet_recp;
	at_dest->destination = st_import(dest, strlen(dest));
	at_dest->signet_destination = signet_dest;
	dime_dmsg_decrypt_message_as_dest(at_dest, message, &dest_kek);

	fprintf(stderr, "---BEGIN AT-DEST---\n");
	fprintf(stderr, "---END AT-DEST---\n");
	ck_assert_dime_noerror();

	//Serialize the message again
	from_dest_bin = dime_dmsg_serial_from_message(message, 0xFF, 0, &from_dest_size);
	ck_assert_dime_noerror();

	//destroy message and deserialize it again from the serialized form as if it was received over wire by the recipient
	dime_dmsg_destroy_message(message);
	message = dime_dmsg_serial_to_message(from_dest_bin, from_dest_size);
	ck_assert_dime_noerror();

	//decrypt message as recipient
	dime_dmsg_kek_derive_in(message, recp_enckey, &recp_kek);
	at_recp = dime_dmsg_decrypt_envelope(message, id_recipient, &recp_kek);
	ck_assert_dime_noerror();
	at_recp->signet_author = signet_auth;
	at_recp->signet_origin = signet_orig;
	at_recp->signet_destination = signet_dest;
	at_recp->signet_recipient = signet_recp;
	dime_dmsg_decrypt_message_as_recp(at_recp, message, &recp_kek);

	//destroy everything
	dime_sgnt_destroy_signet(signet_auth);
	dime_sgnt_destroy_signet(signet_orig);
	dime_sgnt_destroy_signet(signet_dest);
	dime_sgnt_destroy_signet(signet_recp);

	dime_dmsg_destroy_message(message);

	dime_dmsg_destroy_object(draft);
	dime_dmsg_destroy_object(at_orig);
	dime_dmsg_destroy_object(at_dest);
	dime_dmsg_destroy_object(at_recp);

	_free_ec_key(auth_enckey);
	_free_ec_key(orig_enckey);
	_free_ec_key(dest_enckey);
	_free_ec_key(recp_enckey);

	_free_ed25519_key(auth_signkey);
	_free_ed25519_key(orig_signkey);
	_free_ed25519_key(dest_signkey);
	_free_ed25519_key(recp_signkey);

	free(from_auth_bin);
	free(from_orig_bin);
	free(from_dest_bin);
	ck_assert_dime_noerror();
}
END_TEST

Suite *suite_check_dmsg(void) {

	Suite *s = suite_create("signet");
	suite_add_test(s, "message creation and encryption", test_message_encryption);
	return s;
}
