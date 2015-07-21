#include "signet/keys.h"
#include "signet/signet.h"
#include "dmessage/dmime.h"
#include "dmessage/parser.h"
#include "dmessage/dmsg.h"
#include "checks.h"

/**
 * Demonstrates how a message travels from the author to the recipient.
 */
START_TEST(check_dmsg_all)
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
	int res;
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
	signet_orig = dime_sgnt_signet_create_w_keys(SIGNET_TYPE_ORG, orig_keys);
	ck_assert_msg(signet_orig != NULL, "Failed to create origin signet.\n");
	signet_dest = dime_sgnt_signet_create_w_keys(SIGNET_TYPE_ORG, dest_keys);
	ck_assert_msg(signet_dest != NULL, "Failed to create destination signet.\n");

	//create user signet signing requests
	signet_auth = dime_sgnt_signet_create_w_keys(SIGNET_TYPE_SSR, auth_keys);
	ck_assert_msg(signet_auth != NULL, "Failed to create author signet.\n");
	signet_recp = dime_sgnt_signet_create_w_keys(SIGNET_TYPE_SSR, recp_keys);
	ck_assert_msg(signet_recp != NULL, "Failed to create recipeint signet.\n");
	ck_assert_dime_noerror();

	// retrieve all signing and encryption private keys ahead of time
	orig_enckey = dime_keys_enckey_fetch(orig_keys);
	ck_assert_msg(orig_enckey != NULL, "Failed to retrieve origin encryption keys.\n");
	dest_enckey = dime_keys_enckey_fetch(dest_keys);
	ck_assert_msg(dest_enckey != NULL, "Failed to retrieve destination encryption keys.\n");
	auth_enckey = dime_keys_enckey_fetch(auth_keys);
	ck_assert_msg(auth_enckey != NULL, "Failed to retrieve author encryption keys.\n");
	recp_enckey = dime_keys_enckey_fetch(recp_keys);
	ck_assert_msg(recp_enckey != NULL, "Failed to retrieve recipient encryption keys.\n");
	ck_assert_dime_noerror();

	orig_signkey = dime_keys_signkey_fetch(orig_keys);
	ck_assert_msg(orig_signkey != NULL, "Failed to retrieve origin signing keys.\n");
	dest_signkey = dime_keys_signkey_fetch(dest_keys);
	ck_assert_msg(dest_signkey != NULL, "Failed to retrieve destination signing keys.\n");
	auth_signkey = dime_keys_signkey_fetch(auth_keys);
	ck_assert_msg(auth_signkey != NULL, "Failed to retrieve author signing keys.\n");
	recp_signkey = dime_keys_signkey_fetch(recp_keys);
	ck_assert_msg(recp_signkey != NULL, "Failed to retrieve recipient signing keys.\n");

	ck_assert_dime_noerror();

	// sign domain signets with cryptographic signet signature
	res = dime_sgnt_sig_crypto_sign(signet_orig, orig_signkey);
	ck_assert_msg(res == 0, "Failed to sign origin signet with cryptographic signature.\n");
	res = dime_sgnt_sig_crypto_sign(signet_dest, dest_signkey);
	ck_assert_msg(res == 0, "Failed to sign destination signet with cryptographic signature.\n");
	ck_assert_dime_noerror();

	// sign domain signets with full signet signature
	res = dime_sgnt_sig_full_sign(signet_orig, orig_signkey);
	ck_assert_msg(res == 0, "Failed to sign origin signet with full signature.\n");
	res = dime_sgnt_sig_full_sign(signet_dest, dest_signkey);
	ck_assert_msg(res == 0, "Failed to sign destination signet with full signature.\n");
	ck_assert_dime_noerror();

	//add domain ids to domain signets
	res = dime_sgnt_id_set(signet_orig, strlen(orig), (const unsigned char *)orig);
	ck_assert_msg(res == 0, "Failed to set the origin signet id to its domain name.\n");
	res = dime_sgnt_id_set(signet_dest, strlen(dest), (const unsigned char *)dest);
	ck_assert_msg(res == 0, "Failed to set the destination signet id to its domain name.\n");
	ck_assert_dime_noerror();

	//add final domain signet signature
	res = dime_sgnt_sig_id_sign(signet_orig, orig_signkey);
	ck_assert_msg(res == 0, "Failed to sign the origin signet with identifiable signature.\n");
	res = dime_sgnt_sig_id_sign(signet_dest, dest_signkey);
	ck_assert_msg(res == 0, "Failed to sign the destination signet with identifiable signature.\n");
	ck_assert_dime_noerror();

	//sign user ssr's with user user keys
	res = dime_sgnt_sig_ssr_sign(signet_auth, auth_signkey);
	ck_assert_msg(res == 0, "Failed to sign the author signet with SSR signature.\n");
	res = dime_sgnt_sig_ssr_sign(signet_recp, recp_signkey);
	ck_assert_msg(res == 0, "Failed to sign the recipient signet with SSR signature.\n");
	ck_assert_dime_noerror();

	//sign user ssr's with corresponding domain keys
	res = dime_sgnt_sig_crypto_sign(signet_auth, orig_signkey);
	ck_assert_msg(res == 0, "Failed to sign the author signet with cryptographic siganture.\n");
	res = dime_sgnt_sig_crypto_sign(signet_recp, dest_signkey);
	ck_assert_msg(res == 0, "Failed to sign the recipient signet with cryptographic siganture.\n");
	ck_assert_dime_noerror();

	//sign user signets with corresponding domain keys
	res = dime_sgnt_sig_full_sign(signet_auth, orig_signkey);
	ck_assert_msg(res == 0, "Failed to sign the author signet with full siganture.\n");
	res = dime_sgnt_sig_full_sign(signet_recp, dest_signkey);
	ck_assert_msg(res == 0, "Failed to sign the recipient signet with full siganture.\n");
	ck_assert_dime_noerror();

	//set user signet id's
	res = dime_sgnt_id_set(signet_auth, strlen(auth), (const unsigned char *)auth);
	ck_assert_msg(res == 0, "Failed to set the author signet id its email address.\n");
	res = dime_sgnt_id_set(signet_recp, strlen(recp), (const unsigned char *)recp);
	ck_assert_msg(res == 0, "Failed to set the recipient signet id its email address.\n");
	ck_assert_dime_noerror();

	//add final user signet signature with corresponding domain keys
	res = dime_sgnt_sig_id_sign(signet_auth, orig_signkey);
	ck_assert_msg(res == 0, "Failed to sign the author signet with identifiable siganture.\n");
	res = dime_sgnt_sig_id_sign(signet_recp, dest_signkey);
	ck_assert_msg(res == 0, "Failed to sign the author signet with identifiable siganture.\n");
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
	draft->display = dime_dmsg_object_chunk_create(CHUNK_TYPE_DISPLAY_CONTENT, (unsigned char *)display, strlen(display), DEFAULT_CHUNK_FLAGS);
	ck_assert_dime_noerror();

	// turn object into message by encrypting and serialize
	message = dime_dmsg_message_encrypt(draft, auth_signkey);
	ck_assert_msg(message != NULL, "Failed encrypt the message.\n");

	from_auth_bin = dime_dmsg_message_binary_serialize(message, 0xFF, 0, &from_auth_size);
	ck_assert_msg(from_auth_bin != NULL, "Failed to serialize the encrypted message.\n");

	ck_assert_dime_noerror();

	//destroy message and deserialize it again from the serialized form as if it was received over wire by the origin
	dime_dmsg_message_destroy(message);
	message = dime_dmsg_message_binary_deserialize(from_auth_bin, from_auth_size);
	ck_assert_msg(message != NULL, "Failed to deserialize the encrypted message as origin.\n");

	//decrypt message as origin
	res = dime_dmsg_kek_in_derive(message, orig_enckey, &orig_kek);
	ck_assert_msg(res == 0, "Failed to derive the origin key encryption key.\n");
	ck_assert_dime_noerror();

	at_orig = dime_dmsg_message_envelope_decrypt(message, id_origin, &orig_kek);
	ck_assert_msg(at_orig != NULL, "Failed to decrypt the message envelope as origin.\n");

	res = st_cmp_cs_eq(draft->author, at_orig->author);
	ck_assert_msg(res == 0, "The message author was corrupted in the envelope.\n");

	res = st_cmp_cs_eq(draft->destination, at_orig->destination);
	ck_assert_msg(res == 0, "The message destination was corrupted in the envelope.\n");
	ck_assert_dime_noerror();

	at_orig->signet_author = signet_auth;
	at_orig->signet_destination = signet_dest;
	at_orig->origin = st_import(orig, strlen(orig));
	at_orig->signet_origin = signet_orig;

	res = dime_dmsg_message_decrypt_as_orig(at_orig, message, &orig_kek);
	ck_assert_msg(res == 0, "Origin could not decrypt the chunks it needs access to.\n");

	//Add origin signatures and serialize the message again
	res = dime_dmsg_chunks_sig_origin_sign(message, (META_BOUNCE | DISPLAY_BOUNCE), &orig_kek, orig_signkey);
	ck_assert_msg(res == 0, "Origin failed to sign the message.\n");

	from_orig_bin = dime_dmsg_message_binary_serialize(message, 0xFF, 0, &from_orig_size);
	ck_assert_msg(from_orig_bin != NULL, "Failed to serialize the message as origin.\n");

	ck_assert_dime_noerror();

	//destroy message and deserialize it again from the serialized form as if it was received over wire by the destination
	dime_dmsg_message_destroy(message);

	message = dime_dmsg_message_binary_deserialize(from_orig_bin, from_orig_size);
	ck_assert_msg(message != NULL, "Failed to deserialize the message as destination.\n");

	//decrypt message as destination
	res = dime_dmsg_kek_in_derive(message, dest_enckey, &dest_kek);
	ck_assert_msg(res == 0, "Failed to derive the destination key encryption key.\n");
	
	at_dest = dime_dmsg_message_envelope_decrypt(message, id_destination, &dest_kek);
	ck_assert_msg(at_dest != NULL, "Failed to decrypt the message envelope as destination.\n");

	res = st_cmp_cs_eq(draft->origin, at_dest->origin);
	ck_assert_msg(res == 0, "The message origin was corrupted in the envelope.\n");

	res = st_cmp_cs_eq(draft->recipient, at_dest->recipient);
	ck_assert_msg(res == 0, "The message recipient was corrupted in the envelope.\n");
	ck_assert_dime_noerror();

	at_dest->signet_origin = signet_orig;
	at_dest->signet_recipient = signet_recp;
	at_dest->destination = st_import(dest, strlen(dest));
	at_dest->signet_destination = signet_dest;

	res = dime_dmsg_message_decrypt_as_dest(at_dest, message, &dest_kek);
	ck_assert_msg(res == 0, "Destination could not decrypt the chunks it needs access to.\n");

	//Serialize the message again
	from_dest_bin = dime_dmsg_message_binary_serialize(message, 0xFF, 0, &from_dest_size);
	ck_assert_msg(from_dest_bin != NULL, "Failed to serialize the message as destination.\n");

	ck_assert_dime_noerror();

	//destroy message and deserialize it again from the serialized form as if it was received over wire by the recipient
	dime_dmsg_message_destroy(message);

	message = dime_dmsg_message_binary_deserialize(from_dest_bin, from_dest_size);
	ck_assert_msg(message != NULL, "Failed to deserialize encrypted message as recipient.\n");
	ck_assert_dime_noerror();

	//decrypt message as recipient
	res = dime_dmsg_kek_in_derive(message, recp_enckey, &recp_kek);
	ck_assert_msg(res == 0, "Failed to derive recipient key encryption key.\n");

	at_recp = dime_dmsg_message_envelope_decrypt(message, id_recipient, &recp_kek);
	ck_assert_msg(at_recp != NULL, "Failed to decrypt the envelope as the recipient.\n");

	res = st_cmp_cs_eq(draft->author, at_recp->author);
	ck_assert_msg(res == 0, "The message author was corrupted in the envelope.\n");
	res = st_cmp_cs_eq(draft->origin, at_recp->origin);
	ck_assert_msg(res == 0, "The message origin was corrupted in the envelope.\n");
	res = st_cmp_cs_eq(draft->destination, at_recp->destination);
	ck_assert_msg(res == 0, "The message destination was corrupted in the envelope.\n");
	res = st_cmp_cs_eq(draft->recipient, at_recp->recipient);
	ck_assert_msg(res == 0, "The message recipient was corrupted in the envelope.\n");
	ck_assert_dime_noerror();
	
	at_recp->signet_author = signet_auth;
	at_recp->signet_origin = signet_orig;
	at_recp->signet_destination = signet_dest;
	at_recp->signet_recipient = signet_recp;

	res = dime_dmsg_message_decrypt_as_recp(at_recp, message, &recp_kek);
	ck_assert_msg(res == 0, "Failed to decrypt the message as recipient.\n");

	res = st_cmp_cs_eq(draft->common_headers->headers[HEADER_TYPE_DATE], at_recp->common_headers->headers[HEADER_TYPE_DATE]);
	ck_assert_msg(res == 0, "DATE header was corrupted.\n");
	res = st_cmp_cs_eq(draft->common_headers->headers[HEADER_TYPE_FROM], at_recp->common_headers->headers[HEADER_TYPE_FROM]);
	ck_assert_msg(res == 0, "FROM header was corrupted.\n");
	res = st_cmp_cs_eq(draft->common_headers->headers[HEADER_TYPE_ORGANIZATION], at_recp->common_headers->headers[HEADER_TYPE_ORGANIZATION]);
	ck_assert_msg(res == 0, "ORGANIZATION header was corrupted.\n");
	res = st_cmp_cs_eq(draft->common_headers->headers[HEADER_TYPE_SUBJECT], at_recp->common_headers->headers[HEADER_TYPE_SUBJECT]);
	ck_assert_msg(res == 0, "SUBJECT header was corrupted.\n");
	res = st_cmp_cs_eq(draft->common_headers->headers[HEADER_TYPE_TO], at_recp->common_headers->headers[HEADER_TYPE_TO]);
	ck_assert_msg(res == 0, "TO header was corrupted.\n");
	res = st_cmp_cs_eq(draft->other_headers, at_recp->other_headers);
	ck_assert_msg(res == 0, "Other headers were corrupted.\n");
	res = (draft->display->data_size == at_recp->display->data_size);
	ck_assert_msg(res == 1, "Message body data size was corrupted.\n");
	res = memcmp(draft->display->data, at_recp->display->data, draft->display->data_size);
	ck_assert_msg(res == 0, "Message body data was corrupted.\n");
	
	//destroy everything
	dime_sgnt_signet_destroy(signet_auth);
	dime_sgnt_signet_destroy(signet_orig);
	dime_sgnt_signet_destroy(signet_dest);
	dime_sgnt_signet_destroy(signet_recp);

	dime_dmsg_message_destroy(message);

	dime_dmsg_object_destroy(draft);
	dime_dmsg_object_destroy(at_orig);
	dime_dmsg_object_destroy(at_dest);
	dime_dmsg_object_destroy(at_recp);

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

	fprintf(stderr, "Message encryption and decryption check complete.\n");
}
END_TEST

Suite *suite_check_dmsg(void) {

	Suite *s = suite_create("\nDMIME message");
	suite_add_test(s, "Message encryption and decryption", check_dmsg_all);
	return s;
}
