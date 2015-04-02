#include "dmessage/dmime.h"
#include "dmessage/dmsg.h"
#include "check_dmsg.h"

START_TEST (check_message_encryption)
{
	EC_KEY *auth_enckey, *orig_enckey, *dest_enckey, *recp_enckey;
	ED25519_KEY *auth_signkey, *orig_signkey, *dest_signkey, *recp_signkey;
	char *auth = "ivan@darkmail.info", *orig = "darkmail.info", *dest = "lavabit.com", *recp = "ryan@lavabit.com";
	char *auth_keys = "auth.keys", *orig_keys = "orig.keys", *dest_keys = "dest.keys", *recp_keys = "recp.keys";
	char *common_headers = "To: Ryan<ryan@lavabit.com>\r\nFrom: Ivan<ivan@darkmail.info>\r\nSubject: Mr.Watson - Come here - I want to see you\r\n";
	char *other_headers = "SECRET METADATA\r\n";
	char *display = "This is a test\r\nCan you read this?\r\n";
	dmime_kek_t orig_kek, dest_kek, recp_kek;
	dmime_message_t *message;
	dmime_object_t *draft, *at_orig, *at_dest, *at_recp;
	signet_t *signet_auth, *signet_orig, *signet_dest, *signet_recp;
	size_t from_auth_size, from_orig_size, from_dest_size;
	unsigned char *from_auth_bin, *from_orig_bin, *from_dest_bin;

	//initialize crypto	
	_crypto_init();

	memset(&orig_kek, 0, sizeof(dmime_kek_t));
	memset(&dest_kek, 0, sizeof(dmime_kek_t));
	memset(&recp_kek, 0, sizeof(dmime_kek_t));


	//create domain signets
	signet_orig = _signet_new_keysfile(SIGNET_TYPE_ORG, orig_keys);
	signet_dest = _signet_new_keysfile(SIGNET_TYPE_ORG, dest_keys);

	//create user signet signing requests
	signet_auth = _signet_new_keysfile(SIGNET_TYPE_SSR, auth_keys);
	signet_recp = _signet_new_keysfile(SIGNET_TYPE_SSR, recp_keys);

	// retrieve all signing and encryption private keys ahead of time
	orig_enckey = _keys_file_fetch_enc_key(orig_keys);
	dest_enckey = _keys_file_fetch_enc_key(dest_keys);
	auth_enckey = _keys_file_fetch_enc_key(auth_keys);
	recp_enckey = _keys_file_fetch_enc_key(recp_keys);

	orig_signkey = _keys_file_fetch_sign_key(orig_keys);
	dest_signkey = _keys_file_fetch_sign_key(dest_keys);
	auth_signkey = _keys_file_fetch_sign_key(auth_keys);
	recp_signkey = _keys_file_fetch_sign_key(recp_keys);

	// sign domain signets with first signature
	_signet_sign_core_sig(signet_orig, orig_signkey);
	_signet_sign_core_sig(signet_dest, dest_signkey);

	//add domain ids to domain signets
	_signet_set_id(signet_orig, orig);
	_signet_set_id(signet_dest, dest);

	//add final domain signet signature
	_signet_sign_full_sig(signet_orig, orig_signkey);
	_signet_sign_full_sig(signet_dest, dest_signkey);

	//sign user ssr's with user user keys
	_signet_sign_ssr_sig(signet_auth, auth_signkey);
	_signet_sign_ssr_sig(signet_recp, recp_signkey);

	//sign user ssr's with corresponding domain keys
	_signet_sign_initial_sig(signet_auth, orig_signkey);
	_signet_sign_initial_sig(signet_recp, dest_signkey);

	//sign user signets with corresponding domain keys
	_signet_sign_core_sig(signet_auth, orig_signkey);
	_signet_sign_core_sig(signet_recp, dest_signkey);

	//set user signet id's
	_signet_set_id(signet_auth, auth);
	_signet_set_id(signet_recp, recp);

	//add final user signet signature with corresponding domain keys
	_signet_sign_full_sig(signet_auth, orig_signkey);
	_signet_sign_full_sig(signet_recp, dest_signkey);

//	_signet_dump(stderr, signet_auth);
//	_signet_dump(stderr, signet_orig);
//	_signet_dump(stderr, signet_dest);
//	_signet_dump(stderr, signet_recp);

	//create object as a draft
	draft = malloc(sizeof(dmime_object_t));
	memset(draft, 0, sizeof(dmime_object_t));

	draft->actor = id_author;
	draft->author = st_import(auth, strlen(auth));
	draft->recipient = st_import(recp, strlen(recp));
	draft->origin = st_import(orig, strlen(orig));
	draft->destination = st_import(dest, strlen(dest));
	draft->signet_author = signet_auth;
	draft->signet_origin = signet_orig;
	draft->signet_destination = signet_dest;
	draft->signet_recipient = signet_recp;
	draft->common_headers = st_import(common_headers, strlen(common_headers));
	draft->other_headers = st_import(other_headers, strlen(other_headers));
	draft->display = _dmsg_create_object_chunk(CHUNK_TYPE_DISPLAY_CONTENT, (unsigned char *)display, strlen(display), DEFAULT_CHUNK_FLAGS);

	_dmsg_dump_object(draft);

	// turn object into message by encrypting and serialize
	message = _dmsg_object_to_msg(draft, auth_signkey);
	from_auth_bin = _dmsg_msg_to_bin(message, 0b00011111, 0, &from_auth_size);

	//destroy message and deserialize it again from the serialized form as if it was received over wire by the origin
	_dmsg_destroy_msg(message);
	message = _dmsg_bin_to_msg(from_auth_bin, from_auth_size);

	//decrypt message as origin
	_dmsg_get_kek(message, orig_enckey, &orig_kek);

	at_orig = _dmsg_msg_to_object_envelope(message, id_origin, &orig_kek);
	at_orig->signet_author = signet_auth;
	at_orig->signet_destination = signet_dest;
	at_orig->origin = st_import(orig, strlen(orig));
	at_orig->signet_origin = signet_orig;
	_dmsg_msg_to_object_as_orig(at_orig, message, &orig_kek);

	_dmsg_dump_object(at_orig);

	//Add origin signatures and serialize the message again
	_dmsg_sign_origin_sig_chunks(message, (META_BOUNCE | DISPLAY_BOUNCE), &orig_kek, orig_signkey);
	from_orig_bin = _dmsg_msg_to_bin(message, 0b00011111, 0, &from_orig_size);

	//destroy message and deserialize it again from the serialized form as if it was received over wire by the destination
	_dmsg_destroy_msg(message);
	message = _dmsg_bin_to_msg(from_orig_bin, from_orig_size);

	//decrypt message as destination
	_dmsg_get_kek(message, dest_enckey, &dest_kek);
	at_dest = _dmsg_msg_to_object_envelope(message, id_destination, &dest_kek);
	at_dest->signet_origin = signet_orig;
	at_dest->signet_recipient = signet_recp;
	at_dest->destination = st_import(dest, strlen(dest));
	at_dest->signet_destination = signet_dest;
	_dmsg_msg_to_object_as_orig(at_dest, message, &dest_kek);
	_dmsg_dump_object(at_dest);

	//Serialize the message again
	from_dest_bin = _dmsg_msg_to_bin(message, 0b00011111, 0, &from_dest_size);

	//destroy message and deserialize it again from the serialized form as if it was received over wire by the recipient
	_dmsg_destroy_msg(message);
	message = _dmsg_bin_to_msg(from_dest_bin, from_dest_size);

	//decrypt message as recipient
	_dmsg_get_kek(message, recp_enckey, &recp_kek);
	at_recp = _dmsg_msg_to_object_envelope(message, id_recipient, &recp_kek);
	at_recp->signet_author = signet_auth;
	at_recp->signet_origin = signet_orig;
	at_recp->signet_destination = signet_dest;
	at_recp->signet_recipient = signet_recp;
	_dmsg_msg_to_object_as_orig(at_recp, message, &recp_kek);
	_dmsg_dump_object(at_recp);
	

	//destroy everything
	_signet_destroy(signet_auth);
	_signet_destroy(signet_orig);
	_signet_destroy(signet_dest);
	_signet_destroy(signet_recp);

	_dmsg_destroy_msg(message);

	_dmsg_destroy_object(draft);
	_dmsg_destroy_object(at_orig);
	_dmsg_destroy_object(at_dest);
	_dmsg_destroy_object(at_recp);

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
	
}
END_TEST




Suite * suite_check_dmsg(void) {

	Suite *s;
	TCase *tc;

	s = suite_create("signet");
	testcase(s, tc, "check message creation and encryption", check_message_encryption);

	return s;
}


int main(int argc, char *argv[]) {

        SRunner *sr;

        sr = srunner_create(suite_check_dmsg());

        fprintf(stderr, "Running tests ...\n");

	srunner_set_fork_status (sr, CK_NOFORK);
        srunner_run_all(sr, CK_SILENT);
        //srunner_run_all(sr, CK_NORMAL);
        //nr_failed = srunner_ntests_failed(sr);
        // CK_VERBOSE
        srunner_print(sr, CK_VERBOSE);
        srunner_free(sr);

        fprintf(stderr, "Finished.\n");
        //ck_assert
        //ck_assert_msg

        return 0;
}
