
/**
 * @file /magma/servers/dmtp/dmtp.c
 *
 * @brief	Functions used to handle DMTP commands/actions.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#include "magma.h"


// TODO: migrate to header.
int_t dmtp_store_message(smtp_inbound_prefs_t *prefs, stringer_t *message);
extern ED25519_KEY *signet_fetch_signkey(signet_t *signet);


extern command_t dmtp_commands[];
extern size_t dmtp_num_cmds;


/**
 * @brief	Initialize a TLS session for a DMTP session.
 * @param	con		the connection of the DMTP endpoint requesting the transport layer security upgrade.
 * @return	This function returns no value.
 */
void dmtp_srv_starttls(connection_t *con) {

	placer_t domain = pl_null(), pl = pl_clone(con->network.line);

	// Trim any trailing whitespace or command terminator.
	pl_shrink_before_characters(&pl, "\r\n\t ", 4);

	// If after the command we receive nothing but whitespace, it's a legacy command.
	if (!pl_update_start(&pl, 8, true) || !pl_skip_characters (&pl, " \t", 2)) {
		log_pedantic("DMTP client issued SMTP-style STARTTLS request.");
		dmtp_srv_do_fallback(con);
		return;
	} else if (!pl_get_embraced(pl, &domain, '<', '>', true)) {
		log_pedantic("Received DMTP STARTTLS request with bad syntax.");
		con_write_bl(con, "501 BAD STARTTLS SYNTAX.\r\n", 26);
		return;
	} else if (!dmtp_is_valid_domain(&domain)) {
		log_pedantic("Received DMTP STARTTLS request with bad domain parameter.");
		con_write_bl(con, "501 INVALID STARTTLS DOMAIN.\r\n", 30);
		return;
	}
	else {
		printf("XXX: Received STARTTLS domain [%.*s]\n", (int)domain.length, (char *)domain.data);
	}

	// At this point we are definitely in a DMTP session and we can no longer fallback.
	con->dmtp.no_fallback = true;

		// Check for an existing SSL connection.
	if (con_secure(con) == 1) {
		con_write_bl(con, "454 SESSION IS ALREADY ENCRYPTED.\r\n", 35);
		return;
	}

	// Right now we only support our own certificate.
	if (st_cmp_ci_eq(&domain, con->server->domain)) {

		log_pedantic("DMTP client requested certificate for missing domain (%.*s)", (int)pl_length_get(domain), pl_char_get(domain));
		con_write_bl(con, "554 CERTIFICATE NOT FOUND FOR DOMAIN.\r\n", 39);
		return;
	}

	con_print(con, "220-SENDING CERTIFICATE FOR DOMAIN <%.*s>\r\n220 READY\r\n", st_length_int(con->server->domain), st_char_get(con->server->domain));
	//con_write_bl(con, "220 READY\r\n", 11);

	if (!(con->network.ssl = ssl_alloc(con->server, con->network.sockd, M_SSL_BIO_NOCLOSE))) {
		con_write_bl(con, "454 STARTTLS FAILED\r\n", 21);
		log_pedantic("STARTTLS attempt failed.");
		return;
	}

	// Advertise that the connection has been upgraded.
	con_write_bl(con, "250 OK DMTPv1\r\n", 15);

	stats_increment_by_name("dmtp.connections.secure");
	st_length_set(con->network.buffer, 0);
	con->network.line = pl_null();
	con->network.status = 1;

	return;
}

/**
 * @brief	The start of the protocol handler for the DMTP server.
 * @param	con		the new inbound DMTP client connection.
 * @return	This function returns no value.
 */
void dmtp_srv_init(connection_t *con) {

	// Queue a reverse lookup.
	con_reverse_enqueue(con);

	// Are we operating in mixed mode or not?
	if (magma.dmtp.dualmode) {
		con_print(con, "220 <%.*s> ESMTP DMTPv1 Magma\r\n", st_length_int(con->server->domain), st_char_get(con->server->domain));
	} else {
		con_print(con, "220 <%.*s> DMTPv1 Magma\r\n", st_length_int(con->server->domain), st_char_get(con->server->domain));
	}

	dmtp_srv_requeue(con);

	return;
}

/**
 * @brief	A function that is executed when an invalid DMTP command is issued.
 * @return	This function returns no value.
 */
void dmtp_srv_invalid(connection_t *con) {

	con->protocol.violations++;
	usleep(con->server->violations.delay);
	con_write_bl(con, "500 INVALID COMMAND\r\n", 21);

	return;
}

/**
 * @brief	A function that is executed when a DMTP command (other than QUIT) is issued before STARTTLS.
 * @return	This function returns no value.
 */
void dmtp_srv_needstls(connection_t *con) {

	con_write_bl(con, "503 DMTP COMMAND REQUIRES STARTTLS FIRST.\r\n", 43);
	return;
}

/**
 * @brief	A function that is executed when an SMTP command is executed in an established DMTP session.
 * @return	This function returns no value.
 */
void dmtp_srv_nofallback(connection_t *con) {

	con_write_bl(con, "554 DMTP SESSION CANNOT FALLBACK AFTER ESTABLISHMENT.\r\n", 55);
	return;
}

/**
 * @brief	A function that is executed when an SMTP command is executed on a DMTP server that does not support dual mode.
 * @return	This function returns no value.
 */
void dmtp_srv_nodual(connection_t *con) {

	con_print(con, "554 %.*s SMTP SERVICE NOT AVAILABLE\r\n", st_length_int(con->server->domain), st_char_get(con->server->domain));
	return;
}

/**
 * @brief	Gracefully terminate an smtp session, especially in response to a client QUIT command
 * @param	the dmtp client connection to be terminated.
 * @return	This function returns no value.
 */
void dmtp_srv_quit(connection_t *con) {

	if (con_status(con) == 2) {
		con_write_bl(con, "451 Unexpected connection shutdown detected. Goodbye.\r\n", 55);
	}
	else if (con_status(con) >= 0) {
		con_write_bl(con, "221 BYE\r\n", 9);
	}
	else {
		con_write_bl(con, "421 Network connection failure.\r\n", 33);
	}

	con_destroy(con);

	return;
}

/**
 * @brief	Process a DMTP EHLO command.
 * @note	Any prior domain specified by a EHLO command will be overwritten.
 * @param	con		the DMTP client connection issuing the command.
 * @return	This function returns no value.
 */
void dmtp_srv_ehlo(connection_t *con) {

	placer_t domain = pl_null(), pl = pl_clone(con->network.line);

	// Trim any trailing whitespace or command terminator.
	pl_shrink_before_characters(&pl, "\r\n\t ", 4);

	if (!pl_update_start(&pl, 4, true) || !pl_skip_characters (&pl, " \t", 2)) {
		log_pedantic("Received DMTP EHLO request with bad syntax.");
		con_write_bl(con, "501 BAD EHLO SYNTAX.\r\n", 22);
		return;
	// Check to see if an old-style address was passed.
	} else if (st_search_chr(&pl, '@', NULL)) {
		dmtp_srv_do_fallback(con);
		return;
	}
	else if (!pl_get_embraced(pl, &domain, '<', '>', true)) {
		dmtp_srv_do_fallback(con);
		return;
	} else if (!dmtp_is_valid_domain(&domain)) {
		log_pedantic("Received DMTP EHLO request with bad domain parameter.");
		con_write_bl(con, "501 INVALID EHLO DOMAIN.\r\n", 26);
		return;
	}

	// Free any previously provided values.
	st_cleanup(con->dmtp.ehlo);
	con->dmtp.ehlo = st_nullify(pl_char_get(domain), pl_length_get(domain));

	con_print(con, "250-PIPELINING\r\n250-8BITMIME\r\n250-8BITDIME\r\n250-RETURN\r\n250-SIZE %lu\r\n250 OK\r\n",
		magma.smtp.message_length_limit);

	log_pedantic("XXX: Received EHLO: [%.*s]", (int)st_length_get(con->dmtp.ehlo), st_char_get(con->dmtp.ehlo));

	return;
}

/**
 * @brief	Identify the sender of a dmail message, in response to the DMTP MAIL FROM command.
 * @param	con		the DMTP client connection issuing the command.
 * @return	This function returns no value.
 */
void dmtp_srv_mail_from(connection_t *con) {

	placer_t pl = pl_clone(con->network.line), domain = pl_null(), fingerprint = pl_null(),
			param_size = pl_null(), param_return = pl_null(), param_data = pl_null(),
			param_token, param_key, param_val;
	size_t vind;
	uint64_t i, nparams, msgsize;

	// If they try to send this command without saying hello.
	if (!con->dmtp.ehlo) {
		con_write_bl(con, "503 MAIL FROM REJECTED - PLEASE PROVIDE AN EHLO AND TRY AGAIN\r\n", 63);
		return;
	}

	// If they try to send MAIL FROM twice, trigger a session reset.
	if (con->dmtp.mailfrom)	{
		dmtp_srv_session_reset(con);
	}

	// Trim any trailing whitespace or command terminator.
	pl_shrink_before_characters(&pl, "\r\n\t ", 4);

	if (!pl_update_start(&pl, 10, true) || !pl_skip_characters (&pl, " \t", 2)) {
		log_pedantic("Received DMTP MAIL FROM request with bad syntax.");
		con_write_bl(con, "501 BAD MAIL FROM SYNTAX.\r\n", 27);
		return;
	// Get the first mandatory parameter, which is a domain.
	} else if (!pl_get_embraced(pl, &domain, '<', '>', true)) {
		log_pedantic("Received DMTP MAIL FROM request with bad syntax.");
		con_write_bl(con, "501 BAD MAIL FROM SYNTAX.\r\n", 27);
		return;
	}

	if (!dmtp_is_valid_domain(&domain)) {
		log_pedantic("Received DMTP MAIL FROM request with bad domain parameter: %.*s", pl_length_int(domain), pl_char_get(domain));
		con_write_bl(con, "501 INVALID MAIL FROM PARAMETER.\r\n", 34);
		return;
	}

	// The second mandatory parameter is the fingerprint.
	// Seek to the closing bracket, and skip whitespace, and then try to get the optionally enclosed data.
	if (!pl_skip_to_characters (&pl, ">", 1) || !pl_inc(&pl, true) || !pl_skip_characters(&pl, " \t", 2) ||
		!pl_get_embraced(pl, &fingerprint, '[', ']', true)) {
		log_pedantic("Received DMTP MAIL FROM request without fingerprint.");
		con_write_bl(con, "501 INVALID MAIL FROM PARAMETER.\r\n", 34);
		return;
	}

	// Now we skip to the mandatory parameter, and optional parameter(s).
	if (!pl_skip_to_characters(&pl, "]", 1) || !pl_inc(&pl, true) || !pl_skip_characters(&pl, " \t", 2)) {
		log_pedantic("Received DMTP MAIL FROM request without SIZE parameter.");
		con_write_bl(con, "501 INVALID MAIL FROM PARAMETER.\r\n", 34);
		return;
	}

	// We have to get all the parameters, of which there MUST at least be the SIZE supplied.
	nparams = tok_get_count_st(&pl, ' ');

	if ((nparams < 1) || (nparams > 3)) {

		if (nparams < 1) {
			log_pedantic("Received DMTP MAIL FROM request without SIZE parameter.");
		} else {
			log_pedantic("Received DMTP MAIL FROM request with unexpected parameter(s).");
		}

		con_write_bl(con, "501 INVALID MAIL FROM PARAMETER.\r\n", 34);
		return;
	}

	printf("xxx: MAIL FROM requested for [%.*s]\n", (int)st_length_get(&domain), st_char_get(&domain));
//	printf("xxx: MAIL FROM requested fingerprint: [%.*s]\n", (int)pl_length_get(fingerprint), pl_char_get(fingerprint));
//	printf("xxx: got %lu parameters\n", nparams);

	for(i = 0; i < nparams; i++) {

		if (tok_get_pl(pl, ' ', i, &param_token) < 0) {
			log_error("Unexpected tokenization error occurred in DMTP MAIL FROM handler.");
			con_write_bl(con, "451 Unexpected internal error occurred.\r\n", 41);
			return;
		}

		if (!st_search_chr(&param_token, '=', &vind)) {
			log_pedantic("Received DMTP MAIL FROM request with malformed parameter.");
			con_write_bl(con, "501 INVALID MAIL FROM PARAMETER.\r\n", 34);
			return;
		}

		param_key = pl_init(pl_char_get(param_token), vind);
		param_val = pl_init(pl_char_get(param_token) + vind + 1, pl_length_get(param_token) - (vind + 1));

		if (!st_cmp_ci_eq(&param_key, CONSTANT("SIZE"))) {
			param_size = param_val;

			// The parameter to SIZE must be an unsigned integer.
			if (!uint64_conv_st(&param_size, &msgsize)) {
				log_pedantic("Received DMTP MAIL FROM request with invalid SIZE parameter value.");
				con_write_bl(con, "501 INVALID MAIL FROM PARAMETER.\r\n", 34);
				return;
			}

			// We also have to make sure the proposed size is allowed.
			if (msgsize > magma.smtp.message_length_limit) {
				con_print(con, "552 OUTBOUND SIZE LIMIT EXCEEDED - THIS ACCOUNT MAY ONLY SEND MESSAGES UP TO %zu BYTES IN LENGTH\r\n",
					magma.smtp.message_length_limit);
				return;
			}


		} else if (!st_cmp_ci_eq(&param_key, CONSTANT("RETURN"))) {
			param_return = param_val;

			// Only these three RETURN types are supported:
			if (!st_cmp_ci_eq(&param_return, CONSTANT("FULL"))) {

			} else if (!st_cmp_ci_eq(&param_return, CONSTANT("DISPLAY"))) {

			} else if (!st_cmp_ci_eq(&param_return, CONSTANT("HEADER"))) {

			} else {
				log_pedantic("Received DMTP MAIL FROM request with invalid RETURN parameter value.");
				con_write_bl(con, "501 INVALID MAIL FROM PARAMETER.\r\n", 34);
				return;
			}

		} else if (!st_cmp_ci_eq(&param_key, CONSTANT("DATA"))) {
			param_data = param_val;

			// Only two DATA types are supported:
			if (!st_cmp_ci_eq(&param_data, CONSTANT("8BIT"))) {

			} else if (!st_cmp_ci_eq(&param_return, CONSTANT("7BIT"))) {

			} else {
				log_pedantic("Received DMTP MAIL FROM request with invalid DATA parameter value.");
				con_write_bl(con, "501 INVALID MAIL FROM PARAMETER.\r\n", 34);
				return;
			}

		} else {
			log_pedantic("Received DMTP MAIL FROM request with unrecognized parameter name: %.*s",
					pl_length_int(param_key), pl_char_get(param_key));
			con_write_bl(con, "501 UNSUPPORTED MAIL FROM PARAMETER.\r\n", 38);
			return;
		}

	}

	// We still have to make sure that we received a SIZE parameter.
	if (pl_empty(param_size)) {
		log_pedantic("Received DMTP MAIL FROM request without SIZE parameter.");
		con_write_bl(con, "501 INVALID MAIL FROM PARAMETER.\r\n", 34);
		return;
	}

	// Store the data we've received for the RCPT TO command.
	if (!(con->dmtp.mailfrom = st_nullify(pl_char_get(domain), pl_length_get(domain)))) {
		log_error("Could not store MAIL FROM address for DMTP session.");
		con_write_bl(con, "451 Unexpected internal error occurred.\r\n", 41);
		return;
	}

	// We also need to save the message size.
	con->dmtp.msgsize = msgsize;

	con_write_bl(con, "250 OK\r\n", 8);

	return;
}

/**
 * @brief	Identify the recipient of a dmail message, in response to the DMTP RCPT TO command.
 * @param	con		the DMTP client connection issuing the command.
 * @return	This function returns no value.
 */
void dmtp_srv_rcpt_to(connection_t *con) {

	placer_t pl = pl_clone(con->network.line), domain = pl_null(), fingerprint = pl_null();

	if (!con->dmtp.ehlo) {
		con_write_bl(con, "503 RCPT TO REJECTED - PLEASE PROVIDE A HELO OR EHLO AND TRY AGAIN\r\n", 68);
		return;
	} else if (!(con->dmtp.mailfrom)) {
		con_write_bl(con, "503 RCPT TO REJECTED - PLEASE PROVIDE A MAIL FROM AND TRY AGAIN\r\n", 65);
		return;
	}

	// Trim any trailing whitespace or command terminator.
	pl_shrink_before_characters(&pl, "\r\n\t ", 4);

	if (!pl_update_start(&pl, 8, true) || !pl_skip_characters (&pl, " \t", 2)) {
		log_pedantic("Received DMTP RCPT TO request with bad syntax.");
		con_write_bl(con, "501 BAD RCPT TO SYNTAX.\r\n", 25);
		return;
	// Get the first mandatory parameter, which is a domain.
	} else if (!pl_get_embraced(pl, &domain, '<', '>', true)) {
		log_pedantic("Received DMTP RCPT TO request with bad syntax.");
		con_write_bl(con, "501 BAD RCPT TO SYNTAX.\r\n", 25);
		return;
	}

	if (!dmtp_is_valid_domain(&domain)) {
		log_pedantic("Received DMTP RCPT TO request with bad parameter.");
		con_write_bl(con, "501 INVALID RCPT TO PARAMETER.\r\n", 32);
		return;
	}

	// The second mandatory parameter is the fingerprint.
	// Seek to the closing bracket, and skip whitespace, and then try to get the optionally enclosed data.
	if (!pl_skip_to_characters (&pl, ">", 1) || !pl_inc(&pl, true) || !pl_skip_characters(&pl, " \t", 2) ||
		!pl_get_embraced(pl, &fingerprint, '[', ']', true)) {
		log_pedantic("Received DMTP RCPT TO request without fingerprint.");
		con_write_bl(con, "501 INVALID RCPT TO PARAMETER.\r\n", 32);
		return;
	}

	// We expect there to be no more trailing data, and if there is, there's a problem.
	if (!pl_skip_to_characters(&pl, "]", 1) || !pl_inc(&pl, false)) {
		log_pedantic("Received DMTP RCPT TO request with unexpected trailing data.");
		con_write_bl(con, "501 INVALID RCPT TO PARAMETER.\r\n", 32);
		return;
	}

	// TODO: We need to validate that the supplied domain is correct.

	printf("xxx: RCPT TO requested for [%.*s]\n", (int)st_length_get(&domain), st_char_get(&domain));
//	printf("xxx: RCPT TO requested fingerprint: [%.*s]\n", (int)pl_length_get(fingerprint), pl_char_get(fingerprint));

	con_write_bl(con, "250 OK\r\n", 8);

	return;
}

/**
 * @brief	Supply data for a message, in response to the DMTP DATA command.
 * @param	con		the DMTP client connection issuing the command.
 * @return	This function returns no value.
 */
void dmtp_srv_data(connection_t *con) {

	dmime_message_t *encrypted, *decrypted;
	dmime_message_out_t *msg_out;
	credential_t *cred;
	smtp_inbound_prefs_t *prefs;
	ED25519_KEY *verkey;
	stringer_t *msgdata;
	placer_t pl = pl_clone(con->network.line), commit_hash = pl_null();
	int_t state;
	int res;

	// Make sure outsiders say HELO.
	// If the remote host tries to send data before sending a MAIL FROM and RCPT TO, return a protocol error.
	if (!con->dmtp.ehlo) {
		con_write_bl(con, "503 DATA REJECTED - PLEASE PROVIDE A HELO OR EHLO AND TRY AGAIN\r\n", 65);
		return;
	}
	else if (!con->dmtp.mailfrom) {
		con_write_bl(con, "503 DATA REJECTED - PLEASE PROVIDE A MAIL FROM AND TRY AGAIN\r\n", 62);
		return;
	}

	// Trim any trailing whitespace or command terminator.
	pl_shrink_before_characters(&pl, "\r\n\t ", 4);

	if (!pl_update_start(&pl, 4, true) || !pl_skip_characters (&pl, " \t", 2)) {
		log_pedantic("Received DMTP DATA request with bad syntax.");
		con_write_bl(con, "501 BAD DATA SYNTAX.\r\n", 22);
		return;
	// Get the mandatory parameter, which is a commit hash.
	} else if (!pl_get_embraced(pl, &commit_hash, '[', ']', true)) {
		log_pedantic("Received DMTP DATA request with bad syntax.");
		con_write_bl(con, "501 BAD DATA SYNTAX.\r\n", 22);
		return;
	}

	// We expect there to be no more trailing data, and if there is, there's a problem.
	if (!pl_skip_to_characters(&pl, "]", 1) || !pl_inc(&pl, false)) {
		log_pedantic("Received DMTP DATA request with unexpected trailing data.");
		con_write_bl(con, "501 INVALID DATA PARAMETER.\r\n", 29);
		return;
	}

//	printf("xxx: DATA requested for [%.*s]; reading %lu bytes...\n", (int)st_length_get(&commit_hash), st_char_get(&commit_hash), con->dmtp.msgsize);
	printf("xxx: DATA requested; reading %lu bytes...\n", con->dmtp.msgsize);
	con_print(con, "354 CONTINUE [hash]\r\n");

	if (!(msgdata = dmtp_read_raw_data(con, con->dmtp.msgsize))) {
		con_write_bl(con, "421 DATA FAILED - THE CONNECTION TIMED OUT WHILE WAITING FOR DATA - GOOD BYE\r\n", 78);
		return;
	}

	printf("xxx: received data successfully.\n");

	con_print(con, "250 OK [randid]\r\n");

	if (!(encrypted = parse_dmime_raw(st_char_get(msgdata), st_length_get(msgdata)))) {
		log_pedantic("Error: Unable to parse data into new DMIME message holder.");
		dump_error_stack();
		st_free(msgdata);
		con_write_bl(con, "554 INVALID DMIME DATA RECEIVED.\r\n", 34);
		return;
	}

/*printf("ENCRYPTED:\n");
dump_dmsg_buf(st_char_get(encrypted->chunk_data), st_length_get(encrypted->chunk_data), DUMP_CHUNK_CONTENT|DUMP_ENC_DATA);
printf("\n\n\n");*/


//	if (!(decrypted = dmsg_decrypt_message(encrypted, id_destination))) {
	if (!(decrypted = dmsg_decrypt_message(encrypted, id_author))) {
		log_pedantic("Error: a problem occurred while decrypting the received DMIME message.");
		dump_error_stack();
		destroy_dmime_message(encrypted);
		con_write_bl(con, "554 INVALID DMIME DATA RECEIVED.\r\n", 34);
		return;
	}
//	printf("DECRYPTED:\n");
//	dump_buf_outer((const unsigned char *)st_char_get(decrypted->chunk_data), st_length_get(decrypted->chunk_data), 64, 1);
//	dump_dmsg_buf(st_char_get(decrypted->chunk_data), st_length_get(decrypted->chunk_data), DUMP_CHUNK_CONTENT);

	con_print(con, "451 PLANNED FAILURE\r\n");

	decrypted->flags |= DMSG_FLAG_CHUNKS_VERIFIED;

	if (!(msg_out = create_dmsg_out(decrypted, id_destination))) {
//	if (!(msg_out = create_dmsg_out(decrypted, id_author))) {
		log_pedantic("Could not process plaintext DMIME message.\n");
		dump_error_stack();
		destroy_dmime_message(encrypted);
		destroy_dmime_message(decrypted);
		con_write_bl(con, "554 INVALID DMIME DATA RECEIVED.\r\n", 34);
		return;
	}

	// The verification key for the author's signatures is retrieved from the author's signet.
	// This code shouldn't be necessary. The destination domain should not even know who the author is.
/*    if (!(verkey = signet_fetch_signkey(msg_out->signet_author))) {
    	log_pedantic("Could not get author signature verification key from signet.");
    	dump_error_stack();
    	return;
    }

    if ((res = author_vrfy_signatures(encrypted, verkey)) < 0) {
    	log_pedantic("Could not verify author signature against signet key.");
    	dump_error_stack();
    	free_ed25519_key(verkey);
    	return;
    } else if (!res) {
    	free_ed25519_key(verkey);
    	log_pedantic("Author signatures on DMIME message were incorrect.");
    	return;
    }

    free_ed25519_key(verkey); */

	if (_is_buf_zeroed(encrypted->org_full->inner.sig, sizeof(encrypted->org_full->inner.sig))) {
		log_pedantic("Org signature was zeroed out: it appears never to have been taken.");
		return;
	} else {
//		dump_buf(encrypted->org_full->inner.sig, sizeof(encrypted->org_full->inner.sig), 1);
	}

	// Next, the verification key for the org's signatures is retrieved from the author's signet.
	if (!(verkey = signet_fetch_signkey(msg_out->signet_origin))) {
		log_pedantic("Could not get org signature verification key from signet.");
		dump_error_stack();
		free_ed25519_key(verkey);
		return;
	}

	if ((res = _org_vrfy_signatures(encrypted, verkey)) < 0) {
		log_pedantic("Could not verify org signature against signet key.");
		dump_error_stack();
		free_ed25519_key(verkey);
		return;
	} else if (!res) {
		log_pedantic("Org signature(s) on DMIME message were incorrect.");
		free_ed25519_key(verkey);
		return;
	}

	dump_dmime_in(msg_out);
	free_ed25519_key(verkey);
//	return;

	if (!(cred = credential_alloc_mail(msg_out->recipient))) {
		destroy_dmime_message(encrypted);
		destroy_dmime_message(decrypted);
		destroy_dmsg_out(msg_out);
		con_write_bl(con, "451 INTERNAL SERVER ERROR - PLEASE TRY AGAIN LATER\r\n", 52);
		return;
	}

	// TODO: Lots of changes needed, but use existing SMTP code at least temporarily.
	// If the account is locked.
	if ((state = smtp_fetch_inbound(cred, msg_out->recipient, &prefs)) == -2) {
		con_print(con, "550 ACCOUNT LOCKED - THE ACCOUNT HAS BEEN ADMINISTRATIVELY LOCKED\r\n");
	}
	// If the account is inactive.
	else if (state == -3) {
		con_print(con, "550 ACCOUNT LOCKED - THE ACCOUNT HAS BEEN LOCKED FOR INACTIVITY\r\n");
	}
	// The account has been locked for abuse.
	else if (state == -4) {
		con_print(con, "550 ACCOUNT LOCKED - THE ACCOUNT HAS BEEN LOCKED FOR ABUSE POLICY VIOLATIONS\r\n");
	}
	// The user has locked the account.
	else if (state == -5) {
		con_print(con, "550 ACCOUNT LOCKED - THE ACCOUNT HAS BEEN LOCKED AT THE REQUEST OF THE OWNER\r\n");
	}
	// The user has locked the account.
	else if (state == -6) {
		con_print(con, "551 RELAY ACCESS DENIED - THE DOMAIN IS NOT HOSTED LOCALLY AND RELAY ACCESS REQUIRES AUTHENTICATION\r\n");
	}
	// If the domain is local but user wasn't found.
	else if (state == 0) {
		con_print(con, "554 INVALID RECIPIENT - THE EMAIL ADDRESS DOES NOT MATCH AN ACCOUNT ON THIS SYSTEM\r\n");
	}
	// Catch database or any other error here.
	else if (state < 0) {
		con_write_bl(con, "451 INTERNAL SERVER ERROR - PLEASE TRY AGAIN LATER\r\n", 52);
	}

	if ((state <= 0) || (!prefs)) {
		destroy_dmime_message(encrypted);
		destroy_dmime_message(decrypted);
		destroy_dmsg_out(msg_out);
		return;
	}

	credential_free(cred);

//	printf("XXX: smtp_fetch_inbound() state = %d\n", state);

	prefs->foldernum = prefs->inbox;
	state = dmtp_store_message(prefs, encrypted->chunk_data);

//	printf("XXX: dmtp_store_message() state = %d\n", state);


	smtp_free_inbound(prefs);

	// This code shouldn't be executed. The destination can't verify chunks.
/*	if ((res = dmsg_verify_chunk_data(decrypted, verkey)) <= 0) {

		if (res < 0) {
			printf("XXX: chunk verification on plaintext DMIME message encountered an unexpected condition.\n");
			dump_error_stack();
		} else {
			printf("XXX: Error: chunk verification on plaintext DMIME message failed.\n");
		}

		destroy_dmime_message(encrypted);
		destroy_dmime_message(decrypted);
		destroy_dmsg_out(msg_out);
		con_write_bl(con, "554 INVALID DMIME DATA RECEIVED.\r\n", 34);
		return;
	} */

	destroy_dmime_message(encrypted);
	destroy_dmime_message(decrypted);
	destroy_dmsg_out(msg_out);
	return;
}

/**
 * @brief	Look up a user or organization signet, in response to the DMTP SGNT command.
 * @param	con		the DMTP client connection issuing the command.
 * @return	This function returns no value.
 */
void dmtp_srv_sgnt(connection_t *con) {

	signet_db_t *sigdb;
	placer_t pl = pl_clone(con->network.line), signame = pl_null(), fingerprint = pl_null();
	bool_t is_user = false;

	// Trim any trailing whitespace or command terminator.
	pl_shrink_before_characters(&pl, "\r\n\t ", 4);

	if (!pl_update_start(&pl, 4, true) || !pl_skip_characters (&pl, " \t", 2)) {
		log_pedantic("Received DMTP SGNT request with bad syntax.");
		con_write_bl(con, "501 BAD SGNT SYNTAX.\r\n", 22);
		return;
	// Get the mandatory parameter, which is either a domain or address.
	} else if (!pl_get_embraced(pl, &signame, '<', '>', true)) {
		log_pedantic("Received DMTP SGNT request with bad syntax.");
		con_write_bl(con, "501 BAD SGNT SYNTAX.\r\n", 22);
		return;
	}

	if (st_search_chr(&signame, '@', NULL)) {
		is_user = true;
	}

	// If no '@' it must be a valid domain; if there is a '@' it must be a valid address.
	if ((!is_user && !dmtp_is_valid_domain(&signame)) || (is_user && !dmtp_is_valid_address(&signame))) {
		log_pedantic("Received DMTP SGNT request with bad parameter.");
		con_write_bl(con, "501 INVALID SGNT PARAMETER.\r\n", 29);
		return;
	}

	// See if the optional fingerprint parameter was supplied.
	// To do this, seek to the closing bracket, and skip whitespace, and then try to get the optionally enclosed data.
	if (pl_skip_to_characters (&pl, ">", 1) && pl_inc(&pl, true) && pl_skip_characters(&pl, " \t", 2)) {
		pl_get_embraced(pl, &fingerprint, '[', ']', true);
	}

	printf("xxx: signet requested for [%.*s]\n", (int)st_length_get(&signame), st_char_get(&signame));

	if (!pl_empty(fingerprint)) {
//		printf("xxx: signet requested fingerprint: [%.*s]\n", (int)pl_length_get(fingerprint), pl_char_get(fingerprint));
		sigdb = signet_fetch_by_full_fingerprint(&signame, &fingerprint);
	} else {
		sigdb = signet_fetch_current(&signame);
	}

	if (!sigdb) {
		con_write_bl(con, "450 SIGNET NOT FOUND.\r\n", 23);
		return;
	}

	con_print(con, "250 OK [%.*s]\r\n", (int)st_length_get(sigdb->data), st_char_get(sigdb->data));
	signet_db_destroy(sigdb);

	return;
}

/**
 * @brief	Get a user or domain key chain history, in response to the DMTP HIST command.
 * @param	con		the DMTP client connection issuing the command.
 * @return	This function returns no value.
 */
void dmtp_srv_hist(connection_t *con) {

	inx_t *signets, *coc;
	inx_cursor_t *cursor;
	signet_db_t *signet;
	placer_t pl = pl_clone(con->network.line), address = pl_null(), start_print = pl_null(), end_print = pl_null();

	// Trim any trailing whitespace or command terminator.
	pl_shrink_before_characters(&pl, "\r\n\t ", 4);

	if (!pl_update_start(&pl, 4, true) || !pl_skip_characters (&pl, " \t", 2)) {
		log_pedantic("Received DMTP HIST request with bad syntax.");
		con_write_bl(con, "501 BAD HIST SYNTAX.\r\n", 22);
		return;
	// Get the mandatory first parameter, which is an address.
	} else if (!pl_get_embraced(pl, &address, '<', '>', true)) {
		log_pedantic("Received DMTP HIST request with bad syntax.");
		con_write_bl(con, "501 BAD HIST SYNTAX.\r\n", 22);
		return;
	}

	if (!dmtp_is_valid_address(&address)) {
		log_pedantic("Received DMTP HIST request with bad parameter.");
		con_write_bl(con, "501 INVALID HIST PARAMETER.\r\n", 29);
		return;
	}

	// The second mandatory parameter is the fingerprint.
	// To do this, seek to the closing bracket, and skip whitespace, and then try to get the optionally enclosed data.
	if (!pl_skip_to_characters(&pl, ">", 1) || !pl_inc(&pl, true) || !pl_skip_characters(&pl, " \t", 2) ||
		!pl_get_embraced(pl, &start_print, '[', ']', true)) {
		con_write_bl(con, "501 INVALID HIST PARAMETER.\r\n", 29);
		return;
	}

	// The third, and optional parameter, is an ending fingerprint.
	if (pl_skip_to_characters(&pl, "]", 1) && pl_inc(&pl, true) && pl_skip_characters(&pl, " \t", 2)) {
		pl_get_embraced(pl, &end_print, '[', ']', true);
	}

	printf("xxx: HIST signet requested for [%.*s]\n", (int)st_length_get(&address), st_char_get(&address));
	printf("xxx: HIST signet requested start fingerprint: [%.*s], end [%.*s]\n", (int)pl_length_get(start_print), pl_char_get(start_print),
			pl_length_int(end_print), pl_char_get(end_print));

	start_print = pl_trim(start_print);

	if (!pl_empty(end_print)) {
		end_print = pl_trim(end_print);
	}

	// Get all the signets by this name.
	if (!(signets = signets_fetch_by_name(&address))) {
		con_write_bl(con, "450 SIGNET NOT FOUND.\r\n", 23);
		return;
	}

	// Then reduce them to the set of signets that actually belong to the chain of custody.
	if (!(coc = get_signet_coc(signets, &start_print, &end_print))) {
		con_write_bl(con, "450 SIGNET NOT FOUND.\r\n", 23);
		inx_free(signets);
		return;
	}

	if (!(cursor = inx_cursor_alloc(coc))) {
		inx_free(signets);
		inx_free(coc);
		log_error("Unable to traverse database signet reply.");
		con_write_bl(con, "451 Unexpected internal error occurred.\r\n", 41);
		return;
	}

	while ((signet = inx_cursor_value_next(cursor))) {
			con_print(con, "250-[%.*s]\r\n", st_length_get(signet->data), st_char_get(signet->data));
	}

	inx_cursor_free(cursor);
	inx_free(signets);
	inx_free(coc);

	con_write_bl(con, "250 OK\r\n", 8);
	return;
}

/**
 * @brief	Return a nonce to be used by the client with the STATS command.
 * @param	con		the DMTP client connection issuing the command.
 * @return	This function returns no value.
 */
void dmtp_srv_stats(connection_t *con) {

	stringer_t *randstr, *nonce_hex;
	placer_t pl = pl_clone(con->network.line), nonce = pl_null(), randata;
	chr_t randbuf[32];
	uint64_t *randptr = (uint64_t *)randbuf;
	size_t i;

	// Trim any trailing whitespace or command terminator.
	pl_shrink_before_characters(&pl, "\r\n\t ", 4);

	// Check to see if the STATS command was issued with a nonce.
	if (pl_update_start(&pl, 5, true) && pl_skip_characters (&pl, " \t", 2) && pl_get_embraced(pl, &nonce, '[', ']', true)) {

		if (!con->dmtp.stats_nonce) {
			con_print(con, "450 BAD NONCE.\r\n");
			return;
		}

		if (!(nonce_hex = base64_encode_mod(con->dmtp.stats_nonce, NULL))) {
			con_write_bl(con, "451 Unexpected internal error occurred.\r\n", 41);
			return;
		}

		if (st_cmp_ci_eq(nonce_hex, &nonce)) {
			con_print(con, "450 BAD NONCE.\r\n");
		} else {
			con_print(con, "502 Command not implemented\r\n");
		}

		st_free(nonce_hex);
		return;
	}

	for(i = 0; i < sizeof(randbuf)/sizeof(uint64_t); i++) {
		*randptr = rand_get_uint64();
		randptr++;
	}

	randata = pl_init(randbuf, sizeof(randbuf));

	if (!(randstr = base64_encode_mod(&randata, NULL))) {
		con_write_bl(con, "451 Unexpected internal error occurred.\r\n", 41);
	} else {
		con_print(con, "200 ONCE [%.*s]\r\n", st_length_get(randstr), st_char_get(randstr));
		st_free(randstr);
	}

	con->dmtp.stats_nonce = st_import(randbuf, sizeof(randbuf));

	return;
}

/**
 * @brief	Verify that the fingerprint of a user or domain certificate is current, in response to the DMTP VRFY command.
 * @param	con		the DMTP client connection issuing the command.
 * @return	This function returns no value.
 */
void dmtp_srv_vrfy(connection_t *con) {

	signet_db_t *current, *sigdb;
	placer_t pl = pl_clone(con->network.line), signame = pl_null(), fingerprint = pl_null();
	bool_t is_user = false;

	// Trim any trailing whitespace or command terminator.
	pl_shrink_before_characters(&pl, "\r\n\t ", 4);

	if (!pl_update_start(&pl, 4, true) || !pl_skip_characters (&pl, " \t", 2)) {
		log_pedantic("Received DMTP VRFY request with bad syntax.");
		con_write_bl(con, "501 BAD VRFY SYNTAX.\r\n", 22);
		return;
	// Get the first mandatory parameter, which is either a domain or address.
	} else if (!pl_get_embraced(pl, &signame, '<', '>', true)) {
		log_pedantic("Received DMTP VRFY request with bad syntax.");
		con_write_bl(con, "501 BAD VRFY SYNTAX.\r\n", 22);
		return;
	}

	if (st_search_chr(&signame, '@', NULL)) {
		is_user = true;
	}

	// If no '@' it must be a valid domain; if there is a '@' it must be a valid address.
	if ((!is_user && !dmtp_is_valid_domain(&signame)) || (is_user && !dmtp_is_valid_address(&signame))) {
		log_pedantic("Received DMTP VRFY request with bad parameter.");
		con_write_bl(con, "501 INVALID VRFY PARAMETER.\r\n", 29);
		return;
	}

	// See if the optional fingerprint parameter was supplied.
	// To do this, seek to the closing bracket, and skip whitespace, and then try to get the optionally enclosed data.
	if (!pl_skip_to_characters (&pl, ">", 1) || !pl_inc(&pl, true) || !pl_skip_characters(&pl, " \t", 2) ||
		!pl_get_embraced(pl, &fingerprint, '[', ']', true)) {
		log_pedantic("Received DMTP VRFY request with bad parameter.");
		con_write_bl(con, "501 INVALID VRFY PARAMETER.\r\n", 29);
	}

	printf("xxx: VRFY requested for [%.*s]\n", st_length_int(&signame), st_char_get(&signame));

	if (!(current = signet_fetch_current(&signame))) {
		con_write_bl(con, "450 SIGNET NOT FOUND.\r\n", 23);
		return;
	}

	// Get the specified signet-by-fingerprint just to see if it ever existed.
	if (!(sigdb = signet_fetch_by_any_fingerprint(&signame, &fingerprint))) {
		signet_db_destroy(current);
		con_write_bl(con, "450 SIGNET NOT FOUND.\r\n", 23);
		return;
	}

	//if (sigdb->num == current->num) {
	if (!st_cmp_ci_eq(current->fingerprint_full, &fingerprint) || !st_cmp_ci_eq(current->fingerprint_core, &fingerprint)) {
		con_write_bl(con, "250 CURRENT\r\n", 13);
	} else {
		con_print(con, "250 UPDATE [%.*s]\r\n", st_length_int(current->fingerprint_full), st_data_get(current->fingerprint_full));
	}

	signet_db_destroy(current);
	signet_db_destroy(sigdb);

	return;
}

/**
 * @brief	Return a list of supported commands in response to a DMTP HELP command.
 * @param	con		the DMTP client connection issuing the command.
 * @return	This function returns no value.
 */
void dmtp_srv_help(connection_t *con) {

	placer_t pl = pl_clone(con->network.line);
	command_t command = { .function = NULL };
	command_t *cmd;
	size_t i;

	// Trim any trailing whitespace or command terminator.
	pl_shrink_before_characters(&pl, "\r\n\t ", 4);

	// If a parameter is specified, execute the per-instruction help.
	if (pl_update_start(&pl, 4, true) && pl_skip_characters (&pl, " \t", 2)) {
		command.string = pl_char_get(pl);
		command.length = pl_length_get(pl);

		if ((cmd = bsearch(&command, dmtp_commands, dmtp_num_cmds, sizeof(command_t), cmd_compare))) {

			if (cmd->help) {
				con_print(con, "214-%.*s\r\n214-%s\r\n214 OK\r\n", (int)pl_length_get(pl), pl_char_get(pl), cmd->help);
			} else {
				con_print(con, "214 NO HELP AVAILABLE FOR COMMAND %.*s\r\n", (int)pl_length_get(pl), pl_char_get(pl));
			}

		} else {
			con_print(con, "214 HELP SPECIFIED INVALID COMMAND: %.*s\r\n", (int)pl_length_get(pl), pl_char_get(pl));
		}

		return;
	}

	con_write_bl(con, "214-AVAILABLE COMMANDS\r\n", 24);

	for (i = 0; i < dmtp_num_cmds; i++) {
		con_print(con, "214-%s\r\n", dmtp_commands[i].string);
	}

	con_write_bl(con, "214 OK\r\n", 8);

	return;
}

/**
 * @brief	Reset the DMTP session, in response to a DMTP RSET command.
 * @param	con		the DMTP client connection issuing the command.
 * @return	This function returns no value.
 */
void dmtp_srv_rset(connection_t *con) {

	dmtp_srv_session_reset(con);
	con_write_bl(con, "250 OK\r\n", 8);

	return;
}

/**
 * @brief	Execute a DMTP NOOP (no-operation) command.
 * @note	This command does essentially nothing and is mostly a way to keep connections alive without timing out due to inactivity.
 * @return	This function returns no value.
 */
void dmtp_srv_noop(connection_t *con) {

	con_write_bl(con, "250 OK\r\n", 8);
	return;
}

/**
 * @brief	Put the DMTP server into verbose mode.
 * @return	This function returns no value.
 */
void dmtp_srv_verb(connection_t *con) {

	con->dmtp.verbose = true;
	con_write_bl(con, "200 OK\r\n", 8);

	return;
}

/**
 * @brief	Retrieve the mode value of the DMTP server.
 * @return	This function returns no value.
 */
void dmtp_srv_mode(connection_t *con) {

	if (!magma.dmtp.dualmode) {
		con_write_bl(con, "200 OK DMTPv1\r\n", 15);
	} else if (!con->dmtp.fallback && con_secure(con) != 1) {
		con_write_bl(con, "200 OK ESMTP DMTPv1\r\n", 21);
	} else if (!con->dmtp.fallback && con_secure(con) == 1) {
		con_write_bl(con, "200 OK DMTPv1\r\n", 15);
	}
	// This code path shouldn't even be reached.
	else {
		con_write_bl(con, "200 OK ESMTP\r\n", 14);
	}

	return;
}

// Ripped from dmap_read_raw_data()
stringer_t * dmtp_read_raw_data(connection_t *con, size_t expected) {

	stringer_t *result;
	chr_t *holder;
	ssize_t nread;
	size_t left, characters;

	if (!(result = st_alloc(expected))) {
			log_error("Unable to allocate a buffer of %lu bytes for expected data.", expected);
			return NULL;
	}

	left = expected;

	// Where we put the data.
	holder = st_char_get(result);

	// Keep looping until we run out of data.
	while (left) {

		// Read the data.
		if ((nread = con_read(con)) <= 0) {
			log_pedantic("The connection was dropped while reading expected data.");
			st_free(result);
			return NULL;
		}

		characters = nread;

		// If we have a buffer, copy the data into the buffer.
		mm_copy(holder, st_char_get(con->network.buffer), (left > characters) ? characters : left);

		if (left > characters) {
			holder += characters;
			left -= characters;
		}
		else {
		 	st_length_set(result, expected);

			// If we have any extra characters in the buffer, move them to the beginning.
			if (characters > left) {
				mm_move(st_char_get(con->network.buffer), st_char_get(con->network.buffer) + left, characters - left);
				st_length_set(con->network.buffer, characters - left);
				con->network.line = line_pl_st(con->network.buffer, 0);
			}
			else {
					st_length_set(con->network.buffer, 0);
					con->network.line = pl_null();
			}

			// Make sure we have a full line.
			if (pl_empty(con->network.line) && con_read_line(con, true) <= 0) {
				log_pedantic("The connection was dropped while reading the literal.");
				st_free(result);
				return NULL;
			}

			left = 0;
		}
	}

	return result;
}


uint64_t dmime_store_message(uint64_t usernum, uint64_t foldernum, uint32_t *status, stringer_t *message) {

	chr_t *path;
	uint64_t messagenum;
	int64_t transaction, ret;
	uint8_t fflags = 0;
	bool_t store_result;

	// Begin the transaction.
	if ((transaction = tran_start()) < 0) {
		log_error("Could not start a transaction. {start = %li}", transaction);
		return 0;
	}

	// Insert a record into the database.
	if ((messagenum = mail_db_insert_message(usernum, foldernum, *status, st_length_int(message), 0, 0, transaction)) == 0) {
		log_pedantic("Could not create a record in the database. mail_db_insert_message = 0");
		tran_rollback(transaction);
		return 0;
	}
printf("XXX: stored in db: %lu\n", messagenum);

	// Now attempt to save everything to disk.
	store_result = mail_store_message_data(messagenum, fflags, st_char_get(message), st_length_get(message), &path);

	// If storage failed, fail out.
	if (!store_result || !path) {
		log_pedantic("Failed to store user's message to disk.");
		tran_rollback(transaction);

		if (path) {
			unlink(path);
			ns_free(path);
		}

		return 0;
	}

	// Commit the transaction.
	if ((ret = tran_commit(transaction))) {
		log_error("Could not commit the transaction. { commit = %li }", ret);
		unlink(path);
		ns_free(path);
		return 0;
	}

	ns_free(path);
	return messagenum;
}


int_t dmtp_store_message(smtp_inbound_prefs_t *prefs, stringer_t *message) {

	uint32_t status = MAIL_STATUS_DMIME;
	uint64_t messagenum;

	if (!prefs->usernum || !message || !prefs->foldernum) {
		log_pedantic("An invalid DMIME message or session was passed in for storage.");
		return -1;
	}

	if ((prefs->mark & SMTP_MARK_READ) == SMTP_MARK_READ) {
		status |= MAIL_STATUS_SEEN;
	}
	else {
		status |= MAIL_STATUS_RECENT;
	}

	// Begin the transaction.
	if (user_lock(prefs->usernum) != 1) {
		log_pedantic("Could not lock the user account %lu.", prefs->usernum);
		return -1;
	}

	messagenum = dmime_store_message(prefs->usernum, prefs->foldernum, &status, message);
	user_unlock(prefs->usernum);

	// Error check.
	if (!messagenum) {
		log_error("Unable to store message.");
		return -1;
	}

	// Increment the messages checkpoint_t so connected clients know there are new messages waiting.
	serial_increment(OBJECT_MESSAGES, prefs->usernum);

	// Set the output values.
	prefs->messagenum = messagenum;
	return 1;
}
