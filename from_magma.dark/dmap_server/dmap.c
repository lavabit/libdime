
/**
 * @file /magma/servers/dmap/dmap.c
 *
 * @brief	Functions used to handle DMAP commands/actions.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#include "magma.h"

// TODO: migrate to header.
stringer_t * dmail_load_message(meta_message_t *meta, meta_user_t *user, server_t *server, bool_t parse);
ED25519_KEY *signet_fetch_signkey(signet_t *signet) {

        ED25519_KEY *result;
        size_t key_size;
        unsigned char fid, *keydata;

        if (!signet) {
                RET_ERROR_PTR(ERR_BAD_PARAM, NULL);
        }

        switch(signet_get_type(signet)) {

                case SIGNET_TYPE_ORG:
                        fid = SIGNET_ORG_POK;
                        break;
                case SIGNET_TYPE_USER:
                        fid = SIGNET_USER_SIGN_KEY;
                        break;
                default:
                        RET_ERROR_PTR(ERR_UNSPEC, "invalid signet type");
                        break;

        }

        if (!(keydata = signet_fetch_fid_num(signet, fid, 1, &key_size))) {
                RET_ERROR_PTR(ERR_UNSPEC, "could not fetch signing key from signet");
        }

        if (!(result = _deserialize_ed25519_pubkey(keydata))) {
            free(keydata);
            RET_ERROR_PTR(ERR_UNSPEC, "could not deserialize signing key from signet");
    }

    free(keydata);

    return result;
}



/**
 * @brief	Initialize a TLS session for a DMAP session.
 * @param	con		the connection of the DMAP endpoint requesting the transport layer security upgrade.
 * @return	This function returns no value.
 */
void dmap_starttls(connection_t *con) {

	if (con->dmap.session_state != 0) {
		dmap_invalid(con);
		return;
	}
	else if (con_secure(con) == 1) {
		con_print(con, "%.*s BAD This session is already using SSL.\r\n", st_length_get(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}
	// This condition should never be possible.
	else if (con_secure(con) == -1) {
		con_print(con, "%.*s NO This server is not configured to support TLS.\r\n", st_length_get(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}

	// Tell the user that we are ready to start the negotiation.
	con_print(con, "%.*s OK Ready to start TLS negotiation.\r\n", st_length_get(con->dmap.tag), st_char_get(con->dmap.tag));

	if (!(con->network.ssl = ssl_alloc(con->server, con->network.sockd, M_SSL_BIO_NOCLOSE))) {
		con_print(con, "%.*s NO SSL Connection attempt failed.\r\n", st_length_get(con->dmap.tag), st_char_get(con->dmap.tag));
		log_pedantic("The SSL connection attempt failed.");
		return;
	}

	// Clear the input buffer. A shorthand session reset.
	stats_increment_by_name("dmap.connections.secure");
	st_length_set(con->network.buffer, 0);
	con->network.line = pl_null();
	con->network.status = 1;

	return;
}

/**
 * @brief	The main DMAP entry point for all inbound client connnections, as dispatched by the generic protocol handler.
 * @param	con		the newly accepted DMAP client connection.
 * @return	This function returns no value.
 */
void dmap_init(connection_t *con) {

	con_reverse_enqueue(con);

	// Introduce ourselves. Note the string below needs to stay in sync with the capability command.
	con_print(con, "* OK %.*s DMAPv1\r\n",	st_length_int(con->server->domain), st_char_get(con->server->domain));

	dmap_requeue(con);

	return;
}

/**
 * @brief	Terminate a DMAP session gracefully with a BYE message and destroy the underlying connection.
 * @param	con		the DMAP connection to be terminated.
 * @return	This function returns no value.
 */
void dmap_logout(connection_t *con) {

	if (con_status(con) == 2) {
		con_write_bl(con, "* BYE Unexpected connection shutdown detected. Goodbye.\r\n", 57);
	}
	else if (con_status(con) >= 0) {
		con_print(con, "* BYE Goodbye.\r\n%.*s OK Completed.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
	}
	else {
		con_write_bl(con, "* BYE Network connection failure.\r\n", 35);
	}

	con_destroy(con);

	return;
}

/**
 * @brief	A function that is executed when an invalid DMAP command is issued.
 * @return	This function returns no value.
 */
void dmap_invalid(connection_t *con) {

	con->protocol.violations++;
	usleep(con->server->violations.delay);
	con_print(con, "%.*s BAD Command not recognized.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));

	return;
}

/**
 * @brief	A function that is executed when the legacy IMAP LOGIN command is invoked.
 * @return	This function returns no value.
 */
void dmap_login(connection_t *con) {

	con_write_bl(con, "* [ALERT] Please upgrade to a more secure mail client to access your account.\r\n", 79);
	con_print(con, "%.*s NO\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));

	return;
}


/**
 * @brief	Execute a DMAP NOOP (no-operation) command.
 * @return	This function returns no value.
 */
void dmap_noop(connection_t *con) {

	if (false) {//(con->dmap.session_state == 1 && con->dmap.selected != 0 && con->dmap.user && dmap_session_update(con) == 1) {
		con_print(con, "* %lu EXISTS\r\n* %lu RECENT\r\n%.*s OK NOOP Completed.\r\n", con->dmap.messages_total, con->dmap.messages_recent,
			st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
	}
	else {
		con_print(con, "%.*s OK NOOP Completed.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
	}

	return;
}

/**
* @brief	Display the capability string for the DMAP server.
* @return	This function returns no value.
*/
void dmap_capability(connection_t *con) {

	con_write_bl(con, "* CAPABILITY DMAPv1 {UNSELECT} {QUOTA} {IDLE}\r\n", 47);
	return;
}

/**
* @brief	Initiate the authentication process, in response to a DMAP AUTH command.
* @return	This function returns no value.
*/
void dmap_auth(connection_t *con) {

	int_t state = 1;
	credential_t *cred;

	// The LOGIN command is only valid in the non-authenticated state.
	if (con->dmap.session_state) {
		con_print(con, "%.*s BAD This session has already been authenticated. Please logout and connect again to change users.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}

	// Input validation. Requires two non-NULL string arguments.
	if (ar_length_get(con->dmap.arguments) != 2 || imap_get_type_ar(con->dmap.arguments, 0) == IMAP_ARGUMENT_TYPE_ARRAY ||
		!imap_get_st_ar(con->dmap.arguments, 0) ||	imap_get_type_ar(con->dmap.arguments, 1) == IMAP_ARGUMENT_TYPE_ARRAY ||
		!imap_get_st_ar(con->dmap.arguments, 1)) {
		con_print(con, "%.*s BAD The auth command requires two string arguments.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}

	// Convert the strings into a full fledged credential context.
	if (!(cred = credential_alloc_auth(imap_get_st_ar(con->dmap.arguments, 0), imap_get_st_ar(con->dmap.arguments, 1)))) {
		con_print(con, "%.*s NO [ALERT] Internal server error. Please try again in a few minutes.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}

	// Clear the username string from any previous authentication attempts.
	st_cleanup(con->dmap.username);
	con->dmap.username = NULL;

	if (!(con->dmap.username = st_dupe_opts(MANAGED_T | CONTIGUOUS | HEAP, cred->auth.username))) {
		con_print(con, "%.*s NO [ALERT] Internal server error. Please try again in a few minutes.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		credential_free(cred);
		return;
	}

	// Try getting the session out of the global cache.
	state = meta_get(cred->auth.username, cred->auth.domain, cred->auth.password, cred->auth.key, META_PROT_DMAP, META_GET_MESSAGES | META_GET_FOLDERS, &(con->dmap.user));
	credential_free(cred);

	// Not found, or invalid password.
	if (state == 0) {
		con_print(con,  "%.*s NO [AUTHENTICATIONFAILED] The username and password combination is invalid.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}
	// Internal error.
	else if (state < 0 || !con->dmap.user) {
		con_print(con, "%.*s NO [UNAVAILABLE] This server is unable to access your mailbox. Please try again later.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}

	// Locks
	else if (con->dmap.user->lock_status != 0) {

		if (con->dmap.user->lock_status == 1) {
			con_print(con, "%.*s NO [CONTACTADMIN] This account has been administratively locked.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		}
		else if (con->dmap.user->lock_status == 2) {
			con_print(con, "%.*s NO [CONTACTADMIN] This account has been locked for inactivity.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		}
		else if (con->dmap.user->lock_status == 3) {
			con_print(con, "%.*s NO [CONTACTADMIN] This account has been locked on suspicion of abuse.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		}
		else if (con->dmap.user->lock_status == 4) {
			con_print(con, "%.*s NO [CONTACTADMIN] This account has been locked at the request of the user.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		}
		else {
			con_print(con, "%.*s NO [CONTACTADMIN] This account has been locked.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		}

		con->dmap.user = NULL;
		meta_remove(con->dmap.username, META_PROT_DMAP);
		return;
	}

	// Store the checkpoints.
	meta_user_rlock(con->dmap.user);
	con->dmap.messages_checkpoint = con->dmap.user->serials.messages;
	con->dmap.folders_checkpoint = con->dmap.user->serials.folders;
	con->dmap.user_checkpoint = con->dmap.user->serials.user;
	meta_user_unlock(con->dmap.user);

	// Debug logging.
	log_pedantic("User %.*s logged in from %s via DMAP. {poprefs = %lu, imaprefs = %lu, messages = %lu, folders = %lu}",
		st_length_int(con->dmap.username), st_char_get(con->dmap.username), st_char_get(con_addr_presentation(con, MANAGEDBUF(1024))),
		con->imap.user->refs.pop, con->imap.user->refs.imap, con->dmap.user->messages ? inx_count(con->dmap.user->messages) : 0, con->dmap.user->folders ? inx_count(con->imap.user->folders) : 0);

	// Update session state.
	con->dmap.session_state = 1;

	// Tell the client everything worked.
	con_print(con, "%.*s OK Password accepted.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));

	return;
}

/**
* @brief
* @return	This function returns no value.
*/
void dmap_list(connection_t *con) {

	inx_t *list;
	stringer_t *name;
	inx_cursor_t *cursor;
	meta_folder_t *active;

	// Check for the right state.
	if (con->dmap.session_state != 1) {
		con_print(con, "%.*s BAD The list command is not available until you are authenticated.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}

	// Input validation. Requires two string arguments, which can both be NULL.
	if (ar_length_get(con->dmap.arguments) != 2 || imap_get_type_ar(con->dmap.arguments, 0) == IMAP_ARGUMENT_TYPE_ARRAY || imap_get_type_ar(con->dmap.arguments, 1) == IMAP_ARGUMENT_TYPE_ARRAY) {
		con_print(con, "%.*s BAD The list command requires two string arguments.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}

	// To handle the special mailbox case.
	if (!imap_get_st_ar(con->dmap.arguments, 1)) {
		con_print(con, "* LIST (\\Noselect) \".\" \"\"\r\n%.*s OK LIST Complete.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}

	meta_user_rlock(con->dmap.user);

	//Here. Now force the lister to use the new interface.
	if ((cursor = inx_cursor_alloc(con->dmap.user->message_folders))) {

		stringer_t *nm;
		message_folder_t *cur;
		while ((cur = inx_cursor_value_next(cursor))) {
			if ((nm = magma_folder_name(con->dmap.user->message_folders, cur))) {
				log_pedantic("%.*s = %lu", st_length_int(nm), st_char_get(nm), inx_count(cur->records));
				st_free(nm);
			}
			else {
				log_pedantic("Folder name error.");
			}

		}

		inx_cursor_free(cursor);
	}

	// Because the list index is a shallow copy we need to ensure the original memory buffers aren't freed by another thread.
	if ((list = imap_narrow_folders(con->dmap.user->folders, imap_get_st_ar(con->dmap.arguments, 0), imap_get_st_ar(con->dmap.arguments, 1))) != NULL) {

		if ((cursor = inx_cursor_alloc(list))) {

			// Some buggy clients require that the Inbox always come first.
			while ((active = inx_cursor_value_next(cursor))) {
				if (active->parent == 0 && !st_cmp_ci_eq(NULLER(active->name), PLACER("Inbox", 5))) {
					con_print(con, "* LIST (\\Noinferiors) \".\" \"%s\"\r\n", active->name);
				}
			}

			inx_cursor_reset(cursor);

			// On the second pass print all the folders except the Inbox. Because some folders have special characters we need to
			// generate an encoded/sanitized version of the folder name to print.
			while ((active = inx_cursor_value_next(cursor))) {
				if ((active->parent != 0 || st_cmp_ci_eq(NULLER(active->name), PLACER("Inbox", 5))) &&
					(name = imap_folder_name_escaped(con->dmap.user->folders, active))) {
						con_print(con, "* LIST () \".\" %.*s\r\n", st_length_int(name), st_char_get(name));
						st_free(name);
				}
			}

			inx_cursor_free(cursor);
		}

		inx_free(list);
	}

	meta_user_unlock(con->dmap.user);

	// Let the user know everything worked.
	con_print(con, "%.*s OK LIST Complete.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
	return;
}


/**
* @brief	Read in raw, unformatted data from a DMAP client.
* @note		This function is used by the DMAP submission command.
* @return	This function returns no value.
*/
stringer_t * dmap_read_raw_data(connection_t *con, size_t expected) {

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


/**
* @brief	Receive a DMIME message from a user, in response to a DMAP SUBMIT command.
* @return	This function returns no value.
*/
void dmap_submit(connection_t *con) {

	dmime_message_t *decrypted, *encrypted;
	dmime_message_out_t *msg_out;
	ED25519_KEY *verkey;
	stringer_t *msglen, *filedata;
	uint64_t flen;
	int res;

	if (con->dmap.session_state != 1) {
		con_print(con, "%.*s BAD The submit command is not available until you are authenticated.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}

	// Input validation. Requires a single argument.
	if (ar_length_get(con->dmap.arguments) != 1 || imap_get_type_ar(con->dmap.arguments, 0) == IMAP_ARGUMENT_TYPE_ARRAY) {
		con_print(con, "%.*s BAD The submit command requires one string argument.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}

	msglen = imap_get_st_ar(con->dmap.arguments, 0);

	if (!uint64_conv_st(msglen, &flen)) {
		con_print(con, "%.*s BAD The submit command received an invalid size parameter: %.*s\r\n",
				st_length_int(con->dmap.tag), st_char_get(con->dmap.tag),
				st_length_int(msglen), st_char_get(msglen));
		return;
	}

	con_print(con, "%.*s OK Receiving DMIME message of bytes = [%lu]\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag), flen);

	if (!(filedata = dmap_read_raw_data(con, flen))) {
		con_print(con, "%.*s BAD The data for the submit command was unable to be read.\r\n",
					st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}

	con_print(con, "%.*s OK DMIME message successfully received.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));

	if (!(encrypted = parse_dmime_raw(st_char_get(filedata), st_length_get(filedata)))) {
		log_pedantic("Unable to parse data into new DMIME message holder.");
		dump_error_stack();
		st_free(filedata);
		return;
	}

//printf("ENCRYPTED:\n");
//dump_dmsg_buf(st_char_get(filedata), st_length_get(filedata), DUMP_CHUNK_CONTENT|DUMP_ENC_DATA);

	if (!(decrypted = dmsg_decrypt_message(encrypted, id_author))) {
		log_pedantic("A problem occurred while decrypting the received DMIME message.");
		dump_error_stack();
		destroy_dmime_message(encrypted);
		return;
	}

//printf("DECRYPTED:\n");
//	dump_dmsg_buf(st_char_get(decrypted->chunk_data), st_length_get(decrypted->chunk_data), DUMP_CHUNK_CONTENT);
	decrypted->flags |= DMSG_FLAG_CHUNKS_VERIFIED;

	if (!(msg_out = create_dmsg_out(decrypted, id_author))) {
		log_pedantic("Could not process plaintext DMIME message.\n");
		dump_error_stack();
		destroy_dmime_message(encrypted);
		destroy_dmime_message(decrypted);
		return;
	}

    if (!(verkey = signet_fetch_signkey(msg_out->signet_author))) {
    	log_pedantic("Could not get author signature verification key from signet.");
    	dump_error_stack();
    	destroy_dmime_message(encrypted);
    	destroy_dmime_message(decrypted);
    	destroy_dmsg_out(msg_out);
    	return;
    }
    if ((res = author_vrfy_signatures(encrypted, verkey)) < 0) {
    	log_pedantic("Encountered error while verifying author signature against signet key.");
    	dump_error_stack();
    	destroy_dmime_message(encrypted);
    	destroy_dmime_message(decrypted);
    	destroy_dmsg_out(msg_out);
    	return;
    } else if (!res) {
    	log_pedantic("Author signature failed verification against signet key.");
    	destroy_dmime_message(encrypted);
    	destroy_dmime_message(decrypted);
    	destroy_dmsg_out(msg_out);
    	return;

    }

    printf("XXX: author signatures verified\n");


	/*if ((res = dmsg_verify_chunk_data(decrypted, kp)) <= 0) {

		if (res < 0) {
			fprintf(stderr, "Error: chunk verification on plaintext DMIME message encountered an unexpected condition.\n");
			//dump_error_stack();
		} else {
			fprintf(stderr, "Error: chunk verification on plaintext DMIME message failed.\n");
		}

	}*/

	destroy_dmime_message(encrypted);
	destroy_dmime_message(decrypted);
	destroy_dmsg_out(msg_out);

	return;
}


void dmap_fetch(connection_t *con) {

	inx_cursor_t *cursor;
	meta_message_t *active;
	stringer_t *msgno, *msgdata;
	uint64_t mindex;
	size_t i = 0;

	if (con->dmap.session_state != 1) {
		con_print(con, "%.*s BAD The fetch command is not available until you are authenticated.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}

	// Input validation. Requires a single argument.
	if (ar_length_get(con->dmap.arguments) != 1 || imap_get_type_ar(con->dmap.arguments, 0) == IMAP_ARGUMENT_TYPE_ARRAY) {
		con_print(con, "%.*s BAD The submit command requires one string argument.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}

	msgno = imap_get_st_ar(con->dmap.arguments, 0);

	if (!uint64_conv_st(msgno, &mindex)) {
		con_print(con, "%.*s BAD The fetch command received an invalid index parameter: %.*s\r\n",
				st_length_int(con->dmap.tag), st_char_get(con->dmap.tag), st_length_int(msgno), st_char_get(msgno));
		return;
	}

	if ((cursor = inx_cursor_alloc(con->imap.user->messages))) {

		while ((active = inx_cursor_value_next(cursor))) {

			if (active->status & MAIL_STATUS_DMIME) {
				i++;
				printf("XXX: spotted DMIME message; comparing %zu against %lu\n", i, mindex);

				if (i == mindex) {
					printf("XXX: found message\n");


					if (!(msgdata = dmail_load_message(active, con->imap.user, con->server, false))) {
						con_print(con, "%.*s NO [ALERT] Internal server error.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
						return;
					}

					con_print(con, "* %lu FETCH (BODY[] {%zu}\r\n", mindex, st_length_get(msgdata));
					//int64_t con_write_st(connection_t *con, stringer_t *string) {
					printf("XXX: writing data across con: %ld\n", con_write_st(con, msgdata));
					st_free(msgdata);
					return;
				}

			}

		}

	}

	if (i != mindex) {
		con_print(con, "%.*s OK Fetch complete. No messages were found matching the range provided.\r\n",
				st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}

	con_print(con, "%.*s OK Retrieving body of message #: %.*s\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag),
			st_length_int(msgno), st_char_get(msgno));

	return;
}


/**
* @brief	Process a signet signing request from a user, in response to a DMAP AUTH command.
* @return	This function returns no value.
*/
void dmap_ssr(connection_t *con) {

	signet_t *builder;
	signet_db_t *signew, *current;
	stringer_t *ssrdata, *username;
	chr_t *core_fp, *full_fp, *sigdata, *errmsg = NULL;

	if (con->dmap.session_state != 1) {
		con_print(con, "%.*s BAD The SSR command is not available until you are authenticated.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}

	// Input validation. Requires a single argument.
	if (ar_length_get(con->dmap.arguments) != 1 || imap_get_type_ar(con->dmap.arguments, 0) == IMAP_ARGUMENT_TYPE_ARRAY) {
		con_print(con, "%.*s BAD The SSR command requires one string argument.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}

	// We call out to an external API, so we must construct a username string that is null-terminated.
	if (!(username = st_merge("snss", con->dmap.username, "@", magma.system.domain, CONSTANT("\00")))) {
		con_print(con, "%.*s NO SSR operation failed on internal error.\r\n", st_length_get(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}

	// Right now this operation is only supported for the submission of a new user signet.
	if ((current = signet_fetch_current(username))) {
		st_free(username);
		signet_db_destroy(current);
		con_print(con, "%.*s BAD SSR submission is only supported for new signets.\r\n", st_length_get(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}

	ssrdata = imap_get_st_ar(con->dmap.arguments, 0);
printf("XXX: user requesting ssr: [%s]\n", st_char_get(username));

	if (!(builder = sign_user_signet(username, ssrdata, &errmsg))) {

		if (!errmsg) {
			con_print(con, "%.*s NO SSR operation failed.\r\n", st_length_get(con->dmap.tag), st_char_get(con->dmap.tag));
		} else {
			con_print(con, "%.*s NO SSR operation failed: %s.\r\n", st_length_get(con->dmap.tag), st_char_get(con->dmap.tag), errmsg);
		}

		st_free(username);
		return;
	}

	if (!(signew = mm_alloc(sizeof(signet_db_t)))) {
		st_free(username);
		signet_destroy(builder);
		con_print(con, "%.*s NO [ALERT] Internal server error. Please try again in a few minutes.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}

	full_fp = signet_full_fingerprint(builder);
	core_fp = signet_core_fingerprint(builder);
	sigdata = signet_serialize_b64(builder);
	signet_destroy(builder);

	if (!full_fp || !core_fp || !sigdata) {
		st_free(username);
		signet_db_destroy(signew);

		if (full_fp) {
			free(full_fp);
		}

		if (core_fp) {
			free(core_fp);
		}

		if (!sigdata) {
			free(sigdata);
		}

		con_print(con, "%.*s NO SSR operation failed: could not calculate signet data.\r\n", st_length_get(con->dmap.tag), st_char_get(con->dmap.tag));
		return;
	}

	signew->fingerprint_full = st_import(full_fp, ns_length_get(full_fp));
	signew->fingerprint_core = st_import(core_fp, ns_length_get(core_fp));
	signew->data = st_import(sigdata, ns_length_get(sigdata));

	free(full_fp);
	free(core_fp);
	free(sigdata);

	signew->name = username;

	if (!signet_insert_db(signew)) {
		con_print(con, "%.*s NO [ALERT] Internal server error. Please try again in a few minutes.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
	} else {
		con_print(con, "%.*s OK SSR processed successfully.\r\n", st_length_int(con->dmap.tag), st_char_get(con->dmap.tag));
	}

	signet_db_destroy(signew);

	return;
}


stringer_t * dmail_load_message(meta_message_t *meta, meta_user_t *user, server_t *server, bool_t parse) {

	int_t fd;
	chr_t *path;
	stringer_t *raw, *result;
	//mail_message_t *result;
	message_fheader_t fheader;
	struct stat file_info;
	size_t data_len;

	if (!meta || (parse && (!user || !server))) {
		log_pedantic("Invalid parameter combination passed in.");
		return NULL;
	}

	if (!(meta->status & MAIL_STATUS_DMIME)) {
		log_pedantic("Could not load non-DMIME message.");
		return NULL;
	}

	if (!(path = mail_message_path(meta->messagenum, meta->server))) {
		log_pedantic("Could not build the message path.");
		return NULL;
	}

	// Open the file.LZO1X_1_MEM_COMPRESS
	if ((fd = open(path, O_RDONLY)) < 0) {
		log_pedantic("Could not open a file descriptor for the message %s.", path);
		mail_db_hide_message(meta->messagenum);
		serial_increment(OBJECT_MESSAGES, user->usernum);
		ns_free(path);
		return NULL;
	}

	// Figure out how big the file is, and allocate memory for it.
	if (fstat(fd, &file_info) != 0) {
		log_pedantic("Could not fstat the file %s.", path);
		close(fd);
		ns_free(path);
		return NULL;
	}

	if (file_info.st_size < sizeof(message_fheader_t)) {
		log_pedantic("Mail message was missing full file header: { %s }", path);
		close(fd);
		ns_free(path);
		return NULL;
	}

	// Do some sanity checking on the message header
	data_len = file_info.st_size - sizeof(message_fheader_t);

	if (read(fd, &fheader, sizeof(fheader)) != sizeof(fheader)) {
		log_pedantic("Unable to read message file header: { %s }", path);
		close(fd);
		ns_free(path);
		return NULL;
	}

	if ((fheader.magic1 != FMESSAGE_MAGIC_1) || (fheader.magic2 != FMESSAGE_MAGIC_2)) {
		log_pedantic("Mail message had incorrect file format: { %s }", path);
		close(fd);
		ns_free(path);
		return NULL;
	}

	// Allocate a buffer big enough to hold the entire compressed file.
	if (!(raw = st_alloc(data_len))) {
		log_pedantic("Could not allocate a buffer of %li bytes to hold the message.", data_len);
		close(fd);
		ns_free(path);
		return NULL;
	}

	// Read the file in.
	if (read(fd, st_char_get(raw), data_len) != data_len) {
		log_pedantic("Could not read all %li bytes of the file %s.", data_len, path);
		close(fd);
		ns_free(path);
		st_free(raw);
		return NULL;
	}

	close(fd);
	ns_free(path);

	// Tell the stringer how much data is there.
	st_length_set(raw, data_len);

	result = raw;
	/*if (!(result = mail_message(raw))) {
		log_pedantic("Unable to build the message structure.");
		st_free(raw);
		return NULL;
	} */

	return result;
}
