
/**
 * @file /magma/objects/mail/mail.h
 *
 * @brief	Functions used to interface with and manage message data.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#ifndef MAGMA_OBJECTS_MAIL_H
#define MAGMA_OBJECTS_MAIL_H


#include "mime.h"


#define MAIL_MIME_RECURSION_LIMIT 16
#define MAIL_SIGNATURES_RECURSION_LIMIT 16

typedef struct {
	uint64_t messagenum;
	stringer_t *text;
} mail_cache_t;

typedef struct {
	placer_t to;
	placer_t from;
	placer_t date;
	placer_t subject;
	stringer_t *text;
} basic_message_t;

typedef struct {
	array_t *children;
	stringer_t *boundary;
	uint32_t type, encoding;
	placer_t header, body, entire;
} mail_mime_t;

typedef struct {
	mail_mime_t *mime;
	size_t header_length;
	placer_t to, from, date, subject;
	stringer_t *text;
} mail_message_t;

typedef struct {
	chr_t *extension;
	bool_t bin;
	chr_t *name;
} media_type_t;

// counters.c
uint32_t      mail_count_received(stringer_t *message);
size_t        mail_header_end(stringer_t *message);

/// headers.c
//void          mail_add_forward_headers(server_t *server, stringer_t **message, stringer_t *id, int_t mark, uint64_t signum, uint64_t sigkey);
//stringer_t *  mail_add_inbound_headers(connection_t *con, smtp_inbound_prefs_t *prefs);
//int_t         mail_add_outbound_headers(connection_t *con);
//bool_t        mail_add_required_headers(connection_t *con, smtp_message_t *message);
stringer_t *  mail_header_fetch_all(stringer_t *header, stringer_t *key);
stringer_t *  mail_header_fetch_cleaned(stringer_t *header, stringer_t *key);
placer_t      mail_header_pop(stringer_t *header, size_t *position);
//bool_t        mail_headers(smtp_message_t *message);
void          mail_mod_subject(stringer_t **message, chr_t *label);
placer_t      mail_store_header(chr_t *stream, size_t length);

/// mime.c
stringer_t *   mail_mime_boundary(placer_t header);
placer_t       mail_mime_child(placer_t body, stringer_t *boundary, uint32_t child);
stringer_t *   mail_mime_content_encoding(placer_t header);
stringer_t *   mail_mime_content_id(placer_t header);
uint32_t       mail_mime_count(placer_t body, stringer_t *boundary);
int_t          mail_mime_encoding(placer_t header);
void           mail_mime_free(mail_mime_t *mime);
placer_t       mail_mime_header(stringer_t *part);
mail_mime_t *  mail_mime_part(stringer_t *part, uint32_t recursion);
array_t *      mail_mime_split(placer_t body, stringer_t *boundary);
int_t          mail_mime_type(placer_t header);
stringer_t *   mail_mime_type_group(placer_t header);
array_t *      mail_mime_type_parameters(placer_t header);
stringer_t *   mail_mime_type_parameters_key(stringer_t *parameter);
stringer_t *   mail_mime_type_parameters_value(stringer_t *parameter);
stringer_t *   mail_mime_type_sub(placer_t header);
int_t          mail_mime_update(mail_message_t *message);
media_type_t * mail_mime_get_media_type (chr_t *extension);
stringer_t *   mail_mime_generate_boundary (array_t *parts);
stringer_t *   mail_mime_encode_part(stringer_t *data, stringer_t *filename, stringer_t *boundary);
//stringer_t *   mail_mime_get_smtp_envelope(stringer_t *from, inx_t *tos, inx_t *ccs, inx_t *bccs, stringer_t *subject, stringer_t *boundary, bool_t attached);

/// objects.c
mail_message_t * mail_message(stringer_t *text);
//smtp_message_t * mail_create_message(stringer_t *text);
void             mail_destroy(mail_message_t *message);
//void             mail_destroy_message(smtp_message_t *message);
void             mail_setup_basic(basic_message_t *message, stringer_t *text);

/// parsing.c
stringer_t * mail_extract_address(stringer_t *address);
placer_t *   mail_domain_get(stringer_t *address, placer_t *output);

#endif
