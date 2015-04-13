#ifndef DMSG_H
#define DMSG_H

#include "dmessage/dmime.h"

PUBLIC_FUNC_DECL(dmime_object_state_t,          dmsg_init_object_state,      dmime_object_t *object);

PUBLIC_FUNC_DECL(dmime_message_state_t,         dmsg_get_message_state,      const dmime_message_t *msg);

PUBLIC_FUNC_DECL(void,                          dmsg_destroy_msg,            dmime_message_t *msg);

PUBLIC_FUNC_DECL(void,                          dmsg_destroy_object,         dmime_object_t *object);

PUBLIC_FUNC_DECL(dmime_message_t *,             dmsg_object_to_msg,          dmime_object_t *object,       ED25519_KEY *signkey);

PUBLIC_FUNC_DECL(unsigned char *,               dmsg_msg_to_bin,             const dmime_message_t *msg,   unsigned char sections,       unsigned char tracing, size_t *outsize);

PUBLIC_FUNC_DECL(dmime_message_t *,             dmsg_bin_to_msg,             const unsigned char *in,      size_t insize);

PUBLIC_FUNC_DECL(int,                           dmsg_get_kek,                const dmime_message_t *msg,   EC_KEY *enckey,               dmime_kek_t *kek);

PUBLIC_FUNC_DECL(dmime_object_t *,              dmsg_msg_to_object_envelope, const dmime_message_t *msg,   dmime_actor_t actor,          dmime_kek_t *kek);

PUBLIC_FUNC_DECL(int,                           dmsg_msg_to_object_as_auth,  dmime_object_t *object,       const dmime_message_t *msg,   dmime_kek_t *kek);

PUBLIC_FUNC_DECL(int,                           dmsg_msg_to_object_as_orig,  dmime_object_t *object,       const dmime_message_t *msg,   dmime_kek_t *kek);

PUBLIC_FUNC_DECL(int,                           dmsg_sign_origin_sig_chunks, dmime_message_t *msg,         unsigned char bounce_flags,   dmime_kek_t *kek,       ED25519_KEY *signkey);

PUBLIC_FUNC_DECL(int,                           dmsg_msg_to_object_as_dest,  dmime_object_t *object,       const dmime_message_t *msg,   dmime_kek_t *kek);

PUBLIC_FUNC_DECL(int,                           dmsg_msg_to_object_as_recp,  dmime_object_t *object,       const dmime_message_t *msg,   dmime_kek_t *kek);

PUBLIC_FUNC_DECL(int,                           dmsg_dump_object,            dmime_object_t *object);

PUBLIC_FUNC_DECL(int,                           dmsg_msg_to_file,            const dmime_message_t *msg,   const char *filename);

PUBLIC_FUNC_DECL(dmime_message_t *,             dmsg_file_to_msg,            const char *filename);



/* in chunk.c */

dmime_chunk_key_t * _dmsg_get_chunk_type_key(dmime_chunk_type_t type);

int _dmsg_padlen(size_t dsize, unsigned char flags, unsigned int *padlen, unsigned char *padbyte);

void * _dmsg_get_chunk_payload(dmime_message_chunk_t *chunk);

dmime_keyslot_t * _dmsg_get_chunk_keyslot_by_num(dmime_message_chunk_t *chunk, size_t num);

void _dmsg_destroy_message_chunk(dmime_message_chunk_t *msg);

dmime_message_chunk_t * _dmsg_create_message_chunk(dmime_chunk_type_t type, const unsigned char *data, size_t insize, unsigned char flags);

dmime_message_chunk_t * _dmsg_deserialize_chunk(const unsigned char *in, size_t insize, size_t *read);

dmime_message_chunk_t * _dmsg_wrap_chunk_payload(dmime_chunk_type_t type, unsigned char *payload, size_t insize);

unsigned char * _dmsg_get_chunk_data(dmime_message_chunk_t *chunk, size_t *outsize);

unsigned char * _dmsg_get_chunk_padded_data(dmime_message_chunk_t *chunk, size_t *outsize);

unsigned char * _dmsg_get_chunk_plaintext_sig(dmime_message_chunk_t *chunk);

unsigned char _dmsg_get_chunk_flags(dmime_message_chunk_t *chunk);

/* in parser.c */

dmime_common_headers_t * _dmsg_create_common_headers(void);

void _dmsg_destroy_common_headers(dmime_common_headers_t *obj);

unsigned char * _dmsg_format_common_headers(dmime_common_headers_t *obj, size_t *outsize);

dmime_header_type_t _dmsg_parse_next_header(unsigned char *in, size_t insize);

dmime_common_headers_t * _dmsg_parse_common_headers(unsigned char *in, size_t insize);

void _dmsg_destroy_envelope_object(dmime_envelope_object_t *obj);

dmime_envelope_object_t * _dmsg_parse_envelope(const unsigned char *in, size_t insize, dmime_chunk_type_t type);

char * _dmsg_actor_to_string(dmime_actor_t actor);

char * _dmsg_object_state_to_string(dmime_object_state_t state);

/* in dmsg.c */

dmime_message_chunk_t * _dmsg_encode_origin(dmime_object_t *object);

dmime_message_chunk_t * _dmsg_encode_destination(dmime_object_t *object);

dmime_message_chunk_t * _dmsg_encode_common_headers(dmime_object_t *object);

dmime_message_chunk_t * _dmsg_encode_other_headers(dmime_object_t *object);

dmime_message_chunk_t ** _dmsg_encode_display(dmime_object_t *object);

dmime_message_chunk_t ** _dmsg_encode_attach(dmime_object_t *object);

int _dmsg_encode_msg_chunks(dmime_object_t *object, dmime_message_t *message);

int _dmsg_sign_chunk(dmime_message_chunk_t *chunk, ED25519_KEY *signkey);

int _dmsg_sign_msg_chunks(dmime_message_t *message, ED25519_KEY *signkey);

int _dmsg_set_kek(EC_KEY *privkey, signet_t *signet, dmime_kek_t *kekbuf);

int _dmsg_derive_kekset(dmime_object_t *object, EC_KEY *ephemeral, dmime_kekset_t *kekset);

int _dmsg_encrypt_keyslot(dmime_keyslot_t *keyslot, dmime_kek_t *kek);

int _dmsg_encrypt_chunk(dmime_message_chunk_t *chunk, dmime_kekset_t *keks);

int _dmsg_encrypt_message(dmime_message_t *message, dmime_kekset_t *keks);

unsigned char * _dmsg_tree_sig_data(const dmime_message_t *msg, size_t *outsize);

size_t _dmsg_get_sections_size(const dmime_message_t *msg, unsigned char sections);

unsigned char * _dmsg_serialize_sections(const dmime_message_t *msg, unsigned char sections, size_t *outsize);

size_t _dmsg_get_chunks_size(const dmime_message_t *msg, dmime_chunk_type_t first, dmime_chunk_type_t last);

unsigned char * _dmsg_serialize_chunks(const dmime_message_t *msg, dmime_chunk_type_t first, dmime_chunk_type_t last, size_t *outsize);

int _dmsg_add_author_sig_chunks(dmime_message_t *message, ED25519_KEY *signkey, dmime_kekset_t *keks);

size_t _dmsg_deserialize_tracing(dmime_message_t *msg, const unsigned char *in, size_t insize);

dmime_message_chunk_t ** _dmsg_deserialize_section(const unsigned char *in, size_t insize, dmime_chunk_section_t section, size_t *read);

size_t _dmsg_deserialize_helper(dmime_message_t *msg , const unsigned char *in, size_t insize, dmime_chunk_type_t *last_type);

int _dmsg_decrypt_keyslot(dmime_keyslot_t *encrypted, dmime_kek_t *kek, dmime_keyslot_t *decrypted);

dmime_message_chunk_t * _dmsg_decrypt_chunk(dmime_message_chunk_t *chunk, dmime_actor_t actor, dmime_kek_t *kek);

void _dmsg_destroy_object_chunk_list(dmime_object_chunk_t *list);

int _dmsg_verify_chunk_signature(dmime_message_chunk_t *chunk, signet_t *signet);

int _dmsg_msg_to_object_origin(dmime_object_t *object, const dmime_message_t *msg, dmime_kek_t *kek);

int _dmsg_msg_to_object_destination(dmime_object_t *object, const dmime_message_t *msg, dmime_kek_t *kek);

int _dmsg_verify_author_sig_chunks(dmime_object_t *object, const dmime_message_t *msg, dmime_kek_t *kek);

int _dmsg_msg_to_object_common_headers(dmime_object_t *object, const dmime_message_t *msg, dmime_kek_t *kek);

int _dmsg_msg_to_object_other_headers(dmime_object_t *object, const dmime_message_t *msg, dmime_kek_t *kek);

dmime_object_chunk_t * _dmsg_create_object_chunk(dmime_chunk_type_t type, unsigned char *data, size_t data_size, unsigned char flags);

int _dmsg_msg_to_object_content(dmime_object_t *object, const dmime_message_t *msg, dmime_kek_t *kek);

int _dmsg_verify_origin_sig_chunks(dmime_object_t *object, const dmime_message_t *msg, dmime_kek_t *kek);



#endif
