#ifndef DMSG_H
#define DMSG_H

#include <dmessage/dmime.h>

dmime_object_t *          dime_dmsg_decrypt_envelope(const dmime_message_t *msg, dmime_actor_t actor, dmime_kek_t *kek);

int                       dime_dmsg_decrypt_message_as_auth(dmime_object_t *obj, const dmime_message_t *msg, dmime_kek_t *kek);

int                       dime_dmsg_decrypt_message_as_dest(dmime_object_t *obj, const dmime_message_t *msg, dmime_kek_t *kek);

int                       dime_dmsg_decrypt_message_as_orig(dmime_object_t *obj, const dmime_message_t *msg, dmime_kek_t *kek);

int                       dime_dmsg_decrypt_message_as_recp(dmime_object_t *obj, const dmime_message_t *msg, dmime_kek_t *kek);

void                      dime_dmsg_destroy_object(dmime_object_t *object);

void                      dime_dmsg_destroy_message(dmime_message_t *msg);

int                       dime_dmsg_dump_object(dmime_object_t *object);

dmime_message_t *         dime_dmsg_encrypt_message(dmime_object_t *object, ED25519_KEY *signkey);

int                       dime_dmsg_kek_derive_in(const dmime_message_t *msg, EC_KEY *enckey, dmime_kek_t *kek);

dmime_object_state_t      dime_dmsg_object_state_init(dmime_object_t *object);

dmime_message_state_t     dime_dmsg_message_state_get(const dmime_message_t *message);

unsigned char *           dime_dmsg_serial_from_message(const dmime_message_t *msg, unsigned char sections, unsigned char tracing, size_t *outsize);

dmime_message_t *         dime_dmsg_serial_to_message(const unsigned char *in, size_t insize);

int                       dime_dmsg_sign_origin_sig_chunks(dmime_message_t *msg, unsigned char bounce_flags, dmime_kek_t *kek, ED25519_KEY *signkey);
/* TODO not implemented yet */
/*
int                       dime_dmsg_file_create(const dmime_message_t *msg, const char *filename)

dmime_message_t *         dime_dmsg_file_to_message(const char *filename);
*/


#endif
