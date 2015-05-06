#ifndef DMSG_H
#define DMSG_H

#include <dmessage/dmime.h>

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




#endif
