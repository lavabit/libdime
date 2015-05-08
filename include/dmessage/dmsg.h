#ifndef DMSG_H
#define DMSG_H

#include "dmessage/dmime.h"

/**
 * @brief	Returns a string from dmime_actor_t.
 * @param	actor		Actor value.
 * @return	String containing human readable actor.
*/
const char *              dime_dmsg_actor_to_string(dmime_actor_t actor);

/**
 * @brief	Retrieves author name for the following actors: author, origin, recipient.
 * @param	msg		Dmime message the author of which is retrieved.
 * @param	actor		Who is trying to get the message author.
 * @param	kek		Key encryption key for the specified actor.
 * @return	A newly allocated dmime object containing the envelope ids available to the actor.
 * @free_using{dime_dmsg_destroy_object}
 */
dmime_object_t *          dime_dmsg_decrypt_envelope(const dmime_message_t *msg, dmime_actor_t actor, dmime_kek_t *kek);

/**
 * @brief	Decrypts, verifies and extracts all the information available to the author from the message.
 * @param	obj		Dmime object into which the information is extracted, it must already contain the ids and signets of all the actors available to the author.
 * @param	msg		Dmime message to be decrypted.
 * @param	kek		Author's key encryption key.
 * @return	0 on success, all other output values indicate failure.
*/
int                       dime_dmsg_decrypt_message_as_auth(dmime_object_t *obj, const dmime_message_t *msg, dmime_kek_t *kek);

/**
 * @brief	Decrypts, verifies and extracts all the information available to the destination from the message.
 * @param	obj		Dmime object into which the information is extracted, it must already contain the ids and signets of all the actors available to the destination.
 * @param	msg		Dmime message to be decrypted.
 * @param	kek		Destination's key encryption key.
 * @return	0 on success, all other output values indicate failure.
*/
int                       dime_dmsg_decrypt_message_as_dest(dmime_object_t *obj, const dmime_message_t *msg, dmime_kek_t *kek);

/**
 * @brief	Decrypts, verifies and extracts all the information available to the origin from the message.
 * @param	obj		Dmime object into which the information is extracted, it must already contain the ids and signets of all the actors available to the origin.
 * @param	msg		Dmime message to be decrypted.
 * @param	kek		Origin's key encryption key.
 * @return	0 on success, all other output values indicate failure.
*/
int                       dime_dmsg_decrypt_message_as_orig(dmime_object_t *obj, const dmime_message_t *msg, dmime_kek_t *kek);

/**
 * @brief	Decrypts, verifies and extracts all the information available to the recipient from the message.
 * @param	obj		Dmime object into which the information is extracted, it must already contain the ids and signets of all the actors available to the recipient.
 * @param	msg		Dmime message to be decrypted.
 * @param	kek		Recipient's key encryption key.
 * @return	0 on success, all other output values indicate failure.
*/
int                       dime_dmsg_decrypt_message_as_recp(dmime_object_t *obj, const dmime_message_t *msg, dmime_kek_t *kek);

/**
 * @brief	Destroy a dmime_object_t structure.
 * @param	object		Pointer to dmime object to be destroyed.
 */
void                      dime_dmsg_destroy_object(dmime_object_t *object);

/**
 * @brief	Destroys dmime_message_t structure.
 * @param	msg		Pointer to the dmime message to be destroyed.
*/
void                      dime_dmsg_destroy_message(dmime_message_t *msg);

/**
 * @brief	Dumps the contents of the dmime object.
 * @param	object		Dmime object to be dumped.
 * @return	0 on success, all other values indicate failure.
*/
int                       dime_dmsg_dump_object(dmime_object_t *object);

/**
 * @brief       Converts a dmime object to a dmime message, fully encrypting and signing the message !!AS AN AUTHOR!!
 * @param	object		dmime object which contains all the envelope, metadata, display and attachment information.
 *                              As well as pointers to signets of author, origin, destination and recipient.
 * @param	signkey		The author's private ed25519 signing key which will be used.
 * @return	A pointer to a fully signed and encrypted dmime message.
 * @free_using{dime_dmsg_destroy_message}
*/
dmime_message_t *         dime_dmsg_encrypt_message(dmime_object_t *object, ED25519_KEY *signkey);

/**
 * @brief	Calculates the key encryption key for a given private encryption key and dmime message, using the ephemeral key chunk in the message
 * @param	msg		Pointer to the dmime message, which has the ephemeral key chunk to be used.
 * @param	enckey		Private EC encryption key.
 * @param	kek		Pointer to a dmime_kek_t - a key encryption key object that can be used to decrypt the keyslots.
 * @return	Returns 0 on success, all other values indicate failure.
 */
int                       dime_dmsg_kek_derive_in(const dmime_message_t *msg, EC_KEY *enckey, dmime_kek_t *kek);

/**
 * @brief	Takes a dmime object and determines the state it is in.
 * @param	object		Dmime object, state of which will be retrieved.
 * @return	The state of dmime object.
 */
dmime_object_state_t      dime_dmsg_object_state_init(dmime_object_t *object);

/**
 * @brief	Returns a string from dmime_object_state_t.
 * @param	state		Object state value.
 * @return	String containing human readable dmime object state.
*/
const char *              dime_dmsg_object_state_to_string(dmime_object_state_t state);

/**
 * @brief	Retrieves dmime message state.
 * @param	message		Pointer to a dmime message.
 * @return	dmime_message_state_t corresponding to the current state.
 */
dmime_message_state_t     dime_dmsg_message_state_get(const dmime_message_t *message);

/**
 * @brief	Converts the specified sections of a dmime message to a complete binary form. The message must be at least signed by author.
 * @param	msg		Dmime message to be converted.
 * @param	sections	Sections to be included.
 * @param	tracing		If set, include tracing, if clear don't include tracing.
 * @param	outsize		Stores the output size of the binary.
 * @free_using{free}
*/
unsigned char *           dime_dmsg_serial_from_message(const dmime_message_t *msg, unsigned char sections, unsigned char tracing, size_t *outsize);

/**
 * @brief	Converts a binary message into a dmime message. The message is assumed to be encrypted.
 * @param	in		Pointer to the binary message.
 * @param	insize		Pointer to the binary size.
 * @return	Pointer to a dmime message structure.
 * @free_using{dime_dmsg_destroy_message}
*/
dmime_message_t *         dime_dmsg_serial_to_message(const unsigned char *in, size_t insize);

/**
 * @brief	Signs the encrypted, author signed dmime message with the origin signatures. The origin signature chunks must already exist in order for the signing to occur.
 * @param	msg		Dmime message that will be signed by the origin.
 * @param	bounce_flags	Flags indicating bounce signatures that the origin will sign.
 * @param	kek		Origin's key encryption key.
 * @param	signkey		Origin's private signing key that will be used to sign the message. The public part of this key must be included in the origin signet either as the pok or one of the soks with the message signing flag.
 * @return	0 on success, anything else indicates failure.
*/
int                       dime_dmsg_sign_origin_sig_chunks(dmime_message_t *msg, unsigned char bounce_flags, dmime_kek_t *kek, ED25519_KEY *signkey);

/* TODO not implemented yet */
/*
int                       dime_dmsg_file_create(const dmime_message_t *msg, const char *filename)

dmime_message_t *         dime_dmsg_file_to_message(const char *filename);
*/

//TODO public interface for dmime_object_t !!
//TODO Review of message and object states (I think at least one of them doesn't need to be a structure member.)


#endif
