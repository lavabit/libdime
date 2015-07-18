#ifndef SIGNET_H
#define SIGNET_H

#include <signet/general.h>



/**
 * @brief	Adds a field to the target field.
 * @param	signet		Pointer to the target signet.
 * @param	fid		Field id of the field to be added.
 * @param	data_size	Size of the array containing the field data.
 * @param	data		Field data.
 * @return	0 on success, -1 on failure.
 */
int                     dime_sgnt_create_defined_field(signet_t *signet, unsigned char fid, size_t data_size, const unsigned char *data);

/**
 * @brief	Returns	a new signet_t structure.
 * @param	type	signet type user org or sss (SIGNET_TYPE_USER, SIGNET_TYPE_ORG or SIGNET_TYPE_SSR)
 * @return	A pointer to a newly allocated signet_t structure type, NULL if failure.
 * @free_using{dime_sgnt_destroy_signet}
 */
signet_t *              dime_sgnt_create_signet(signet_type_t type);

/**
 * @brief	Creates a signet structure with public signing and encyption keys. Also creates a keys file in which the private keys are stored.
 * @param	type		Signet type, org, user or ssr (SIGNET_TYPE_ORG, SIGNET_TYPE_USER or SIGNET_TYPE_SSR).
 * @param	keysfile	Null terminated string containing the name of the keyfile to be created.
 * @return	Pointer to the newly created and allocated signet_t structure or NULL on error.
 * @free_using{dime_sgnt_destroy_signet}
 */
signet_t *              dime_sgnt_create_signet_w_keys(signet_type_t type, const char *keysfile);

/**
 * @brief	Adds a SOK (Secondary Organizational Signing Key) to an organizational signet.
 * @param	signet		Pointer to the target org signet.
 * @param	key		ED25519 key to be added as a SOK to the signet.
 * @param	format		Format specifier byte dictating the format.
 * @param	perm		Permissions for the usage of the SOK.
 * @return	0 on success, -1 on failure.
 */
int                     dime_sgnt_create_sok(signet_t *signet, ED25519_KEY *key, unsigned char format, sok_permissions_t perm);

/**
 * @brief	Adds an undefined field to signet with specified name and data.
 * @param	signet		Pointer to the target signet to which the field is added.
 * @param	name_size	Size of field name.
 * @param	name		Pointer to  field name.
 * @param	data_size	Size of field data.
 * @param	data		Pointer to field data.
 * @return	0 on success, -1 on failure.
 */
int                     dime_sgnt_create_undefined_field(signet_t *signet, size_t name_size, const unsigned char *name, size_t data_size, const unsigned char *data);

/**
 * @brief	Destroys a signet_t structure.
 * @param	record	Void pointer to a signet_t structure to be destroyed.
 */
void                    dime_sgnt_destroy_signet(signet_t *signet);

/**
 * @brief	Dumps signet into the specified file descriptor.
 * @param	fp	File descriptor the signet is dumped to.
 * @param	signet	Pointer to the signet_t structure to be dumped.
 */
void                    dime_sgnt_dump_signet(FILE *fp, signet_t *signet);

/**
 * @brief	Retrieves the public encryption key from the signet, if the signet is a user signet only retrieves the main encryption key (not alternate).
 * @param	signet	Pointer to the target signet.
 * @return	Pointer to the target encryption public key.
 * @free_using{free_ec_key}
 */
EC_KEY *                dime_sgnt_fetch_enckey(const signet_t *signet);

/**
 * @brief	Fetches the binary data value of the field specified by field id and the number at which it appears in the signet amongst fields with the same field id (1, 2, ...).
 * @param	signet	Pointer to the target signet.
 * @param	fid	Specified field id.
 * @param	num	Specified field number based on the order in which it appears in the signet.
 * @param	out_len	Pointer to the length of returned array.
 * @return	Array containing the binary data of the specified field, NULL if an error occurs. Caller is responsible for freeing memory.
 * @free_using{free}
 */
unsigned char *         dime_sgnt_fetch_fid_num(const signet_t *signet, unsigned char fid, unsigned int num, size_t *data_size);

/**
 * @brief	Retrieves all the signing keys from an org signet that can be used to sign a message.
 * @param	signet	Pointer to target organizational signet.
 * @return	A NULL pointer terminated array of ed25519 public signing key objects.
 * @NOTE	Always returns at least POK.
 * @free_using{free_ed25519_key_chain}
 */
ED25519_KEY **          dime_sgnt_fetch_msg_signkeys(const signet_t *signet);

/**
 * @brief	Retrieves the public signing key from the signet, if the signet is an org signet only retrieves the POK.
 * @param	signet	Pointer to the target signet.
 * @return	Pointer to the target ed25519 public key.
 * @free_using{free_ed25519_key}
 */
ED25519_KEY *           dime_sgnt_fetch_signkey(const signet_t *signet);

/**
 * @brief	Retrieves all the signing keys from an org signet that can be used to sign a signet.
 * @param	signet	Pointer to target organizational signet.
 * @return	A NULL pointer terminated array of ed25519 public signing key objects.
 * @NOTE	Always returns at least POK.
 * @free_using{free_ed25519_key_chain}
 */
ED25519_KEY **          dime_sgnt_fetch_signet_signkeys(const signet_t *signet);

/**
 * @brief	Retrieves all the signing keys from an org signet that can be used to sign software.
 * @param	signet	Pointer to target organizational signet.
 * @return	A NULL pointer terminated array of ed25519 public signing key objects.
 * @NOTE	Always returns at least POK.
 * @free_using{free_ed25519_key_chain}
 */
ED25519_KEY **          dime_sgnt_fetch_software_signkeys(const signet_t *signet);

/**
 * @brief	Fetch the secondary organizational signing key from the signet by number (starting at 1)
 * @param	signet	Pointer to the target organizational signet.
 * @param	num	The sok number to be fetched.
 * @return	Retrieved ED25519 key.
 * @free_using{free_ed25519_key}
 */
ED25519_KEY *           dime_sgnt_fetch_sok_num(const signet_t *signet, unsigned int num);

/**
 * @brief	Retrieves all the signing keys from an org signet that can be used to sign a TLS certificate.
 * @param	signet	Pointer to target organizational signet.
 * @return	A NULL pointer terminated array of ed25519 public signing key objects.
 * @NOTE	Always returns at least POK.
 * @free_using{free_ed25519_key_chain}
 */
ED25519_KEY **          dime_sgnt_fetch_tls_signkeys(const signet_t *signet);

/**
 * @brief	Fetches the first undefined field with the specified field name.
 * @param	signet		Pointer to the target signet.
 * @param	name_size	Length of the passed array containing the length of the target field name.
 * @param	name		Array containing the name of the desired undefined field.
 * @param	data_size       Pointer to the size of the array that gets returned by the function.
 * @return	The array containing the data from the specified field or NULL in case of failure such as if the field was not found.
 * @free_using{free}
 */
unsigned char *         dime_sgnt_fetch_undefined_field(const signet_t *signet, size_t name_size, const unsigned char *name, size_t *data_size);

/**
 * @brief	Checks for presence of field with specified id in the signet
 * @param	signet	The signet to be checked
 * @param	fid	Specified field id
 * @return	1 if such a field exists, 0 if it does not exist, -1 if error.
 */
int                     dime_sgnt_fid_exists(const signet_t *signet, unsigned char fid);

/**
 * @brief	Retrieves the number of fields with the specified field id.
 * @param	signet	Pointer to the target signet.
 * @param	fid	The target field id.
 * @return	The number of fields with specified field id. On various errors returns -1.
 *              NOTE: int overflow should not occur because of field size lower and signet size upper bounds.
 */
int                     dime_sgnt_fid_get_count(const signet_t *signet, unsigned char fid);

/**
 * @brief	Loads signet_t structure from a PEM formatted file specified by filename.
 * @param	filename	Null terminated string containing the filename of the file containing the signet.
 * @return	Pointer to a newly created signet_t structure loaded from the file, NULL on failure.
 * @free_using{dime_sgnt_destroy_signet}
 */
signet_t *              dime_sgnt_file_to_signet(const char *filename);

/**
 * @brief	Stores a signet from the signet_t structure in a PEM formatted file specified by the filename.
 * @param	signet		Pointer to the signet_t structure containing the signet.
 * @param	filename	Null terminated string containing the desired filename for the signet.
 * @return	0 on success, -1 on failure.
 */
int                     dime_sgnt_file_create(signet_t *signet, const char *filename);

/**
 * @brief	Takes a SHA512 fingerprint of a signet with all fields after the cryptographic signature field stripped off.
 * @note	To take an SSR fingerprint, use the signet_ssr_fingerprint() function.
 * @param	signet	Pointer to the target signet.
 * @return	Allocated NULL terminated string to a base64 encoded unpadded fingerprint. Null on error.
 * @free_using{free}
 */
char *                  dime_sgnt_fingerprint_crypto(const signet_t *signet);

/**
 * @brief	Takes a SHA512 fingerprint of the user or org signet with the ID and FULL signature fields stripped off.
 * @note	To take an SSR fingerprint, use the signet_ssr_fingerprint() function.
 * @param	signet	Pointer to the target signet.
 * @return	Allocated NULL terminated buffer to a base64 encoded unpadded fingerprint. Null on failure.
 * @free_using{free}
 */
char *                  dime_sgnt_fingerprint_full(const signet_t *signet);

/**
 * @brief	Takes a SHA512 fingerprint of the entire user or org signet.
 * @param	signet	Pointer to the target signet.
 * @return	Allocated NULL terminated buffer to a base64 encoded unpadded fingerprint. Null on failure;
 * @free_using{free}
 */
char *                  dime_sgnt_fingerprint_id(const signet_t *signet);

/**
 * @brief	Takes a SHA512 fingerprint of a user signet or an ssr with all fields after the SSR signature stripped off.
 * @param	signet	Pointer to the target signet.
 * @return	Allocated NULL terminated buffer to a base64 encoded unpadded fingerprint.
 * @free_using{free}
 */
char *                  dime_sgnt_fingerprint_ssr(const signet_t *signet);

/**
 * @brief	Removes the field specified by a field id and the number in which it appears in the target signet amongst fields with the same field id from the target signet.
 * @param	signet	Pointer to the target signet.
 * @param	fid	Field id of the field to be removed.
 * @param	num	The number in which the field to be removed appears amongst other fields with the same field id in the target signet, (1, 2, ...).
 * @return	0 on success, -1 on failure.
 */
int                     dime_sgnt_remove_fid_num(signet_t *signet, unsigned char fid, int num);

/**
 * @brief	Removes an undefined field from the target signet by name.
 * @param	signet		Pointer to the target signet.
 * @param	name_size	Size of field name.
 * @param	name		Name of the field to be removed.
 * @return	0 on success, -1 on failure.
 */
int                     dime_sgnt_remove_undefined_field(signet_t *signet, size_t name_size, const unsigned char *name);

/**
 * @brief	Deserializes a b64 signet into a signet structure.
 * @param	b64_in	Null terminated array of b64 signet data.
 * @return	Pointer to newly allocated signet structure, NULL if failure.
 * @free_using{dime_sgnt_destroy_signet}
 */
signet_t *              dime_sgnt_serial_b64_to_signet(const char *b64_in);

/**
 * @brief	Serializes a signet structure into binary data.
 * @param	signet		Pointer to the target signet.
 * @param	serial_size	Pointer to the value that stores the length of the array returned.
 * @return	Signet serialized into binary data. Null on error.
 * @free_using{free}
 */
unsigned char *         dime_sgnt_serial_from_signet(signet_t *signet, uint32_t *serial_size);

/**
 * @brief	Serializes a signet structure into b64 data.
 * @param	signet		Pointer to the target signet.
 * @return	Signet serialized into b64 data. Null on error.
 * @free_using{free}
 */
char *                  dime_sgnt_serial_signet_to_b64(signet_t *signet);

/**
 * @brief	Returns a new signet_t structure that gets deserialized from a data buffer
 * @param	in	data buffer that should contain the binary form of a signet
 * @param	in_len	length of data buffer
 * @return	A pointer to a newly allocated signet_t structure type, NULL on failure.
 * @free_using{dime_sgnt_destroy_signet}
 */
signet_t *              dime_sgnt_serial_to_signet(const unsigned char *in, size_t len);

/**
 * @brief	Replaces all fields in the target signet with the specified field id with a new field specified by the parameters.
 * @param	signet		Pointer to the target signet_t structure.
 * @param	fid			Field id which specifies the fields to be replaced with the new field.
 * @param	data_size	Size of field data array.
 * @param	data		Array contaning field data.
 * @return	0 on success, -1 on failure.
 */
int                     dime_sgnt_set_defined_field(signet_t *signet, unsigned char fid, size_t data_size, const unsigned char *data);

/**
 * @brief	Sets the public encryption key (non-alterante encryption key) for the signet.
 * @param	signet	Target signet.
 * @param	key	Public encryption key.
 * @param	format	Format specifier. TODO currently unused! (spec requires 0x04 but openssl natively serializes it to 0x02).
 * @return	0 on success, -1 on failure.
 */
int                     dime_sgnt_set_enckey(signet_t *signet, EC_KEY *key, unsigned char format);

/**
 * @brief	Sets the ID of the signet to the specified NULL terminated string.
 * @param	signet	Pointer to the target signet.
 * @param	id_size	Size of signet id.
 * @param	id		Signet id.
 * @return	0 on success, -1 on failure.
 */
int                     dime_sgnt_set_id_field(signet_t *signet, size_t id_size, const unsigned char *id);

/**
 * @brief	Sets the signing key (pok - primary signing key in case of an org signet).
 * @param	signet	Pointer to the target signet.
 * @param	key	Public signing key to be set as the signing key of the signet.
 * @param	format	Format specifier byte, dictating the format.
 * @return	0 on success, -1 on failure.
 */
int                     dime_sgnt_set_signkey(signet_t *signet, ED25519_KEY *key, unsigned char format);

/**
 * @brief	Checks for the presence of all required fields that come before the chain of custody signature field and adds the SSR signature.
 * @param	signet	Pointer to the target signet_t structure.
 * @param	key	Specified ed25519 key used for signing.
 * @return	0 on success, -1 on failure.
 */
int                     dime_sgnt_sign_coc_sig(signet_t *signet, ED25519_KEY *key);

/**
 * @brief	Signs an SSR or an incomplete ORG signet with the cryptographic signature after checking for the presence of all previous required fields.
 * @param	signet	Pointer to the target signet_t structure.
 * @param	key	Specified ed25519 key used for signing.
 * @return	0 on success, -1 on failure.
 */
int                     dime_sgnt_sign_crypto_sig(signet_t *signet, ED25519_KEY *key);

/**
 * @brief	Checks for the presence of all required fields that come before the full signature and signs all the fields that come before the CORE signature field
 * @param	signet	Pointer to the target signet_t structure.
 * @param	key	Specified ed25519 key used for signing.
 * @return	0 on success, -1 on failure.
 */
int                     dime_sgnt_sign_full_sig(signet_t *signet, ED25519_KEY *key);

/**
 * @brief	Checks for the presence of all required fields that come before the FULL signature and signs the entire target signet using the specified key.
 * @param	signet	Pointer to the target signet_t structure.
 * @param	key	Specified ed25519 key used for signing.
 * @return	0 on success, -1 on failure.
 */
int                     dime_sgnt_sign_id_sig(signet_t *signet, ED25519_KEY *key);

/**
 * @brief	Checks for the presence of all required fields that come before the SSR signature field and adds the SSR signature.
 * @param	signet	Pointer to the target signet_t structure.
 * @param	key	Specified ed25519 key used for signing.
 * @return	0 on success, -1 on failure.
 */
int                     dime_sgnt_sign_ssr_sig(signet_t *signet, ED25519_KEY *key);

/**
 * @brief	Creates a copy of the target user signet with all fields beyond the INITIAL signature stripped off.
 * @param	signet	Pointer to the target signet.
 * @return	Pointer to a stripped signet on success, NULL on failure.
 * @free_using{dime_sgnt_destroy_signet}
 */
signet_t *              dime_sgnt_split_crypto(const signet_t *signet);

/**
 * @brief	Creates a copy of the target signet with the ID field and the FULL signature stripped off.
 * @param	signet	Pointer to the target signet.
 * @return	Pointer to a stripped signet on success, NULL on failure.
 * @free_using{dime_sgnt_destroy_signet}
 */
signet_t *              dime_sgnt_split_full(const signet_t *signet);

/**
 * @brief	Retrieves the signet type, org or user (SIGNET_TYPE_ORG or SIGNET_TYPE_USER)
 * @param	signet	Pointer to the target signet.
 * @return	A signet_type_t enum type with the signet type, SIGNET_TYPE_ERROR on failure.
 */
signet_type_t           dime_sgnt_type_get(const signet_t *signet);

/**
 * @brief	Returns a string from a signet_state_t enum type.
 * @param	state	Signet state.
 * @return	Null terminated string corresponding to the state.
 */
const char *            dime_sgnt_state_to_str(signet_state_t state);

/**
 * @brief	Sets the target signet to a specified type.
 * @param	signet	Pointer to the target signet.
 * @param	type	Specified signet type.
 * @return	0 on success, -1 on error.
 */
int                     dime_sgnt_type_set(signet_t *signet, signet_type_t type);

/**
 * @brief	Verifies a user signet, org signet or ssr for syntax, context and cryptographic validity. Does NOT perform chain of custody validation.
 * @param	signet		Pointer to the target signet_t structure.
 * @param	orgsig		Pointer to the org signet associated with the target signet IF the target signet is a user signet.
 *                              If target signet is not a user signet, orgsig should be passed as NULL.
 * @param	previous	Pointer to the previous user signet, which will be used validate the chain of custody signature, if such is available.
 * @param	dime_pok	A NULL terminated array of pointers to ed25519 POKs from the dime record associated with the target signet if the target signet is an org signet.
 *                              If the target signet is not an org signet dime_pok should be passed as NULL;
 * @return	Signet state as a signet_state_t enum type. SS_UNKNOWN on error.
 */
signet_state_t          dime_sgnt_validate_all(const signet_t *signet, const signet_t *previous, const signet_t *orgsig, const unsigned char **dime_pok);

/**
 * @brief	Uses a signet's signing keys to verify a signature.
 * @param	signet	Pointer to the signet.
 * @param	sig	ed25519 signature buffer to be verified.
 * @param	buf	Data buffer over which the signature was taken.
 * @param	buf_len	Length of data buffer.
 * @return	1 on successful verification, 0 if the signature could not be verified, -1 if an error occurred.
 */
int                     dime_sgnt_verify_message_sig(const signet_t *signet, ed25519_signature sig, const unsigned char *buf, size_t buf_len);



#endif
