
/**
 * @file /magma/objects/signets/signets.h
 *
 * @brief	Functions to interface with and manage user signets.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#ifndef MAGMA_OBJECTS_SIGNETS_H
#define MAGMA_OBJECTS_SIGNETS_H

// The database representation of a signet.
typedef struct {
	uint64_t num;
	stringer_t *name;
	stringer_t *data;
	stringer_t *fingerprint_full;
	stringer_t *fingerprint_core;
	stringer_t *signed_next;
} signet_db_t;

/// datatier.c
bool_t             signet_insert_db(signet_db_t *signet_db);
inx_t *            signets_fetch_by_name(stringer_t *owner);
signet_db_t *      signet_fetch_current(stringer_t *owner);
signet_db_t *      signet_fetch_by_full_fingerprint(stringer_t *owner, stringer_t *fingerprint);
signet_db_t *      signet_fetch_by_any_fingerprint(stringer_t *owner, stringer_t *fingerprint);
inx_t *            get_signet_coc(inx_t *signets, stringer_t *start_fp, stringer_t *end_fp);

/// signets.c
void               signet_db_destroy(signet_db_t *signet_db);
signet_db_t *      signet_db_clone(signet_db_t *signet_db);
chr_t *            get_signet_filename(stringer_t *basename, stringer_t *extension);
signet_t *         sign_user_signet(stringer_t *username, stringer_t *ssr, chr_t **errstring);

#endif
