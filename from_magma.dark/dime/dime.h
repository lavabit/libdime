
/**
 * @file /magma/objects/dime/dime.h
 *
 * @brief	Functions used to interface with and manage message data.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#ifndef MAGMA_OBJECTS_DIME_H
#define MAGMA_OBJECTS_DIME_H

#define DIME_DNS_PREFIX                 "_dime"
#define DIME_POLICY_VERSION             1
#define DIME_DEFAULT_DNS_TTL            86400
#define DIME_DEFAULT_DNS_EXPIRY         2592000

#define DIME_MSG_POLICY_EXPERIMENTAL    1
#define DIME_MSG_POLICY_MIXED           2
#define DIME_MSG_POLICY_STRICT          3

#define DIME_ACCEPT_POLICY_NAKED        1
#define DIME_ACCEPT_POLICY_MIXED        2
#define DIME_ACCEPT_POLICY_REQUIRED     3

#define DIME_SEND_POLICY_NAKED          1
#define DIME_SEND_POLICY_MIXED          2
#define DIME_SEND_POLICY_REQUIRED       3

#define DIME_SUBDOMAIN_RELAXED          1
#define DIME_SUBDOMAIN_STRICT           2

typedef struct {
	// Required fields
	unsigned char version;  /* The DIME policy record syntax version. */
	stringer_t *public;     /* 43 byte armored organization public key. */
	// Suggested fields
	stringer_t *tls;        /* 43 byte armored TLS signature for MX/DX. */
	uchr_t policy;          /* Policy for sending/accepting messages. */
	uchr_t inbound;         /* Policy for accepting messages. */
	uchr_t outbound;        /* Policy for sending messages. */
	// Optional fields
	stringer_t *syndicates; /* Alternate authoritative signet lookup sources. */
	stringer_t *deliver;    /* CNAME for the DIME delivery host (if not MX). */
	stringer_t *keys;       /* CNAME for DIME key lookup host (if not MX). */
	uint32_t ttl;           /* The number of seconds between DNS record refreshes. */
	uint32_t expiry;        /* The number of seconds before a cached policy record is discarded. */
	uint32_t subdomain;     /* Whether or not subdomains will have their own records. */

} dime_policy_record_t;

/// resolv.c
bool_t   dime_get_policy_record (char *domain, void *buf, size_t blen);

#endif
