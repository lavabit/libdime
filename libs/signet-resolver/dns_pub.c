#include "signet-resolver/dns.h"

unsigned int get_keytag(const unsigned char *rdata, size_t rdlen) {
	PUBLIC_FUNC_IMPL(get_keytag, rdata, rdlen);
}

int rsa_verify_record(const char *label, unsigned char algorithm, RSA *pubkey, const unsigned char *rrsig, const unsigned char *sigbuf, size_t siglen, ns_msg *dhandle) {
	PUBLIC_FUNC_IMPL(rsa_verify_record, label, algorithm, pubkey, rrsig, sigbuf, siglen, dhandle);
}

int load_dnskey_file(const char *filename) {
	PUBLIC_FUNC_IMPL(load_dnskey_file, filename);
}

int is_validated_key(dnskey_t *dk) {
	PUBLIC_FUNC_IMPL(is_validated_key, dk);
}

int compute_dnskey_sha_hash(const dnskey_t *key, size_t nbits, unsigned char *outbuf) {
	PUBLIC_FUNC_IMPL(compute_dnskey_sha_hash, key, nbits, outbuf);
}

dnskey_t *get_dnskey_by_tag(unsigned int tag, char *signer, int force_lookup) {
	PUBLIC_FUNC_IMPL(get_dnskey_by_tag, tag, signer, force_lookup);
}

ds_t * get_ds_by_dnskey(const dnskey_t *key) {
	PUBLIC_FUNC_IMPL(get_ds_by_dnskey, key);
}

void destroy_dnskey(dnskey_t *key) {
	PUBLIC_FUNC_IMPL(destroy_dnskey, key);
}

void destroy_ds(ds_t *ds) {
	PUBLIC_FUNC_IMPL(destroy_ds, ds);
}

int validate_rrsig_rr(char *label, ns_msg *dhandle, unsigned short covered, const unsigned char *rdata, size_t rdlen, dnskey_t **outkey) {
	PUBLIC_FUNC_IMPL(validate_rrsig_rr, label, dhandle, covered, rdata, rdlen, outkey);
}

void * lookup_dnskey(char *label) {
	PUBLIC_FUNC_IMPL(lookup_dnskey, label);
}

void * lookup_ds(char *label) {
	PUBLIC_FUNC_IMPL(lookup_ds, label);
}

char * get_txt_record(const char *qstring, unsigned long *ttl, int *validated) {
	PUBLIC_FUNC_IMPL(get_txt_record, qstring, ttl, validated);
}

void free_mx_records(mx_record_t **mxs) {
	PUBLIC_FUNC_IMPL(free_mx_records, mxs);
}

mx_record_t ** get_mx_records(const char *qstring) {
	PUBLIC_FUNC_IMPL(get_mx_records, qstring);
}
