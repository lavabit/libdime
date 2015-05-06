#ifndef PARSER_H
#define PARSER_H

dmime_common_headers_t *_dmsg_create_common_headers(void);

void _dmsg_destroy_common_headers(dmime_common_headers_t *obj);

unsigned char *_dmsg_format_common_headers(dmime_common_headers_t *obj, size_t *outsize);

dmime_header_type_t _dmsg_parse_next_header(unsigned char *in, size_t insize);

dmime_common_headers_t *_dmsg_parse_common_headers(unsigned char *in, size_t insize);

void _dmsg_destroy_envelope_object(dmime_envelope_object_t *obj);

dmime_envelope_object_t *_dmsg_parse_envelope(const unsigned char *in, size_t insize, dmime_chunk_type_t type);

const char *_dmsg_actor_to_string(dmime_actor_t actor);

const char *_dmsg_object_state_to_string(dmime_object_state_t state);





#endif
