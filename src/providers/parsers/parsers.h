
/**
 * @file /magma/providers/parsers/parsers.h
 *
 * @brief The entry point for modules involved with accessing functionality provided by alien code.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#ifndef MAGMA_PROVIDERS_PARSERS_H
#define MAGMA_PROVIDERS_PARSERS_H

/// utf.c
bool_t   lib_load_utf8proc(void);
chr_t *  lib_version_utf8proc(void);
bool_t utf8_valid_st(stringer_t *s);
size_t utf8_length_st(stringer_t *s);
const chr_t * utf8_error_string(ssize_t error_code);

#endif
