
/**
 * @file /libdime/src/core/core.c
 *
 * @brief DESCRIPTIONxxxGOESxxxHERE
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#include "core/core.h"

core_t core = {
	.page_length = 4096
};

 __thread char threadBuffer[1024];
