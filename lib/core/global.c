
/**
 *
 * @file /magma/engine/config/global/global.c
 *
 * @brief	Functions for handling the global configuration.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */
#include "magma.h"

__thread char threadBuffer[1024];
magma_t magma = { .config.file = "magma.config" };
