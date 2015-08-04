/**
 * @file
 * @brief   Functions for handling the global configuration.
 */

#include <dime/core/magma.h>

__thread char threadBuffer[1024];
magma_t magma = { .config.file = "magma.config" };
