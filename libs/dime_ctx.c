#include "dime/dime_ctx.h"

static log_level_t DEBUG_LOG_LEVEL = {
    LOG_CODE_DEBUG,
    "DEBUG"
};
log_level_t const * const
LOG_LEVEL_DEBUG = &DEBUG_LOG_LEVEL;

static log_level_t INFO_LOG_LEVEL = {
    LOG_CODE_INFO,
    "INFO"
};
log_level_t const * const
LOG_LEVEL_INFO = &INFO_LOG_LEVEL;

static log_level_t ERROR_LOG_LEVEL = {
    LOG_CODE_ERROR,
    "DEBUG"
};
log_level_t const * const
LOG_LEVEL_ERROR = &ERROR_LOG_LEVEL;

#define LOG(log_callback, log_level, ...) \
    log_callback( \
        __FILE__, \
        __LINE__, \
        log_level \
        __VA_ARGS__)

static void
default_log_callback(
    char const *file,
    size_t line,
    log_level_t level,
    va_list argp)
{
    assert(file != NULL);
    assert(level != NULL);

    fprintf(
        stderr,
        "[%s:%l:%s]: ",
        file,
        line,
        level);
    vprintf(stderr, argp);
    fprintf(stderr, "\n");
}

struct dime_ctx {
    log_function_t log_callback;
};

error_t *
dime_ctx_new(
    dime_ctx_t *result,
    log_function_t log_callback)
{
    result = malloc(sizeof(dime_ctx_t));
    if (result == NULL) {
        LOG(log_callback,
            LOG_LEVEL_ERROR,
            "couldn't allocate DIME context");
        return ERR_NOMEM;
    }

    if (log_callback == NULL) {
        result->log_callback = default_log_callback;
    } else {
        result->log_callback = log_callback;
    }

    return NULL;
}

void
dime_ctx_free(
    dime_ctx_t *ctx)
{
    free(ctx);
}

void
dime_ctx_log(
    dime_ctx_t *ctx,
    char const * file,
    size_t line,
    log_level_t level,
    ...)
{
    va_list argp;
    va_start(argp, level);
    ctx->log_callback(
        file,
        line,
        level,
        argp);
    va_end(argp);
}
