#ifndef DIME_DMTP_COMMANDS
#define DIME_DMTP_COMMANDS

#define DMTP_MAX_ARGUMENT_NUM  3
#define DMTP_COMMANDS_NUM     14

typedef enum {
    DMTP_STARTTLS = 0,
    DMTP_HELO,
    DMTP_EHLO,
    DMTP_MODE,
    DMTP_RSET,
    DMTP_NOOP,
    DMTP_HELP,
    DMTP_QUIT,
    DMTP_MAIL,
    DMTP_RCPT,
    DMTP_DATA,
    DMTP_SGNT,
    DMTP_HIST,
    DMTP_VRFY,
    DMTP_COMMAND_INVALID
} dmtp_command_type_t;

typedef enum {
    DMTP_ARG_NONE = 0,
    DMTP_ARG_PLAIN,
    DMTP_ARG_REQ_STR,
    DMTP_ARG_OPT_STR
} dmtp_argument_type_t;


typedef struct {
    char const *arg_name;
    size_t arg_name_len;
    dmtp_argument_type_t type;
    size_t size;          //optional for when argument size is required to be constant
} dmtp_argument_t;

typedef struct {
    dmtp_command_type_t type;
    sds args[DMTP_MAX_ARGUMENT_NUM];
} dmtp_command_t;

typedef struct {
    char const *com_name;
    size_t com_name_len;
    dmtp_argument_t args[DMTP_MAX_ARGUMENT_NUM];
} dmtp_command_key_t;

extern dmtp_command_key_t dmtp_command_list[DMTP_COMMANDS_NUM];

#endif
