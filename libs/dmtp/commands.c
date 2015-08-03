#include "sds.h"
#include "dmtp_commands.h"

#define DMTP_IGNORE_ARG { NULL, 0,  DMTP_ARG_PLAIN, 0 }
#define DMTP_EMPTY_ARG  { NULL, 0,  DMTP_ARG_NONE,  0 }

static int                  dmtp_command_argument_parse(const char *line, size_t insize, unsigned int arg_index, size_t *parsed, dmpt_command_t *command);
static dmtp_command_t *     dmtp_command_create(dmtp_command_type_t type);
static void                 dmtp_command_destroy(dmtp_command_t *command);
static sds                  dmtp_command_format(dmtp_command_t *command);
static int                  dmtp_command_is_valid(dmtp_command_t *command);
static dmtp_command_key_t * dmtp_command_key_get(dmtp_command_type_t type);
static dmtp_command_t *     dmtp_command_parse(sds command);
static int                  dmtp_command_type_cmp(sds command, dmtp_command_type_t type);
static dmtp_command_type_t  dmtp_command_type_get(sds command);




static
int
dmtp_command_argument_parse(
    const char *line,
    size_t insize,
    unsigned int arg_index,
    size_t *parsed;
    dmpt_command_t *command)
{

   char *arg_start, arg_end;
   dmtp_command_key_t *key;
   size_t arg_len;
   unsigned int arg_num, at, arg_offset;

   if(!line) {
       PUSH_ERROR(ERR_BAD_PARAM, NULL);
       goto error;
   }

   if(!insize) {
       PUSH_ERROR(ERR_BAD_PARAM, NULL);
       goto error;
   }

   if(arg_index >= DMTP_MAX_ARGUMENT_NUM) {
       PUSH_ERROR(ERR_BAD_PARAM, NULL);
       goto error;
   }

   if(!key) {
       PUSH_ERROR(ERR_BAD_PARAM, NULL);
       goto error;
   }
  
   if(!command) {
       PUSH_ERROR(ERR_BAD_PARAM, NULL);
       goto error;
   }

   if(!(key = dmtp_command_key_get(command->type))) {
       PUSH_ERROR(ERR_UNSPEC, "failed to retrieve command key");
       goto error;
   }

   for(arg_num = arg_index; arg_num < DMTP_MAX_ARGUMENT_NUM; ++arg_num) {

       if(key->args[arg_num].arg_name_len > insize) {
           continue;
       }

       if(memcmp(line, key->args[arg_num].arg_name, key->args[arg_num].arg_name_len) != 0) {
           continue;
       }

   }

   if(arg_num >= DMTP_MAX_ARGUMENT_NUM) {
       PUSH_ERROR(ERR_UNSPEC, "no valid arguments could be parsed");
       goto error;
   }

   at = key->args[arg_num].arg_name_len;

   switch(key->args[arg_num].type) {

   case DMTP_ARG_REQ_STR:
       arg_start = "=<";
       arg_end = '>';
       break;
   case DMTP_ARG_OPT_STR:
       arg_start = "=[";
       arg_end = ']';
       break;
   case DMTP_ARG_PLAIN:
       arg_start = "=";
       arg_end = ' ';  // special case
       break;
   default:
       PUSH_ERROR(ERR_UNSPEC, "invalid argument type");
       goto error;
   }

   if(at + strlen(arg_start) > insize) {
       PUSH_ERROR(ERR_UNSPEC, "invalid command string size");
       goto error;
   }

   if(memcmp(line + at, arg_start, strlen(arg_start)) != 0) {
       PUSH_ERROR(ERR_UNSPEC, "invalid argument syntax");
       goto error;
   }

   at += strlen(arg_start);
   arg_offset = at;

   if(key->args[arg_num].type != DMTP_ARG_PLAIN) {

       while(line[at] != arg_end && at < insize) {
           ++at;
       }

       if(at >= insize) {
           PUSH_ERROR(ERR_UNSPEC, "argument line too short");
           goto error;
       }

       command[arg_num] = sdsnewlen(line + arg_offset, at - arg_offset);
       parsed = at+1;
   }
   else {

       while(!isspace(line[at]) && at < insize) {
           ++at;
       }

       if(at >= insize) {
           PUSH_ERROR(ERR_UNSPEC, "argument line too short");
           goto error;
       }

       command[arg_num] = sdsnewlen(line + arg_offset, at - arg_offset);
       parsed = at;

   }

   return arg_num + 1;

error:
   return -1
}





static dmtp_command_t * dmtp_command_create(dmtp_command_type_t type) {

    dmtp_command_t *result;

    if(type >= DMTP_COMMANDS_NUM) {
        PUSH_ERROR(ERR_BAD_PARAM, NULL);
        goto error;
    }

    if(!(result = malloc(sizeof(dmtp_command_t)))) {
        PUSH_ERROR(ERR_NOMEM, "failed to allocate memory for a dmtp command");
        PUSH_ERROR_SYSCALL("malloc");
        goto error;
    }

    memset(result, 0, sizeof(dmtp_command_t));
    result->type = type;

    return result;

error:
    return NULL;
}


static void dmtp_command_destroy(dmtp_command_t *command) {

    if(!command) {
        return;
    }

    for(int i = 0; i < DMTP_MAX_ARGUMENT_NUM; ++i) {
        sdsfree(command->args[i]);
    }

    free(command);
}



static sds dmtp_command_format(dmtp_command_t *command) {

    char open, close;
    dmtp_command_key_t *key;
    sds result;
    size_t command_size = 0;

    if(!command) {
        PUSH_ERROR(ERR_BAD_PARAM, NULL);
        goto error;
    }

    if(!(dmtp_command_is_valid(command))) {
        PUSH_ERROR(ERR_UNSPEC, "invalid dmtp command");
        goto error;
    }

    if(!(key = dmtp_command_key_get(command->type))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to retrieve dmtp command key");
        goto error;
    }

    command_size = 2 + key->com_name_len;

    for(int i = 0; i < DMTP_MAX_ARGUMENT_NUM; ++i) {

        if(command->args[i]) {

            switch(key->args[i].type) {

            case DMTP_ARG_NONE:
                    break;
            case DMTP_ARG_REQ_STR:
            case DMTP_ARG_OPT_STR:
                command_size += 2;
            case DMTP_ARG_PLAIN:
                command_size += 1;
                command_size += sdslen(command->args[i]);
                command_size += key->args[i].arg_name_len;
                    break;
            default:
                PUSH_ERROR(ERR_UNSPEC, "invalid argument type");
                goto error;

            }

        }

    }

    if(arg_size > 512) {
        PUSH_ERROR(ERR_UNSPEC, "command is too long");
        goto error;
    }

    if(!(result = sdsempty())) {
        PUSH_ERROR(ERR_UNSPEC, "failed to allocate sds string for command");
        goto error;
    }

    if(!(result = sdsMakeRoomFor(result, arg_size))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to make room for arguments");
        goto cleanup_result;
    }

    if(!(result = sdscatlen(result, key->com_name, key->com_name_len))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to concatenate command name");
        goto cleanup_result;
    }

    for(int i = 0; i < DMTP_MAX_ARGUMENT_NUM; ++i) {

        if( command->args[i] && (key->args[i].type != DMTP_ARG_NONE) ) {

            if(!(result = sdscatlen(result, " ", 1))) {
                PUSH_ERROR(ERR_UNSPEC, "failed to concatenate white space");
                goto cleanup_result;
            }

            if(!(result = sdscatlen(result, key->args[i].arg_name, key->args[i].arg_name_len))) {
                PUSH_ERROR(ERR_UNSPEC, "failed to concatenate argument name");
                goto cleanup_result;
            }

            if(!(result = sdscatlen(result, "=", 1))) {
                PUSH_ERROR(ERR_UNSPEC, "failed to concatenate argument equals sign");
                goto cleanup_result;
            }

            if(keys->args[i].type == DMTP_ARG_REQ_STR) {

                if(!(result = sdscatlen(result, "<", 1))) {
                    PUSH_ERROR(ERR_UNSPEC, "failed to concatenate angular bracket");
                    goto cleanup_result;
                }

            }

            if(keys->args[i].type == DMTP_ARG_OPT_STR) {

                if(!(result = sdscatlen(result, "[", 1))) {
                    PUSH_ERROR(ERR_UNSPEC, "failed to concatenate square bracket");
                    goto cleanup_result;
                }

            }

            if(!(result = sdscatsds(result, command->args[i]))) {
                PUSH_ERROR(ERR_UNSPEC, "failed to concatenate argument");
                goto cleanup_result;
            }

            if(keys->args[i].type == DMTP_ARG_REQ_STR) {

                if(!(result = sdscatlen(result, ">", 1))) {
                    PUSH_ERROR(ERR_UNSPEC, "failed to concatenate angular bracket");
                    goto cleanup_result;
                }

            }

            if(keys->args[i].type == DMTP_ARG_OPT_STR) {

                if(!(result = sdscatlen(result, "]", 1))) {
                    PUSH_ERROR(ERR_UNSPEC, "failed to concatenate square bracket");
                    goto cleanup_result;
                }

            }

        }

    }

    if(!(result = sdscatlen(result, "\r\n", 2))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to concatenate end of command line characters");
        goto cleanup_result;
    }

    if(sdslen > 512) {
        PUSH_ERROR(ERR_UNSPEC, "command is too long");
        goto error;
    }

    return result;

cleanup_result:
    sdsfree(result);
error:
    return NULL;
}


static int dmtp_command_is_valid(dmtp_command_t *command) {

    dmtp_command_key_t *key;
    int arg1, arg2, arg3, result;

    if(!command) {
        PUSH_ERROR(ERR_BAD_PARAM, NULL);
        goto error;
    }

    if(!(key = dmtp_command_key_get(command->type))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to retrieve dmtp command key");
        goto error;
    }

    for(int i = 0; i < DMTP_MAX_ARGUMENT_NUM; ++i) {

        if( command->args[i] && (key->args[i].type == DMTP_ARG_NONE) ) {
            PUSH_ERROR(ERR_UNSPEC, "invalid argument type provided");
            goto error;
        }

        if( key->args[i].size && ( key->args[i].size[i] != sdslen(comman->args[i])) ) {
            PUSH_ERROR(ERR_UNSPEC, "invalid argument size");
            goto error;
        }

    }

    arg1 = (command->args[1] != NULL);
    arg2 = (command->args[2] != NULL);
    arg3 = (command->args[3] != NULL);

    switch(command->type) {

    case DMTP_STARTTLS:
        result = arg1 && !arg3;
        break;
    case DMTP_HELO:
        result = arg1 && !arg2 && !arg3;
        break;
    case DMTP_EHLO:
        result = arg1 && !arg2 && !arg3;
        break;
    case DMTP_MODE:
        result = !arg1 && !arg2 && !arg3;
        break;
    case DMTP_RSET:
        result = !arg1 && !arg2 && !arg3;
        break;
    case DMTP_NOOP:
        result = 1;
        break;
    case DMTP_HELP:
        result = !arg1 && !arg2 && !arg3;
        break;
    case DMTP_QUIT:
        result = !arg1 && !arg2 && !arg3;
        break;
    case DMTP_MAIL:
        result = arg1 && arg2 && !arg3;
        break;
    case DMTP_RCPT:
        result = arg1 && arg2 && !arg3;
        break;
    case DMTP_DATA:
        result = !arg1 && !arg2 && !arg3;
        break;
    case DMTP_SGNT:
        result = arg1 ^^ arg2;
        break;
    case DMTP_HIST:
        result = arg1;
        break;
    case DMTP_VRFY:
        result = arg1 ^^ arg2 && arg3;
        break;
    default:
        PUSH_ERROR(ERR_UNSPEC, "invalid command type");
        goto error;

    }

    return result;

error:
    return 0;
}


static dmtp_command_key_t * dmtp_command_key_get(dmtp_command_type_t type) {

    if(type >= DMTP_COMMANDS_NUM) {
        PUSH_ERROR(ERR_BAD_PARAM, NULL);
        goto error;
    }

    return dmtp_command_list[type];

error:
    return NULL;
}


static dmtp_command_t * dmtp_command_parse(sds command) {

    dmtp_command_key_t *key;
    dmtp_command_t *result;
    dmtp_command_type_t type;
    size_t at = 0, len, parsed;
    unsigned int i = 0;

    if(!command) {
        PUSH_ERROR(ERR_BAD_PARAM, NULL);
        goto error;
    }

    if((len = sdslen(command)) > 512) {
        PUSH_ERROR(ERR_UNSPEC, "command line is too long");
        goto error;
    }

    if( (type = dmtp_command_type_get(command)) == DMTP_COMMAND_INVALID ) {
        PUSH_ERROR(ERR_UNSPEC, "failed find a valid command");
        goto error;
    }

    if(!(key = dmtp_command_key_get(type))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to find command key");
        goto error;
    }

    at = key->com_name_len;

    if(!(result = dmtp_command_create(type))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to create a new command object");
        goto error;
    }

    if(at + 2 > len) {
        PUSH_ERROR(ERR_UNSPEC, "command string is too short to contain valid ending characters");
        goto cleanup_result;
    }

    if(memcmp(command+at, "\r\n", 2) == 0) {

        if(at + 2 != len) {
            PUSH_ERROR(ERR_UNSPEC, "command string does not end after the ending characters");
            goto cleanup_result;
        }

        goto out;
    }

    if(command[at++] != ' ') {
        PUSH_ERROR(ERR_UNSPEC, "arguments must be separated by white space");
        goto cleanup_result;
    }

    while( (command[at] == ' ' || command[at] == '\t') && (at < len) ) {
        ++at;
    }

    if(at + 2 > len) {
        PUSH_ERROR(ERR_UNSPEC, "command string is too short to contain valid ending characters");
        goto cleanup_result;
    }

    if(memcmp(command+at, "\r\n", 2) == 0) {

        if(at + 2 != len) {
            PUSH_ERROR(ERR_UNSPEC, "command string does not end after the ending characters");
            goto cleanup_result;
        }

        goto out;
    }


    while(i < DMTP_MAX_COMMANDS_NUM) {

        if(key->args[i].type == DMTP_ARG_NONE) {
            PUSH_ERROR(ERR_UNSPEC, "unexpected command argument");
            goto cleanup_result;
        }

        if((i = dmtp_command_argument_parse(command + at, len - at, i, &parsed, result)) == -1) {
            PUSH_ERROR(ERR_UNSPEC, "error occurred while parsing an argument");
            goto cleanup_result;
        }

        at += parsed;

        if(at + 2 > len) {
            PUSH_ERROR(ERR_UNSPEC, "command string is too short to contain valid ending characters");
            goto cleanup_result;
        }

        if(memcmp(command+at, "\r\n", 2) == 0) {

            if(at + 2 != len) {
                PUSH_ERROR(ERR_UNSPEC, "command string does not end after the ending characters");
                goto cleanup_result;
            }

            goto out;
        }

        if(command[at++] != ' ') {
            PUSH_ERROR(ERR_UNSPEC, "arguments must be separated by white space");
            goto cleanup_result;
        }

        while( (command[at] == ' ' || command[at] == '\t') && (at < len) ) {
            ++at;
        }

        if(at + 2 > len) {
            PUSH_ERROR(ERR_UNSPEC, "command string is too short to contain valid ending characters");
            goto cleanup_result;
        }

        if(memcmp(command+at, "\r\n", 2) == 0) {

            if(at + 2 != len) {
                PUSH_ERROR(ERR_UNSPEC, "command string does not end after the ending characters");
                goto cleanup_result;
            }

            goto out;
        }

    }

out:
    return result;

cleanup_result:
    dmtp_command_destroy(result);
error:
    return NULL;
}



static int dmtp_command_type_cmp(sds command, dmtp_command_type_t type) {

    dmtp_command_key_t *key;
    int result;
    size_t min_len;

    if(!command) {
        PUSH_ERROR(ERR_BAD_PARAM, NULL);
        goto error;
    }

    if(type >= DMTP_COMMANDS_NUM) {
        PUSH_ERROR(ERR_UNSPEC, "invalid dmtp command");
        goto error;
    }

    if(!(key = dmtp_command_key_get(type))) {
        PUSH_ERROR(ERR_UNSPEC, "failed to retrieve command key");
        goto error;
    }

    if(sdslen(command) < key->com_name_len) {
        PUSH_ERROR(ERR_UNSPEC, "command line is too short to match a valid command");
        goto error;
    }

    if((memcmp(command, key->com_name, key->com_name_len) != 0)) {
        PUSH_ERROR(ERR_UNSPEC, "command line did not match the expected command");
        goto error;
    }

    return 0;

error:
    return -1;
}



static dmtp_command_type_t  dmtp_command_type_get(sds command) {

    dmtp_command_type_t result;
    sds temp;

    if(!command) {
        PUSH_ERROR(ERR_BAD_PARAM, NULL);
        goto error;
    }

    if(sdslen(command) < 4) {
        PUSH_ERROR(ERR_UNSPEC, "DMTP command-line is too short");
        goto error;
    }

    switch(command[0]) {

    case 'S':

        switch(command[1]) {

        case 'T':

            if(dmtp_command_type_cmp(command, DMTP_STARTTLS) != 0) {
                PUSH_ERROR(ERR_UNSPEC, "command looked like STARTTLS but comparison failed");
                goto error;
            }

            result = DMTP_STARTTLS;
            break;
        case 'G':

            if(dmtp_command_type_cmp(command, DMTP_SGNT) != 0) {
                PUSH_ERROR(ERR_UNSPEC, "command looked like SGNT but comparison failed");
                goto error;
            }

            result = DMTP_SGNT;
            break;
        default:
            PUSH_ERROR(ERR_UNSPEC, "invalid command");
            goto error;

        }

        break;
    case 'H':

        switch(command[1])
        {

        case 'E':

            switch(command[2])
            {

                case 'L':

                    switch(command[3])
                    {

                        case 'O':

                            if(dmtp_command_type_cmp(command, DMTP_HELO) != 0) {
                                PUSH_ERROR(ERR_UNSPEC, "command looked like HELO but comparison failed");
                                goto error;
                            }

                            result = DMTP_HELO;
                            break;
                        case 'P':

                            if(dmtp_command_type_cmp(command, DMTP_HELP) != 0) {
                                PUSH_ERROR(ERR_UNSPEC, "command looked like HELP but comparison failed");
                                goto error;
                            }

                            result = DMTP_HELP;
                            break;
                        default:
                            PUSH_ERROR(ERR_UNSPEC, "invalid command");
                            goto error;

                    }

                    break;
                default:
                    PUSH_ERROR(ERR_UNSPEC, "invalid command");
                    goto error;

            }

            break;
        case 'I':

            if(dmtp_command_type_cmp(command, DMTP_HIST) != 0) {
                PUSH_ERROR(ERR_UNSPEC, "command looked like HIST but comparison failed");
                goto error;
            }

            result = DMTP_HIST;
            break;
        default:
            PUSH_ERROR(ERR_UNSPEC, "invalid command");
            goto error;
        }

        break;
    case 'E':

        if(dmtp_command_type_cmp(command, DMTP_EHLO) != 0) {
            PUSH_ERROR(ERR_UNSPEC, "command looked like EHLO but comparison failed");
            goto error;
        }

        result = DMTP_EHLO;
        break;
    case 'M':

        switch(command[1]) {

        case 'O':

            if(dmtp_command_type_cmp(command, DMTP_MODE) != 0) {
                PUSH_ERROR(ERR_UNSPEC, "command looked like MODE but comparison failed");
                goto error;
            }

            result = DMTP_MODE;
            break;
        case 'A':

            if(dmtp_command_type_cmp(command, DMTP_MAIL) != 0) {
                PUSH_ERROR(ERR_UNSPEC, "command looked like MAIL but comparison failed");
                goto error;
            }

            result = DMTP_MAIL;
            break;
        default:
            PUSH_ERROR(ERR_UNSPEC, "invalid command");
            goto error;

        }

        break;
    case 'R':

        switch(command[1]) {

        case 'S':
            
            if(dmtp_command_type_cmp(command, DMTP_RSET) != 0) {
                PUSH_ERROR(ERR_UNSPEC, "command looked like RSET but comparison failed");
                goto error;
            }

            result = DMTP_RSET;
            break;
        case 'C':

            if(dmtp_command_type_cmp(command, DMTP_RCPT) != 0) {
                PUSH_ERROR(ERR_UNSPEC, "command looked like RCPT but comparison failed");
                goto error;
            }

            result = DMTP_RCPT;
            break;
        default:
            PUSH_ERROR(ERR_UNSPEC, "invalid command");
            goto error;

        }

        break;
    case 'N':

        if(dmtp_command_type_cmp(command, DMTP_NOOP) != 0) {
            PUSH_ERROR(ERR_UNSPEC, "command looked like NOOP but comparison failed");
            goto error;
        }

        result = DMTP_NOOP;
        break;
    case 'Q':

        if(dmtp_command_type_cmp(command, DMTP_QUIT) != 0) {
            PUSH_ERROR(ERR_UNSPEC, "command looked like QUIT but comparison failed");
            goto error;
        }

        result = DMTP_QUIT;
        break;
    case 'D':

        if(dmtp_command_type_cmp(command, DMTP_DATA) != 0) {
            PUSH_ERROR(ERR_UNSPEC, "command looked like DATA but comparison failed");
            goto error;
        }

        result = DMTP_DATA;
        break;
    case 'V':

        if(dmtp_command_type_cmp(command, DMTP_VRFY) != 0) {
            PUSH_ERROR(ERR_UNSPEC, "command looked like VRFY but comparison failed");
            goto error;
        }

        result = DMTP_VRFY;
        break;
    default:
        PUSH_ERROR("invalid command");
        goto error;

    }

    return result;

error:
    return DMTP_COMMAND_INVALID; 
}









sds dime_dmtp_command_format(dmtp_command_t *command);





dmtp_command_key_t dmtp_command_list[DMTP_COMMANDS_NUM] = {
//  {   .com_name,   .com_name_len, 
//      { 
//          {.arg_name,         .arg_name_len, .type             .size },
//          {.arg_name,         .arg_name_len, .type             .size },
//          {.arg_name,         .arg_name_len, .type             .size }
//       }  
//  }
    {
        "STARTTLS",  8,
        {
            { "HOST",           4,             DMTP_ARG_REQ_STR, 0 },
            { "MODE",           4,             DMTP_ARG_PLAIN,   0 },
            DMTP_EMPTY_ARG
        }
    },

    {
        "HELO",      4,
        {
            { "HOST",           4,             DMTP_ARG_REQ_STR, 0 },
            DMTP_EMPTY_ARG,
            DMTP_EMPTY_ARG
        }
    },

    {
        "EHLO",      4,
        {
            { "HOST",           4,             DMTP_ARG_REQ_STR, 0 },
            DMTP_EMPTY_ARG,
            DMTP_EMPTY_ARG
        }
    },

    {
        "MODE",      4,
        {
            DMTP_EMPTY_ARG,
            DMTP_EMPTY_ARG,
            DMTP_EMPTY_ARG
        }
    },

    {
        "RSET",      4,
        {
            DMTP_EMPTY_ARG,
            DMTP_EMPTY_ARG,
            DMTP_EMPTY_ARG
        }
    },

    {
        "NOOP",      4,
        {
            DMTP_IGNORE_ARG,
            DMTP_IGNORE_ARG,
            DMTP_IGNORE_ARG
        }
    },

    {
        "HELP",      4,
        {
            DMTP_EMPTY_ARG,
            DMTP_EMPTY_ARG,
            DMTP_EMPTY_ARG
        }
    },

    {
        "QUIT",      4,
        {
            DMTP_EMPTY_ARG,
            DMTP_EMPTY_ARG,
            DMTP_EMPTY_ARG
        }
    },

    {
        "MAIL",      4,
        {
            { "FROM",           4,             DMTP_ARG_REQ_STR, 0 },
            { "FINGERPRINT",   11,             DMTP_ARG_OPT_STR, 0 },
            DMTP_EMPTY_ARG
        }
    },

    {
        "RCPT",      4,
        {
            { "TO",             2,             DMTP_ARG_REQ_STR, 0 },
            { "FINGERPRINT",   11,             DMTP_ARG_OPT_STR, 0 },
            DMTP_EMPTY_ARG
        }
    },

    {
        "DATA",      4,             
        {
            DMTP_EMPTY_ARG,
            DMTP_EMPTY_ARG,
            DMTP_EMPTY_ARG
        }
    },

    {
        "SGNT",      4,
        {
            { "USER",           4,             DMTP_ARG_REQ_STR, 0 },
            { "DOMAIN",         6,             DMTP_ARG_REQ_STR, 0 },
            { "FINGERPRINT",   11,             DMTP_ARG_OPT_STR, 0 }
        }
    },

    {
        "HIST",      4,
        {
            { "USER",           4,             DMTP_ARG_REQ_STR, 0 },
            { "START",          4,             DMTP_ARG_OPT_STR, 0 },
            { "STOP",           4,             DMTP_ARG_OPT_STR, 0 }
        }
    },

    {
        "VRFY",      4,
        {
            { "USER",           4,             DMTP_ARG_REQ_STR, 0 },
            { "DOMAIN",         6,             DMTP_ARG_REQ_STR, 0 },
            { "FINGERPRINT",   11,             DMTP_ARG_OPT_STR, 0 }
        }
    }

};
