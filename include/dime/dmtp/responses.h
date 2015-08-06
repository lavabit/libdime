#ifndef DIME_DMTP_RESPONSES
#define DIME_DMTP_RESPONSES

#include <stdlib.h>
#include "sds.h"

typedef enum {
    DMTP_214 = 0,   //in response to HELP
    DMTP_220,       //<domain.tld> Welcome banner
    DMTP_221,       //BYE
    DMTP_250,       //OK
    DMTP_254,       //ACCEPTED=fingerprint
    DMTP_255,       //DUPLICATE=fingerprint
    DMTP_270,       //OK organizational signet transfer
    DMTP_271,       //ORGANIZATIONAL SIGNET CURRENT
    DMTP_280,       //OK user signet transfer
    DMTP_281,       //USER SIGNET CURRENT
    DMTP_290,       //OK user signet history
    DMTP_291,       //USER SIGNET CURRENT
    DMTP_354,       //READY TO RECEIVE MESSAGE !no freeform!
    DMTP_421,       //CONNECTION REQUIRES ABNORMAL TERMINATION
    DMTP_431,       //DESTINATION LIMITS EXCEEDED
    DMTP_450,       //ACCESS DENIED
    DMTP_451,       //DATA CORRUPTED
    DMTP_470,       //ORIGIN SIGNET UNAVAILABLE (temp)
    DMTP_476,       //SIGNET TEMPORARILY UNAVAILABLE??
    DMTP_500,       //COMMAND SYNTAX ERROR
    DMTP_501,       //ARGUMENT SYNTAX ERROR
    DMTP_502,       //COMMAND DISABLED
    DMTP_503,       //INVALID COMMAND SEQUENCE
    DMTP_510,       //INVALID RECIPIENT
    DMTP_570,       //ORIGIN SIGNET UNAVAILABLE (perm)
    DMTP_575,       //INVALID ORIGIN SIGNET
    DMTP_576,       //INVALID DESTINATION SIGNET or... SIGNET UNAVAILABLE??
    DMTP_578,       //INVALID ORIGIN SIGNATURE
    DMTP_586        //INVALID RECIPIENT SIGNET
} dmtp_response_type_t;



#endif
