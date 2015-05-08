#include "signet/general.h"

#define SKEY_EMPTY {     0,     0,     0, 0, 0,       0, NULL, NULL }
#define SKEY_SIZE1 {     0,     1,     0, 1, 0, UNICODE, NULL, NULL }
#define SKEY_SIZE2 {     0,     1,     0, 2, 0, UNICODE, NULL, NULL }

signet_field_key_t signet_org_field_keys[256] = {
//	{ .required .unique .bytes_name_size .bytes_data_size, .data_size, .data_type, .name, .description }
/*  0*/ SKEY_EMPTY,
/*  1*/ {     1,     1,     0, 1,  0,                   B64,           "Primary-Organizational-Key", "Primary organizational signing key, also located in the DIME record SIGNET." },
/*  2*/ {     0,     0,     0, 1,  0,                   B64,         "Secondary-Organizational-Key", "Secondary organizational signing key fields." },
/*  3*/ {     1,     1,     0, 2,  0,                   B64,                       "Encryption-Key", "The ECC public key used to encrypt data sent to the holder of organizational SIGNET holder." },
/*  4*/ {     1,     1,     0, 0,  ED25519_SIG_SIZE,    B64,             "Organizational-Signature", "ED25519 signature of the previous cryptographic." },
/*  5*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/* 10*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/* 16*/ {     0,     1,     0, 1,  0,                   UNICODE,                             "Name", "Organization name." },
/* 17*/ {     0,     1,     0, 1,  0,                   UNICODE,                          "Address", "Organization address." },
/* 18*/ {     0,     1,     0, 1,  0,                   UNICODE,                         "Province", "Organization state/province." },
/* 19*/ {     0,     1,     0, 1,  0,                   UNICODE,                          "Country", "Organization country." },
/* 20*/ {     0,     1,     0, 1,  0,                   UNICODE,                      "Postal-Code", "Organization zip or postal code." },
/* 21*/ {     0,     0,     0, 1,  0,                   UNICODE,                     "Phone-Number", "Organization phone number." },
/* 22*/ {     0,     1,     0, 1,  0,                   UNICODE,                         "Language", "Organization language." },
/* 23*/ {     0,     1,     0, 1,  0,                   UNICODE,                         "Currency", "Organization currency." },
/* 24*/ {     0,     1,     0, 1,  0,                   UNICODE,                   "Cryptocurrency", "Organization cryptocurrency." },
/* 25*/ {     0,     1,     0, 1,  0,                   UNICODE,                            "Motto", "Organization motto." },
/* 26*/ {     0,     1,     0, 1,  0,                   UNICODE,                       "Extensions", "Organization Extensions." },
/* 27*/ {     0,     1,     0, 1,  0,                   UNICODE,               "Message-Size-Limit", "Organization Message-Size-Limit." },
/* 28*/ SKEY_SIZE1, SKEY_SIZE1,
/* 30*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/* 40*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/* 50*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/* 60*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/* 70*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/* 80*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/* 90*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/*100*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/*110*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/*120*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/*130*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/*140*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/*150*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/*160*/ {     0,     1,     0, 2,  0,                   UNICODE,                          "Website", "Organization Website." },
/*161*/ SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2,
/*170*/ SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2,
/*180*/ SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2,
/*190*/ SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2,
/*200*/ {     0,     1,     0, 2,  0,                   UNICODE,                    "Contact-Abuse", "Address to report service abuse to." },
/*201*/ {     0,     1,     0, 2,  0,                   UNICODE,                    "Contact-Admin", "Address to contact service admin." },
/*202*/ {     0,     1,     0, 2,  0,                   UNICODE,                  "Contact-Support", "Address to contact service support." },
/*203*/ {     0,     1,     0, 2,  0,                   UNICODE,                  "Web-Access-Host", "DNS name of web access hostname which supports HTTPS and provides a webmail access." },
/*204*/ {     0,     1,     0, 2,  0,                   UNICODE,              "Web-Access-Location", "HTTPS resource location of the webmail system." },
/*205*/ {     0,     1,     0, 2,  0,                   UNICODE,           "Web-Access-Certificate", "Base 64 encoded ed25519 signature of the webmail TLS certificate, may have more than a single signature separated by semicolons." },
/*206*/ {     0,     1,     0, 2,  0,                   UNICODE,                 "Mail-Access-Host", "DNS name of the mail access hostname which offers connectivity using DMAP." },
/*207*/ {     0,     1,     0, 2,  0,                   UNICODE,          "Mail-Access-Certificate", "Base 64 encoded ed25519 signature of the DMAP-supporting mail server's TLS certificate, may have mroe than a single signature separated by semicolons." },
/*208*/ {     0,     1,     0, 2,  0,                   UNICODE,                "Onion-Access-Host", "Onion hostname for mail access, a semicolon terminates the hostname string and provides an optional separator." },
/*209*/ {     0,     1,     0, 2,  0,                   UNICODE,         "Onion-Access-Certificate", "Base 64 encoded ed25519 signature of the TLS certificate corresponding to the Onion access hostname, a semicolon terminates the signature and provides an optional separator." },
/*210*/ {     0,     1,     0, 2,  0,                   UNICODE,              "Onion-Delivery-Host", "Onion hostname for mail delivery, a semicolon terminates the hostname string and provides an optional separator." },
/*211*/ {     0,     1,     0, 2,  0,                   UNICODE,       "Onion-Delivery-Certificate", "Base 64 encoded ed25519 signature of the TLS certificate corresponding to the Onion delivery hostname, a semicolon terminates the signature and provides an optional separator." },
/*212*/ SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2,
/*220*/ SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2,
/*230*/ SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2,
/*240*/ SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2,
/*250*/ SKEY_SIZE2,
/*251*/ {     0,     0,     1, 2,  0,                   UNICODE,                  "Undefined-Field", "Organization undefined field specified by a name." },
/*252*/ {     0,     1,     0, 3,  0,                   PNG,                                "Photo", "Organization photo." },
/*253*/ {     1,     1,     0, 0,  ED25519_SIG_SIZE,    B64,             "Organizational-Signature", "ED25519 signature of all the previous fields signed by the organization POK." },
/*254*/ {     1,     1,     0, 1,  0,                   UNICODE,                "Signet-Identifier", "Mail service domain name." },
/*255*/ {     1,     1,     0, 0,  ED25519_SIG_SIZE,    B64,             "Organizational-Signature", "ED25519 signature of all the previous fields including the Signet-Identifer field signed by the organization POK." }, // TODO
};


signet_field_key_t signet_user_field_keys[256] = {
//	{ .required .unique .bytes_name_size .bytes_data_size, .data_size, .data_type, .name, .description }
/*  0*/ SKEY_EMPTY,
/*  1*/ {     1,     1,     0, 1, 0,                    B64,                          "Signing-Key", "User signing key." },
/*  2*/ {     1,     1,     0, 2, 0,                    B64,                       "Encryption-Key", "User encryption key which is used to encrypt messages to the holder of the user signet." },
/*  3*/ {     0,     0,     0, 2, 0,                    B64,             "Alternate-Encryption-Key", "Alternative user encryption keys." },
/*  4*/ {     0,     1,     0, 0, ED25519_SIG_SIZE,     B64,                              "Custody", "The 'Chain-of-custody' Signature. HMAC of the previous fields signed by user's previous private signing key." },
/*  5*/ {     1,     1,     0, 0, ED25519_SIG_SIZE,     B64,                       "User-Signature", "User's signature and the last field of the User's SSR. HMAC of the previous fields signed by user's private Signing key." },
/*  6*/ {     1,     1,     0, 0, ED25519_SIG_SIZE,     B64,             "Organizational-Signature", "HMAC of the fields provided by the user's SSR signed by the Organization's private Signing Key." },
/*  7*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/* 10*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/* 16*/ {     0,     1,     0, 1,  0,                   UNICODE,                             "Name", "User name." },
/* 17*/ {     0,     1,     0, 1,  0,                   UNICODE,                          "Address", "User address." },
/* 18*/ {     0,     1,     0, 1,  0,                   UNICODE,                         "Province", "User state/province." },
/* 19*/ {     0,     1,     0, 1,  0,                   UNICODE,                          "Country", "User country." },
/* 20*/ {     0,     1,     0, 1,  0,                   UNICODE,                      "Postal-Code", "User zip or postal code." },
/* 21*/ {     0,     0,     0, 1,  0,                   UNICODE,                     "Phone-Number", "User phone number." },
/* 22*/ {     0,     1,     0, 1,  0,                   UNICODE,                         "Language", "User language." },
/* 23*/ {     0,     1,     0, 1,  0,                   UNICODE,                         "Currency", "User currency." },
/* 24*/ {     0,     1,     0, 1,  0,                   UNICODE,                   "Cryptocurrency", "User cryptocurrency." },
/* 25*/ {     0,     1,     0, 1,  0,                   UNICODE,                            "Motto", "User motto." },
/* 26*/ {     0,     1,     0, 1,  0,                   UNICODE,                       "Extensions", "User Extensions." },
/* 27*/ {     0,     1,     0, 1,  0,                   UNICODE,               "Message-Size-Limit", "User Message-Size-Limit." },
/* 28*/ SKEY_SIZE1, SKEY_SIZE1,
/* 30*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/* 40*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/* 50*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/* 60*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/* 70*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/* 80*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/* 90*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/* 93*/ {     0,     1,     0, 1,  0,                   UNICODE,                 "Supported-Codecs", "Semicolon delimited list of optional media codecs supported by user's client, final semicolon is optional." },
/* 94*/ {     0,     1,     0, 1,  0,                   UNICODE,                            "Title", "User's job title and optionally title label delimited by a semicolon." },
/* 95*/ {     0,     1,     0, 1,  0,                   UNICODE,                         "Employer", "User's employer and optionally employer label delimited by a semicolon." },
/* 96*/ {     0,     1,     0, 1,  0,                   UNICODE,                           "Gender", "User's gender and optionally gender label delimited by a semicolon." },
/* 97*/ {     0,     1,     0, 1,  0,                   UNICODE,                       "Alma-Mater", "User's 'alma matter' and optionally 'alma matter' label delimited by a semicolon." },
/* 98*/ {     0,     1,     0, 1,  0,                   UNICODE,                       "Supervisor", "User's supervisor name and optionally supervisor name label delimited by a semicolon." },
/* 99*/ {     0,     1,     0, 1,  0,                   UNICODE,                  "Political-Party", "User's political party and optionally political party label delimited by a semicolon." },
/*100*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/*110*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/*120*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/*130*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/*140*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/*150*/ SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1, SKEY_SIZE1,
/*160*/ {     0,     1,     0, 2,  0,                   UNICODE,                          "Website", "User Website." },
/*161*/ SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2,
/*170*/ SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2,
/*180*/ SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2,
/*190*/ SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2,
/*200*/ {     0,     1,     0, 2,  0,                   UNICODE,                "Alternate-Address", "User alternate email address, semicolon used as optional separator." },
/*201*/ {     0,     1,     0, 2,  0,                   UNICODE,                           "Resume", "User resume." },
/*202*/ {     0,     0,     0, 2,  0,                   UNICODE,                     "Endorsements", "User endorsements." },
/*203*/ SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2,
/*210*/ SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2,
/*220*/ SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2,
/*230*/ SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2,
/*240*/ SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2, SKEY_SIZE2,
/*250*/ SKEY_SIZE2,
/*251*/ {     0,     0,     1, 2,  0,                   UNICODE,                  "Undefined-Field", "User undefined field specified by a name." },
/*252*/ {     0,     1,     0, 3,  0,                   PNG,                                "Photo", "User photo." },
/*253*/ {     1,     1,     0, 0,  ED25519_SIG_SIZE,    B64,             "Organizational-Signature", "HMAC of all the previous fields signed by the organization POK." },
/*254*/ {     1,     1,     0, 1,  0,                   UNICODE,                "Signet-Identifier", "User mail address." },
/*255*/ {     1,     1,     0, 0,  ED25519_SIG_SIZE,    B64,             "Organizational-Signature", "HMAC of all the previous fields including the Signet-Identifer field signed by the organization POK." }, // TODO
};


signet_field_key_t signet_ssr_field_keys[256] = {
//	{ .required .unique .bytes_name_size .bytes_data_size, .data_size, .data_type, .name, .description }
/*  0*/ SKEY_EMPTY,
/*  1*/ {     1,     1,     0, 1,  0,                   B64,                     "User-Signing-Key", "User signing key." },
/*  2*/ {     1,     1,     0, 2,  0,                   B64,                  "User-Encryption-Key", "User encryption key which is used to encrypt messages to the holder of the user signet." },
/*  3*/ {     0,     0,     0, 1,  0,                   B64,             "Alternate-Encryption-Key", "Alternative user encryption keys." },
/*  4*/ {     0,     1,     0, 0,  ED25519_SIG_SIZE,    B64,           "Chain-Of-Custody-Signature", "The 'Chain-of-custody' Signature. HMAC of the previous fields signed by user's previous private signing key." },
/*  5*/ {     1,     1,     0, 0,  ED25519_SIG_SIZE,    B64,                   "User-Ssr-Signature", "User's signature and the last field of the User's SSR. HMAC of the previous fields signed by user's private Signing key." },
/*  6*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/* 10*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/* 20*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/* 30*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/* 40*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/* 50*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/* 60*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/* 70*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/* 80*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/* 90*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*100*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*110*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*120*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*130*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*140*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*150*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*160*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*170*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*180*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*190*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*200*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*210*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*220*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*230*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*240*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY,
/*250*/ SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY, SKEY_EMPTY
};


/**
 * @brief	Returns a string from a dime_number_t enum type.
 * @param	number	Dime number input.
 * @return	Null terminated string corresponding to the dime number.
*/
const char *dime_number_to_str(dime_number_t number) {

	switch(number) {

	case DIME_ORG_SIGNET:
		return "organizational signet";
	case DIME_USER_SIGNET:
		return "user signet";
	case DIME_SSR:
		return "SSR";
	case DIME_ORG_KEYS:
		return "organizational signet keychain";
	case DIME_USER_KEYS:
		return "user signet keychain";
	case DIME_MSG_TRACING:
		return "message tracing";
	case DIME_ENCRYPTED_MSG:
		return "encrypted message";
	}

	return NULL;
}
