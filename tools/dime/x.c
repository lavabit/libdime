#include "../../lib/dime/dime/cache.h"
#include "../../lib/dime/dime/dmtp.h"
#include "../../lib/dime/dime/dns.h"
#include "../../lib/dime/dime/mrec.h"
#include "../../lib/dime/dime/ssl.h"
#include "network.h"
#include "misc.h"
#include "error.h"



int main(int argc, char *argv[]) {

	dime_record_t xdrec;
	dmtp_session_t xsession;
	SSL *s;
	int res;

//	char *hostname = "technodrome";
//	unsigned short port = 31301;
	char *hostname = "www.google.com";
//	char *hostname = "tv.eurosport.com";
//	char *hostname = "testssl-expire.disig.sk";
	unsigned short port = 443;

set_dbg_level(3);

	if (!(s = ssl_connect_host(hostname, port, AF_INET))) {
		fprintf(stderr, "Could not connect to host %s:%u\n", hostname, port);
		dump_error_stack();
		exit(EXIT_FAILURE);
	}
//	s = ssl_connect_host("www.wikipedia.org", 443, AF_INET);
//	s = ssl_connect_host("www.google.com", 443, AF_INET);
//	s = ssl_connect_host("www.yahoo.com", 443, AF_INET);
//	s = ssl_connect_host("localhost", 31301, AF_INET);
	memset(&xdrec, 0, sizeof(xdrec));
	memset(&xsession, 0, sizeof(xsession));
	xsession.drec = &xdrec;
	xsession.con = s;
	xsession.domain = hostname;
	xsession.dx = hostname;
load_cache_contents();
	res = verify_dx_certificate(&xsession);
	printf("verification = %d\n", res);

	if (res < 0) {
		fprintf(stderr, "DX certificate verification failure:\n");
		dump_error_stack();
		exit(EXIT_FAILURE);
	}

/*_dump_cache(cached_data_ocsp, 1);
save_cache_contents(); */

	return 0;
}
