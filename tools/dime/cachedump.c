#include <stdio.h>
#include <stdlib.h>

#include "../../lib/dime/dime/cache.h"
#include "../../lib/dime/dime/dns.h"


void usage(const char *progname) {

	fprintf(stderr, "\nUsage: %s [-mkdos] [-v] [-r anchor-file]    where\n", progname);
	fprintf(stderr, " -m   dumps all cached DIME management records.\n");
	fprintf(stderr, " -k   dumps all cached DNSKEY records.\n");
	fprintf(stderr, " -d   dumps all cached DS records.\n");
	fprintf(stderr, " -o   dumps all cached OCSP responses.\n");
	fprintf(stderr, " -s   dumps all cached signets.\n");
	fprintf(stderr, " -r   specifies a root key anchor file for DNSKEY records to simulate loading.\n");
	fprintf(stderr, " -v   turns on verbose mode to dump all data associated with the cached object.\n");
	fprintf(stderr, "\n");

	exit(EXIT_FAILURE);
}


int main(int argc, char *argv[]) {

	unsigned int do_dime = 0, do_dnskey = 0, do_ds = 0, do_ocsp = 0, do_signet = 0, verbose = 0;
	int opt;

	if (load_cache_contents() < 0) {
		fprintf(stderr, "Error: unable to load cache contents from disk.\n");
		dump_error_stack();
		exit(EXIT_FAILURE);
	}

 	while ((opt = getopt(argc, argv, "dhkmor:sv")) != -1) {

		switch (opt) {
			case 'd':
				do_ds = 1;
				break;
			case 'h':
				usage(argv[0]);
				break;
			case 'k':
				do_dnskey = 1;
				break;
			case 'm':
				do_dime = 1;
				break;
			case 'o':
				do_ocsp = 1;
				break;
			case 'r':

				if (load_dnskey_file(optarg) < 0) {
					fprintf(stderr, "Error: could not load DNSKEY anchor records from file.\n");
					dump_error_stack();
					exit(EXIT_FAILURE);
				}

				break;
			case 's':
				do_signet = 1;
				break;
			case 'v':
				verbose = 1;
				break;
			default:
				usage(argv[0]);
				break;
		}

	}

	// If none of the options are set, then we set them all by default.
	if (!do_ds && !do_dnskey && !do_dime && !do_signet && !do_ocsp) {
		_dump_cache(cached_data_unknown, verbose, 1);
		exit(EXIT_SUCCESS);
	}

	if (do_dime) {
		_dump_cache(cached_data_drec, verbose, 1);
	}

	if (do_dnskey) {
		_dump_cache(cached_data_dnskey, verbose, 1);
	}

	if (do_ds) {
		_dump_cache(cached_data_ds, verbose, 1);
	}

	if (do_ocsp) {
		_dump_cache(cached_data_ocsp, verbose, 1);
	}

	if (do_signet) {
		_dump_cache(cached_data_signet, verbose, 1);
	}

	exit(EXIT_SUCCESS);
}
