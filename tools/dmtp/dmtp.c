#include <signet-resolver/dmtp.h>
#include <signet-resolver/cache.h>
#include <signet-resolver/dns.h>
#include <signet-resolver/mrec.h>
#include <signet-resolver/signet-ssl.h>

#include <signet/keys.h>

#include <common/misc.h>
#include <common/network.h>
#include <common/error.h>

#include <dmessage/dmsg.h>

static void usage(const char *progname) {

	fprintf(stderr, "\nUsage: %s <-o origin> <-d destination> [-k org_key_file] [-x dxserver] [-p port] [-0] [-n] [-4 or -6] [-v] <dmime_msg_file>    where\n", progname);
	fprintf(stderr, " dmime_msg_file is the pathname of the DMIME message to be transmitted.\n");
	fprintf(stderr, " -o   is the mandatory name of the origin domain responsible for sending the DMIME message,\n");
	fprintf(stderr, " -d   is the mandatory name of the destination domain that will receive the DMIME message.\n");
	fprintf(stderr, " -k   is the pathname of the (origin) org private key file to take an org full signature for the message (otherwise left blank).\n");
	fprintf(stderr, " -x   specifies an optional DX server hostname to be used instead of the one found from the destination domain's DIME record.\n");
	fprintf(stderr, " -p   forces a DX port to be used (only %u [ssl] or %u [dual mode] are allowed values).\n", DMTP_PORT, DMTP_PORT_DUAL);
	fprintf(stderr, " -n   disables use of the persistent object cache.\n");
	fprintf(stderr, " -4   forces ipv4 address resolution (-6 for ipv6).\n");
	fprintf(stderr, " -v   turns on verbose output (-v can be specified multiple times to increase the debugging level).\n");
	fprintf(stderr, "\n");

	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {

	dime_record_t *drec;
	dmtp_session_t *session;
//	signet_t *signet, *org_signet;
	dmap_msg_t *encrypted;
	ED25519_KEY *signkey = NULL;
	struct stat sb;
	void *fbuf;
	char *dxname = NULL, *origin = NULL, *destination = NULL, *dmimefile = NULL, *keyfile = NULL, *tid;
	unsigned long ttl = 0;
	unsigned short port = 0;
	int opt, is_org = 0, family = 0, no_cache = 0, vres, fd;

	while ((opt = getopt(argc, argv, "46d:k:no:p:vx:")) != -1) {

		switch (opt) {
		case '4':
			family = AF_INET;
			break;
		case '6':
			family = AF_INET6;
			break;
		case 'd':
			destination = optarg;
			break;
		case 'k':
			keyfile = optarg;
			break;
		case 'n':
			no_cache = 1;
			break;
		case 'o':
			origin = optarg;
			break;
		case 'p':

			if (!(port = atoi(optarg))) {
				fprintf(stderr, "Error: specified invalid port number.\n");
				exit(EXIT_FAILURE);
			}

			if ((port != DMTP_PORT) && (port != DMTP_PORT_DUAL)) {
				fprintf(stderr, "Error: invalid port specified; must be %u or %u.\n", DMTP_PORT, DMTP_PORT_DUAL);
				exit(EXIT_FAILURE);
			}

			break;
		case 'v':
			_verbose++;
			break;
		case 'x':
			dxname = optarg;
			break;
		default:
			usage(argv[0]);
			break;
		}

	}

	if (no_cache) {

		dbgprint(1, "Disabling object cache.\n");

		// We need to be able to use the cache, but not to load or save to disk.
		if (set_cache_permissions(CACHE_PERM_READ | CACHE_PERM_ADD | CACHE_PERM_DELETE) < 0) {
			fprintf(stderr, "Error: could not adjust cache permissions.\n");
			dump_error_stack();
			exit(EXIT_FAILURE);
		}

	}

	if (!origin || !destination) {
		usage(argv[0]);
	}

	if (argc == 1) {
		usage(argv[0]);
	} else if (argc == optind) {
		fprintf(stderr, "Error: no DMIME message was specified as input.\n");
		exit(EXIT_FAILURE);
	}

	// Are we a user or organizational signet?
	dmimefile = argv[optind];

	if (strchr(origin, '@')) {
		fprintf(stderr, "Error: invalid origin domain was supplied.\n");
		exit(EXIT_FAILURE);
	} else if (strchr(destination, '@')) {
		fprintf(stderr, "Error: invalid destinationdomain was supplied.\n");
		exit(EXIT_FAILURE);
	}

	if ((fd = open(dmimefile, O_RDONLY)) < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (fstat(fd, &sb) < 0) {
		perror("fstat");
		close(fd);
		exit(EXIT_FAILURE);
	}

	if ((fbuf = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == (void *)-1) {
		perror("mmap");
		close(fd);
		exit(EXIT_FAILURE);
	}

	// Only if we want org signature(s).
	if (keyfile) {

		if (!(signkey = keys_file_fetch_sign_key(keyfile))) {
			fprintf(stderr, "Error: unable to load org signing key.\n");
			dump_error_stack();
			exit(EXIT_FAILURE);
		}

	}

	dbgprint(1, "Running with verbose = %u ...\n", _verbose);
	dbgprint(1, "Performing query on %s signet.\n", (is_org ? "organizational" : "user"));

	if (load_cache_contents() < 0) {
		fprintf(stderr, "Error: unable to load cache contents from disk.\n");
		dump_error_stack();
	} else if (_verbose >= 5) {
		dbgprint(5, "Loaded object cache; dumping contents:\n");
		_dump_cache(cached_data_unknown, 1, 1);
	}

	printf("Querying DIME management record for: %s\n", destination);

	if (!(drec = get_dime_record(destination, &ttl, 1))) {
		fprintf(stderr, "Failed to query DIME management record.\n");
		dump_error_stack();
		exit(EXIT_FAILURE);
	}

/*	if (save_cache_contents() < 0) {
                fprintf(stderr, "Error: unable to save cache contents to disk.\n");
                dump_error_stack();
        }
        */

	if (family == AF_INET) {
		dbgprint(0, "Forcing connection to DX server over IPv4.\n");
	} else if (family == AF_INET6) {
		dbgprint(0, "Forcing connection to DX server over IPv6.\n");
	}

	// Now we need to connect to the DX server for the dark domain.
	// We can either use the command line input, if a DX server is explicitly provided, or use the normal route.
	if (dxname) {
		// If no port was specified, we assume the default DMTP port.
		if (!port) {
			port = DMTP_PORT;
		}

		fprintf(stderr, "Connecting to DX at %s:%d ...\n", dxname, port);

		// Only the dual mode port is considered an SSL service.
		if (port == DMTP_PORT_DUAL) {
			session = dx_connect_dual(dxname, destination, family, drec, 0);
		} else {
			session = dx_connect_standard(dxname, destination, family, drec);
		}

	} else {
		fprintf(stderr, "Establishing connection to DX server...\n");
		session = libdime_dmtp_connect(destination, family);
	}

	if (!session) {
		fprintf(stderr, "Error: could not connect to DX server.\n");
		dump_error_stack();
		exit(EXIT_FAILURE);
	}

	printf("DX connection succeeded.\n");

	if ((vres = verify_dx_certificate(session)) < 0) {
		fprintf(stderr, "Error: an error was encountered during the DX certificate verification process.\n");
		dump_error_stack();
		exit(EXIT_FAILURE);
	} else if (!vres) {
		fprintf(stderr, "Error: DX certificate verification failed.\n");
		exit(EXIT_FAILURE);
	}

	dbgprint(1, "DX certificate successfully verified.\n");

	if (libdime_dmtp_ehlo(session, origin) < 0) {
		fprintf(stderr, "Error: EHLO command failed.\n");
		dump_error_stack();
		exit(EXIT_FAILURE);
	}

	dbgprint(1, "EHLO return OK.\n");

	if (dmtp_mail_from(session, origin, sb.st_size, return_type_default, data_type_default) < 0) {
		fprintf(stderr, "Error: MAIL FROM command failed.\n");
		dump_error_stack();
		exit(EXIT_FAILURE);
	}

	dbgprint(1, "MAIL FROM return OK.\n");

	if (dmtp_rcpt_to(session, destination) < 0) {
		fprintf(stderr, "Error: MAIL FROM command failed.\n");
		dump_error_stack();
		exit(EXIT_FAILURE);
	}

	dbgprint(1, "MAIL FROM return OK.\n");

	// The simplest case is if we don't care about an org signature going out.
	if (!signkey) {

		if (!(tid = dmtp_data(session, fbuf, sb.st_size))) {
			fprintf(stderr, "Error: DATA command failed.\n");
			dump_error_stack();
			exit(EXIT_FAILURE);
		}

	} else {
		_dbgprint(0, "Attaching org signature to outbound DMIME message...\n");

		if (!(encrypted = parse_dmime_raw(fbuf, sb.st_size))) {
			fprintf(stderr, "Error: could not parse encrypted DMIME message.\n");
			dump_error_stack();
			exit(EXIT_FAILURE);
		}

		if (org_take_dmsg_signature(encrypted, 0, signkey) < 0) {
			fprintf(stderr, "Error: could not make org full siginature on DMIME message.\n");
			dump_error_stack();
			exit(EXIT_FAILURE);
		}

		if (!(tid = dmtp_data(session, st_char_get(encrypted->chunk_data), st_length_get(encrypted->chunk_data)))) {
			fprintf(stderr, "Error: DATA command failed.\n");
			dump_error_stack();
			exit(EXIT_FAILURE);
		}

	}

	printf("Message sent; received transaction ID: %s\n", tid);
	free(tid);

	if (munmap(fbuf, sb.st_size) < 0) {
		perror("munmap");
	}

	close(fd);

	printf("Done.\n");

	return 0;
}
