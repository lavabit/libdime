#include <unistd.h>

#include <signet/keys.h>
#include <common/misc.h>
#include <common/dcrypto.h>

static void usage(const char *progname) {

	fprintf(stderr, "\nUsage: %s <-g or -d> [-p] [-f keyfile]  where\n", progname);
	fprintf(stderr, "  -g generates a new ED25519 keypair.\n");
	fprintf(stderr, "  -d dumps the ED25519 key data supplied by the user.\n");
	fprintf(stderr, "  -p can be used with -d to fetch the POK from a private keychain.\n");
	fprintf(stderr, "  -f specifies a keyfile to be used with -g or -d (otherwise stdout/stdin will be used by default).\n\n");

	exit(EXIT_FAILURE);
}


int main(int argc, char *argv[]) {

	ED25519_KEY *key;
	FILE *fp;
	char *filename = NULL, *pubb64, *privb64, *hexkey;
	int opt, generate = 0, dump = 0, pok = 0;

	while ((opt = getopt(argc, argv, "gdf:p")) != -1) {

		switch (opt) {
			case 'g':
				generate = 1;
				break;
			case 'd':
				dump = 1;
				break;
			case 'f':
				filename = optarg;
				break;
			case 'p':
				pok = 1;
				break;
			default:
				usage(argv[0]);
				break;
		}

	}

	if (!dump && !generate) {
		usage(argv[0]);
	} else if (dump && generate) {
		fprintf(stderr, "Error: -d and -g cannot be specified together.\n");
		exit(EXIT_FAILURE);
	}

	if (optind != argc) {
		usage(argv[0]);
	}

	if (pok && (!dump || !filename)) {
		fprintf(stderr, "Error: -p must be specified together with the -d and -f options.\n");
		exit(EXIT_FAILURE);
	}

	if (generate) {

		if (!(key = generate_ed25519_keypair())) {
			fprintf(stderr, "Error: Unable to generate new ED25519 key pair.\n");
			dump_error_stack();
			exit(EXIT_FAILURE);
		}

		fp = stdout;

		if (filename) {

			if (!(fp = fopen(filename, "w"))) {
				perror("fopen");
				fprintf(stderr, "Error: Unable to open ED25519 key data file for writing.\n");
				free_ed25519_key(key);
				exit(EXIT_FAILURE);
			}

		}

		if (!(privb64 = b64encode(key->private_key, sizeof(key->private_key)))) {
			fprintf(stderr, "Error: Unable to base64 encode ED25519 private key.\n");
			dump_error_stack();
			free_ed25519_key(key);
			exit(EXIT_FAILURE);
		}

		if (!(pubb64 = b64encode(key->public_key, sizeof(key->public_key)))) {
			fprintf(stderr, "Error: Unable to base64 encode ED25519 public key.\n");
			dump_error_stack();
			free_ed25519_key(key);
			free(privb64);
			exit(EXIT_FAILURE);
		}

		fprintf(fp, "-----BEGIN ED25519 PRIVATE KEY-----\n");
		fprintf(fp, "%s\n", privb64);
		fprintf(fp, "-----END ED25519 PRIVATE KEY-----\n\n");
		fprintf(fp, "-----BEGIN ED25519 PUBLIC KEY-----\n");
		fprintf(fp, "%s\n", pubb64);
		fprintf(fp, "-----END ED25519 PUBLIC KEY-----\n");

		free_ed25519_key(key);
		free(privb64);
		free(pubb64);
	} else if (dump) {

		if (pok) {

			if (!(key = keys_file_fetch_sign_key(filename))) {
				fprintf(stderr, "Error: could not read POK from keyfile.\n");
				dump_error_stack();
				exit(EXIT_FAILURE);
			}

		} else {

			if (filename) {

				if (!(fp = fopen(filename, "r"))) {
					perror("fopen");
					fprintf(stderr, "Error: Unable to open ED25519 key data file for reading.\n");
					exit(EXIT_FAILURE);
				}

			}

			if (!(key = load_ed25519_privkey(filename))) {
				fprintf(stderr, "Error: Unable to read in ED25519 key data.\n");
				dump_error_stack();
				exit(EXIT_FAILURE);
			}

		}

		if (!(hexkey = hex_encode(key->private_key, sizeof(key->private_key)))) {
			fprintf(stderr, "Error: Unable to encode ED25519 private key.\n");
			dump_error_stack();
			exit(EXIT_FAILURE);
		}

		printf("ED25519 private key: %s\n", hexkey);
		free(hexkey);

		if (!(hexkey = hex_encode(key->public_key, sizeof(key->public_key)))) {
			fprintf(stderr, "Error: Unable to encode ED25519 public key.\n");
			dump_error_stack();
			exit(EXIT_FAILURE);
		}

		printf("ED25519 public key:  %s\n", hexkey);
		free(hexkey);
	}

	exit(EXIT_SUCCESS);
}
