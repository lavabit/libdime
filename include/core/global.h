
/**
 * @file /magma/engine/config/global/global.h
 *
 * @brief	The global configuration structure used for overall system settings, and functions to initialize it at startup and free it at shutdown.
 *
 * $Author$
 * $Date$
 * $Revision$
 *
 */

#ifndef MAGMA_ENGINE_CONFIG_GLOBAL_H
#define MAGMA_ENGINE_CONFIG_GLOBAL_H

typedef struct {
	void *store; /* The location in memory to store the setting value. */
	multi_t norm; /* The default value. */
	chr_t *name; /* The search key/name of the setting. */
	chr_t *description; /* Description of the setting and its default value. */
	bool_t file; /* Can this value be set using the config file? */
	bool_t database; /* Can this value be set using the config file? */
	bool_t overwrite; /* Can this value be overwritten? */
	bool_t set; /* Has this setting already been provided? */
	bool_t required; /* Is this setting required? */
} magma_keys_t;

typedef struct {

	struct {
		bool_t output_config; /* Dump the configuration to the log file. */
		bool_t output_resource_limits; /* Should attempts to increase system limits trigger an error. */

		// LOW: Filenames are limited to 255 characters, but file paths can be up to 4096. As such we should probably be storing this using a block of memory off the heap.
		chr_t file[MAGMA_FILEPATH_MAX + 1]; /* Path to the magmad.config file. */
	} config;

	struct {
		stringer_t *contact; /* The general purpose contact email address. */
		stringer_t *abuse; /* The contact email address for abuse complaints. */
	} admin;

	struct {
		uint64_t number; /* The unique numeric identifier for this host. */
		chr_t name[MAGMA_HOSTNAME_MAX + 1]; /* The hostname. Size can be MAGMA_HOSTNAME_MAX (64) or MAGMA_HOSTNAME_MAX (255). Make sure the gethostname() calls match. */
	} host;

	struct {
		chr_t *file; /* Path to the magma.open.so library. */
		bool_t unload; /* Unload the magma.open.so symbols at exit. */
	} library;

	struct {
		bool_t daemonize; /* Spawn a daemon process and release the console session. */
		char * root_directory; /* Change the root path to the provided value. */
		char * impersonate_user; /* Change the effective user account of the process to the user provided. */
		bool_t increase_resource_limits; /* Attempt to increase system limits. */
		uint32_t thread_stack_size; /* How much memory should be allocated for thread stacks? */
		uint32_t worker_threads; /* How many worker threads should we spawn? */
		uint32_t network_buffer; /* The size of the network buffer? */

		bool_t enable_core_dumps; /* Should fatal errors leave behind a core dump. */
		uint64_t core_dump_size_limit; /* If core dumps are enabled, what size should they be limited too. */

		stringer_t *domain; /* The default domain name used in new user email addresses and for unqualified login names. */
		char * ca_store; /* Certification authority certificates will be loaded from this directory. */
	} system;

	struct {
		struct {
			bool_t enable; /* Should the secure memory sub-system be enabled. */
			uint64_t length; /* The size of the secure memory pool. The pool must fit within any memory locking limits. */
		} memory;

		stringer_t *salt; /* The string added to hash operations to improve security. */
		stringer_t *links; /* The string used to encrypt links that reflect back to the daemon. */
		stringer_t *sessions; /* The string used to encrypt session tokens. */
	} secure;

	struct {
		bool_t file; /* Send log messages to a file. */
		chr_t *path; /* If log files are enabled, this will control whether the logs are stored. */
	} output;

	struct {

		bool_t imap; /* Output IMAP request details. */
		bool_t http; /* Output HTTP request details. */
		bool_t dmap; /* Output DMAP request details. */
		bool_t content; /* Output the web resource files loaded. */

		bool_t file; /* Output the source file that recorded the log entry. */
		bool_t line; /* Output the source line that recorded the log entry. */
		bool_t time; /* Output time that the log entry was recorded. */
		bool_t stack; /* Output the stack that triggered the log entry. */
		bool_t function; /* Output the function that made the log entry. */
	} log;

	struct {
		chr_t *tank; /* The path of the storage tank. */
		stringer_t *active; /* The default storage server used by the legacy mail storage logic. */
		stringer_t *root; /* The root portion of the storage server directory paths. */
	} storage;

	struct {

		struct {
			uint32_t seed_length; /* How much data should be used to seed the random number generator. */
		} cryptography;

		struct {
			chr_t *host; /* The database host name. */
			chr_t *user; /* The database user name. */
			chr_t *password; /* The database password. */
			chr_t *schema; /* The database schema name. */
			uint32_t port; /* The database server port. */

			struct {
				uint32_t timeout; /* The number of seconds to wait for a free database connection. */
				uint32_t connections; /* The number of database connections in the pool. */
			} pool;
		} database;

	} iface;

	// Global config section
	chr_t * spool; /* The spool directory. */
	int_t page_length; /* The memory page size. This value is used to align memory mapped files to page boundaries. */

	// Global variables section
	uint32_t init; /* How far into the initialization process we've gotten. */
	pthread_rwlock_t lock; /* Used to grab a global read or write lock on the configuration. */

} magma_t;


/// global.c
void            config_free(void);
magma_keys_t *  config_key_lookup(stringer_t *name);
bool_t          config_load_database_settings(void);
bool_t			config_load_cmdline_settings(void);
bool_t          config_load_defaults(void);
bool_t          config_load_file_settings(void);
void            config_output_help(void);
void            config_output_settings(void);
void			config_output_value_generic(chr_t *prefix, chr_t *name, M_TYPE type, void *val, bool_t required);
void            config_output_value(magma_keys_t *key);
bool_t          config_validate_settings(void);
bool_t          config_value_set(magma_keys_t *setting, stringer_t *value);

#endif
