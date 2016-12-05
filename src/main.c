/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"            // for VERSION

#include "picocoin.h"                   // for network_sync, setting
#include <ccoin/blkdb.h>                // for blkinfo, blkdb, etc
#include <ccoin/clist.h>                // for clist, clist_free_ext, etc
#include <ccoin/compat.h>               // for strndup
#include <ccoin/core.h>                 // for bp_address
#include <ccoin/coredefs.h>             // for chain_find, chain_info
#include <ccoin/crypto/prng.h>          // for prng_get_random_bytes
#include <ccoin/log.h>                  // for log_info, log_debug, etc
#include <ccoin/net/dns.h>              // for bu_dns_seed_addrs
#include <ccoin/net/net.h>              // for net_child_info, nc_conns_gc, etc
#include <ccoin/net/netbase.h>          // for bn_address_str, etc
#include <ccoin/net/peerman.h>          // for peer_manager, peerman_write, etc
#include <ccoin/util.h>                 // for ARRAY_SIZE, czstr_equal, etc

#include "wallet.h"                     // for cur_wallet_addresses, etc

#include <argp.h>
#include <assert.h>                     // for assert
#include <stdbool.h>                    // for bool
#include <ctype.h>                      // for isspace
#include <errno.h>                      // for errno
#include <event2/event.h>               // for event_free, event_base_new, etc
#include <fcntl.h>                      // for open
#include <stdio.h>                      // for fprintf, printf, NULL, etc
#include <stdlib.h>                     // for free, exit
#include <string.h>                     // for strcmp, strdup, strlen, etc
#include <jansson.h>

enum command_type {
	CMD_CHAIN_SET,
	CMD_DNS_SEEDS,
	CMD_LIST_SETTINGS,
	CMD_NETSYNC,
	CMD_ADDRESS_NEW,
	CMD_WALLET_NEW,
	CMD_WALLET_ADDR,
	CMD_WALLET_DUMP,
	CMD_WALLET_INFO,
	CMD_ACCT_DEFAULT,
	CMD_ACCT_CREATE,
};

const char *prog_name = "picocoin";
struct bp_hashtab *settings;
const struct chain_info *chain = NULL;
bu256_t chain_genesis;
uint64_t instance_nonce;
struct logging *log_state;
bool debugging = false;
static enum command_type opt_command = CMD_WALLET_INFO;
static const char *opt_arg1 = NULL;

static struct blkdb db;
static unsigned int net_conn_timeout = 60;
struct wallet *cur_wallet;

static bool do_setting(const char *arg);

static const char *const_settings[] = {
	"net.connect.timeout=11",
	"wallet=picocoin.wallet",
	"chain=bitcoin",
	"peers=picocoin.peers",
	"blkdb=picocoin.blkdb",
};

/* Command line arguments and processing */
const char *argp_program_version =
	"picocoin " PACKAGE_VERSION "\n"
	"Copyright 2016 Bloq, Inc.\n"
	"This is free software; see the source for copying conditions.  There is NO "
	"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.";

/*
 * command line processing
 */

const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static const char args_doc[] = "COMMAND [COMMAND-OPTIONS...]";

static char global_doc[] =
	"command line wallet client\n"
	"\n"
	"Supported commands:\n"
	"\tchain-set - Select blockchain and network.\n"
	"\tdns-seeds - Query and display bitcoin DNS seeds.\n"
	"\tsettings - Display settings map.\n"
	"\taddress - Generate a new HD address in default account, and output it.\n"
	"\tcreate - Initialize a new HD wallet. Refuses to initialize if the file exists.\n"
	"\tcreateAccount - Create new HD account\n"
	"\tdefault - Switch default HD account\n"
	"\tnetsync - Synchronize with the network, sending and receiving payments.\n"
	"\taddressList - List all legacy addresses (non-HD) in the wallet.\n"
	"\tdump - Dump entire wallet contents, including private keys.\n"
	"\tinfo - Print informational summary of wallet data.\n"
	"\n"
	"Run \"picocoin cmd --help\" for extended, per-command help.\n"
	"\n"
	"Global options:\n";

static struct argp_option options[] = {
	{ "set", 1001, "KEY=VALUE", 0,
	  "Set global setting KEY to VALUE" },

	{ 0 }
};

static struct argp_option cmd_no_options[] = { { 0 } };

static error_t parse_no_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static error_t parse_arg1_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {
	case ARGP_KEY_ARG:
		if (state->arg_num >= 1)	// too many arguments
			argp_usage(state);

		opt_arg1 = arg;
		break;

	case ARGP_KEY_END:
		if (state->arg_num < 1)		// not enough arguments
			argp_usage(state);
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}


// ======================== command: chain-set ==========================

static char cmd_chain_set_doc[] = "Set chain\n";

static struct argp argp_cmd_chain_set = { cmd_no_options, parse_no_opt, NULL, cmd_chain_set_doc };

// ======================== command: dns-seeds ==========================

static char cmd_dns_seeds_doc[] = "DNS seeds\n";

static struct argp argp_cmd_dns_seeds = { cmd_no_options, parse_no_opt, NULL, cmd_dns_seeds_doc };

// ======================== command: settings ==========================

static char cmd_settings_doc[] = "Global program settings\n";

static struct argp argp_cmd_settings = { cmd_no_options, parse_no_opt, NULL, cmd_settings_doc };

// ======================== command: netsync ==========================

static char cmd_netsync_doc[] = "Sync with network\n";

static struct argp argp_cmd_netsync = { cmd_no_options, parse_no_opt, NULL, cmd_netsync_doc };

// ======================== command: address ==========================

static char cmd_address_doc[] = "Generate new address\n";

static struct argp argp_cmd_address = { cmd_no_options, parse_no_opt, NULL, cmd_address_doc };

// ======================== command: create ==========================

static char cmd_create_doc[] = "Create new wallet\n";

static struct argp argp_cmd_create = { cmd_no_options, parse_no_opt, NULL, cmd_create_doc };

// ======================== command: createAccount ==========================

static char cmd_createAccount_doc[] = "Create new HD account\n";
static const char cmd_args_account_name_doc[] = "account-name";

static struct argp argp_cmd_createAccount = { cmd_no_options, parse_arg1_opt, cmd_args_account_name_doc, cmd_createAccount_doc };

// ======================== command: default ==========================

static char cmd_default_doc[] = "Set default HD account\n";

static struct argp argp_cmd_default = { cmd_no_options, parse_arg1_opt, cmd_args_account_name_doc, cmd_default_doc };

// ======================== command: dump ==========================

static char cmd_dump_doc[] = "Dump wallet\n";

static struct argp argp_cmd_dump = { cmd_no_options, parse_no_opt, NULL, cmd_dump_doc };

// ======================== command: info ==========================

static char cmd_info_doc[] = "Wallet info\n";

static struct argp argp_cmd_info = { cmd_no_options, parse_no_opt, NULL, cmd_info_doc };

// ======================== command: addressList ==========================

static char cmd_addressList_doc[] = "Wallet addressList\n";

static struct argp argp_cmd_addressList = { cmd_no_options, parse_no_opt, NULL, cmd_addressList_doc };

// ======================== top-level command processing ================

static void parse_secondary_cmd(struct argp_state* state,
				const struct argp *argp_2nd,
				const char *name_2nd)
{
	int    argc = state->argc - state->next + 1;
	char** argv = &state->argv[state->next - 1];
	char*  argv0 =  argv[0];

	char new_arg0[strlen(state->name) + strlen(name_2nd) + 2];

	strcpy(new_arg0, state->name);
	strcat(new_arg0, " ");
	strcat(new_arg0, name_2nd);

	argv[0] = new_arg0;

	argp_parse(argp_2nd, argc, argv, ARGP_IN_ORDER, &argc, NULL);

	argv[0] = argv0;

	state->next += argc - 1;
}

static error_t parse_global_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {
	case 1001:		// --set=KEY=VALUE
		if (!do_setting(arg))
			argp_usage(state);
		break;

	case ARGP_KEY_ARG:
		if (strcmp(arg, "chain-set") == 0) {
			opt_command = CMD_CHAIN_SET;
			parse_secondary_cmd(state, &argp_cmd_chain_set, "chain-set");
		} else if (strcmp(arg, "dns-seeds") == 0) {
			opt_command = CMD_DNS_SEEDS;
			parse_secondary_cmd(state, &argp_cmd_dns_seeds, "dns-seeds");
		} else if (strcmp(arg, "settings") == 0) {
			opt_command = CMD_LIST_SETTINGS;
			parse_secondary_cmd(state, &argp_cmd_settings, "settings");
		} else if (strcmp(arg, "netsync") == 0) {
			opt_command = CMD_NETSYNC;
			parse_secondary_cmd(state, &argp_cmd_netsync, "netsync");
		} else if (strcmp(arg, "address") == 0) {
			opt_command = CMD_ADDRESS_NEW;
			parse_secondary_cmd(state, &argp_cmd_address, "address");
		} else if (strcmp(arg, "create") == 0) {
			opt_command = CMD_WALLET_NEW;
			parse_secondary_cmd(state, &argp_cmd_create, "create");
		} else if (strcmp(arg, "createAccount") == 0) {
			opt_command = CMD_ACCT_CREATE;
			parse_secondary_cmd(state, &argp_cmd_createAccount, "createAccount");
		} else if (strcmp(arg, "default") == 0) {
			opt_command = CMD_ACCT_DEFAULT;
			parse_secondary_cmd(state, &argp_cmd_default, "default");
		} else if (strcmp(arg, "addressList") == 0) {
			opt_command = CMD_WALLET_ADDR;
			parse_secondary_cmd(state, &argp_cmd_addressList, "addressList");
		} else if (strcmp(arg, "dump") == 0) {
			opt_command = CMD_WALLET_DUMP;
			parse_secondary_cmd(state, &argp_cmd_dump, "dump");
		} else if (strcmp(arg, "info") == 0) {
			opt_command = CMD_WALLET_INFO;
			parse_secondary_cmd(state, &argp_cmd_info, "info");
		} else {
			argp_error(state, "%s is not a valid command", arg);
		}
		break;


	case ARGP_KEY_END:
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp = { options, parse_global_opt, args_doc, global_doc };

static bool parse_kvstr(const char *s, char **key, char **value)
{
	char *eql;

	eql = strchr(s, '=');
	if (eql) {
		unsigned int keylen = eql - s;
		*key = strndup(s, keylen);
		*value = strdup(s + keylen + 1);
	} else {
		*key = strdup(s);
		*value = strdup("");
	}

	/* blank keys forbidden; blank values permitted */
	if (!strlen(*key)) {
		free(*key);
		free(*value);
		*key = NULL;
		*value = NULL;
		return false;
	}

	return true;
}

static bool read_config_file(const char *cfg_fn)
{
	FILE *cfg = fopen(cfg_fn, "r");
	if (!cfg)
		return false;

	bool rc = false;

	char line[1024];
	while (fgets(line, sizeof(line), cfg) != NULL) {
		char *key, *value;

		if (line[0] == '#')
			continue;
		while (line[0] && (isspace(line[strlen(line) - 1])))
			line[strlen(line) - 1] = 0;

		if (!parse_kvstr(line, &key, &value))
			continue;

		bp_hashtab_put(settings, key, value);
	}

	rc = ferror(cfg) == 0;

	fclose(cfg);
	return rc;
}

static bool do_setting(const char *arg)
{
	char *key, *value;

	if (!parse_kvstr(arg, &key, &value))
		return false;

	bp_hashtab_put(settings, key, value);

	/*
	 * trigger special setting-specific behaviors
	 */

	if (!strcmp(key, "debug"))
		debugging = true;

	else if (!strcmp(key, "config") || !strcmp(key, "c"))
		return read_config_file(value);

	/* clear previous wallet, if new wallet file seen */
	else if (!strcmp(key, "wallet") || !strcmp(key, "w"))
		cur_wallet_free();

	return true;
}

static bool preload_settings(void)
{
	unsigned int i;

	/* preload static settings */
	for (i = 0; i < ARRAY_SIZE(const_settings); i++)
		if (!do_setting(const_settings[i]))
			return false;

	return true;
}

struct lsi_info {
	unsigned int	table_len;
	json_t		*settings_obj;
	unsigned int	iter_count;
};

static void list_setting_iter(void *key_, void *value_, void *lsi_)
{
	char *key = key_;
	char *value = value_;
	struct lsi_info *lsi = lsi_;

	json_object_set_new(lsi->settings_obj, key, json_string(value));
}

static void list_settings(void)
{
	json_t *settings_obj = json_object();

	struct lsi_info lsi = { bp_hashtab_size(settings), settings_obj };
	bp_hashtab_iter(settings, list_setting_iter, &lsi);

	json_dumpf(settings_obj, stdout, JSON_INDENT(2) | JSON_SORT_KEYS);
	json_decref(settings_obj);

	printf("\n");
}

static void list_dns_seeds(void)
{
	clist *tmp, *addrlist = bu_dns_seed_addrs();

	size_t list_len = clist_length(addrlist);
	unsigned int n_ent = 0;

	printf("[\n");

	for (tmp = addrlist; tmp != NULL; tmp = tmp->next) {
		struct bp_address *addr = tmp->data;
		char host[64];

		bool is_ipv4 = is_ipv4_mapped(addr->ip);
		bn_address_str(host, sizeof(host), addr->ip);

		printf("  [ %s, \"%s\", %u, %llu ]%s\n",
		       is_ipv4 ? "true" : "false",
		       host,
		       addr->port,
		       (unsigned long long) addr->nServices,
		       (n_ent == (list_len - 1)) ? "" : ",");

		n_ent++;
	}

	clist_free_ext(addrlist, free);

	printf("]\n");
}

static void chain_set(void)
{
	char *name = setting("chain");
	const struct chain_info *new_chain = chain_find(name);
	if (!new_chain) {
		log_info("chain-set: unknown chain '%s'", name);
		exit(1);
	}

	bu256_t new_genesis;
	if (!hex_bu256(&new_genesis, new_chain->genesis_hash)) {
		log_info("chain-set: invalid genesis hash %s",
			new_chain->genesis_hash);
		exit(1);
	}

	chain = new_chain;
	bu256_copy(&chain_genesis, &new_genesis);
}

static void init_log(void)
{
	log_state = malloc(sizeof(struct logging));

	log_state->stream = stdout;

	setvbuf(log_state->stream, NULL, _IONBF, BUFSIZ);

	log_state->logtofile = false;
	log_state->debug = debugging;
}

static void init_peers(struct net_child_info *nci)
{
	/*
	 * read network peers
	 */
	struct peer_manager *peers;

	peers = peerman_read(setting("peers"));
	if (!peers) {
		log_info("%s: initializing empty peer list", prog_name);

		peers = peerman_seed(setting("no_dns") == NULL ? true : false);
		if (!peerman_write(peers, setting("peers"), chain)) {
			log_info("%s: failed to write peer list", prog_name);
			exit(1);
		}
	}

	char *addnode = setting("addnode");
	if (addnode)
		peerman_addstr(peers, addnode);

	peerman_sort(peers);

	log_debug("%s: have %u/%zu peers",
		prog_name,
		bp_hashtab_size(peers->map_addr),
		clist_length(peers->addrlist));

	nci->peers = peers;
}

static void init_blkdb(void)
{
	if (!blkdb_init(&db, chain->netmagic, &chain_genesis)) {
		log_info("%s: blkdb init failed", prog_name);
		exit(1);
	}

	char *blkdb_fn = setting("blkdb");
	if (!blkdb_fn)
		return;

	if ((access(blkdb_fn, F_OK) == 0) &&
	    !blkdb_read(&db, blkdb_fn)) {
		log_info("%s: blkdb read failed", prog_name);
		exit(1);
	}

	db.fd = open(blkdb_fn,
		     O_WRONLY | O_APPEND | O_CREAT | O_LARGEFILE, 0666);
	if (db.fd < 0) {
		log_info("%s: blkdb file open failed: %s", prog_name, strerror(errno));
		exit(1);
	}

    log_debug("%s: blkdb opened", prog_name);
}

static void shutdown_nci(struct net_child_info *nci)
{
	nci->read_fd = -1;
	nci->write_fd = -1;
	peerman_free(nci->peers);
	nc_conns_gc(nci, true);
	assert(nci->conns->len == 0);
	parr_free(nci->conns, true);
	event_base_free(nci->eb);
}

static void init_nci(struct net_child_info *nci)
{
	memset(nci, 0, sizeof(*nci));
	nci->read_fd = -1;
	nci->write_fd = -1;
	nci->db = &db;
	nci->conns = parr_new(NC_MAX_CONN, NULL);
	nci->eb = event_base_new();
	nci->net_conn_timeout = net_conn_timeout;
	nci->chain = chain;
	nci->instance_nonce = &instance_nonce;
	nci->running = false;
	nci->last_getblocks = 2147483647;
}

static void network_child(int read_fd, int write_fd)
{
    struct net_child_info nci;

    init_nci(&nci);

    nci.read_fd = read_fd;
    nci.write_fd = write_fd;

    /*
     * set up libevent dispatch
     */
    struct event *pipe_evt;

    pipe_evt = event_new(nci.eb, nci.read_fd, EV_READ | EV_PERSIST,
				nc_pipe_evt, &nci);
	event_add(pipe_evt, NULL);

    /* wait for NC_START command */
	while (!nci.running) {
		event_base_dispatch(nci.eb);
    }

    init_blkdb();
    init_peers(&nci);


	/* main loop (child) */
	do {
		nc_conns_process(&nci);
		event_base_dispatch(nci.eb);
	} while (nci.running);

	/* cleanup: just the minimum for file I/O correctness */
	peerman_write(nci.peers, setting("peers"), nci.chain);
	blkdb_free(nci.db);
	shutdown_nci(&nci);
	exit(0);
}

void network_sync(void)
{
	char *sleep_str = setting("sleep");
	int nsec = atoi(sleep_str ? sleep_str : "");
	if (nsec < 1)
		nsec = 10 * 60;

	char *timeout_str = setting("net.connect.timeout");
	int v = atoi(timeout_str ? timeout_str : "0");
	if (v > 0)
		net_conn_timeout = (unsigned int) v;

	struct net_engine *neteng = neteng_new_start(network_child);

	log_debug("net: engine started. sleeping %d %s (cxn tmout %u sec)",
			(nsec > 60) ? nsec/60 : nsec,
			(nsec > 60) ? "minutes" : "seconds",
			net_conn_timeout);

	sleep(nsec);

	neteng_free(neteng);
}

int main (int argc, char *argv[])
{
	settings = bp_hashtab_new_ext(czstr_hash, czstr_equal,
				      free, free);

	if (!preload_settings())
		return 1;

	/* Parsing of commandline parameters */
	argp_parse(&argp, argc, argv, ARGP_IN_ORDER, NULL, NULL);

	if (prng_get_random_bytes((unsigned char *)&instance_nonce, sizeof(instance_nonce)) < 0) {
		fprintf(stderr, "picocoin: no random data available\n");
		return 1;
	}

	init_log();
	chain_set();

	switch (opt_command) {
	case CMD_CHAIN_SET:	chain_set(); break;
	case CMD_DNS_SEEDS:	list_dns_seeds(); break;
	case CMD_LIST_SETTINGS:	list_settings(); break;
	case CMD_NETSYNC:	network_sync(); break;
	case CMD_ADDRESS_NEW:	cur_wallet_new_address(); break;
	case CMD_WALLET_NEW:	cur_wallet_create(); break;
	case CMD_WALLET_ADDR:	cur_wallet_addresses(); break;
	case CMD_WALLET_DUMP:	cur_wallet_dump(); break;
	case CMD_WALLET_INFO:	cur_wallet_info(); break;
	case CMD_ACCT_CREATE:	cur_wallet_createAccount(opt_arg1); break;
	case CMD_ACCT_DEFAULT:	cur_wallet_defaultAccount(opt_arg1); break;
	}

	free(log_state);

	return 0;
}
