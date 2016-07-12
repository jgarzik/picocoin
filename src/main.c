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
#include <ccoin/net/dns.h>              // for bu_dns_seed_addrs
#include <ccoin/net/net.h>              // for net_child_info, nc_conns_gc, etc
#include <ccoin/net/netbase.h>          // for bn_address_str, etc
#include <ccoin/net/peerman.h>          // for peer_manager, peerman_write, etc
#include <ccoin/util.h>                 // for ARRAY_SIZE, czstr_equal, etc
#include "wallet.h"                     // for cur_wallet_addresses, etc

#include <assert.h>                     // for assert
#include <ctype.h>                      // for isspace
#include <errno.h>                      // for errno
#include <event2/event.h>               // for event_free, event_base_new, etc
#include <fcntl.h>                      // for open
#include <openssl/rand.h>               // for RAND_bytes
#include <stdio.h>                      // for fprintf, printf, NULL, etc
#include <stdlib.h>                     // for free, exit
#include <string.h>                     // for strcmp, strdup, strlen, etc

const char *prog_name = "picocoin";
struct bp_hashtab *settings;
const struct chain_info *chain = NULL;
bu256_t chain_genesis;
uint64_t instance_nonce;
bool debugging = false;
FILE *plog = NULL;


static struct blkdb db;
static unsigned int net_conn_timeout = 60;
struct wallet *cur_wallet;

static const char *const_settings[] = {
	"net.connect.timeout=11",
	"wallet=picocoin.wallet",
	"chain=bitcoin",
	"peers=picocoin.peers",
	"blkdb=picocoin.blkdb",
};

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
	unsigned int	iter_count;
};

static void list_setting_iter(void *key_, void *value_, void *lsi_)
{
	char *key = key_;
	char *value = value_;
	struct lsi_info *lsi = lsi_;

	printf("  \"%s\": \"%s\"%s\n",
	       key,
	       value,
	       lsi->iter_count == (lsi->table_len - 1) ? "" : ",");

	lsi->iter_count++;
}

static void list_settings(void)
{
	struct lsi_info lsi = { bp_hashtab_size(settings), };

	printf("{\n");

	bp_hashtab_iter(settings, list_setting_iter, &lsi);

	printf("}\n");
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
		fprintf(plog, "chain-set: unknown chain '%s'\n", name);
		exit(1);
	}

	bu256_t new_genesis;
	if (!hex_bu256(&new_genesis, new_chain->genesis_hash)) {
		fprintf(plog, "chain-set: invalid genesis hash %s\n",
			new_chain->genesis_hash);
		exit(1);
	}

	chain = new_chain;
	bu256_copy(&chain_genesis, &new_genesis);
}

static void print_help()
{
	const char *settings[] = {
		"config","Pathname to the configuration file.",
		"wallet","Pathname to the wallet file.",
		"chain","One of 'bitcoin' or 'testnet3', use with chain-set command.",
		"debug","Enable debugging output",
	};

	const char *commands[] = {
		"chain-set","Select blockchain and network.",
		"dns-seeds","Query and display bitcoin DNS seeds.",
		"list-settings","Display settings map.",
		"new-address","Generate a new address and output it. Store pair in wallet.",
		"new-wallet","Initialize a new wallet. Refuses to initialize if the file exists.",
		"netsync","\tSynchronize with the network, sending and receiving payments.",
		"wallet-addr","List all address in the wallet.",
		"wallet-dump","Dump entire wallet contents, including private keys.",
		"wallet-info","Print informational summary of wallet data."
	};

	fprintf(stderr, "usage: %s <command|setting> [<command|setting>...]",
			prog_name);
	fprintf(stderr, "\n\nsettings, list in the form key=value:\n\n");
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(settings); i += 2)
		fprintf(stderr, "\t%s\t%s\n", settings[i], settings[i+1]);
	fprintf(stderr, "\ncommands:\n\n");
	for (i = 0; i < ARRAY_SIZE(commands); i += 2)
		fprintf(stderr, "\t%s\t%s\n", commands[i], commands[i+1]);
}

static bool is_command(const char *s)
{
	return	!strcmp(s, "chain-set") ||
		!strcmp(s, "dns-seeds") ||
		!strcmp(s, "help") ||
		!strcmp(s, "list-settings") ||
		!strcmp(s, "new-address") ||
		!strcmp(s, "new-wallet") ||
		!strcmp(s, "netsync") ||
		!strcmp(s, "version") ||
		!strcmp(s, "wallet-addr") ||
		!strcmp(s, "wallet-dump") ||
		!strcmp(s, "wallet-info")
		;
}

static void init_peers(struct net_child_info *nci)
{
	/*
	 * read network peers
	 */
	struct peer_manager *peers;
    peerman_debug(debugging);

	peers = peerman_read(setting("peers"));
	if (!peers) {
		fprintf(plog, "%s: initializing empty peer list\n", prog_name);

		peers = peerman_seed(setting("no_dns") == NULL ? true : false);
		if (!peerman_write(peers, setting("peers"), chain)) {
			fprintf(plog, "%s: failed to write peer list\n", prog_name);
			exit(1);
		}
	}

	char *addnode = setting("addnode");
	if (addnode)
		peerman_addstr(peers, addnode);

	peerman_sort(peers);

	if (debugging)
		fprintf(plog, "%s: have %u/%zu peers\n",
            prog_name,
			bp_hashtab_size(peers->map_addr),
			clist_length(peers->addrlist));

	nci->peers = peers;
}

static void init_blkdb(void)
{
	if (!blkdb_init(&db, chain->netmagic, &chain_genesis)) {
		fprintf(plog, "%s: blkdb init failed\n", prog_name);
		exit(1);
	}

	char *blkdb_fn = setting("blkdb");
	if (!blkdb_fn)
		return;

	if ((access(blkdb_fn, F_OK) == 0) &&
	    !blkdb_read(&db, blkdb_fn)) {
		fprintf(plog, "%s: blkdb read failed\n", prog_name);
		exit(1);
	}

	db.fd = open(blkdb_fn,
		     O_WRONLY | O_APPEND | O_CREAT | O_LARGEFILE, 0666);
	if (db.fd < 0) {
		fprintf(plog, "%s: blkdb file open failed: %s\n", prog_name, strerror(errno));
		exit(1);
	}

    if (debugging)
		fprintf(plog, "%s: blkdb opened\n", prog_name);
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
//	memset(nci, 0, sizeof(*nci));
	nci->read_fd = -1;
	nci->write_fd = -1;
	nci->db = &db;
	nci->conns = parr_new(NC_MAX_CONN, NULL);
	nci->eb = event_base_new();
	nci->net_conn_timeout = net_conn_timeout;
	nci->chain = chain;
	nci->instance_nonce = &instance_nonce;
	nci->running = false;
	nci->debugging = debugging;
	nci->plog = plog;
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

	struct net_engine *neteng = neteng_new_start(network_child, debugging, plog);

	if (debugging)
		fprintf(plog, "net: engine started. sleeping %d %s (cxn tmout %u sec)\n",
			(nsec > 60) ? nsec/60 : nsec,
			(nsec > 60) ? "minutes" : "seconds",
			net_conn_timeout);

	sleep(nsec);

	neteng_free(neteng);
}

static bool do_command(const char *s)
{
	if (!strcmp(s, "chain-set"))
		chain_set();

	else if (!strcmp(s, "dns-seeds"))
		list_dns_seeds();

	else if (!strcmp(s, "help"))
		print_help();

	else if (!strcmp(s, "list-settings"))
		list_settings();

	else if (!strcmp(s, "new-address"))
		cur_wallet_new_address();

	else if (!strcmp(s, "new-wallet"))
		cur_wallet_create();

	else if (!strcmp(s, "netsync"))
		network_sync();

	else if (!strcmp(s, "version"))
		printf("version=%s\n", VERSION);

	else if (!strcmp(s, "wallet-addr"))
		cur_wallet_addresses();

	else if (!strcmp(s, "wallet-info"))
		cur_wallet_info();

	else if (!strcmp(s, "wallet-dump"))
		cur_wallet_dump();

	return true;
}

int main (int argc, char *argv[])
{
	prog_name = argv[0];
	plog = stderr;
	settings = bp_hashtab_new_ext(czstr_hash, czstr_equal,
				      free, free);

	if (!preload_settings())
		return 1;
	chain_set();

	RAND_bytes((unsigned char *)&instance_nonce, sizeof(instance_nonce));

	bool done_command = false;
	unsigned int arg;
	for (arg = 1; arg < argc; arg++) {
		const char *argstr = argv[arg];
		if (is_command(argstr)) {
			done_command = true;
			if (!do_command(argstr))
				return 1;
		} else {
			if (!do_setting(argstr))
				return 1;
		}
	}

	if (!done_command)
		do_command("help");
	return 0;
}
