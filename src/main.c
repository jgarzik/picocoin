/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif
#include <ctype.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include "picocoin.h"
#include <ccoin/coredefs.h>
#include "wallet.h"
#include <ccoin/core.h>
#include <ccoin/util.h>
#include <ccoin/hashtab.h>
#include <ccoin/net.h>
#include <ccoin/compat.h>		/* for strndup */

const char *prog_name = "picocoin";
struct bp_hashtab *settings;
struct wallet *cur_wallet;
const struct chain_info *chain = NULL;
bu256_t chain_genesis;
uint64_t instance_nonce;
bool debugging = false;

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
		fprintf(stderr, "chain-set: unknown chain '%s'\n", name);
		exit(1);
	}

	bu256_t new_genesis;
	if (!hex_bu256(&new_genesis, new_chain->genesis_hash)) {
		fprintf(stderr, "chain-set: invalid genesis hash %s\n",
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

