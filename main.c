
#include "picocoin-config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netdb.h>
#include <ctype.h>
#include <glib.h>
#include "picocoin.h"
#include "coredefs.h"
#include "wallet.h"

const char *prog_name = "picocoin";
GHashTable *settings;
struct wallet *cur_wallet;
const char ipv4_mapped_pfx[12] = "\0\0\0\0\0\0\0\0\0\0\xff\xff";
const unsigned char netmagic_main[4] = NETMAGIC_MAINNET;

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

		g_hash_table_replace(settings, key, value);
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

	g_hash_table_replace(settings, key, value);

	/*
	 * trigger special setting-specific behaviors
	 */

	if (!strcmp(key, "config") || !strcmp(key, "c"))
		return read_config_file(value);

	/* clear previous wallet, if new wallet file seen */
	if (!strcmp(key, "wallet") || !strcmp(key, "w"))
		cur_wallet_free();

	return true;
}

static const char *const_settings[] = {
	"wallet=picocoin.wallet",
};

static bool preload_settings(void)
{
	unsigned int i;

	/* preload static settings */
	for (i = 0; i < ARRAY_SIZE(const_settings); i++)
		if (!do_setting(const_settings[i]))
			return false;
	
	return true;
}

static void list_setting_iter(gpointer key_, gpointer value_, gpointer dummy)
{
	char *key = key_;
	char *value = value_;

	printf("%s=%s\n", key, value);
}

static void list_settings(void)
{
	printf("=SETTINGS\n");
	g_hash_table_foreach(settings, list_setting_iter, NULL);
	printf("=END_SETTINGS\n");
}

static void list_dns_seeds(void)
{
	GList *tmp, *addrlist = get_dns_seed_addrs();

	printf("=DNS_SEEDS\n");

	for (tmp = addrlist; tmp != NULL; tmp = tmp->next) {
		struct p2p_addr *addr = tmp->data;
		char host[64];
		bool is_ipv4 = is_ipv4_mapped(addr->ip);

		if (is_ipv4) {
			struct sockaddr_in saddr;

			memset(&saddr, 0, sizeof(saddr));
			saddr.sin_family = AF_INET;
			memcpy(&saddr.sin_addr, &addr->ip[12], 4);

			getnameinfo((struct sockaddr *) &saddr, sizeof(saddr),
				    host, sizeof(host),
				    NULL, 0, NI_NUMERICHOST);
		} else {
			struct sockaddr_in6 saddr;

			memset(&saddr, 0, sizeof(saddr));
			saddr.sin6_family = AF_INET6;
			memcpy(&saddr.sin6_addr, &addr->ip, 16);

			getnameinfo((struct sockaddr *) &saddr, sizeof(saddr),
				    host, sizeof(host),
				    NULL, 0, NI_NUMERICHOST);
		}

		printf("v%c %s %u %llu\n",
		       is_ipv4 ? '4' : '6',
		       host,
		       addr->port,
		       (unsigned long long) addr->nServices);
	}

	g_list_free_full(addrlist, g_free);

	printf("=END_DNS_SEEDS\n");
}

static bool is_command(const char *s)
{
	return	!strcmp(s, "dns-seeds") ||
		!strcmp(s, "list-settings") ||
		!strcmp(s, "new-address") ||
		!strcmp(s, "new-wallet") ||
		!strcmp(s, "netsync") ||
		!strcmp(s, "wallet-addr") ||
		!strcmp(s, "wallet-info")
		;
}

static bool do_command(const char *s)
{
	if (!strcmp(s, "dns-seeds"))
		list_dns_seeds();

	else if (!strcmp(s, "list-settings"))
		list_settings();

	else if (!strcmp(s, "new-address"))
		wallet_new_address();

	else if (!strcmp(s, "new-wallet"))
		wallet_create();

	else if (!strcmp(s, "netsync"))
		network_sync();

	else if (!strcmp(s, "wallet-addr"))
		wallet_addresses();

	else if (!strcmp(s, "wallet-info"))
		wallet_info();

	return true;
}

int main (int argc, char *argv[])
{
	prog_name = argv[0];
	settings = g_hash_table_new_full(g_str_hash, g_str_equal,
					 g_free, g_free);
	if (!preload_settings())
		return 1;

	unsigned int arg;
	for (arg = 1; arg < argc; arg++) {
		const char *argstr = argv[arg];
		if (is_command(argstr)) {
			if (!do_command(argstr))
				return 1;
		} else {
			if (!do_setting(argstr))
				return 1;
		}
	}

	return 0;
}

