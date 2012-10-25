
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

const char *prog_name = "picocoin";
GHashTable *settings;
const char ipv4_mapped_pfx[12] = "\0\0\0\0\0\0\0\0\0\0\xff\xff";

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

static void const_setting(const char *key_, const char *value_)
{
	char *key = strdup(key_);
	char *value = strdup(value_);
	g_hash_table_replace(settings, key, value);
}

static const struct {
	const char	*k;
	const char	*v;
} const_settings[] = {
	{ "wallet", "picocoin.wallet" },
};

static void parse_settings(int argc, char **argv)
{
	unsigned int i;
	char *key, *value;

	/* preload static settings */
	for (i = 0; i < ARRAY_SIZE(const_settings); i++)
		const_setting(const_settings[i].k, const_settings[i].v);

	/* read settings from command line */
	for (i = 1; i < argc; i++) {

		if (!parse_kvstr(argv[i], &key, &value))
			continue;

		g_hash_table_replace(settings, key, value);
	}

	/* read settings from configuration file */
	char *cfg_fn = setting("config");
	if (!cfg_fn) {
		cfg_fn = setting("c");
		if (!cfg_fn)
			return;
	}

	FILE *cfg = fopen(cfg_fn, "r");
	if (!cfg)
		return;
	
	char line[1024];
	while (fgets(line, sizeof(line), cfg) != NULL) {
		if (line[0] == '#')
			continue;
		while (line[0] && (isspace(line[strlen(line) - 1])))
			line[strlen(line) - 1] = 0;

		if (!parse_kvstr(line, &key, &value))
			continue;

		g_hash_table_replace(settings, key, value);
	}

	fclose(cfg);
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

int main (int argc, char *argv[])
{
	prog_name = argv[0];
	settings = g_hash_table_new_full(g_str_hash, g_str_equal,
					 g_free, g_free);

	parse_settings(argc, argv);

	if (setting("list-settings"))
		list_settings();
	if (setting("dns-seeds"))
		list_dns_seeds();

	return 0;
}

