
#include "picocoin-config.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <glib.h>

const char *prog_name = "picocoin";
GHashTable *settings;

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

static void parse_settings(int argc, char **argv)
{
	unsigned int i;
	char *key, *value;

	for (i = 1; i < argc; i++) {

		if (!parse_kvstr(argv[i], &key, &value))
			continue;

		g_hash_table_replace(settings, key, value);
	}

	char *cfg_fn = g_hash_table_lookup(settings, "cfg");
	if (!cfg_fn)
		return;

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
	g_hash_table_foreach(settings, list_setting_iter, NULL);
}

int main (int argc, char *argv[])
{
	prog_name = argv[0];
	settings = g_hash_table_new_full(g_str_hash, g_str_equal,
					 g_free, g_free);

	parse_settings(argc, argv);

	list_settings();

	return 0;
}

