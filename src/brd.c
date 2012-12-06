/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <openssl/rand.h>
#include <ccoin/core.h>
#include <ccoin/util.h>
#include <ccoin/buint.h>
#include <ccoin/blkdb.h>
#include "brd.h"

GHashTable *settings;
const struct chain_info *chain = NULL;
bu256_t chain_genesis;
uint64_t instance_nonce;
bool debugging = false;
FILE *plog = NULL;

struct blkdb db;
int blocks_fd;

static const char *const_settings[] = {
	"net.connect.timeout=11",
	"chain=bitcoin",
	"peers=brd.peers",
	"blkdb=brd.blkdb",
	"blocks=brd.blocks",
	"log=-", /* "log=brd.log", */
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

	if (!strcmp(key, "debug"))
		debugging = true;

	else if (!strcmp(key, "config") || !strcmp(key, "c"))
		return read_config_file(value);

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

static void init_log(void)
{
	char *log_fn = setting("log");
	if (!log_fn || !strcmp(log_fn, "-"))
		plog = stdout;
	else {
		plog = fopen(log_fn, "a");
		if (!plog) {
			perror(log_fn);
			exit(1);
		}
	}
}

static void init_blkdb(void)
{
	if (!blkdb_init(&db, chain->netmagic, &chain_genesis)) {
		fprintf(plog, "blkdb init failed\n");
		exit(1);
	}

	char *blkdb_fn = setting("blkdb");
	if ((access(blkdb_fn, F_OK) == 0) &&
	    !blkdb_read(&db, blkdb_fn)) {
		fprintf(plog, "blkdb read failed\n");
		exit(1);
	}

	db.fd = open(blkdb_fn,
		     O_WRONLY | O_APPEND | O_CREAT | O_LARGEFILE, 0666);
	if (db.fd < 0) {
		fprintf(plog, "blkdb file open failed: %s\n", strerror(errno));
		exit(1);
	}
}

static void init_blocks(void)
{
	char *blocks_fn = setting("blocks");
	blocks_fd = open(blocks_fn, O_RDWR | O_CREAT | O_LARGEFILE, 0666);
	if (blocks_fd < 0) {
		fprintf(plog, "blocks file open failed: %s\n", strerror(errno));
		exit(1);
	}
}

static void init_daemon(void)
{
	init_log();
	init_blkdb();
	init_blocks();
	/* TODO: verify that blocks file offsets are present in blkdb */
}

int main (int argc, char *argv[])
{
	settings = g_hash_table_new_full(g_str_hash, g_str_equal,
					 g_free, g_free);

	if (!preload_settings())
		return 1;
	chain_set();

	RAND_bytes((unsigned char *)&instance_nonce, sizeof(instance_nonce));

	unsigned int arg;
	for (arg = 1; arg < argc; arg++) {
		const char *argstr = argv[arg];
		if (!do_setting(argstr))
			return 1;
	}

	init_daemon();
	// run();

	return 0;
}

