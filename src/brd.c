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
#include <assert.h>
#include <openssl/rand.h>
#include <ccoin/core.h>
#include <ccoin/util.h>
#include <ccoin/buint.h>
#include <ccoin/blkdb.h>
#include <ccoin/message.h>
#include <ccoin/mbr.h>
#include <ccoin/script.h>
#include "brd.h"

GHashTable *settings;
const struct chain_info *chain = NULL;
bu256_t chain_genesis;
uint64_t instance_nonce;
bool debugging = false;
FILE *plog = NULL;

static struct blkdb db;
static struct bp_utxo_set uset;
static int blocks_fd = -1;
static bool script_verf = false;


static const char *const_settings[] = {
	"net.connect.timeout=11",
	"chain=bitcoin",
	"peers=brd.peers",
	/* "blkdb=brd.blkdb", */
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
	if (!blkdb_fn)
		return;

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
	if (!blocks_fn)
		return;

	blocks_fd = open(blocks_fn, O_RDWR | O_CREAT | O_LARGEFILE, 0666);
	if (blocks_fd < 0) {
		fprintf(plog, "blocks file open failed: %s\n", strerror(errno));
		exit(1);
	}
}

static bool spend_tx(struct bp_utxo_set *uset, const struct bp_tx *tx,
		     unsigned int tx_idx, unsigned int height)
{
	bool is_coinbase = (tx_idx == 0);

	struct bp_utxo *coin;

	int64_t total_in = 0, total_out = 0;

	unsigned int i;

	/* verify and spend this transaction's inputs */
	if (!is_coinbase) {
		for (i = 0; i < tx->vin->len; i++) {
			struct bp_txin *txin;
			struct bp_txout *txout;

			txin = g_ptr_array_index(tx->vin, i);

			coin = bp_utxo_lookup(uset, &txin->prevout.hash);
			if (!coin || !coin->vout)
				return false;

			if (coin->is_coinbase &&
			    ((coin->height + COINBASE_MATURITY) > height))
				return false;

			txout = NULL;
			if (txin->prevout.n >= coin->vout->len)
				return false;
			txout = g_ptr_array_index(coin->vout, txin->prevout.n);
			total_in += txout->nValue;

			if (script_verf &&
			    !bp_verify_sig(coin, tx, i,
						/* SCRIPT_VERIFY_P2SH */ 0, 0))
				return false;

			if (!bp_utxo_spend(uset, &txin->prevout))
				return false;
		}
	}

	for (i = 0; i < tx->vout->len; i++) {
		struct bp_txout *txout;

		txout = g_ptr_array_index(tx->vout, i);
		total_out += txout->nValue;
	}

	if (!is_coinbase) {
		if (total_out > total_in)
			return false;
	}

	/* copy-and-convert a tx into a UTXO */
	coin = calloc(1, sizeof(*coin));
	bp_utxo_init(coin);

	if (!bp_utxo_from_tx(coin, tx, is_coinbase, height))
		return false;

	/* add unspent outputs to set */
	bp_utxo_set_add(uset, coin);

	return true;
}

static bool spend_block(struct bp_utxo_set *uset, const struct bp_block *block,
			unsigned int height)
{
	unsigned int i;

	for (i = 0; i < block->vtx->len; i++) {
		struct bp_tx *tx;

		tx = g_ptr_array_index(block->vtx, i);
		if (!spend_tx(uset, tx, i, height)) {
			char hexstr[BU256_STRSZ];
			bu256_hex(hexstr, &tx->sha256);
			fprintf(plog, "brd: spent_block tx fail %s\n", hexstr);
			return false;
		}
	}

	return true;
}

static bool read_block_msg(struct p2p_message *msg, int64_t fpos)
{
	/* unknown records are invalid */
	if (strncmp(msg->hdr.command, "block",
		    sizeof(msg->hdr.command)))
		return false;

	bool rc = false;

	struct bp_block block;
	bp_block_init(&block);

	struct const_buffer buf = { msg->data, msg->hdr.data_len };
	if (!deser_bp_block(&block, &buf)) {
		fprintf(plog, "brd: block deser fail\n");
		goto out;
	}
	bp_block_calc_sha256(&block);

	if (!bp_block_valid(&block)) {
		fprintf(plog, "brd: block not valid\n");
		goto out;
	}

	struct blkinfo *bi = bi_new();
	bu256_copy(&bi->hash, &block.sha256);
	bp_block_copy_hdr(&bi->hdr, &block);
	bi->n_file = 0;
	bi->n_pos = fpos;

	struct blkdb_reorg reorg;

	if (!blkdb_add(&db, bi, &reorg)) {
		fprintf(plog, "brd: blkdb add fail\n");
		goto out;
	}

	assert(reorg.conn == 1);
	assert(reorg.disconn == 0);

	/* if best chain, mark TX's as spent */
	if (bu256_equal(&db.best_chain->hash, &bi->hdr.sha256)) {
		if (!spend_block(&uset, &block, bi->height)) {
			char hexstr[BU256_STRSZ];
			bu256_hex(hexstr, &bi->hdr.sha256);
			fprintf(plog,
				"brd: block fail %u %s\n",
				bi->height, hexstr);
			goto out;
		}
	}

	rc = true;

out:
	/* TODO: leak bi on err? */
	bp_block_free(&block);
	return rc;
}

static void read_blocks(void)
{
	int fd = blocks_fd;

	struct p2p_message msg = {};
	bool read_ok = true;
	int64_t fpos = 0;
	while (fread_message(fd, &msg, &read_ok)) {
		if (memcmp(msg.hdr.netmagic, chain->netmagic, 4)) {
			fprintf(plog, "blocks file: invalid network magic\n");
			exit(1);
		}

		if (!read_block_msg(&msg, fpos))
			exit(1);

		fpos += P2P_HDR_SZ;
		fpos += msg.hdr.data_len;
	}

	if (!read_ok) {
		fprintf(plog, "blocks file: read failed\n");
		exit(1);
	}

	free(msg.data);
}

static void readprep_blocks_file(void)
{
	/* if no blk index, but blocks are present, read and index
	 * all block data (several gigabytes)
	 */
	if (blocks_fd >= 0) {
		if (db.fd < 0)
			read_blocks();
		else {
			/* TODO: verify that blocks file offsets are
			 * present in blkdb */

			if (lseek(blocks_fd, 0, SEEK_END) == (off_t)-1) {
				fprintf(plog, "blocks file: seek failed: %s\n",
					strerror(errno));
				exit(1);
			}
		}
	}
}

static void init_daemon(void)
{
	init_log();
	init_blkdb();
	bp_utxo_set_init(&uset);
	init_blocks();
	readprep_blocks_file();
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

