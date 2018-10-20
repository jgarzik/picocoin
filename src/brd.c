/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"           // for VERSION, _LARGE_FILES, etc

#include "brd.h"
#include <ccoin/db/chaindb.h>           // for blkinfo, chaindb, etc
#include <ccoin/db/db.h>                // for blockdb_add, blockdb_init, etc
#include <ccoin/buffer.h>               // for const_buffer, buffer_copy, etc
#include <ccoin/clist.h>                // for clist_length
#include <ccoin/core.h>                 // for bp_block, bp_utxo, bp_tx, etc
#include <ccoin/coredefs.h>             // for chain_info, chain_find, etc
#include <ccoin/crypto/prng.h>          // for prng_get_random_bytes
#include <ccoin/cstr.h>                 // for cstring, cstr_free
#include <ccoin/hexcode.h>              // for decode_hex
#include <ccoin/log.h>                  // for log_info, logging, etc
#include <ccoin/mbr.h>                  // for fread_message
#include <ccoin/message.h>              // for p2p_message, etc
#include <ccoin/net/net.h>              // for net_child_info, nc_conns_gc, etc
#include <ccoin/net/peerman.h>          // for peer_manager, peerman_write, etc
#include <ccoin/parr.h>                 // for parr, parr_idx, parr_free, etc
#include <ccoin/script.h>               // for bp_verify_sig
#include <ccoin/util.h>                 // for ARRAY_SIZE, czstr_equal, etc

#include <assert.h>                     // for assert
#include <stdbool.h>                    // for false, bool, true
#include <ctype.h>                      // for isspace
#include <errno.h>                      // for errno
#include <event2/event.h>               // for event_base_dispatch, etc
#include <fcntl.h>                      // for open
#include <signal.h>                     // for signal, SIG_IGN, SIGHUP, etc
#include <stddef.h>                     // for NULL, size_t
#include <stdio.h>                      // for fclose, fopen, ferror, etc
#include <stdlib.h>                     // for exit, free, calloc
#include <string.h>                     // for strcmp, strlen, strdup, etc
#include <sys/uio.h>                    // for iovec, writev
#include <unistd.h>                     // for for access, F_OK

#if defined(__GNUC__)
/* For add_orphan */
# pragma GCC diagnostic ignored "-Wunused-function"
#endif

const char *prog_name = "brd";
struct bp_hashtab *settings;
const struct chain_info *chain = NULL;
bu256_t chain_genesis;
uint64_t instance_nonce;
struct logging *log_state;
bool debugging = false;

static char *peer_filename = NULL;
static struct chaindb db;
static struct bp_hashtab *orphans;
static struct bp_utxo_set uset;
static bool script_verf = false;
static unsigned int net_conn_timeout = 11;
struct net_child_info global_nci;

static const char *const_settings[] = {
	"net.connect.timeout=11",
	"chain=bitcoin",
	"log=-", /* "log=brd.log", */
};

static bool block_process(const struct bp_block *block);
static bool have_orphan(const bu256_t *v);
static bool add_orphan(const bu256_t *hash_in, struct const_buffer *buf_in);

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
		log_error("chain-set: unknown chain '%s'", name);
		exit(1);
	}

	bu256_t new_genesis;
	if (!hex_bu256(&new_genesis, new_chain->genesis_hash)) {
		log_error("chain-set: invalid genesis hash %s",
			new_chain->genesis_hash);
		exit(1);
	}

	chain = new_chain;
	bu256_copy(&chain_genesis, &new_genesis);
}

static void init_log(void)
{
	log_state = calloc(0, sizeof(struct logging));

	char *log_fn = setting("log");
	if (!log_fn || !strcmp(log_fn, "-"))
		log_state->stream = stdout;
	else {
		log_state->stream = fopen(log_fn, "a");
		if (!log_state->stream) {
			perror(log_fn);
			exit(1);
		}
	}

	setvbuf(log_state->stream, NULL, _IONBF, BUFSIZ);

	if ( log_state->stream != stdout && log_state->stream != stderr )
		log_state->logtofile = true;

	log_state->debug = debugging;

}

static void init_chaindb(void)
{
	char hexstr[BU256_STRSZ];

	if (!chaindb_init(&db, chain->netmagic, &chain_genesis)) {
		log_info("%s: chaindb initialisation failed", prog_name);
		exit(1);
	}

    log_debug("%s: Initialised chaindb", prog_name);
}

static void init_db(void)
{
	if (!metadb_init(chain->netmagic, &chain_genesis) ||
		!blockdb_init() ||
		!blockheightdb_init())
		{
		log_error("%s: db initialisation failed", prog_name);
		exit(1);
	}

}
static const char *genesis_bitcoin =
"0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
static const char *genesis_testnet =
"0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae180101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

static void init_block0(void)
{
	const char *genesis_hex = NULL;

	switch (chain->chain_id) {
	case CHAIN_BITCOIN:
		genesis_hex = genesis_bitcoin;
		break;
	case CHAIN_TESTNET3:
		genesis_hex = genesis_testnet;
		break;
	default:
		log_info("%s: unsupported chain. add genesis block here!", prog_name);
		exit(1);
		break;
	}

	size_t olen = 0;
	size_t genesis_rawlen = strlen(genesis_hex) / 2;
	char genesis_raw[genesis_rawlen];
	if (!decode_hex(genesis_raw, sizeof(genesis_raw), genesis_hex, &olen)) {
		log_error("%s: chain hex decode fail", prog_name);
		exit(1);
	}

	init_db();

	struct const_buffer buf0 = { genesis_raw, genesis_rawlen };
	if (blockdb_add(&chain_genesis, &buf0)) {
		log_info("%s: Genesis block written to block database", prog_name);
		blockheightdb_add(0, &chain_genesis);
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

			txin = parr_idx(tx->vin, i);

			coin = bp_utxo_lookup(uset, &txin->prevout.hash);
			if (!coin || !coin->vout)
				return false;

			if (coin->is_coinbase &&
			    ((coin->height + COINBASE_MATURITY) > height))
				return false;

			txout = NULL;
			if (txin->prevout.n >= coin->vout->len)
				return false;
			txout = parr_idx(coin->vout, txin->prevout.n);
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

		txout = parr_idx(tx->vout, i);
		total_out += txout->nValue;
	}

	if (!is_coinbase) {
		if (total_out > total_in)
			return false;
	}

	/* copy-and-convert a tx into a UTXO */
	coin = calloc(1, sizeof(*coin));
	bp_utxo_init(coin);

	if (!bp_utxo_from_tx(coin, tx, is_coinbase, height)) {
		bp_utxo_freep(coin);
		return false;
	}

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

		tx = parr_idx(block->vtx, i);
		if (!spend_tx(uset, tx, i, height)) {
			char hexstr[BU256_STRSZ];
			bu256_hex(hexstr, &tx->sha256);
			log_error("%s: spent_block tx fail %s", prog_name, hexstr);
			return false;
		}
	}

	return true;
}

static bool block_process(const struct bp_block *block)
{
	struct blkinfo *bi = bi_new();
	bu256_copy(&bi->hash, &block->sha256);
	bp_block_copy_hdr(&bi->hdr, block);
	char hexstr[BU256_STRSZ];
	bu256_hex(hexstr, &bi->hash);

	struct chaindb_reorg reorg;

	if (!chaindb_add(&db, bi, &reorg)) {
		log_debug("%s: Adding block %s to chaindb failed", prog_name, hexstr);
		goto err_out;
	}

	/* FIXME: support reorg */
	assert(reorg.conn == 1);
	assert(reorg.disconn == 0);

	/* if best chain, mark TX's as spent */
	if (bu256_equal(&db.best_chain->hash, &bi->hdr.sha256)) {
		if (!spend_block(&uset, block, bi->height)) {
			bu256_hex(hexstr, &bi->hdr.sha256);
			log_info("%s: block spend fail %u %s",
				prog_name,
				bi->height, hexstr);
			/* FIXME: bad record is now in chaindb */
			goto err_out;
		}
	}

	return true;

err_out:
	bi_free(bi);
	return false;
}

static bool read_block(void *p, size_t len)
{
	bool rc = false;

	struct bp_block block;
	bp_block_init(&block);
	struct const_buffer buf = { p, len };
	if (!deser_bp_block(&block, &buf)) {
		log_error("%s: block deser fail", prog_name);
		goto out;
	}
	bp_block_calc_sha256(&block);

	if (!bp_block_valid(&block)) {
		log_info("%s: block not valid", prog_name);
		goto out;
	}

	/* used at runtime */
	bool		sha256_valid;
	bu256_t		sha256;
	rc = block_process(&block);

out:
	bp_block_free(&block);
	return rc;
}

static void init_orphans(void)
{
	orphans = bp_hashtab_new_ext(bu256_hash, bu256_equal_,
				     bu256_freep, buffer_freep);
}

static bool have_orphan(const bu256_t *v)
{
	return bp_hashtab_get(orphans, v);
}

static bool add_orphan(const bu256_t *hash_in, struct const_buffer *buf_in)
{
	if (have_orphan(hash_in))
		return false;

	bu256_t *hash = bu256_new(hash_in);
	if (!hash) {
		log_info("%s: OOM", prog_name);
		return false;
	}

	struct buffer *buf = buffer_copy(buf_in->p, buf_in->len);
	if (!buf) {
		bu256_freep(hash);
		log_info("%s: OOM", prog_name);
		return false;
	}

	bp_hashtab_put(orphans, hash, buf);

	return true;
}

static void init_peers(struct net_child_info *nci)
{
	/*
	 * read network peers
	 */
	struct peer_manager *peers;

	peers = peerman_read(peer_filename);
	if (!peers) {
		log_info("%s: initializing empty peer list", prog_name);

		peers = peerman_seed(setting("no_dns") == NULL ? true : false);
		if (!peerman_write(peers, peer_filename, chain)) {
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

static bool inv_block_process(bu256_t *hash)
{
    return (!chaindb_lookup(&db, hash) &&
			    !have_orphan(hash));
}

static bool add_block(struct bp_block *block, struct const_buffer *buf)
{
    /* check for duplicate block */
    if (chaindb_lookup(&db, &block->sha256) ||
        have_orphan(&block->sha256))
        return true;

	blockdb_add(&block->sha256, buf);
    /* process block */
    if (!block_process(block))
        return false;

    return true;

}

static void init_nci(struct net_child_info *nci)
{
	memset(nci, 0, sizeof(*nci));
	nci->read_fd = -1;
	nci->write_fd = -1;
	init_peers(nci);
    nci->db = &db;
    nci->conns = parr_new(NC_MAX_CONN, NULL);
	nci->eb = event_base_new();
    nci->inv_block_process = inv_block_process;
	nci->block_process = add_block;
	nci->net_conn_timeout = net_conn_timeout;
    nci->chain = chain;
    nci->instance_nonce = &instance_nonce;
	nci->running = true;
}

static void init_daemon(struct net_child_info *nci)
{
	init_chaindb();
	bp_utxo_set_init(&uset);
	init_block0();
	init_orphans();
	blockheightdb_getall(read_block);
	init_nci(nci);
}

static void run_daemon(struct net_child_info *nci)
{
	/* main loop */
	do {
		nc_conns_process(nci);
		event_base_dispatch(nci->eb);
	} while (nci->running);
}

static void shutdown_nci(struct net_child_info *nci)
{
	peerman_free(nci->peers);
	nc_conns_gc(nci, true);
	assert(nci->conns->len == 0);
	parr_free(nci->conns, true);
	event_base_free(nci->eb);
}

static void shutdown_daemon(struct net_child_info *nci)
{
	bool rc = peerman_write(nci->peers, peer_filename, chain);
	log_info("%s: %s %u/%zu peers", prog_name,
		rc ? "wrote" : "failed to write",
		bp_hashtab_size(nci->peers->map_addr),
		clist_length(nci->peers->addrlist));

	db_close();

	if (log_state->logtofile) {
		fclose(log_state->stream);
		log_state->stream = NULL;
	}
	free(log_state);

	if (setting("free")) {
		shutdown_nci(nci);
		bp_hashtab_unref(orphans);
		bp_hashtab_unref(settings);
		chaindb_free(&db);
		bp_utxo_set_free(&uset);
	}
}

static void term_signal(int signo)
{
	global_nci.running = false;
	event_base_loopbreak(global_nci.eb);
}

int main (int argc, char *argv[])
{
	settings = bp_hashtab_new_ext(czstr_hash, czstr_equal,
				      free, free);

	if (!preload_settings())
		return 1;

	if (prng_get_random_bytes((unsigned char *)&instance_nonce, sizeof(instance_nonce)) < 0) {
		fprintf(stderr, "brd: no random data available\n");
		return 1;
	};

	unsigned int arg;
	for (arg = 1; arg < argc; arg++) {
		const char *argstr = argv[arg];
		if (!do_setting(argstr))
			return 1;
	}

	init_log();
	chain_set();

	char peer_filename_tmp[strlen(chain->name) + 6 + 1];
	snprintf(peer_filename_tmp, sizeof(peer_filename_tmp), "%s.peers", chain->name);
	peer_filename = peer_filename_tmp;

	/*
	 * properly capture TERM and other signals
	 */
	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, term_signal);
	signal(SIGTERM, term_signal);

	init_daemon(&global_nci);
	run_daemon(&global_nci);

	log_info("%s: daemon exiting", prog_name);

	shutdown_daemon(&global_nci);

	return 0;
}
