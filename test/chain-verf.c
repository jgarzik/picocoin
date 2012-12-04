#include "picocoin-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <ccoin/coredefs.h>
#include <ccoin/message.h>
#include <ccoin/mbr.h>
#include <ccoin/blkdb.h>
#include <ccoin/script.h>
#include <ccoin/util.h>
#include "libtest.h"

static bool spend_tx(struct bp_utxo_set *uset, const struct bp_tx *tx,
		     unsigned int tx_idx, unsigned int height)
{
	assert(tx->sha256_valid == true);

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

#if 0
			if (!bp_verify_sig(coin, tx, i,
				/* SCRIPT_VERIFY_P2SH */ 0, 0))
				return false;
#endif

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

	assert(bp_utxo_from_tx(coin, tx, is_coinbase, height) == true);

	/* add unspent outputs to set */
	bp_utxo_set_add(uset, coin);

	return true;
}

static bool spend_block(struct bp_utxo_set *uset, const struct bp_block *block,
			unsigned int height)
{
	unsigned int i;

	if (height % 10000 == 0)
		fprintf(stderr, "chain-verf: spend block @ %u\n", height);

	for (i = 0; i < block->vtx->len; i++) {
		struct bp_tx *tx;

		tx = g_ptr_array_index(block->vtx, i);
		if (!spend_tx(uset, tx, i, height)) {
			char hexstr[BU256_STRSZ];
			bu256_hex(hexstr, &tx->sha256);
			fprintf(stderr, 
				"chain-verf: tx fail %s\n", hexstr);
			return false;
		}
	}

	return true;
}

static void read_test_msg(struct blkdb *db, struct bp_utxo_set *uset,
			  const struct p2p_message *msg, int64_t fpos)
{
	assert(strncmp(msg->hdr.command, "block",
		       sizeof(msg->hdr.command)) == 0);

	struct bp_block block;
	bp_block_init(&block);

	struct const_buffer buf = { msg->data, msg->hdr.data_len };
	assert(deser_bp_block(&block, &buf) == true);
	bp_block_calc_sha256(&block);

	assert(bp_block_valid(&block) == true);

	struct blkinfo *bi = bi_new();
	bu256_copy(&bi->hash, &block.sha256);
	bp_block_copy_hdr(&bi->hdr, &block);
	bi->n_file = 0;
	bi->n_pos = fpos + P2P_HDR_SZ;

	assert(blkdb_add(db, bi) == true);

	/* if best chain, mark TX's as spent */
	if (bu256_equal(&db->hashBestChain, &bi->hdr.sha256)) {
		if (!spend_block(uset, &block, bi->height)) {
			char hexstr[BU256_STRSZ];
			bu256_hex(hexstr, &bi->hdr.sha256);
			fprintf(stderr, 
				"chain-verf: block fail %u %s\n",
				bi->height, hexstr);
			assert(!"spend_block");
		}
	}

	bp_block_free(&block);
}

static void runtest(bool use_testnet, const char *blocks_fn)
{
	const struct chain_info *chain =
		&chain_metadata[use_testnet ? CHAIN_TESTNET3 : CHAIN_BITCOIN];

	struct blkdb blkdb;
	bu256_t blk0;

	hex_bu256(&blk0, chain->genesis_hash);
	assert(blkdb_init(&blkdb, chain->netmagic, &blk0) == true);

	struct bp_utxo_set uset;
	bp_utxo_set_init(&uset);

	fprintf(stderr, "chain-verf: validating %s chainfile %s\n",
		use_testnet ? "testnet3" : "mainnet",
		blocks_fn);

	int fd = file_seq_open(blocks_fn);
	if (fd < 0) {
		perror(blocks_fn);
		assert(fd >= 0);
	}

	struct p2p_message msg = {};
	bool read_ok = true;
	int64_t fpos = 0;
	unsigned int records = 0;
	while (fread_message(fd, &msg, &read_ok)) {
		assert(memcmp(msg.hdr.netmagic, chain->netmagic, 4) == 0);

		read_test_msg(&blkdb, &uset, &msg, fpos);

		fpos += P2P_HDR_SZ;
		fpos += msg.hdr.data_len;
		records++;
	}

	assert(read_ok == true);

	close(fd);
	free(msg.data);

	blkdb_free(&blkdb);
	bp_utxo_set_free(&uset);

	fprintf(stderr, "chain-verf: %u records validated\n", records);
}

int main (int argc, char *argv[])
{
	char *fn;
	unsigned int verfd = 0;

	fn = getenv("TEST_TESTNET3_VERF");
	if (fn) {
		verfd++;
		runtest(true, fn);
	}

	fn = getenv("TEST_MAINNET_VERF");
	if (fn) {
		verfd++;
		runtest(false, fn);
	}

	if (!verfd) {
		fprintf(stderr,
	"chain-verf: Skipping lengthy, extended chain verification test.\n"
	"chain-verf: Set TEST_TESTNET3_VERF and/or TEST_MAINNET_VERF to a\n"
	"chain-verf: valid pynode blocks.dat file, to enable.\n"
	"chain-verf: (a linear sequence of P2P \"block\" messages)\n"
			);
		return 77;
	}
	
	return 0;
}
