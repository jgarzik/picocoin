/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <ccoin/blkdb.h>
#include <ccoin/coredefs.h>
#include <ccoin/buint.h>
#include <ccoin/buffer.h>
#include <ccoin/util.h>
#include "libtest.h"

static void add_header(struct blkdb *db, char *raw)
{
	struct const_buffer buf = { raw, 80 };

	struct blkinfo *bi = bi_new();
	assert(bi != NULL);

	assert(deser_bp_block(&bi->hdr, &buf) == true);

	bp_block_calc_sha256(&bi->hdr);

	bu256_copy(&bi->hash, &bi->hdr.sha256);

	struct blkdb_reorg reorg;

	assert(blkdb_add(db, bi, &reorg) == true);

	assert(reorg.conn == 1);
	assert(reorg.disconn == 0);
}

static void read_headers(const char *ser_base_fn, struct blkdb *db)
{
	char *filename = test_filename(ser_base_fn);
	int fd = file_seq_open(filename);
	assert(fd >= 0);

	char hdrbuf[80];

	while (read(fd, hdrbuf, 80) == 80) {
		add_header(db, hdrbuf);
	}

	close(fd);
	free(filename);
}

static void test_blkinfo_prev(struct blkdb *db)
{
	struct blkinfo *tmp = db->best_chain;
	int height = db->best_chain->height;

	while (tmp) {
		assert(height == tmp->height);

		height--;
		tmp = tmp->prev;
	}

	assert(height == -1);
}

static void runtest(const char *ser_base_fn, const struct chain_info *chain,
		    unsigned int check_height, const char *check_hash)
{
	struct blkdb db;

	bu256_t block0;
	bool rc = hex_bu256(&block0, chain->genesis_hash);
	assert(rc);

	rc = blkdb_init(&db, chain->netmagic, &block0);
	assert(rc);

	read_headers(ser_base_fn, &db);

	assert(db.best_chain->height == check_height);

	bu256_t best_block;
	rc = hex_bu256(&best_block, check_hash);

	assert(bu256_equal(&db.best_chain->hash, &best_block));

	test_blkinfo_prev(&db);

	blkdb_free(&db);
}

int main (int argc, char *argv[])
{
	runtest("hdr193000.ser", &chain_metadata[CHAIN_BITCOIN], 193000,
	    "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317");
	runtest("tn_hdr35141.ser", &chain_metadata[CHAIN_TESTNET3], 35141,
	    "0000000000dde6ce4b9ad1e2a5be59f1b7ace6ef8d077d846263b0bfbc984f7f");

	return 0;
}

