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
#include "libtest.h"

static void add_header(struct blkdb *db, char *raw)
{
	struct const_buffer buf = { raw, 80 };

	struct blkinfo *bi = bi_new();
	assert(bi != NULL);

	assert(deser_bp_block(&bi->hdr, &buf) == true);

	bp_block_calc_sha256(&bi->hdr);

	bu256_copy(&bi->hash, &bi->hdr.sha256);

	assert(blkdb_add(db, bi) == true);
}

static void read_headers(struct blkdb *db)
{
	char *filename = test_filename("hdr193000.ser");
	int fd = open(filename, O_RDONLY);
	assert(fd >= 0);

	char hdrbuf[80];

	while (read(fd, hdrbuf, 80) == 80) {
		add_header(db, hdrbuf);
	}

	close(fd);
}

int main (int argc, char *argv[])
{
	struct blkdb db;

	bu256_t block0;
	bool rc = hex_bu256(&block0,
			    chain_metadata[CHAIN_BITCOIN].genesis_hash);
	assert(rc);

	rc = blkdb_init(&db, chain_metadata[CHAIN_BITCOIN].netmagic, &block0);
	assert(rc);

	read_headers(&db);

	assert(db.nBestHeight == 193000);

	bu256_t block193k;
	rc = hex_bu256(&block193k,
	    "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317");

	assert(bu256_equal(&db.hashBestChain, &block193k));

	blkdb_free(&db);

	return 0;
}
