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
#include "libtest.h"

static void read_test_msg(struct blkdb *db, const struct p2p_message *msg,
			  int64_t fpos)
{
	assert(strncmp(msg->hdr.command, "block",
		       sizeof(msg->hdr.command)) == 0);

	struct bp_block block;
	bp_block_init(&block);

	struct const_buffer buf = { msg->data, msg->hdr.data_len };
	assert(deser_bp_block(&block, &buf) == true);
	bp_block_calc_sha256(&block);

	/* clear transaction list; don't want to load all that into RAM! */
	bp_block_vtx_free(&block);

	struct blkinfo *bi = bi_new();
	bu256_copy(&bi->hash, &block.sha256);
	memcpy(&bi->hdr, &block, sizeof(block));
	bi->n_file = 0;
	bi->n_pos = fpos + P2P_HDR_SZ;

	assert(blkdb_add(db, bi) == true);

	/* note: no bp_block_free(&block), due to memcpy into *bi */
}

static void runtest(bool use_testnet, const char *blocks_fn)
{
	const struct chain_info *chain =
		&chain_metadata[use_testnet ? CHAIN_TESTNET3 : CHAIN_BITCOIN];

	struct blkdb blkdb;
	bu256_t blk0;

	hex_bu256(&blk0, chain->genesis_hash);
	assert(blkdb_init(&blkdb, chain->netmagic, &blk0) == true);

	fprintf(stderr, "chain-verf: validating %s chainfile %s\n",
		use_testnet ? "testnet3" : "mainnet",
		blocks_fn);

	int fd = open(blocks_fn, O_RDONLY);
	if (fd < 0) {
		perror(blocks_fn);
		assert(fd >= 0);
	}

#if _XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L
	posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
#endif

	struct p2p_message msg = {};
	bool read_ok = true;
	int64_t fpos = 0;
	unsigned int records = 0;
	while (fread_message(fd, &msg, &read_ok)) {
		assert(memcmp(msg.hdr.netmagic, chain->netmagic, 4) == 0);

		read_test_msg(&blkdb, &msg, fpos);

		fpos += P2P_HDR_SZ;
		fpos += msg.hdr.data_len;
		records++;
	}

	assert(read_ok == true);

	close(fd);
	free(msg.data);

	blkdb_free(&blkdb);

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
