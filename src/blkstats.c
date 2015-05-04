/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <argp.h>
#include <ccoin/coredefs.h>
#include <ccoin/buffer.h>
#include <ccoin/core.h>
#include <ccoin/util.h>
#include <ccoin/mbr.h>
#include <ccoin/script.h>
#include <ccoin/message.h>

const char *argp_program_version = PACKAGE_VERSION;

static struct argp_option options[] = {
	{ "blocks", 'b', "FILE", 0,
	  "Load blockchain data from mkbootstrap-produced FILE.  Default filename \"blocks.dat\"." },

	{ "quiet", 'q', NULL, 0,
	  "Silence informational messages" },

	{ }
};

static const char doc[] =
"blkstats - command line interface to scan blocks and generate statistics";

static char *blocks_fn = "blocks.dat";
static bool opt_quiet = false;

enum stat_type {
	STA_BLOCK,
	STA_TX,
	STA_TXOUT,
	STA_MULTISIG,
	STA_OP_DROP,
	STA_OP_RETURN,
	STA_PUBKEY,
	STA_PUBKEYHASH,
	STA_SCRIPTHASH,
	STA_UNKNOWN,

	STA_LAST = STA_UNKNOWN
};

static const char *stat_names[STA_LAST + 1] = {
	"block",
	"tx",
	"txout",
	"multisig",
	"op_drop",
	"op_return",
	"pubkey",
	"pubkeyhash",
	"scripthash",
	"unknown",
};

static unsigned long gbl_stats[STA_LAST + 1];

static inline void incstat(enum stat_type stype)
{
	gbl_stats[stype]++;
}

static inline unsigned long getstat(enum stat_type stype)
{
	return gbl_stats[stype];
}

static error_t parse_opt (int key, char *arg, struct argp_state *state);

static const struct argp argp = { options, parse_opt, NULL, doc };

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {

	case 'b':
		blocks_fn = arg;
		break;
	case 'q':
		opt_quiet = true;
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static int block_fd = -1;

static bool match_op_pos(parr *script, enum opcodetype opcode,
			 unsigned int pos)
{
	if (pos >= script->len)
		return false;
	
	struct bscript_op *op = parr_idx(script, pos);
	return (op->op == opcode);
}

static void scan_txout(struct bp_txout *txout)
{
	incstat(STA_TXOUT);

	parr *script = bsp_parse_all(txout->scriptPubKey->str,
					  txout->scriptPubKey->len);
	if (!script) {
		fprintf(stderr, "error at txout %lu\n", getstat(STA_TXOUT)-1);
		return;
	}

	enum txnouttype outtype = bsp_classify(script);

	switch (outtype) {
	case TX_PUBKEY:
		incstat(STA_PUBKEY);
		break;
	case TX_PUBKEYHASH:
		incstat(STA_PUBKEYHASH);
		break;
	case TX_SCRIPTHASH:
		incstat(STA_SCRIPTHASH);
		break;
	case TX_MULTISIG:
		incstat(STA_MULTISIG);
		break;
	default: {
		if (match_op_pos(script, OP_RETURN, 0))
			incstat(STA_OP_RETURN);
		else if (match_op_pos(script, OP_DROP, 1))
			incstat(STA_OP_DROP);
		else
			incstat(STA_UNKNOWN);
		break;
	 }
	}

	parr_free(script, true);
}

static void scan_tx(struct bp_tx *tx)
{
	unsigned int i;
	for (i = 0; i < tx->vout->len; i++) {
		struct bp_txout *txout;

		txout = parr_idx(tx->vout, i);

		scan_txout(txout);
	}

	incstat(STA_TX);
}

static void scan_block(struct bp_block *block)
{
	unsigned int n;
	for (n = 0; n < block->vtx->len; n++) {
		struct bp_tx *tx;

		tx = parr_idx(block->vtx, n);

		scan_tx(tx);
	}

	incstat(STA_BLOCK);
}

static void scan_decode_block(struct p2p_message *msg, uint64_t *fpos)
{
	struct bp_block block;
	bp_block_init(&block);

	struct const_buffer buf = { msg->data, msg->hdr.data_len };

	bool rc = deser_bp_block(&block, &buf);
	if (!rc) {
		fprintf(stderr, "block deser failed at block %lu\n",
			getstat(STA_BLOCK));
		exit(1);
	}

	scan_block(&block);

	uint64_t pos_tmp = msg->hdr.data_len;
	*fpos += (pos_tmp + 8);

	bp_block_free(&block);
}

static void scan_blocks(void)
{
	int fd = file_seq_open(blocks_fn);
	if (fd < 0) {
		perror(blocks_fn);
		exit(1);
	}

	struct p2p_message msg = {};
	bool read_ok = false;

	uint64_t fpos = 0;

	block_fd = fd;

	while (fread_block(fd, &msg, &read_ok)) {
		scan_decode_block(&msg, &fpos);

		if ((getstat(STA_BLOCK) % 10000 == 0) && (!opt_quiet))
			fprintf(stderr, "Scanned block %lu\n",
				getstat(STA_BLOCK));
	}

	block_fd = -1;

	if (!read_ok) {
		fprintf(stderr, "block read %s failed\n", blocks_fn);
		exit(1);
	}

	close(fd);
	free(msg.data);
}

static void show_report(void)
{
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(gbl_stats); i++)
		printf("%lu %s\n",
		       getstat(i),
		       stat_names[i]);
}

int main (int argc, char *argv[])
{
	error_t aprc;

	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, "argp_parse failed: %s\n", strerror(aprc));
		return 1;
	}

	scan_blocks();
	show_report();

	return 0;
}


