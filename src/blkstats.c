/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <argp.h>
#include <glib.h>
#include <openssl/ripemd.h>
#include <ccoin/coredefs.h>
#include <ccoin/base58.h>
#include <ccoin/buffer.h>
#include <ccoin/key.h>
#include <ccoin/core.h>
#include <ccoin/util.h>
#include <ccoin/mbr.h>
#include <ccoin/script.h>
#include <ccoin/addr_match.h>
#include <ccoin/message.h>

const char *argp_program_version = PACKAGE_VERSION;

static struct argp_option options[] = {
	{ "blocks", 'b', "FILE", 0,
	  "Load blockchain data from mkbootstrap-produced FILE.  Default filename \"blocks.dat\"." },

	{ "no-decimal", 'N', NULL, 0,
	  "Print values as integers (satoshis), not decimal numbers" },

	{ "quiet", 'q', NULL, 0,
	  "Silence informational messages" },

	{ }
};

static const char doc[] =
"blkstats - command line interface to scan blocks and generate statistics";

static char *blocks_fn = "blocks.dat";
static bool opt_quiet = false;
static bool opt_decimal = true;

static error_t parse_opt (int key, char *arg, struct argp_state *state);

static const struct argp argp = { options, parse_opt, NULL, doc };

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {

	case 'b':
		blocks_fn = arg;
		break;
	case 'N':
		opt_decimal = false;
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

static void scan_txout(struct bp_txout *txout)
{
	// FIXME
}

static void scan_tx(struct bp_tx *tx)
{
	unsigned int i;
	for (i = 0; i < tx->vout->len; i++) {
		struct bp_txout *txout;

		txout = g_ptr_array_index(tx->vout, i);

		scan_txout(txout);
	}
}

static void scan_block(unsigned int height, struct bp_block *block)
{
	unsigned int n;
	for (n = 0; n < block->vtx->len; n++) {
		struct bp_tx *tx;

		tx = g_ptr_array_index(block->vtx, n);

		scan_tx(tx);
	}
}

static void scan_decode_block(unsigned int height, struct p2p_message *msg,
			      uint64_t *fpos)
{
	struct bp_block block;
	bp_block_init(&block);

	struct const_buffer buf = { msg->data, msg->hdr.data_len };

	bool rc = deser_bp_block(&block, &buf);
	if (!rc) {
		fprintf(stderr, "block deser failed at height %u\n", height);
		exit(1);
	}

	scan_block(height, &block);

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

	unsigned int height = 0;
	uint64_t fpos = 0;

	block_fd = fd;

	while (fread_block(fd, &msg, &read_ok)) {
		scan_decode_block(height, &msg, &fpos);
		height++;

		if ((height % 10000 == 0) && (!opt_quiet))
			fprintf(stderr, "Scanned at height %u\n",
				height);
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


