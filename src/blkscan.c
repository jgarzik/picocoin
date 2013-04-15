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
	{ "addresses", 'a', "FILE", 0,
	  "Load bitcoin addresses from text FILE.  Default filename \"blocks.dat\"." },
	{ "blocks", 'b', "FILE", 0,
	  "Load blockchain data from mkbootstrap-produced FILE.  Default filename \"addresses.txt\"." },

	{ "quiet", 'q', NULL, 0,
	  "Silence informational messages" },

	{ }
};

static const char doc[] =
"blkscan - command line interface to scan blocks";

static char *blocks_fn = "blocks.dat";
static char *address_fn = "addresses.txt";
static bool opt_quiet = false;

static struct bp_keyset bpks;

static error_t parse_opt (int key, char *arg, struct argp_state *state);

static const struct argp argp = { options, parse_opt, NULL, doc };

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {

	case 'a':
		address_fn = arg;
		break;
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

static void load_address(unsigned int line_no, const char *line)
{
	unsigned char addrtype;
	GString *s = base58_decode_check(&addrtype, line);

	if (!s || addrtype != PUBKEY_ADDRESS) {
		fprintf(stderr, "Invalid address on line %d: %s\n", line_no, line);
		exit(1);
	}

	if (s->len != RIPEMD160_DIGEST_LENGTH) {
		fprintf(stderr, "Invalid decoded address length %u on line %d: %s\n",
			(unsigned int) s->len, line_no, line);
		exit(1);
	}

	struct buffer *buf_pkhash = buffer_copy(s->str,RIPEMD160_DIGEST_LENGTH);
	g_hash_table_replace(bpks.pubhash, buf_pkhash, buf_pkhash);

	g_string_free(s, TRUE);
}

static void load_addresses(void)
{
	char line[512];

	FILE *f = fopen(address_fn, "r");
	if (!f) {
		perror(address_fn);
		exit(1);
	}

	unsigned int line_no = 0;

	while (fgets(line, sizeof(line), f) != NULL) {
		line_no++;

		/* trim trailing whitespace */
		while (line[0] && isspace(line[strlen(line) - 1]))
			line[strlen(line) - 1] = 0;

		/* skip blanks and comments */
		if (line[0] == '#' || line[0] == 0)
			continue;

		load_address(line_no, line);
	}

	fclose(f);

	if (!opt_quiet)
		fprintf(stderr, "%d addresses loaded\n",
			g_hash_table_size(bpks.pubhash));
}

static void print_txout(unsigned int i, struct bp_txout *txout)
{
	char valstr[VALSTR_SZ];
	btc_decimal(valstr, VALSTR_SZ, txout->nValue);

	printf("\tOutput %u: %s",
		i, valstr);

	struct bscript_addr addrs;
	if (!bsp_addr_parse(&addrs, txout->scriptPubKey->str,
			    txout->scriptPubKey->len)) {
		printf(" UNPARSEABLE-ADDRESS!\n");
		return;
	}

	if (addrs.pub)
		printf(" SOME-PUBKEYS!");

	struct const_buffer *buf;
	GList *tmp = addrs.pubhash;
	while (tmp) {
		buf = tmp->data;
		tmp = tmp->next;

		GString *addr = base58_encode_check(PUBKEY_ADDRESS, true,
						    buf->p, buf->len);
		if (!addr) {
			printf(" ENCODE-FAILED!\n");
			goto out;
		}

		printf(" %s", addr->str);

		g_string_free(addr, TRUE);
	}

	printf("\n");

out:
        g_list_free_full(addrs.pub, g_buffer_free);
        g_list_free_full(addrs.pubhash, g_buffer_free);
}

static void print_txouts(struct bp_tx *tx)
{
	unsigned int i;
	for (i = 0; i < tx->vout->len; i++) {
		struct bp_txout *txout;

		txout = g_ptr_array_index(tx->vout, i);

		print_txout(i + 1, txout);
	}
}

static unsigned int tx_matches = 0;

static void scan_block(unsigned int height, struct bp_block *block)
{
	unsigned int n;
	for (n = 0; n < block->vtx->len; n++) {
		struct bp_tx *tx;

		tx = g_ptr_array_index(block->vtx, n);

		if (bp_tx_match(tx, &bpks)) {
			char hashstr[BU256_STRSZ];
			bp_tx_calc_sha256(tx);
			bu256_hex(hashstr, &tx->sha256);

			printf("%u, %s\n",
			       block->nTime,
			       hashstr);

			print_txouts(tx);

			tx_matches++;
		}
	}
}

static void scan_decode_block(unsigned int height, struct p2p_message *msg)
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

	while (fread_block(fd, &msg, &read_ok)) {
		scan_decode_block(height, &msg);
		height++;

		if ((height % 25000 == 0) && (!opt_quiet))
			fprintf(stderr, "Scanned height %u\n", height);
	}

	if (!read_ok) {
		fprintf(stderr, "block read %s failed\n", blocks_fn);
		exit(1);
	}

	close(fd);
	free(msg.data);

	if (!opt_quiet) {
		fprintf(stderr, "Scanned to height %u\n", height);
		fprintf(stderr, "TX matches: %u\n", tx_matches);
	}
}

int main (int argc, char *argv[])
{
	error_t aprc;

	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, "argp_parse failed: %s\n", strerror(aprc));
		return 1;
	}

	bpks_init(&bpks);
	load_addresses();
	scan_blocks();

	return 0;
}


