/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <jansson.h>
#include <ccoin/message.h>
#include <ccoin/mbr.h>
#include <ccoin/util.h>
#include "libtest.h"

static void runtest(const char *json_fn_base, const char *ser_fn_base)
{
	char *fn = test_filename(json_fn_base);
	json_t *meta = read_json(fn);
	assert(json_is_object(meta));

	char *ser_fn = test_filename(ser_fn_base);
	int fd = file_seq_open(ser_fn);
	if (fd < 0) {
		perror(ser_fn);
		exit(1);
	}

	struct p2p_message msg = {};
	bool read_ok = false;
	bool rc = fread_message(fd, &msg, &read_ok);
	assert(rc);
	assert(read_ok);
	assert(!strncmp(msg.hdr.command, "block", 12));

	close(fd);

	const char *hashstr = json_string_value(json_object_get(meta, "hash"));
	assert(hashstr != NULL);

	unsigned int size = json_integer_value(json_object_get(meta, "size"));
	assert((24 + msg.hdr.data_len) == size);

	struct bp_block block;
	bp_block_init(&block);

	struct const_buffer buf = { msg.data, msg.hdr.data_len };

	rc = deser_bp_block(&block, &buf);
	assert(rc);

	cstring *gs = cstr_new_sz(100000);
	ser_bp_block(gs, &block);

	if (gs->len != msg.hdr.data_len) {
		fprintf(stderr, "gs->len %ld, msg.hdr.data_len %u\n",
			(long)gs->len, msg.hdr.data_len);
		assert(gs->len == msg.hdr.data_len);
	}
	assert(memcmp(gs->str, msg.data, msg.hdr.data_len) == 0);

	bp_block_calc_sha256(&block);

	char hexstr[BU256_STRSZ];
	bu256_hex(hexstr, &block.sha256);

	if (strcmp(hexstr, hashstr)) {
		fprintf(stderr, "block: wanted hash %s,\n       got    hash %s\n",
			hashstr, hexstr);
		assert(!strcmp(hexstr, hashstr));
	}

	rc = bp_block_valid(&block);
	assert(rc);

	bp_block_free(&block);
	cstr_free(gs, true);
	free(msg.data);
	free(fn);
	free(ser_fn);
	json_decref(meta);
}

int main (int argc, char *argv[])
{
	runtest("blk0.json", "blk0.ser");
	runtest("blk120383.json", "blk120383.ser");

	return 0;
}
