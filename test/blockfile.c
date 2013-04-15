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
#include <ccoin/message.h>
#include <ccoin/mbr.h>
#include <ccoin/buffer.h>
#include <ccoin/util.h>
#include "libtest.h"

static void handle_block(struct p2p_message *msg)
{
	struct bp_block block;
	bp_block_init(&block);

	struct const_buffer buf = { msg->data, msg->hdr.data_len };

	bool rc = deser_bp_block(&block, &buf);
	assert(rc);

	bp_block_free(&block);
}

static void runtest(const char *ser_fn_base)
{
	char *ser_fn = test_filename(ser_fn_base);
	int fd = file_seq_open(ser_fn);
	if (fd < 0) {
		perror(ser_fn);
		exit(1);
	}

	struct p2p_message msg = {};
	bool read_ok = false;

	unsigned int n_blocks = 0;

	while (fread_block(fd, &msg, &read_ok)) {
		n_blocks++;
		handle_block(&msg);
	}

	assert(read_ok == true);
	assert(n_blocks == 11);

	close(fd);
	free(msg.data);
	free(ser_fn);
}

int main (int argc, char *argv[])
{
	runtest("blks10.ser");

	return 0;
}
