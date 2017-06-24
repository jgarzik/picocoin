/* Copyright 2016 Bloq, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include <stdio.h>
#include <assert.h>
#include <ccoin/mbr.h>
#include <ccoin/util.h>
#include "libtest.h"

static void testit(const char *ser_fn_base)
{
	char *ser_fn = test_filename(ser_fn_base);
	void *data = NULL;
	size_t data_len = 0;

	bool rc = bu_read_file(ser_fn, &data, &data_len, 10*1000*1000);
	assert(rc == true);

	struct const_buffer buf = { data, data_len };

	struct mbuf_reader mbr;
	mbr_init(&mbr, &buf);

	rc = mbr_read(&mbr);
	assert(rc == true);
	assert(mbr.eof == false);
	assert(mbr.error == false);

	assert(!strncmp(mbr.msg.hdr.command, "block", 12));

	rc = mbr_read(&mbr);
	assert(rc == false);
	assert(mbr.eof == true);
	assert(mbr.error == false);

	mbr_free(&mbr);
	free(data);
	free(ser_fn);
}

int main (int argc, char *argv[])
{
	testit("data/blk120383.ser");
	return 0;
}

