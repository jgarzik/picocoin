/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <openssl/sha.h>

#include <ccoin/util.h>
#include <ccoin/hexcode.h>

#include "libtest.h"

#define RANDOM_DATA_SHA1SUM "18833691a6d0ad9c481dcbc6d0da0d3245d7c627"

void *data = NULL;
size_t data_len = 0;

static void test_read(const char *filename)
{
	bool rc = bu_read_file(filename, &data, &data_len, 100);
	assert(!rc);
	assert(data == NULL);
	assert(data_len == 0);

	rc = bu_read_file(filename, &data, &data_len, 100 * 1024 * 1024);
	assert(rc);
	assert(data != NULL);
	assert(data_len == 8193);

	unsigned char md[SHA_DIGEST_LENGTH];
	SHA1(data, data_len, md);

	char hexstr[(SHA_DIGEST_LENGTH * 2) + 1];
	encode_hex(hexstr, md, SHA_DIGEST_LENGTH);

	assert(strcmp(hexstr, RANDOM_DATA_SHA1SUM) == 0);
}

static void test_write(const char *filename)
{
	bool rc = bu_write_file(filename, data, data_len);
	assert(rc == true);

	void *data2 = NULL;
	size_t data2_len = 0;
	rc = bu_read_file(filename, &data2, &data2_len, 100 * 1024 * 1024);
	assert(rc == true);
	assert(data_len == data2_len);
	assert(memcmp(data, data2, data2_len) == 0);

	int rcv = unlink(filename);
	assert(rcv == 0);

	free(data2);
}

int main (int argc, char *argv[])
{
	char *filename = test_filename("random.data");
	const char *w_filename = "fileio.out";

	test_read(filename);
	test_write(w_filename);

	free(filename);

	free(data);

	return 0;
}
