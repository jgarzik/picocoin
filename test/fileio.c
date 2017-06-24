/* Copyright 2017 Bloq, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include "libtest.h"                    // for test_filename

#include <ccoin/crypto/sha1.h>          // for SHA1_DIGEST_LENGTH, etc
#include <ccoin/hexcode.h>              // for encode_hex
#include <ccoin/util.h>                 // for bu_read_file, bu_write_file, etc

#include <assert.h>                     // for assert
#include <stdio.h>                      // for NULL
#include <stdlib.h>                     // for free
#include <string.h>                     // for memcmp, strcmp
#include <unistd.h>                     // for unlink


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

	unsigned char md[SHA1_DIGEST_LENGTH];
	sha1_Raw(data, data_len, md);

	char hexstr[(SHA1_DIGEST_LENGTH * 2) + 1];
	encode_hex(hexstr, md, SHA1_DIGEST_LENGTH);

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

static void test_misc(void)
{
	int rcv = file_seq_open("does-not-exist");
	assert(rcv < 0);
}

int main (int argc, char *argv[])
{
	char *filename = test_filename("data/random.data");
	const char *w_filename = "fileio.out";

	test_read(filename);
	test_write(w_filename);
	test_misc();

	free(filename);

	free(data);

	return 0;
}
