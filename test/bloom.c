/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <string.h>
#include <assert.h>
#include <openssl/sha.h>
#include <ccoin/bloom.h>
#include "libtest.h"

static const char *data1 = "foo";
static const char *data2 = "bar";

static void runtest (void)
{
	unsigned char md1[SHA256_DIGEST_LENGTH];
	unsigned char md2[SHA256_DIGEST_LENGTH];

	SHA256((unsigned char *)data1, strlen(data1), md1);
	SHA256((unsigned char *)data2, strlen(data2), md2);

	struct bloom bloom;

	assert(bloom_init(&bloom, 1000, 0.001) == true);

	bloom_insert(&bloom, md1, sizeof(md1));

	assert(bloom_contains(&bloom, md1, sizeof(md1)) == true);
	assert(bloom_contains(&bloom, md2, sizeof(md2)) == false);

	cstring *ser = cstr_new_sz(1024);
	ser_bloom(ser, &bloom);

	struct bloom bloom2;
	__bloom_init(&bloom2);

	struct const_buffer buf = { ser->str, ser->len };

	assert(deser_bloom(&bloom2, &buf) == true);

	assert(bloom.nHashFuncs == bloom2.nHashFuncs);
	assert(bloom.vData->len == bloom2.vData->len);
	assert(memcmp(bloom.vData->str, bloom2.vData->str, bloom2.vData->len) == 0);

	assert(bloom_contains(&bloom2, md1, sizeof(md1)) == true);
	assert(bloom_contains(&bloom2, md2, sizeof(md2)) == false);

	bloom_free(&bloom2);

	bloom_free(&bloom);

	cstr_free(ser, true);
}

int main (int argc, char *argv[])
{
	runtest();

	return 0;
}
