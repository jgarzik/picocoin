/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <ccoin/hexcode.h>

static const char *data = "chitty chitty bang bang\x1\x2\x3\x4";
static size_t data_len;

static char *hexstr;

static void test_encode1(void)
{
	const char *data1 = "\xf1\x1f";
	size_t data1_len = strlen(data1);

	size_t alloc_len = (data_len * 2) + 1000;
	char *hexstr1 = malloc(alloc_len);
	memset(hexstr1, 0xef, alloc_len);

	encode_hex(hexstr1, data1, data1_len);

	assert(strcmp(hexstr1, "f11f") == 0);

	free(hexstr1);
}

static void test_encode2(void)
{
	size_t alloc_len = (data_len * 2) + 1000;
	hexstr = malloc(alloc_len);
	memset(hexstr, 0xef, alloc_len);

	encode_hex(hexstr, data, data_len);

	assert(strlen(hexstr) == (data_len * 2));

	assert((unsigned char)hexstr[(data_len * 2) + 1] == 0xef);
}

static void test_decode(void)
{
	char decode_buf[(data_len * 2) + 1000];
	memset(decode_buf, 0xef, sizeof(decode_buf));

	size_t out_len = 0;
	bool rc = decode_hex(decode_buf, 10, hexstr, &out_len);
	assert(!rc);
	assert(out_len == 0);

	memset(decode_buf, 0xef, sizeof(decode_buf));
	rc = decode_hex(decode_buf, sizeof(decode_buf), hexstr, &out_len);
	assert(rc);
	assert(out_len == data_len);
	assert(memcmp(data, decode_buf, out_len) == 0);
	assert((unsigned char)decode_buf[out_len] == 0xef);
}

static void test_decode2(void)
{
	cstring *s = hex2str(hexstr);
	assert(s != NULL);
	assert(s->len == data_len);
	assert(memcmp(s->str, data, data_len) == 0);

	cstr_free(s, true);
}

int main (int argc, char *argv[])
{
	data_len = strlen(data);
	test_encode1();
	test_encode2();
	test_decode();
	test_decode2();
	return 0;
}

