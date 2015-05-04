/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <string.h>
#include <assert.h>
#include <ccoin/util.h>
#include <ccoin/net.h>

static const char *s_a = "12345";
static const char *s_b = "54321";

static void test_reverse_copy(void)
{
	size_t a_len = strlen(s_a);
	char buf[a_len + 1];

	bu_reverse_copy((unsigned char *)buf, (unsigned char *)s_a, a_len);
	buf[a_len] = 0;

	assert(!strcmp(s_b, buf));
}

static const char *addr1 = "\0\0\0\0\0\0\0\0\0\0\xff\xff\x1\x2\x3\x4";
static const char *addr2 = "\0\0\x32\0\0\0\0\0\0\0\xff\xff\x1\x2\x3\x4";

static void test_ipv4_mapped(void)
{
	bool rc = is_ipv4_mapped((const unsigned char *)addr1);
	assert(rc);

	rc = is_ipv4_mapped((const unsigned char *)addr2);
	assert(!rc);
}

static const struct {
	int64_t		v;
	const char	*s;
} btcdec_valstr[] = {
	{ 0LL, "0.0" },
	{ 1LL, "0.00000001" },
	{ 1000000LL, "0.01" },
	{ 100000000LL, "1.0" },
	{ 2000000000LL, "20.0" },
};

static void test_btc_decimal(int64_t v, const char *s)
{
	char valstr[128];

	btc_decimal(valstr, sizeof(valstr), v);

	if (strcmp(valstr, s)) {
		fprintf(stderr, "util: conv(%lld) yielded %s, expected %s\n",
			(long long) v,
			valstr,
			s);

		assert(!strcmp(valstr, s));
	}
}

static void test_btc_decimals(void)
{
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(btcdec_valstr); i++)
		test_btc_decimal(btcdec_valstr[i].v,
				 btcdec_valstr[i].s);
}

int main (int argc, char *argv[])
{
	test_reverse_copy();
	test_ipv4_mapped();
	test_btc_decimals();
	return 0;
}

