/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <string.h>
#include <assert.h>
#include <ccoin/util.h>

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

int main (int argc, char *argv[])
{
	test_reverse_copy();
	test_ipv4_mapped();
	return 0;
}

