/* Copyright 2016 Bloq, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <ccoin/net/netbase.h>
#include "libtest.h"

static void test_addr_str(void)
{
	static const unsigned char v6addr[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
	static const unsigned char v4addr[16] = "\0\0\0\0\0\0\0\0\0\0\xff\xff\x01\x02\x03\x04";

	char host[64];
	bn_address_str(host, sizeof(host), v6addr);
	assert(strcmp(host, "::1") == 0);

	bn_address_str(host, sizeof(host), v4addr);
	assert(strcmp(host, "1.2.3.4") == 0);
}

int main (int argc, char *argv[])
{
	test_addr_str();
	return 0;
}
