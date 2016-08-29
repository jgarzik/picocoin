/* Copyright 2016 Bloq, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <string.h>
#include <assert.h>
#include <ccoin/coredefs.h>

static void test_chain_find(void)
{
	const struct chain_info *main_chain, *test_chain, *tmp_chain;

	main_chain = chain_find("bitcoin");
	assert(main_chain != NULL);

	assert(main_chain == chain_find_by_netmagic(main_chain->netmagic));

	test_chain = chain_find("testnet3");
	assert(test_chain != NULL);

	assert(test_chain == chain_find_by_netmagic(test_chain->netmagic));

	tmp_chain = chain_find("jeffcoin");
	assert(tmp_chain == NULL);
}

int main (int argc, char *argv[])
{
	test_chain_find();

	return 0;
}

