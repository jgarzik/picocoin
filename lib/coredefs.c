/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <string.h>
#include <ccoin/coredefs.h>
#include <ccoin/util.h>

const struct chain_info chain_metadata[] = {
	[CHAIN_BITCOIN] = {
		CHAIN_BITCOIN, "bitcoin",
		PUBKEY_ADDRESS, SCRIPT_ADDRESS,
		"\xf9\xbe\xb4\xd9",
	"0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	},

	[CHAIN_TESTNET3] = {
		CHAIN_TESTNET3, "testnet3",
		PUBKEY_ADDRESS_TEST, SCRIPT_ADDRESS_TEST,
		"\x0b\x11\x09\x07",
	"0x000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
	},
};

const struct chain_info *chain_find(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(chain_metadata); i++) {
		const struct chain_info *chain;

		chain = &chain_metadata[i];
		if (!chain->name || !chain->genesis_hash)
			continue;

		if (!strcmp(name, chain->name))
			return chain;
	}

	return NULL;
}

const struct chain_info *chain_find_by_netmagic(unsigned char netmagic[4])
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(chain_metadata); i++) {
		const struct chain_info *chain;

		chain = &chain_metadata[i];
		if (!chain->name || !chain->genesis_hash)
			continue;

		if (!memcmp(netmagic, chain->netmagic, 4))
			return chain;
	}

	return NULL;
}
