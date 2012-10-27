
#include "picocoin-config.h"

#include <string.h>
#include "coredefs.h"
#include "util.h"

const struct chain_info chain_metadata[] = {
	[CHAIN_BITCOIN] = { CHAIN_BITCOIN, "bitcoin", "\xf9\xbe\xb4\xd9",
	"0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	},

	[CHAIN_TESTNET3] = { CHAIN_TESTNET3, "testnet3", "\x0b\x11\x09\x07",
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
