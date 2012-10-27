
#include "picocoin-config.h"

#include <openssl/ripemd.h>
#include <glib.h>
#include "address.h"
#include "base58.h"
#include "util.h"

GString *bp_pubkey_get_address(struct bp_key *key, unsigned char addrtype)
{
	void *pubkey = NULL;
	size_t pk_len = 0;

	bp_pubkey_get(key, &pubkey, &pk_len);

	unsigned char md160[RIPEMD160_DIGEST_LENGTH];

	bu_Hash160(md160, pubkey, pk_len);

	free(pubkey);

	GString *btc_addr = base58_address_encode(addrtype,
						  md160, sizeof(md160));

	return btc_addr;
}

