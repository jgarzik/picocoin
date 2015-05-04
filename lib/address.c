/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <openssl/ripemd.h>
#include <ccoin/address.h>
#include <ccoin/base58.h>
#include <ccoin/util.h>
#include <ccoin/cstr.h>

cstring *bp_pubkey_get_address(struct bp_key *key, unsigned char addrtype)
{
	void *pubkey = NULL;
	size_t pk_len = 0;

	bp_pubkey_get(key, &pubkey, &pk_len);

	unsigned char md160[RIPEMD160_DIGEST_LENGTH];

	bu_Hash160(md160, pubkey, pk_len);

	free(pubkey);

	cstring *btc_addr = base58_encode_check(addrtype, true,
						md160, sizeof(md160));

	return btc_addr;
}

