/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <string.h>
#include <assert.h>
#include <openssl/ripemd.h>
#include <ccoin/key.h>
#include <ccoin/util.h>
#include "libtest.h"

static void runtest(void)
{
	unsigned int i;
	struct bp_key keys[4];

	/* generate keys */
	for (i = 0; i < ARRAY_SIZE(keys); i++) {
		struct bp_key *key = &keys[i];
		assert(bp_key_init(key) == true);
		assert(bp_key_generate(key) == true);
	}

	struct bp_keyset ks;

	bpks_init(&ks);

	/* add all but one to keyset */
	for (i = 0; i < (ARRAY_SIZE(keys) - 1); i++)
		assert(bpks_add(&ks, &keys[i]) == true);

	/* verify all-but-one are in keyset */
	for (i = 0; i < (ARRAY_SIZE(keys) - 1); i++) {
		unsigned char md160[RIPEMD160_DIGEST_LENGTH];
		void *pubkey;
		size_t pklen;

		assert(bp_pubkey_get(&keys[i], &pubkey, &pklen) == true);

		bu_Hash160(md160, pubkey, pklen);

		assert(bpks_lookup(&ks, pubkey, pklen, true) == false);
		assert(bpks_lookup(&ks, pubkey, pklen, false) == true);

		assert(bpks_lookup(&ks, md160, sizeof(md160), true) == true);
		assert(bpks_lookup(&ks, md160, sizeof(md160), false) == false);

		free(pubkey);
	}

	/* verify last key not in keyset */
	{
		unsigned char md160[RIPEMD160_DIGEST_LENGTH];
		void *pubkey;
		size_t pklen;

		struct bp_key *key = &keys[ARRAY_SIZE(keys) - 1];
		assert(bp_pubkey_get(key, &pubkey, &pklen) == true);

		bu_Hash160(md160, pubkey, pklen);

		assert(bpks_lookup(&ks, pubkey, pklen, true) == false);
		assert(bpks_lookup(&ks, pubkey, pklen, false) == false);

		assert(bpks_lookup(&ks, md160, sizeof(md160), true) == false);
		assert(bpks_lookup(&ks, md160, sizeof(md160), false) == false);

		free(pubkey);
	}

	bpks_free(&ks);
}

int main (int argc, char *argv[])
{
	runtest();

	return 0;
}
