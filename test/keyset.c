/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <assert.h>                     // for assert
#include <string.h>                     // for NULL, memset

#include <ccoin/crypto/ripemd160.h>     // for RIPEMD160_DIGEST_LENGTH
#include <ccoin/crypto/sha2.h>          // for sha256_Raw
#include <ccoin/key.h>                  // for bpks_lookup, bp_key, etc
#include <ccoin/util.h>                 // for ARRAY_SIZE, bu_Hash160
#include "libtest.h"

static void keytest_secp256k1()
{
	secp256k1_context *secp_ctx = secp256k1_context_create(
		SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN
	);

	{
		uint8_t test_private_key[32];
		memset(test_private_key, 0, sizeof(test_private_key));
		assert(!secp256k1_ec_seckey_verify(secp_ctx, test_private_key));

		test_private_key[31] = 0x1;
		assert(secp256k1_ec_seckey_verify(secp_ctx, test_private_key));
	}

	secp256k1_context_destroy(secp_ctx);
}

static void keytest()
{
	{
		struct bp_key k;
		bp_key_init(&k);
		bp_key_free(&k);
	}

	// Signature

	{
		const uint8_t test_secret[32] = { 0x1 };
		const uint8_t test_data[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
		bu256_t hash;
		sha256_Raw(test_data, sizeof(test_data), (uint8_t *)&hash);

		void *pub = NULL;
		size_t publen = 0;
		void *sig = NULL;
		size_t siglen = 0;

		struct bp_key k;
		bp_key_init(&k);
		assert(bp_key_secret_set(&k, test_secret, sizeof(test_secret)));
		assert(bp_pubkey_get(&k, &pub, &publen));
		assert(NULL != pub);
		assert(0 != publen);

		assert(bp_sign(&k, (uint8_t *)&hash, sizeof(hash), &sig, &siglen));
		assert(NULL != sig);
		assert(0 != siglen);
		bp_key_free(&k);

		struct bp_key pubk;
		bp_key_init(&k);
		assert(bp_pubkey_set(&pubk, pub, publen));
		assert(bp_verify(&pubk, (uint8_t *)&hash, sizeof(hash), sig, siglen));

		bp_key_free(&k);
		free(pub);
		free(sig);
	}
}

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

	for (i = 0; i < ARRAY_SIZE(keys); i++) {
		struct bp_key *key = &keys[i];
		bp_key_free(key);
	}
}

int main (int argc, char *argv[])
{
	keytest_secp256k1();
	keytest();
	runtest();

	bp_key_static_shutdown();
	return 0;
}
