/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <stdbool.h>
#include <assert.h>
#include <ccoin/checkpoints.h>
#include <ccoin/util.h>

static const struct bp_checkpoint bp_ck_main[] = {
        { 11111, "0x0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"},
        { 33333, "0x000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6"},
        { 74000, "0x0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20"},
        {105000, "0x00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97"},
        {134444, "0x00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe"},
        {168000, "0x000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763"},
        {193000, "0x000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317"},
};

static const struct bp_checkpoint bp_ck_testnet3[] = {
        { 546, "000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70" },
};

const struct bp_checkpoint_set bp_ckpts[] = {
	[CHAIN_BITCOIN] =
	{ CHAIN_BITCOIN, ARRAY_SIZE(bp_ck_main), bp_ck_main },

	[CHAIN_TESTNET3] =
	{ CHAIN_TESTNET3, ARRAY_SIZE(bp_ck_testnet3), bp_ck_testnet3 },

	{}
};

bool bp_ckpt_block(enum chains chain, unsigned int height, const bu256_t *hash)
{
	assert(chain <= CHAIN_LAST);
	const struct bp_checkpoint_set *ckset = &bp_ckpts[chain];
	unsigned int i;

	for (i = 0; i < ckset->ckpt_len; i++) {
		if (ckset->ckpts[i].height == height) {
			bu256_t tmp;
			bool rc = hex_bu256(&tmp, ckset->ckpts[i].hashstr);
			assert(rc == true);

			if (!bu256_equal(&tmp, hash))
				return false;
		}
	}

	return true;
}

unsigned int bp_ckpt_last(enum chains chain)
{
	assert(chain <= CHAIN_LAST);
	const struct bp_checkpoint_set *ckset = &bp_ckpts[chain];
	return ckset->ckpts[ckset->ckpt_len - 1].height;
}

