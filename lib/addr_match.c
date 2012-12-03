/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <ccoin/core.h>
#include <ccoin/script.h>
#include <ccoin/key.h>
#include <ccoin/addr_match.h>
#include <ccoin/compat.h>		/* for g_ptr_array_new_full */

bool bp_txout_match(const struct bp_txout *txout,
		    const struct bp_keyset *ks)
{
	if (!txout || !txout->scriptPubKey || !ks)
		return false;

	bool rc = false;
	
	struct bscript_addr addrs;
	if (!bsp_addr_parse(&addrs, txout->scriptPubKey->str,
			    txout->scriptPubKey->len))
		return false;

	struct const_buffer *buf;
	GList *tmp = addrs.pub;
	while (tmp) {
		buf = tmp->data;
		tmp = tmp->next;

		if (bpks_lookup(ks, buf->p, buf->len, false)) {
			rc = true;
			goto out;
		}
	}

	tmp = addrs.pubhash;
	while (tmp) {
		buf = tmp->data;
		tmp = tmp->next;

		if (bpks_lookup(ks, buf->p, buf->len, true)) {
			rc = true;
			goto out;
		}
	}

out:
	g_list_free_full(addrs.pub, (GDestroyNotify) buffer_free);
	g_list_free_full(addrs.pubhash, (GDestroyNotify) buffer_free);

	return rc;
}

bool bp_tx_match(const struct bp_tx *tx, const struct bp_keyset *ks)
{
	if (!tx || !tx->vout || !ks)
		return false;

	unsigned int i;
	for (i = 0; i < tx->vout->len; i++) {
		struct bp_txout *txout;

		txout = g_ptr_array_index(tx->vout, i);
		if (bp_txout_match(txout, ks))
			return true;
	}

	return false;
}

bool bp_tx_match_mask(BIGNUM *mask, const struct bp_tx *tx,
		      const struct bp_keyset *ks)
{
	if (!tx || !tx->vout || !ks || !mask)
		return false;

	BN_zero(mask);

	unsigned int i;
	for (i = 0; i < tx->vout->len; i++) {
		struct bp_txout *txout;

		txout = g_ptr_array_index(tx->vout, i);
		if (bp_txout_match(txout, ks))
			BN_set_bit(mask, i);
	}

	return true;
}

void bbm_init(struct bp_block_match *match)
{
	memset(match, 0, sizeof(*match));

	BN_init(&match->mask);
}

struct bp_block_match *bbm_new(void)
{
	struct bp_block_match *match = malloc(sizeof(struct bp_block_match));
	if (!match)
		return NULL;
	
	bbm_init(match);
	match->self_alloc = true;

	return match;
}

void bbm_free(struct bp_block_match *match)
{
	if (!match)
		return;

	BN_clear_free(&match->mask);

	if (match->self_alloc)
		free(match);
}

GPtrArray *bp_block_match(const struct bp_block *block,
			  const struct bp_keyset *ks)
{
	if (!block || !block->vtx || !ks)
		return NULL;

	GPtrArray *arr = g_ptr_array_new_full(block->vtx->len,
				(GDestroyNotify) bbm_free);
	if (!arr)
		return NULL;
	
	BIGNUM tmp_mask;
	BN_init(&tmp_mask);

	unsigned int n;
	for (n = 0; n < block->vtx->len; n++) {
		struct bp_tx *tx;

		tx = g_ptr_array_index(block->vtx, n);
		if (!bp_tx_match_mask(&tmp_mask, tx, ks))
			goto err_out;

		if (!BN_is_zero(&tmp_mask)) {
			struct bp_block_match *match;

			match = bbm_new();
			match->n = n;
			BN_copy(&match->mask, &tmp_mask);

			g_ptr_array_add(arr, match);
		}
	}

	BN_clear_free(&tmp_mask);
	return arr;

err_out:
	BN_clear_free(&tmp_mask);
	g_ptr_array_free(arr, TRUE);
	return NULL;
}

