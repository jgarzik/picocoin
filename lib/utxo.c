/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <string.h>
#include <ccoin/core.h>
#include <ccoin/compat.h>

void bp_utxo_init(struct bp_utxo *coin)
{
	memset(coin, 0, sizeof(*coin));
}

static void bp_utxo_free_vout(struct bp_utxo *coin)
{
	if (!coin || !coin->vout)
		return;

	unsigned int i;
	for (i = 0; i < coin->vout->len; i++) {
		struct bp_txout *txout;

		txout = g_ptr_array_index(coin->vout, i);
		bp_txout_free(txout);
	}

	g_ptr_array_free(coin->vout, TRUE);

	coin->vout = NULL;
}

void bp_utxo_free(struct bp_utxo *coin)
{
	if (!coin)
		return;

	bp_utxo_free_vout(coin);
}

bool bp_utxo_from_tx(struct bp_utxo *coin, const struct bp_tx *tx,
		     bool is_coinbase, unsigned int height)
{
	if (!tx || !coin || !tx->vout || !tx->sha256_valid)
		return false;

	bu256_copy(&coin->hash, &tx->sha256);
	coin->is_coinbase = is_coinbase;
	coin->height = height;
	coin->version = tx->nVersion;

	coin->vout = g_ptr_array_new_full(tx->vout->len, g_free);
	unsigned int i;

	for (i = 0; i < tx->vout->len; i++) {
		struct bp_txout *old_out, *new_out;

		old_out = g_ptr_array_index(tx->vout, i);
		new_out = calloc(1, sizeof(*new_out));
		bp_txout_copy(new_out, old_out);
		g_ptr_array_add(coin->vout, new_out);
	}
	
	return true;
}

void utxo_free_ent(gpointer data_)
{
	struct bp_utxo *coin = data_;
	if (!coin)
		return;
	
	bp_utxo_free(coin);
	free(coin);
}

void bp_utxo_set_init(struct bp_utxo_set *uset)
{
	memset(uset, 0, sizeof(*uset));

	uset->map = g_hash_table_new_full(g_bu256_hash, g_bu256_equal,
					  NULL, utxo_free_ent);
}

void bp_utxo_set_free(struct bp_utxo_set *uset)
{
	if (!uset)
		return;
	
	if (uset->map) {
		g_hash_table_unref(uset->map);
		uset->map = NULL;
	}
}

bool bp_utxo_is_spent(struct bp_utxo_set *uset, const struct bp_outpt *outpt)
{
	struct bp_utxo *coin = bp_utxo_lookup(uset, &outpt->hash);
	if (!coin || !coin->vout || !coin->vout->len ||
	    (outpt->n >= coin->vout->len))
		return true;
	
	struct bp_txout *txout = g_ptr_array_index(coin->vout, outpt->n);
	if (!txout)
		return true;
	
	return false;
}

static bool bp_utxo_null(const struct bp_utxo *coin)
{
	if (!coin || !coin->vout || !coin->vout->len)
		return true;
	
	unsigned int i;
	for (i = 0; i < coin->vout->len; i++) {
		struct bp_txout *txout;

		txout = g_ptr_array_index(coin->vout, i);
		if (txout)
			return false;
	}

	return true;
}

bool bp_utxo_spend(struct bp_utxo_set *uset, const struct bp_outpt *outpt)
{
	struct bp_utxo *coin = bp_utxo_lookup(uset, &outpt->hash);
	if (!coin || !coin->vout || !coin->vout->len ||
	    (outpt->n >= coin->vout->len))
		return false;
	
	/* find txout, given index */
	struct bp_txout *txout = g_ptr_array_index(coin->vout, outpt->n);
	if (!txout)
		return false;

	/* free txout, replace with NULL marker indicating spent-ness */
	coin->vout->pdata[outpt->n] = NULL;
	bp_txout_free(txout);
	free(txout);

	/* if coin entirely spent, free it */
	if (bp_utxo_null(coin))
		g_hash_table_remove(uset->map, &coin->hash);

	return true;
}

