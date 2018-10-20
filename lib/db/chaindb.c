/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <ccoin/buint.h>                // for bu256_hex, bu256_copy, etc
#include <ccoin/core.h>                 // for bp_block, bp_locator_push, etc
#include <ccoin/db/chaindb.h>           // for blkinfo, chaindb, etc
#include <ccoin/db/db.h>                // for blockheightdb_add
#include <ccoin/hashtab.h>              // for bp_hashtab_new_ext, etc
#include <ccoin/log.h>                  // for log_debug, log_info
#include <ccoin/parr.h>                 // for parr
#include <ccoin/serialize.h>            // for u256_from_compact

#include <gmp.h>                        // for mpz_clear, mpz_init, etc

#include <stddef.h>                     // for NULL
#include <stdlib.h>                     // for calloc, free
#include <string.h>                     // for memset
#include <stdbool.h>                    // for bool, true, false

struct logging *log_state;

struct blkinfo *bi_new(void)
{
	struct blkinfo *bi;

	bi = calloc(1, sizeof(*bi));
	mpz_init(bi->work);
	bi->height = -1;

	bp_block_init(&bi->hdr);

	return bi;
}

void bi_free(struct blkinfo *bi)
{
	if (!bi)
		return;

	mpz_clear(bi->work);

	bp_block_free(&bi->hdr);

	memset(bi, 0, sizeof(*bi));
	free(bi);
}

bool chaindb_init(struct chaindb *db, const unsigned char *netmagic,
		const bu256_t *genesis_block)
{
	memset(db, 0, sizeof(*db));

	bu256_copy(&db->block0, genesis_block);

	db->blocks = bp_hashtab_new_ext(bu256_hash, bu256_equal_,
					NULL, (bp_freefunc) bi_free);

	return true;
}

bool chaindb_add(struct chaindb *db, struct blkinfo *bi,
			  struct chaindb_reorg *reorg_info)
{
	memset(reorg_info, 0, sizeof(*reorg_info));

	if (chaindb_lookup(db, &bi->hash))
		return false;

	bool rc = false;
	char hexstr[BU256_STRSZ];
	mpz_t cur_work;
	mpz_init(cur_work);

	u256_from_compact(cur_work, bi->hdr.nBits);

	bool best_chain = false;

	/* verify genesis block matches first record */
	if (bp_hashtab_size(db->blocks) == 0) {
		if (!bu256_equal(&bi->hdr.sha256, &db->block0))
			goto out;

		/* bi->prev = NULL; */
		bi->height = 0;

		mpz_set(bi->work, cur_work);

		best_chain = true;
	}

	/* lookup and verify previous block */
	else {
		struct blkinfo *prev = chaindb_lookup(db, &bi->hdr.hashPrevBlock);
		if (!prev)
			goto out;

		bi->prev = prev;
		bi->height = prev->height + 1;

		mpz_add(bi->work, cur_work, prev->work);

		if (mpz_cmp(bi->work, db->best_chain->work) > 0)
			best_chain = true;
	}

	/* add to block map */
	bp_hashtab_put(db->blocks, &bi->hash, bi);
	blockheightdb_add(bi->height, &bi->hash);

	/* if new best chain found, update pointers */
	if (best_chain) {
		struct blkinfo *old_best = db->best_chain;
		struct blkinfo *new_best = bi;

		reorg_info->old_best = old_best;

		/* likely case: new best chain has greater height */
		if (!old_best) {
			while (new_best) {
				new_best = new_best->prev;
				reorg_info->conn++;
			}
		} else {
			while (new_best &&
			       (new_best->height > old_best->height)) {
				new_best = new_best->prev;
				reorg_info->conn++;
			}
		}

		/* unlikely case: old best chain has greater height */
		while (old_best && new_best &&
		       (old_best->height > new_best->height)) {
			old_best = old_best->prev;
			reorg_info->disconn++;
		}

		/* height matches, but we are still walking parallel chains */
		while (old_best && new_best && (old_best != new_best)) {
			new_best = new_best->prev;
			reorg_info->conn++;

			old_best = old_best->prev;
			reorg_info->disconn++;
		}

		/* reorg analyzed. update database's best-chain pointer */
		db->best_chain = bi;

		bu256_hex(hexstr, &db->best_chain->hdr.sha256);
		log_info("chaindb: New best = %s Height = %i",hexstr, bi->height);
	}
	rc = true;
	bu256_hex(hexstr, &bi->hdr.sha256);
	log_debug("chaindb: Adding block %s to chaindb successful", hexstr);

out:
	mpz_clear(cur_work);
	return rc;
}


void chaindb_free(struct chaindb *db)
{
	bp_hashtab_unref(db->blocks);
}

void chaindb_locator(struct chaindb *db, struct blkinfo *bi,
		   struct bp_locator *locator)
{
	if (!bi)
		bi = db->best_chain;

	int step = 1;
	while (bi) {
		bp_locator_push(locator, &bi->hash);

		unsigned int i;
		for (i = 0; bi && i < step; i++)
			bi = bi->prev;
		if (locator->vHave->len > 10)
			step *= 2;
	}

	bp_locator_push(locator, &db->block0);
}

