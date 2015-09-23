#ifndef __LIBCCOIN_ADDR_MATCH_H__
#define __LIBCCOIN_ADDR_MATCH_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdbool.h>
#include <openssl/bn.h>
#include <ccoin/parr.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bp_txout;
struct bp_keyset;
struct bp_tx;
struct bp_block;

extern bool bp_txout_match(const struct bp_txout *txout,
		    const struct bp_keyset *ks);
extern bool bp_tx_match(const struct bp_tx *tx, const struct bp_keyset *ks);
extern bool bp_tx_match_mask(BIGNUM *mask, const struct bp_tx *tx,
		      const struct bp_keyset *ks);

struct bp_block_match {
	unsigned int	n;		/* block.vtx array index */
	BIGNUM		mask;		/* bitmask of matched txout's */
	bool		self_alloc;	/* alloc'd by bbm_new? */
};

extern void bbm_init(struct bp_block_match *match);
extern struct bp_block_match *bbm_new(void);
extern void bbm_free(void *bp_block_match_match);

extern parr *bp_block_match(const struct bp_block *block,
			    const struct bp_keyset *ks);

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_ADDR_MATCH_H__ */
