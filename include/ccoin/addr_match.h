#ifndef __LIBCCOIN_ADDR_MATCH_H__
#define __LIBCCOIN_ADDR_MATCH_H__

#include <stdbool.h>
#include <glib.h>
#include <openssl/bn.h>

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
extern void bbm_free(struct bp_block_match *match);

extern GPtrArray *bp_block_match(const struct bp_block *block,
			  const struct bp_keyset *ks);

#endif /* __LIBCCOIN_ADDR_MATCH_H__ */
