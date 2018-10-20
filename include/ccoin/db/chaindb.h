#ifndef __LIBCCOIN_CHAINDB_H__
#define __LIBCCOIN_CHAINDB_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <ccoin/buint.h>                // for bu256_t
#include <ccoin/core.h>                 // for bp_block
#include <ccoin/hashtab.h>              // for bp_hashtab_get

#include <gmp.h>                        // for mpz_t

#include <stdbool.h>                    // for bool

#ifdef __cplusplus
extern "C" {
#endif

struct blkinfo;

struct blkinfo {
	bu256_t		hash;
	struct bp_block	hdr;

	mpz_t		work;
	int		height;

	struct blkinfo	*prev;
};

struct chaindb_reorg {
	struct blkinfo	*old_best;	/* previous best_chain */
	unsigned int	conn;		/* # blocks connected (normally 1) */
	unsigned int	disconn;	/* # blocks disconnected (normally 0) */
};

struct chaindb {
	bu256_t		block0;

	struct bp_hashtab *blocks;

	struct blkinfo	*best_chain;
};

extern struct blkinfo *bi_new(void);
extern void bi_free(struct blkinfo *bi);

extern bool chaindb_init(struct chaindb *db, const unsigned char *netmagic,
		       const bu256_t *genesis_block);
extern void chaindb_free(struct chaindb *db);
extern bool chaindb_add(struct chaindb *db, struct blkinfo *bi,
		      struct chaindb_reorg *reorg_info);
extern void chaindb_locator(struct chaindb *db, struct blkinfo *bi,
		   struct bp_locator *locator);

static inline struct blkinfo *chaindb_lookup(struct chaindb *db,const bu256_t *hash)
{
	return (struct blkinfo *)bp_hashtab_get(db->blocks, hash);
}

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_CHAINDB_H__ */
