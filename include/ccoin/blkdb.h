#ifndef __LIBCCOIN_BLKDB_H__
#define __LIBCCOIN_BLKDB_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdbool.h>
#include <ccoin/core.h>
#include <ccoin/buint.h>
#include <ccoin/hashtab.h>

#ifdef __cplusplus
extern "C" {
#endif

struct blkinfo;

struct blkinfo {
	bu256_t		hash;
	struct bp_block	hdr;

	BIGNUM		work;
	int		height;

	int32_t		n_file;		/* uninitialized == -1 */
	int64_t		n_pos;		/* uninitialized == -1 */

	struct blkinfo	*prev;
};

struct blkdb_reorg {
	struct blkinfo	*old_best;	/* previous best_chain */
	unsigned int	conn;		/* # blocks connected (normally 1) */
	unsigned int	disconn;	/* # blocks disconnected (normally 0) */
};

struct blkdb {
	int		fd;
	bool		datasync_fd;
	bool		close_fd;

	unsigned char	netmagic[4];
	bu256_t		block0;

	struct bp_hashtab *blocks;

	struct blkinfo	*best_chain;
};

extern struct blkinfo *bi_new(void);
extern void bi_free(struct blkinfo *bi);

extern bool blkdb_init(struct blkdb *db, const unsigned char *netmagic,
		       const bu256_t *genesis_block);
extern void blkdb_free(struct blkdb *db);
extern bool blkdb_read(struct blkdb *db, const char *idx_fn);
extern bool blkdb_add(struct blkdb *db, struct blkinfo *bi,
		      struct blkdb_reorg *reorg_info);
extern void blkdb_locator(struct blkdb *db, struct blkinfo *bi,
		   struct bp_locator *locator);

static inline struct blkinfo *blkdb_lookup(struct blkdb *db,const bu256_t *hash)
{
	return (struct blkinfo *)bp_hashtab_get(db->blocks, hash);
}

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_BLKDB_H__ */
