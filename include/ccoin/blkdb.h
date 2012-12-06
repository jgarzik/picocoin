#ifndef __LIBCCOIN_BLKDB_H__
#define __LIBCCOIN_BLKDB_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdbool.h>
#include <glib.h>
#include <ccoin/core.h>
#include <ccoin/buint.h>

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

struct blkdb {
	int		fd;
	bool		datasync_fd;
	bool		close_fd;

	unsigned char	netmagic[4];
	bu256_t		block0;

	GHashTable	*blocks;

	struct blkinfo	*best_chain;
};

extern struct blkinfo *bi_new(void);
extern void bi_free(struct blkinfo *bi);

extern bool blkdb_init(struct blkdb *db, const unsigned char *netmagic,
		       const bu256_t *genesis_block);
extern void blkdb_free(struct blkdb *db);
extern bool blkdb_read(struct blkdb *db, const char *idx_fn);
extern bool blkdb_add(struct blkdb *db, struct blkinfo *bi);
extern void blkdb_locator(struct blkdb *db, struct blkinfo *bi,
		   struct bp_locator *locator);

#endif /* __LIBCCOIN_BLKDB_H__ */
