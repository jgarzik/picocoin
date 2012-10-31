#ifndef __LIBCCOIN_BLKDB_H__
#define __LIBCCOIN_BLKDB_H__

#include <stdbool.h>
#include <glib.h>
#include <ccoin/core.h>
#include <ccoin/buint.h>

struct blkinfo {
	bu256_t		hash;
	struct bp_block	hdr;

	BIGNUM		work;
	int		height;
};

struct blkdb {
	int		fd;
	bool		datasync_fd;
	bool		close_fd;

	unsigned char	netmagic[4];
	bu256_t		block0;

	GHashTable	*blocks;

	bu256_t		hashBestChain;
	BIGNUM		bnBestChainWork;
	int		nBestHeight;
};

extern struct blkinfo *bi_new(void);
extern void bi_free(struct blkinfo *bi);

extern bool blkdb_init(struct blkdb *db, const unsigned char *netmagic,
		       const bu256_t *genesis_block);
extern void blkdb_free(struct blkdb *db);
extern bool blkdb_read(struct blkdb *db, const char *idx_fn);
extern bool blkdb_add(struct blkdb *db, struct blkinfo *bi);

#endif /* __LIBCCOIN_BLKDB_H__ */
