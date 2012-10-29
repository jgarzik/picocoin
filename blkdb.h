#ifndef __LIBCCOIN_BLKDB_H__
#define __LIBCCOIN_BLKDB_H__

#include <stdbool.h>
#include <glib.h>
#include "core.h"

struct blkinfo {
	unsigned char	ser_hash[32];
	struct bp_block	hdr;
};

struct blkdb {
	int		fd;
	bool		datasync_fd;
	bool		close_fd;

	unsigned char	netmagic[4];
	BIGNUM		*block0;

	GHashTable	*blocks;
};

extern bool blkdb_init(struct blkdb *db, const unsigned char *netmagic,
		       const char *genesis_hash);
extern void blkdb_free(struct blkdb *db);
extern bool blkdb_read(struct blkdb *db, const char *idx_fn);
extern bool blkdb_add(struct blkdb *db, struct blkinfo *bi);

#endif /* __LIBCCOIN_BLKDB_H__ */
