#ifndef __LIBCCOIN_DB_H__
#define __LIBCCOIN_DB_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <ccoin/buffer.h>               // for const_buffer
#include <ccoin/buint.h>                // for bu256_t

#include <lmdb.h>                       // for MDB_dbi, MDB_env

#include <stdbool.h>                    // for bool
#include <stddef.h>                     // for size_t

#ifdef __cplusplus
extern "C" {
#endif

enum {
	NETMAGIC_LEN = 4
};

 enum {
 	MAX_DB_SIZE = 17179869184	// Maximum database size in bytes
 };

enum db_list {
	METADB,
	BLOCKDB,
	BLOCKHEIGHTDB,
	MAX_NUM_DBS,
};

enum metadb_key {
	NETMAGIC_KEY,
	GENESIS_KEY,
};

struct db_handle {
	const char	*name;
	MDB_dbi		dbi;
	bool		open;
};

struct db_info {
	MDB_env				*env;
	struct db_handle	handle[MAX_NUM_DBS];
};

extern bool metadb_init(const unsigned char *netmagic,
		       const bu256_t *genesis_block);

extern bool blockdb_init(void);
extern bool blockdb_add(bu256_t *hash, struct const_buffer *buf);

extern bool blockheightdb_init(void);
extern bool blockheightdb_add(int height, bu256_t *hash);
extern bool blockheightdb_getall(bool (*read_block)(void *p, size_t len));

extern void db_close(void);

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_DB_H__ */
