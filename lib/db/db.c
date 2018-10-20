/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <ccoin/db/db.h>                // for db_handle, db_info, etc
#include <ccoin/coredefs.h>             // for chain_find_by_netmagic, etc
#include <ccoin/log.h>                  // for log_error, log_info, etc

#include <stdint.h>                     // for uint8_t
#include <stdio.h>                      // for snprintf
#include <string.h>                     // for memcmp, strlen
#include <unistd.h>                     // for sysconf, _SC_PAGESIZE

struct db_info dbinfo = {NULL,
	{[METADB] = {"metadb", (MDB_dbi) 0, false},
	[BLOCKDB] = {"blockdb", (MDB_dbi) 0, false},
	[BLOCKHEIGHTDB] = {"blockheightdb", (MDB_dbi) 0, false},}
};

long get_pagesize()
{
#ifdef PAGESIZE
	return PAGESIZE;
#else
	long sz = sysconf(_SC_PAGESIZE);
	return sz;
#endif
}

bool metadb_init(const unsigned char *netmagic,
		const bu256_t *genesis_block)
{
	const struct chain_info *db_chain = chain_find_by_netmagic(netmagic);

	if (!db_chain)
		return false;

	int mdb_rc;
	MDB_txn *txn;
	MDB_val key_nm, key_gen, data_nm, data_gen;
	char db_filename[strlen(db_chain->name) + 4 + 1];
	enum metadb_key key_netmagic = NETMAGIC_KEY;
	enum metadb_key key_genesis = GENESIS_KEY;

	key_nm.mv_size = sizeof(enum metadb_key);
	key_nm.mv_data = &key_netmagic;
	key_gen.mv_size = sizeof(enum metadb_key);
	key_gen.mv_data = &key_genesis;

	snprintf(db_filename, sizeof(db_filename), "%s.mdb", db_chain->name);

	if ((mdb_rc = mdb_env_create(&dbinfo.env)) != MDB_SUCCESS) goto err_out;
	if ((mdb_rc = mdb_env_set_mapsize(dbinfo.env,(size_t)(((MAX_DB_SIZE - 1) | (get_pagesize() - 1)) + 1))) != MDB_SUCCESS) goto err_out;
	if ((mdb_rc = mdb_env_set_maxdbs(dbinfo.env, (MDB_dbi) MAX_NUM_DBS)) != MDB_SUCCESS) goto err_out;
	log_debug("db: Opening database file '%s'", db_filename);
	if ((mdb_rc = mdb_env_open(dbinfo.env, db_filename, MDB_NOSUBDIR, 0664)) != MDB_SUCCESS) goto err_out;
	if ((mdb_rc = mdb_txn_begin(dbinfo.env, NULL, 0, &txn)) != MDB_SUCCESS) goto err_out;

	if ((mdb_rc = mdb_dbi_open(txn, dbinfo.handle[METADB].name, MDB_INTEGERKEY, &dbinfo.handle[METADB].dbi)) == MDB_SUCCESS) {
		dbinfo.handle[METADB].open = true;
		log_info("db: Opening %s database", dbinfo.handle[METADB].name);

		if ((mdb_rc = mdb_get(txn, dbinfo.handle[METADB].dbi, &key_nm, &data_nm)) != MDB_SUCCESS) goto err_abort;
		if ((mdb_rc = mdb_get(txn, dbinfo.handle[METADB].dbi, &key_gen, &data_gen)) != MDB_SUCCESS) goto err_abort;
		if ((mdb_rc = mdb_txn_commit(txn)) != MDB_SUCCESS) goto err_close;

		if ((data_nm.mv_size != NETMAGIC_LEN) || (memcmp(data_nm.mv_data, netmagic, NETMAGIC_LEN))) {
			log_error("db: invalid netmagic");
			goto close_out;
		}

		if ((data_gen.mv_size != sizeof(bu256_t)) || (!bu256_equal(data_gen.mv_data, genesis_block))) {
			log_error("db: invalid genesis block");
			goto close_out;
		}

	} else if (mdb_rc == MDB_NOTFOUND) {
		log_info("db: Creating %s database", dbinfo.handle[METADB].name);

		data_nm.mv_size = NETMAGIC_LEN;
		data_nm.mv_data = (unsigned char *) netmagic;

		data_gen.mv_size = sizeof(bu256_t);
		data_gen.mv_data = (bu256_t *) genesis_block;

		if ((mdb_rc = mdb_dbi_open(txn, dbinfo.handle[METADB].name, MDB_CREATE, &dbinfo.handle[METADB].dbi)) != MDB_SUCCESS) goto err_abort;
		dbinfo.handle[METADB].open = true;

		if ((mdb_rc = mdb_put(txn, dbinfo.handle[METADB].dbi, &key_nm, &data_nm, MDB_NOOVERWRITE | MDB_APPEND)) != MDB_SUCCESS) goto err_abort;
		if ((mdb_rc = mdb_put(txn, dbinfo.handle[METADB].dbi, &key_gen, &data_gen, MDB_NOOVERWRITE | MDB_APPEND)) != MDB_SUCCESS) goto err_abort;
		if ((mdb_rc = mdb_txn_commit(txn)) != MDB_SUCCESS) goto err_close;
	} else goto err_abort;

	return true;

close_out:
	db_close();
	return false;
err_abort:
	mdb_txn_abort(txn);
err_close:
	db_close();
err_out:
	log_error("db: Database %s error '%s'", dbinfo.handle[METADB].name, mdb_strerror(mdb_rc));
	return false;
}

bool blockdb_init(void)
{
	int mdb_rc;
	MDB_txn *txn;

	if ((mdb_rc = mdb_txn_begin(dbinfo.env, NULL, 0, &txn)) != MDB_SUCCESS) goto err_out;

	log_info("db: Opening %s database", dbinfo.handle[BLOCKDB].name);
	if ((mdb_rc = mdb_dbi_open(txn, dbinfo.handle[BLOCKDB].name, MDB_CREATE, &dbinfo.handle[BLOCKDB].dbi)) != MDB_SUCCESS) goto err_abort;
	dbinfo.handle[BLOCKDB].open = true;

	if ((mdb_rc = mdb_txn_commit(txn)) != MDB_SUCCESS) goto err_close;

	return true;

err_abort:
	mdb_txn_abort(txn);
err_close:
	db_close();
err_out:
	log_error("db: Database %s error '%s'", dbinfo.handle[BLOCKDB].name, mdb_strerror(mdb_rc));
	return false;
}

bool blockdb_add(bu256_t *hash, struct const_buffer *buf)
{
	int mdb_rc;
	MDB_txn *txn;
	MDB_val key_hash, data_block;
	char hexstr[BU256_STRSZ];

	key_hash.mv_size = sizeof(bu256_t);
	key_hash.mv_data = hash;
	data_block.mv_size = buf->len;
	data_block.mv_data = (void *)buf->p;

	if ((mdb_rc = mdb_txn_begin(dbinfo.env, NULL, 0, &txn)) != MDB_SUCCESS) goto err_out;
	if (((mdb_rc = mdb_put(txn, dbinfo.handle[BLOCKDB].dbi, &key_hash, &data_block, MDB_NOOVERWRITE)) != MDB_SUCCESS) && (mdb_rc != MDB_KEYEXIST)) goto err_abort;
	bu256_hex(hexstr, key_hash.mv_data);
	if (mdb_rc == MDB_SUCCESS) {
		log_info("db: Adding block %s to %s database", hexstr, dbinfo.handle[BLOCKDB].name);
	} else if (mdb_rc == MDB_KEYEXIST) {
		log_debug("db: Block %s already exists in %s database", hexstr, dbinfo.handle[BLOCKDB].name);
	}

	if ((mdb_rc = mdb_txn_commit(txn)) != MDB_SUCCESS) goto err_out;

	return true;

err_abort:
	mdb_txn_abort(txn);
err_out:
	log_error("db: Database %s error '%s'", dbinfo.handle[BLOCKDB].name, mdb_strerror(mdb_rc));
	return false;
}

bool blockheightdb_init(void)
{
	int mdb_rc;
	MDB_txn *txn;

	if ((mdb_rc = mdb_txn_begin(dbinfo.env, NULL, 0, &txn)) != MDB_SUCCESS) goto err_out;

	log_info("db: Opening %s database", dbinfo.handle[BLOCKHEIGHTDB].name);
	if ((mdb_rc = mdb_dbi_open(txn, dbinfo.handle[BLOCKHEIGHTDB].name, MDB_CREATE | MDB_INTEGERKEY, &dbinfo.handle[BLOCKHEIGHTDB].dbi)) != MDB_SUCCESS) goto err_abort;
	dbinfo.handle[BLOCKHEIGHTDB].open = true;

	if ((mdb_rc = mdb_txn_commit(txn)) != MDB_SUCCESS) goto err_close;

	return true;

err_abort:
	mdb_txn_abort(txn);
err_close:
	db_close();
err_out:
	log_error("db: Database %s error '%s'", dbinfo.handle[BLOCKHEIGHTDB].name, mdb_strerror(mdb_rc));
	return false;
}

bool blockheightdb_add(int height, bu256_t *hash)
{
	int mdb_rc;
	MDB_txn *txn;
	MDB_val key_height, data_hash;
	char hexstr[BU256_STRSZ];
	bu256_hex(hexstr, hash);

	key_height.mv_size = sizeof(int);
	key_height.mv_data = &height;
	data_hash.mv_size = sizeof(bu256_t);
	data_hash.mv_data = hash;

	if ((mdb_rc = mdb_txn_begin(dbinfo.env, NULL, 0, &txn)) != MDB_SUCCESS) goto err_out;
	if (((mdb_rc = mdb_put(txn, dbinfo.handle[BLOCKHEIGHTDB].dbi, &key_height, &data_hash, MDB_APPEND)) != MDB_SUCCESS) && (mdb_rc != MDB_KEYEXIST)) goto err_abort;
	if (mdb_rc == MDB_SUCCESS) {
		log_debug("db: Adding %s with height %i to %s database", hexstr, *(int *)key_height.mv_data, dbinfo.handle[BLOCKHEIGHTDB].name);
	} else if (mdb_rc == MDB_KEYEXIST) {
		log_debug("db: Updating block height %i with hash %s in %s database", *(int *)key_height.mv_data, hexstr, dbinfo.handle[BLOCKHEIGHTDB].name);
	}
	if ((mdb_rc = mdb_txn_commit(txn)) != MDB_SUCCESS) goto err_out;

	return true;

err_abort:
	mdb_txn_abort(txn);
err_out:
	log_error("db: Database %s error '%s'", dbinfo.handle[BLOCKHEIGHTDB].name, mdb_strerror(mdb_rc));
	return false;
}

bool blockheightdb_getall(bool (*read_block)(void *p, size_t len))
{
	int mdb_rc;
	MDB_txn *txn;
	MDB_cursor *cursorheight;
	MDB_cursor_op op = MDB_FIRST;
	MDB_val key_height, data_hash, data_block;

	if ((mdb_rc = mdb_txn_begin(dbinfo.env, NULL, MDB_RDONLY, &txn)) != MDB_SUCCESS) goto err_out;
	if ((mdb_rc = mdb_cursor_open(txn, dbinfo.handle[BLOCKHEIGHTDB].dbi, &cursorheight)) != MDB_SUCCESS) goto err_abort;

	log_info("db: Reading %s database", dbinfo.handle[BLOCKHEIGHTDB].name);
	while ((mdb_rc = mdb_cursor_get(cursorheight, &key_height, &data_hash, op)) == MDB_SUCCESS) {
		if ((mdb_rc = mdb_get(txn, dbinfo.handle[BLOCKDB].dbi, &data_hash, &data_block)) != MDB_SUCCESS) goto err_abort;
		read_block(data_block.mv_data, data_block.mv_size);
		if (op != MDB_NEXT) op = MDB_NEXT;
	}

	mdb_cursor_close(cursorheight);
	mdb_txn_abort(txn);
	return true;

err_abort:
	mdb_txn_abort(txn);
err_out:
	log_error("db: Database %s error '%s'", dbinfo.handle[BLOCKHEIGHTDB].name, mdb_strerror(mdb_rc));
	return false;
}

void db_close(void) {

	uint8_t i;
	log_info("db: Closing databases");

	for(i=METADB; i < MAX_NUM_DBS; i++) {
		if (dbinfo.handle[i].open) {
			mdb_dbi_close(dbinfo.env, dbinfo.handle[i].dbi);
			dbinfo.handle[i].open = false;
			log_debug("db: Closed %s database", dbinfo.handle[i].name);
		}
	}

	mdb_env_close(dbinfo.env);

	return;
}
