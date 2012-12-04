/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <openssl/bn.h>
#include <glib.h>
#include <ccoin/blkdb.h>
#include <ccoin/message.h>
#include <ccoin/serialize.h>
#include <ccoin/buint.h>
#include <ccoin/mbr.h>
#include <ccoin/util.h>
#include <ccoin/compat.h>		/* for fdatasync */

struct blkinfo *bi_new(void)
{
	struct blkinfo *bi;

	bi = calloc(1, sizeof(*bi));
	BN_init(&bi->work);
	bi->height = -1;
	bi->n_file = -1;
	bi->n_pos = -1LL;

	bp_block_init(&bi->hdr);

	return bi;
}

void bi_free(struct blkinfo *bi)
{
	if (!bi)
		return;
	
	BN_clear_free(&bi->work);

	bp_block_free(&bi->hdr);

	memset(bi, 0, sizeof(*bi));
	free(bi);
}

bool blkdb_init(struct blkdb *db, const unsigned char *netmagic,
		const bu256_t *genesis_block)
{
	memset(db, 0, sizeof(*db));

	db->fd = -1;

	bu256_copy(&db->block0, genesis_block);

	bu256_zero(&db->hashBestChain);
	BN_init(&db->bnBestChainWork);
	db->nBestHeight = -1;

	memcpy(db->netmagic, netmagic, sizeof(db->netmagic));
	db->blocks = g_hash_table_new_full(g_bu256_hash, g_bu256_equal,
					   NULL, (GDestroyNotify) bi_free);

	return true;
}

static struct blkinfo *blkdb_lookup(struct blkdb *db, const bu256_t *hash)
{
	return g_hash_table_lookup(db->blocks, hash);
}

static bool blkdb_connect(struct blkdb *db, struct blkinfo *bi)
{
	bool rc = false;
	BIGNUM cur_work;
	BN_init(&cur_work);

	u256_from_compact(&cur_work, bi->hdr.nBits);

	bool best_chain = false;

	/* verify genesis block matches first record */
	if (g_hash_table_size(db->blocks) == 0) {
		if (!bu256_equal(&bi->hdr.sha256, &db->block0))
			goto out;

		bi->height = 0;

		BN_copy(&bi->work, &cur_work);

		best_chain = true;
	}
	
	/* lookup and verify previous block */
	else {
		struct blkinfo *prev = blkdb_lookup(db, &bi->hdr.hashPrevBlock);
		if (!prev)
			goto out;

		bi->height = prev->height + 1;

		if (!BN_add(&bi->work, &cur_work, &prev->work))
			goto out;

		if (BN_cmp(&bi->work, &db->bnBestChainWork) > 0)
			best_chain = true;
	}

	/* if new best chain found, update pointers */
	if (best_chain) {
		bu256_copy(&db->hashBestChain, &bi->hdr.sha256);
		BN_copy(&db->bnBestChainWork, &cur_work);
		db->nBestHeight = bi->height;
	}

	/* add to block map */
	g_hash_table_insert(db->blocks, &bi->hash, bi);

	rc = true;

out:
	BN_clear_free(&cur_work);
	return rc;
}

static bool blkdb_read_rec(struct blkdb *db, const struct p2p_message *msg)
{
	struct blkinfo *bi;
	struct const_buffer buf = { msg->data, msg->hdr.data_len };

	if (strncmp(msg->hdr.command, "rec", 12))
		return false;

	bi = bi_new();
	if (!bi)
		return false;

	/* deserialize record */
	if (!deser_u256(&bi->hash, &buf))
		goto err_out;
	if (!deser_bp_block(&bi->hdr, &buf))
		goto err_out;
	
	/* verify that provided hash matches block header, as an additional
	 * self-verification step
	 */
	bp_block_calc_sha256(&bi->hdr);
	if (!bu256_equal(&bi->hash, &bi->hdr.sha256))
		goto err_out;

	/* verify block may be added to chain, then add it */
	if (!blkdb_connect(db, bi))
		goto err_out;

	return true;

err_out:
	bi_free(bi);
	return false;
}

static GString *ser_blkinfo(const struct blkinfo *bi)
{
	GString *rs = g_string_sized_new(sizeof(*bi));

	ser_u256(rs, &bi->hash);
	ser_bp_block(rs, &bi->hdr);

	return rs;
}

static GString *blkdb_ser_rec(struct blkdb *db, const struct blkinfo *bi)
{
	GString *data = ser_blkinfo(bi);

	GString *rs = message_str(db->netmagic, "rec", data->str, data->len);

	g_string_free(data, TRUE);

	return rs;
}

bool blkdb_read(struct blkdb *db, const char *idx_fn)
{
	bool rc = true;
	int fd = file_seq_open(idx_fn);
	if (fd < 0)
		return false;

	struct p2p_message msg;
	memset(&msg, 0, sizeof(msg));
	bool read_ok = true;

	while (fread_message(fd, &msg, &read_ok)) {
		rc = blkdb_read_rec(db, &msg);
		if (!rc)
			break;
	}

	close(fd);

	free(msg.data);

	return read_ok && rc;
}

bool blkdb_add(struct blkdb *db, struct blkinfo *bi)
{
	if (db->fd >= 0) {
		GString *data = blkdb_ser_rec(db, bi);
		if (!data)
			return false;

		/* assume either at EOF, or O_APPEND */
		size_t data_len = data->len;
		ssize_t wrc = write(db->fd, data->str, data_len);

		g_string_free(data, TRUE);

		if (wrc != data_len)
			return false;

		if (db->datasync_fd && (fdatasync(db->fd) < 0))
			return false;
	}

	/* verify block may be added to chain, then add it */
	return blkdb_connect(db, bi);
}

void blkdb_free(struct blkdb *db)
{
	if (db->close_fd && (db->fd >= 0))
		close(db->fd);

	BN_clear_free(&db->bnBestChainWork);

	g_hash_table_unref(db->blocks);
}

