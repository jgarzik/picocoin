/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <ccoin/core.h>
#include <ccoin/util.h>
#include <ccoin/coredefs.h>
#include <ccoin/serialize.h>
#include <ccoin/compat.h>		/* for parr_new */

bool deser_bp_addr(unsigned int protover,
		struct bp_address *addr, struct const_buffer *buf)
{
	bp_addr_free(addr);

	if (protover >= CADDR_TIME_VERSION)
		if (!deser_u32(&addr->nTime, buf)) return false;
	if (!deser_u64(&addr->nServices, buf)) return false;
	if (!deser_bytes(&addr->ip, buf, 16)) return false;
	if (!deser_u16(&addr->port, buf)) return false;
	return true;
}

void ser_bp_addr(cstring *s, unsigned int protover, const struct bp_address *addr)
{
	if (protover >= CADDR_TIME_VERSION)
		ser_u32(s, addr->nTime);
	ser_u64(s, addr->nServices);
	ser_bytes(s, addr->ip, 16);
	ser_u16(s, addr->port);
}

void bp_inv_init(struct bp_inv *inv)
{
	memset(inv, 0, sizeof(*inv));
}

bool deser_bp_inv(struct bp_inv *inv, struct const_buffer *buf)
{
	bp_inv_free(inv);

	if (!deser_u32(&inv->type, buf)) return false;
	if (!deser_u256(&inv->hash, buf)) return false;
	return true;
}

void ser_bp_inv(cstring *s, const struct bp_inv *inv)
{
	ser_u32(s, inv->type);
	ser_u256(s, &inv->hash);
}

bool deser_bp_locator(struct bp_locator *locator, struct const_buffer *buf)
{
	bp_locator_free(locator);

	if (!deser_u32(&locator->nVersion, buf)) return false;
	if (!deser_u256_array(&locator->vHave, buf)) return false;

	return true;
}

void ser_bp_locator(cstring *s, const struct bp_locator *locator)
{
	ser_u32(s, locator->nVersion);
	ser_u256_array(s, locator->vHave);
}

void bp_locator_free(struct bp_locator *locator)
{
	if (!locator)
		return;

	if (locator->vHave) {
		parr_free(locator->vHave, true);
		locator->vHave = NULL;
	}
}

void bp_locator_push(struct bp_locator *locator, const bu256_t *hash_in)
{
	/* TODO: replace '16' with number based on real world usage */
	if (!locator->vHave)
		locator->vHave = parr_new(16, bu256_free);

	bu256_t *hash = bu256_new(hash_in);
	parr_add(locator->vHave, hash);
}

void bp_outpt_init(struct bp_outpt *outpt)
{
	memset(outpt, 0, sizeof(*outpt));
}

bool deser_bp_outpt(struct bp_outpt *outpt, struct const_buffer *buf)
{
	bp_outpt_free(outpt);

	if (!deser_u256(&outpt->hash, buf)) return false;
	if (!deser_u32(&outpt->n, buf)) return false;
	return true;
}

void ser_bp_outpt(cstring *s, const struct bp_outpt *outpt)
{
	ser_u256(s, &outpt->hash);
	ser_u32(s, outpt->n);
}

void bp_txin_init(struct bp_txin *txin)
{
	memset(txin, 0, sizeof(*txin));
	bp_outpt_init(&txin->prevout);
}

bool deser_bp_txin(struct bp_txin *txin, struct const_buffer *buf)
{
	bp_txin_free(txin);

	if (!deser_bp_outpt(&txin->prevout, buf)) return false;
	if (!deser_varstr(&txin->scriptSig, buf)) return false;
	if (!deser_u32(&txin->nSequence, buf)) return false;
	return true;
}

void ser_bp_txin(cstring *s, const struct bp_txin *txin)
{
	ser_bp_outpt(s, &txin->prevout);
	ser_varstr(s, txin->scriptSig);
	ser_u32(s, txin->nSequence);
}

void bp_txin_free(struct bp_txin *txin)
{
	if (!txin)
		return;

	bp_outpt_free(&txin->prevout);

	if (txin->scriptSig) {
		cstr_free(txin->scriptSig, true);
		txin->scriptSig = NULL;
	}
}

void bp_txin_free_cb(void *data)
{
	if (!data)
		return;

	struct bp_txin *txin = data;
	bp_txin_free(txin);

	memset(txin, 0, sizeof(*txin));
	free(txin);
}

void bp_txin_copy(struct bp_txin *dest, const struct bp_txin *src)
{
	bp_outpt_copy(&dest->prevout, &src->prevout);
	dest->nSequence = src->nSequence;

	if (!src->scriptSig)
		dest->scriptSig = NULL;
	else {
		dest->scriptSig = cstr_new_sz(src->scriptSig->len);
		cstr_append_buf(dest->scriptSig,
				    src->scriptSig->str, src->scriptSig->len);
	}
}

void bp_txout_init(struct bp_txout *txout)
{
	memset(txout, 0, sizeof(*txout));
}

bool deser_bp_txout(struct bp_txout *txout, struct const_buffer *buf)
{
	bp_txout_free(txout);

	if (!deser_s64(&txout->nValue, buf)) return false;
	if (!deser_varstr(&txout->scriptPubKey, buf)) return false;
	return true;
}

void ser_bp_txout(cstring *s, const struct bp_txout *txout)
{
	ser_s64(s, txout->nValue);
	ser_varstr(s, txout->scriptPubKey);
}

void bp_txout_free(struct bp_txout *txout)
{
	if (!txout)
		return;

	if (txout->scriptPubKey) {
		cstr_free(txout->scriptPubKey, true);
		txout->scriptPubKey = NULL;
	}
}

void bp_txout_free_cb(void *data)
{
	if (!data)
		return;

	struct bp_txout *txout = data;
	bp_txout_free(txout);

	memset(txout, 0, sizeof(*txout));
	free(txout);
}

void bp_txout_set_null(struct bp_txout *txout)
{
	bp_txout_free(txout);

	txout->nValue = -1;
	txout->scriptPubKey = cstr_new("");
}

void bp_txout_copy(struct bp_txout *dest, const struct bp_txout *src)
{
	dest->nValue = src->nValue;

	if (!src->scriptPubKey)
		dest->scriptPubKey = NULL;
	else {
		dest->scriptPubKey = cstr_new_sz(src->scriptPubKey->len);
		cstr_append_buf(dest->scriptPubKey,
				    src->scriptPubKey->str,
				    src->scriptPubKey->len);
	}
}

void bp_tx_init(struct bp_tx *tx)
{
	memset(tx, 0, sizeof(*tx));
	tx->nVersion = 1;
}

bool deser_bp_tx(struct bp_tx *tx, struct const_buffer *buf)
{
	bp_tx_free(tx);

	tx->vin = parr_new(8, bp_txin_free_cb);
	tx->vout = parr_new(8, bp_txout_free_cb);

	if (!deser_u32(&tx->nVersion, buf)) return false;

	uint32_t vlen;
	if (!deser_varlen(&vlen, buf)) return false;

	unsigned int i;
	for (i = 0; i < vlen; i++) {
		struct bp_txin *txin;

		txin = calloc(1, sizeof(*txin));
		bp_txin_init(txin);
		if (!deser_bp_txin(txin, buf)) {
			free(txin);
			goto err_out;
		}

		parr_add(tx->vin, txin);
	}

	if (!deser_varlen(&vlen, buf)) return false;

	for (i = 0; i < vlen; i++) {
		struct bp_txout *txout;

		txout = calloc(1, sizeof(*txout));
		bp_txout_init(txout);
		if (!deser_bp_txout(txout, buf)) {
			free(txout);
			goto err_out;
		}

		parr_add(tx->vout, txout);
	}

	if (!deser_u32(&tx->nLockTime, buf)) return false;
	return true;

err_out:
	bp_tx_free(tx);
	return false;
}

void ser_bp_tx(cstring *s, const struct bp_tx *tx)
{
	ser_u32(s, tx->nVersion);

	ser_varlen(s, tx->vin ? tx->vin->len : 0);

	unsigned int i;
	if (tx->vin) {
		for (i = 0; i < tx->vin->len; i++) {
			struct bp_txin *txin;

			txin = parr_idx(tx->vin, i);
			ser_bp_txin(s, txin);
		}
	}

	ser_varlen(s, tx->vout ? tx->vout->len : 0);

	if (tx->vout) {
		for (i = 0; i < tx->vout->len; i++) {
			struct bp_txout *txout;

			txout = parr_idx(tx->vout, i);
			ser_bp_txout(s, txout);
		}
	}

	ser_u32(s, tx->nLockTime);
}

void bp_tx_free_vout(struct bp_tx *tx)
{
	if (!tx || !tx->vout)
		return;

	parr_free(tx->vout, true);
	tx->vout = NULL;
}

void bp_tx_free(struct bp_tx *tx)
{
	if (!tx)
		return;

	if (tx->vin) {
		parr_free(tx->vin, true);
		tx->vin = NULL;
	}

	bp_tx_free_vout(tx);

	tx->sha256_valid = false;
}

void bp_tx_calc_sha256(struct bp_tx *tx)
{
	if (tx->sha256_valid)
		return;

	/* TODO: introduce hashing-only serialization mode */

	cstring *s = cstr_new_sz(512);
	ser_bp_tx(s, tx);

	bu_Hash((unsigned char *) &tx->sha256, s->str, s->len);
	tx->sha256_valid = true;

	cstr_free(s, true);
}

unsigned int bp_tx_ser_size(const struct bp_tx *tx)
{
	unsigned int tx_ser_size;

	/* TODO: introduce a counting-only serialization mode */

	cstring *s = cstr_new_sz(512);
	ser_bp_tx(s, tx);

	tx_ser_size = s->len;

	cstr_free(s, true);

	return tx_ser_size;
}

void bp_tx_copy(struct bp_tx *dest, const struct bp_tx *src)
{
	dest->nVersion = src->nVersion;
	dest->nLockTime = src->nLockTime;
	dest->sha256_valid = src->sha256_valid;
	bu256_copy(&dest->sha256, &src->sha256);

	if (!src->vin)
		dest->vin = NULL;
	else {
		unsigned int i;

		dest->vin = parr_new(src->vin->len, bp_txin_free_cb);

		for (i = 0; i < src->vin->len; i++) {
			struct bp_txin *txin_old, *txin_new;

			txin_old = parr_idx(src->vin, i);
			txin_new = malloc(sizeof(*txin_new));
			bp_txin_copy(txin_new, txin_old);
			parr_add(dest->vin, txin_new);
		}
	}

	if (!src->vout)
		dest->vout = NULL;
	else {
		unsigned int i;

		dest->vout = parr_new(src->vout->len,
						  bp_txout_free_cb);

		for (i = 0; i < src->vout->len; i++) {
			struct bp_txout *txout_old, *txout_new;

			txout_old = parr_idx(src->vout, i);
			txout_new = malloc(sizeof(*txout_new));
			bp_txout_copy(txout_new, txout_old);
			parr_add(dest->vout, txout_new);
		}
	}
}

void bp_block_init(struct bp_block *block)
{
	memset(block, 0, sizeof(*block));
}

bool deser_bp_block(struct bp_block *block, struct const_buffer *buf)
{
	bp_block_free(block);

	if (!deser_u32(&block->nVersion, buf)) return false;
	if (!deser_u256(&block->hashPrevBlock, buf)) return false;
	if (!deser_u256(&block->hashMerkleRoot, buf)) return false;
	if (!deser_u32(&block->nTime, buf)) return false;
	if (!deser_u32(&block->nBits, buf)) return false;
	if (!deser_u32(&block->nNonce, buf)) return false;

	/* permit header-only blocks */
	if (buf->len == 0)
		return true;

	block->vtx = parr_new(512, free);

	uint32_t vlen;
	if (!deser_varlen(&vlen, buf)) return false;

	unsigned int i;
	for (i = 0; i < vlen; i++) {
		struct bp_tx *tx;

		tx = calloc(1, sizeof(*tx));
		bp_tx_init(tx);
		if (!deser_bp_tx(tx, buf)) {
			free(tx);
			goto err_out;
		}

		parr_add(block->vtx, tx);
	}

	return true;

err_out:
	bp_block_free(block);
	return false;
}

static void ser_bp_block_hdr(cstring *s, const struct bp_block *block)
{
	ser_u32(s, block->nVersion);
	ser_u256(s, &block->hashPrevBlock);
	ser_u256(s, &block->hashMerkleRoot);
	ser_u32(s, block->nTime);
	ser_u32(s, block->nBits);
	ser_u32(s, block->nNonce);
}

void ser_bp_block(cstring *s, const struct bp_block *block)
{
	ser_bp_block_hdr(s, block);

	unsigned int i;
	if (block->vtx) {
		ser_varlen(s, block->vtx->len);

		for (i = 0; i < block->vtx->len; i++) {
			struct bp_tx *tx;

			tx = parr_idx(block->vtx, i);
			ser_bp_tx(s, tx);
		}
	}
}

void bp_block_vtx_free(struct bp_block *block)
{
	if (block && block->vtx) {
		unsigned int i;

		for (i = 0; i < block->vtx->len; i++) {
			struct bp_tx *tx;

			tx = parr_idx(block->vtx, i);
			bp_tx_free(tx);
		}

		parr_free(block->vtx, true);

		block->vtx = NULL;
	}
}

void bp_block_free(struct bp_block *block)
{
	if (!block)
		return;

	bp_block_vtx_free(block);
}

void bp_block_free_cb(void *data)
{
	if (!data)
		return;

	struct bp_block *block = data;
	bp_block_free(block);

	memset(block, 0, sizeof(*block));
	free(block);
}

void bp_block_calc_sha256(struct bp_block *block)
{
	if (block->sha256_valid)
		return;

	/* TODO: introduce hashing-only serialization mode */

	cstring *s = cstr_new_sz(10 * 1024);
	ser_bp_block_hdr(s, block);

	bu_Hash((unsigned char *)&block->sha256, s->str, s->len);
	block->sha256_valid = true;

	cstr_free(s, true);
}

unsigned int bp_block_ser_size(const struct bp_block *block)
{
	unsigned int block_ser_size;

	/* TODO: introduce a counting-only serialization mode */

	cstring *s = cstr_new_sz(200 * 1024);
	ser_bp_block(s, block);

	block_ser_size = s->len;

	cstr_free(s, true);

	return block_ser_size;
}

