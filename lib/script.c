/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <assert.h>
#include <ccoin/script.h>
#include <ccoin/serialize.h>
#include <ccoin/util.h>
#include <ccoin/buffer.h>
#include <ccoin/endian.h>

bool bsp_getop(struct bscript_op *op, struct bscript_parser *bp)
{
	if (bp->buf->len == 0)
		return false;			/* EOF */

	unsigned char opcode;
	if (!deser_bytes(&opcode, bp->buf, 1))
		goto err_out;
	op->op = opcode;

	uint32_t data_len;

	if (opcode < OP_PUSHDATA1)
		data_len = opcode;

	else if (opcode == OP_PUSHDATA1) {
		uint8_t v8;
		if (!deser_bytes(&v8, bp->buf, 1))
			goto err_out;
		data_len = v8;
	}
	else if (opcode == OP_PUSHDATA2) {
		uint16_t v16;
		if (!deser_u16(&v16, bp->buf))
			goto err_out;
		data_len = v16;
	}
	else if (opcode == OP_PUSHDATA4) {
		uint32_t v32;
		if (!deser_u32(&v32, bp->buf))
			goto err_out;
		data_len = v32;
	} else {
		assert(!is_bsp_pushdata(opcode));
		op->data.p = NULL;
		op->data.len = 0;
		return true;
	}

	op->data.p = bp->buf->p;
	op->data.len = data_len;

	if (!deser_skip(bp->buf, data_len))
		goto err_out;

	return true;

err_out:
	bp->error = true;
	return false;
}

parr *bsp_parse_all(const void *data_, size_t data_len)
{
	struct const_buffer buf = { data_, data_len };
	struct bscript_parser bp;
	struct bscript_op op;
	parr *arr = parr_new(16, free);

	bsp_start(&bp, &buf);

	while (bsp_getop(&op, &bp))
		parr_add(arr, memdup(&op, sizeof(op)));
	if (bp.error)
		goto err_out;

	return arr;

err_out:
	parr_free(arr, true);
	return NULL;
}

bool is_bsp_pushonly(struct const_buffer *buf)
{
	struct bscript_parser bp;
	struct bscript_op op;

	bsp_start(&bp, buf);

	while (bsp_getop(&op, &bp))
		if (!is_bsp_pushdata(op.op))
			return false;
	if (bp.error)
		return false;

	return true;
}

static bool is_bsp_op(const struct bscript_op *op, enum opcodetype opcode)
{
	return (op->op == opcode);
}

static bool is_bsp_op_smallint(const struct bscript_op *op)
{
	return ((op->op == OP_0) ||
		(op->op >= OP_1 && op->op <= OP_16));
}

static bool is_bsp_op_pubkey(const struct bscript_op *op)
{
	if (!is_bsp_pushdata(op->op))
		return false;
	if (op->data.len < 33 || op->data.len > 120)
		return false;
	return true;
}

static bool is_bsp_op_pubkeyhash(const struct bscript_op *op)
{
	if (!is_bsp_pushdata(op->op))
		return false;
	if (op->data.len != 20)
		return false;
	return true;
}

// OP_PUBKEY, OP_CHECKSIG
bool is_bsp_pubkey(parr *ops)
{
	return ((ops->len == 2) &&
	        is_bsp_op(parr_idx(ops, 1), OP_CHECKSIG) &&
	        is_bsp_op_pubkey(parr_idx(ops, 0)));
}

// OP_DUP, OP_HASH160, OP_PUBKEYHASH, OP_EQUALVERIFY, OP_CHECKSIG,
bool is_bsp_pubkeyhash(parr *ops)
{
	return ((ops->len == 5) &&
	        is_bsp_op(parr_idx(ops, 0), OP_DUP) &&
	        is_bsp_op(parr_idx(ops, 1), OP_HASH160) &&
	        is_bsp_op_pubkeyhash(parr_idx(ops, 2)) &&
	        is_bsp_op(parr_idx(ops, 3), OP_EQUALVERIFY) &&
	        is_bsp_op(parr_idx(ops, 4), OP_CHECKSIG));
}

// OP_HASH160, OP_PUBKEYHASH, OP_EQUAL
bool is_bsp_scripthash(parr *ops)
{
	return ((ops->len == 3) &&
	        is_bsp_op(parr_idx(ops, 0), OP_HASH160) &&
	        is_bsp_op_pubkeyhash(parr_idx(ops, 1)) &&
	        is_bsp_op(parr_idx(ops, 2), OP_EQUAL));
}

// OP_SMALLINTEGER, OP_PUBKEYS, OP_SMALLINTEGER, OP_CHECKMULTISIG
bool is_bsp_multisig(parr *ops)
{
	if ((ops->len < 3) || (ops->len > (16 + 3)) ||
	    !is_bsp_op_smallint(parr_idx(ops, 0)) ||
	    !is_bsp_op_smallint(parr_idx(ops, ops->len - 2)) ||
	    !is_bsp_op(parr_idx(ops, ops->len - 1), OP_CHECKMULTISIG))
		return false;

	unsigned int i;
	for (i = 1; i < (ops->len - 2); i++)
		if (!is_bsp_op_pubkey(parr_idx(ops, i)))
			return false;

	return true;
}

enum txnouttype bsp_classify(parr *ops)
{
	if (is_bsp_pubkeyhash(ops))
		return TX_PUBKEYHASH;
	if (is_bsp_scripthash(ops))
		return TX_SCRIPTHASH;
	if (is_bsp_pubkey(ops))
		return TX_PUBKEY;
	if (is_bsp_multisig(ops))
		return TX_MULTISIG;

	return TX_NONSTANDARD;
}

bool bsp_addr_parse(struct bscript_addr *addr,
		    const void *data, size_t data_len)
{
	memset(addr, 0, sizeof(*addr));

	parr *ops = bsp_parse_all(data, data_len);
	if (!ops)
		return false;

	enum txnouttype txtype = bsp_classify(ops);
	switch (txtype) {

	case TX_PUBKEY: {
		struct bscript_op *op = parr_idx(ops, 0);
		struct buffer *buf = buffer_copy(op->data.p, op->data.len);
		addr->pub = clist_append(addr->pub, buf);
		break;
	}

	case TX_PUBKEYHASH: {
		struct bscript_op *op = parr_idx(ops, 2);
		struct buffer *buf = buffer_copy(op->data.p, op->data.len);
		addr->pubhash = clist_append(addr->pubhash, buf);
		break;
	}

	default:
		/* do nothing */
		break;
	}

	addr->txtype = txtype;

	parr_free(ops, true);
	return true;
}

void bsp_addr_free(struct bscript_addr *addrs)
{
	if (!addrs)
		return;

	if (addrs->pub) {
		clist_free_ext(addrs->pub, buffer_free);
		addrs->pub = NULL;
	}
	if (addrs->pubhash) {
		clist_free_ext(addrs->pubhash, buffer_free);
		addrs->pubhash = NULL;
	}
}

void bsp_push_data(cstring *s, const void *data, size_t data_len)
{
	if (data_len < OP_PUSHDATA1) {
		uint8_t c = (uint8_t) data_len;

		cstr_append_buf(s, &c, sizeof(c));
	}

	else if (data_len <= 0xff) {
		uint8_t opcode = OP_PUSHDATA1;
		uint8_t v8 = (uint8_t) data_len;

		cstr_append_buf(s, &opcode, sizeof(opcode));
		cstr_append_buf(s, &v8, sizeof(v8));
	}

	else if (data_len <= 0xffff) {
		uint8_t opcode = OP_PUSHDATA2;
		uint16_t v16_le = htole16((uint16_t) data_len);

		cstr_append_buf(s, &opcode, sizeof(opcode));
		cstr_append_buf(s, &v16_le, sizeof(v16_le));
	}

	else {
		uint8_t opcode = OP_PUSHDATA4;
		uint32_t v32_le = htole32((uint32_t) data_len);

		cstr_append_buf(s, &opcode, sizeof(opcode));
		cstr_append_buf(s, &v32_le, sizeof(v32_le));
	}

	cstr_append_buf(s, data, data_len);
}

void bsp_push_int64(cstring *s, int64_t n)
{
	if (n == -1 || (n >= 1 && n <= 16)) {
		unsigned char c = (unsigned char) (n + (OP_1 - 1));
		cstr_append_buf(s, &c, 1);
		return;
	}

	bool neg = false;
	if (n < 0) {
		neg = true;
		n = -n;
	}

	BIGNUM bn, bn_lo, bn_hi;
	BN_init(&bn);
	BN_init(&bn_hi);
	BN_init(&bn_lo);

	BN_set_word(&bn_hi, (n >> 32));
	BN_lshift(&bn_hi, &bn_hi, 32);
	BN_set_word(&bn_lo, (n & 0xffffffffU));
	BN_add(&bn, &bn_hi, &bn_lo);
	if (neg)
		BN_set_negative(&bn, 1);

	cstring *vch = bn_getvch(&bn);

	bsp_push_data(s, vch->str, vch->len);

	cstr_free(vch, true);
	BN_clear_free(&bn);
	BN_clear_free(&bn_hi);
	BN_clear_free(&bn_lo);
}

void bsp_push_uint64(cstring *s, uint64_t n)
{
	if (n >= 1 && n <= 16) {
		unsigned char c = (unsigned char) (n + (OP_1 - 1));
		cstr_append_buf(s, &c, 1);
		return;
	}

	BIGNUM bn, bn_lo, bn_hi;
	BN_init(&bn);
	BN_init(&bn_hi);
	BN_init(&bn_lo);

	BN_set_word(&bn_hi, (n >> 32));
	BN_lshift(&bn_hi, &bn_hi, 32);
	BN_set_word(&bn_lo, (n & 0xffffffffU));
	BN_add(&bn, &bn_hi, &bn_lo);

	cstring *vch = bn_getvch(&bn);

	bsp_push_data(s, vch->str, vch->len);

	cstr_free(vch, true);
	BN_clear_free(&bn);
	BN_clear_free(&bn_hi);
	BN_clear_free(&bn_lo);
}

cstring *bsp_make_scripthash(cstring *hash)
{
	cstring *script_out = cstr_new_sz(32);

	bsp_push_op(script_out, OP_HASH160);
	bsp_push_data(script_out, hash->str, hash->len);
	bsp_push_op(script_out, OP_EQUAL);

	return script_out;
}

cstring *bsp_make_pubkeyhash(cstring *hash)
{
	cstring *script_out = cstr_new_sz(32);

	bsp_push_op(script_out, OP_DUP);
	bsp_push_op(script_out, OP_HASH160);
	bsp_push_data(script_out, hash->str, hash->len);
	bsp_push_op(script_out, OP_EQUALVERIFY);
	bsp_push_op(script_out, OP_CHECKSIG);

	return script_out;
}

