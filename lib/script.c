/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <ccoin/script.h>
#include <ccoin/serialize.h>
#include <ccoin/util.h>
#include <ccoin/buffer.h>
#include <ccoin/compat.h>		/* for g_ptr_array_new_full */

static const unsigned char stdscr_pubkey[] = {
	OP_PUBKEY, OP_CHECKSIG,
};
static const unsigned char stdscr_pubkeyhash[] = {
	OP_DUP, OP_HASH160, OP_PUBKEYHASH, OP_EQUALVERIFY, OP_CHECKSIG,
};

static const struct {
	enum txnouttype		txtype;
	size_t			len;
	const unsigned char	*script;
} std_scripts[] = {
	{ TX_PUBKEY, sizeof(stdscr_pubkey), stdscr_pubkey, },
	{ TX_PUBKEYHASH, sizeof(stdscr_pubkeyhash), stdscr_pubkeyhash, },
};

bool bsp_getop(struct bscript_op *op, struct bscript_parser *bp)
{
	if (bp->buf->len == 0)
		return false;			/* EOF */

	unsigned char opcode;
	if (!deser_bytes(&opcode, bp->buf, 1))
		goto err_out;
	op->op = opcode;

	if (!is_bsp_pushdata(opcode)) {
		op->data.p = NULL;
		op->data.len = 0;
		return true;
	}

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

GPtrArray *bsp_parse_all(const void *data_, size_t data_len)
{
	struct const_buffer buf = { data_, data_len };
	struct bscript_parser bp;
	struct bscript_op op;
	GPtrArray *arr = g_ptr_array_new_full(16, g_free);

	bsp_start(&bp, &buf);

	while (bsp_getop(&op, &bp))
		g_ptr_array_add(arr, g_memdup(&op, sizeof(op)));
	if (bp.error)
		goto err_out;

	return arr;

err_out:
	g_ptr_array_free(arr, TRUE);
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

static bool bsp_match_op(const struct bscript_op *op, unsigned char template)
{
	switch (template) {

	case OP_PUBKEY:
		if (!is_bsp_pushdata(op->op))
			return false;
		if (op->data.len < 33 || op->data.len > 120)
			return false;
		return true;

	case OP_PUBKEYHASH:
		if (!is_bsp_pushdata(op->op))
			return false;
		if (op->data.len != 20)
			return false;
		return true;

	default:
		if (is_bsp_pushdata(op->op))
			return false;

		return (op->op == template);
	}
}

enum txnouttype bsp_classify(GPtrArray *ops)
{
	unsigned int n_scr;

	for (n_scr = 0; n_scr < ARRAY_SIZE(std_scripts); n_scr++) {
		const unsigned char *script = std_scripts[n_scr].script;
		size_t slen = std_scripts[n_scr].len;

		/* easy check: varying script length */
		if (ops->len != slen)
			continue;

		/* verify each op matches template character's op */
		unsigned int i;
		bool match = true;
		for (i = 0; i < slen; i++) {
			struct bscript_op *op;

			op = g_ptr_array_index(ops, i);

			match = bsp_match_op(op, script[i]);
			if (!match)
				break;
		}

		if (!match)
			continue;

		return std_scripts[n_scr].txtype;
	}

	return TX_NONSTANDARD;
}

bool bsp_addr_parse(struct bscript_addr *addr,
		    const void *data, size_t data_len)
{
	memset(addr, 0, sizeof(*addr));

	GPtrArray *ops = bsp_parse_all(data, data_len);
	if (!ops)
		return false;

	enum txnouttype txtype = bsp_classify(ops);
	switch (txtype) {

	case TX_PUBKEY: {
		struct bscript_op *op = g_ptr_array_index(ops, 0);
		struct buffer *buf = buffer_copy(op->data.p, op->data.len);
		addr->pub = g_list_append(addr->pub, buf);
		break;
	}

	case TX_PUBKEYHASH: {
		struct bscript_op *op = g_ptr_array_index(ops, 2);
		struct buffer *buf = buffer_copy(op->data.p, op->data.len);
		addr->pubhash = g_list_append(addr->pub, buf);
		break;
	}
	
	default:
		/* do nothing */
		break;
	}

	addr->txtype = txtype;

	g_ptr_array_free(ops, TRUE);
	return true;
}

void bsp_addr_free(struct bscript_addr *addrs)
{
	if (!addrs)
		return;

	if (addrs->pub) {
		g_list_free_full(addrs->pub, (GDestroyNotify) buffer_free);
		addrs->pub = NULL;
	}
	if (addrs->pubhash) {
		g_list_free_full(addrs->pubhash, (GDestroyNotify) buffer_free);
		addrs->pubhash = NULL;
	}
}

void bsp_push_data(GString *s, const void *data, size_t data_len)
{
	if (data_len < OP_PUSHDATA1) {
		uint8_t c = (uint8_t) data_len;

		g_string_append_len(s, (gchar *) &c, sizeof(c));
	}

	else if (data_len <= 0xff) {
		uint8_t opcode = OP_PUSHDATA1;
		uint8_t v8 = (uint8_t) data_len;

		g_string_append_len(s, (gchar *) &opcode, sizeof(opcode));
		g_string_append_len(s, (gchar *) &v8, sizeof(v8));
	}

	else if (data_len <= 0xffff) {
		uint8_t opcode = OP_PUSHDATA2;
		uint16_t v16_le = GUINT16_TO_LE((uint16_t) data_len);

		g_string_append_len(s, (gchar *) &opcode, sizeof(opcode));
		g_string_append_len(s, (gchar *) &v16_le, sizeof(v16_le));
	}

	else {
		uint8_t opcode = OP_PUSHDATA4;
		uint32_t v32_le = GUINT32_TO_LE((uint32_t) data_len);

		g_string_append_len(s, (gchar *) &opcode, sizeof(opcode));
		g_string_append_len(s, (gchar *) &v32_le, sizeof(v32_le));
	}

	g_string_append_len(s, data, data_len);
}

void bsp_push_int64(GString *s, int64_t n)
{
	if (n == -1 || (n >= 1 && n <= 16)) {
		unsigned char c = (unsigned char) (n + (OP_1 - 1));
		g_string_append_len(s, (gchar *) &c, 1);
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

	GString *vch = bn_getvch(&bn);

	bsp_push_data(s, vch->str, vch->len);

	g_string_free(vch, TRUE);
	BN_clear_free(&bn);
	BN_clear_free(&bn_hi);
	BN_clear_free(&bn_lo);
}

void bsp_push_uint64(GString *s, uint64_t n)
{
	if (n >= 1 && n <= 16) {
		unsigned char c = (unsigned char) (n + (OP_1 - 1));
		g_string_append_len(s, (gchar *) &c, 1);
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

	GString *vch = bn_getvch(&bn);

	bsp_push_data(s, vch->str, vch->len);

	g_string_free(vch, TRUE);
	BN_clear_free(&bn);
	BN_clear_free(&bn_hi);
	BN_clear_free(&bn_lo);
}

