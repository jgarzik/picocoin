/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <ccoin/serialize.h>
#include <ccoin/util.h>
#include <ccoin/compat.h>
#include <ccoin/endian.h>

void ser_bytes(cstring *s, const void *p, size_t len)
{
	cstr_append_buf(s, p, len);
}

void ser_u16(cstring *s, uint16_t v_)
{
	uint16_t v = htole16(v_);
	cstr_append_buf(s, &v, sizeof(v));
}

void ser_u32(cstring *s, uint32_t v_)
{
	uint32_t v = htole32(v_);
	cstr_append_buf(s, &v, sizeof(v));
}

void ser_u64(cstring *s, uint64_t v_)
{
	uint64_t v = htole64(v_);
	cstr_append_buf(s, &v, sizeof(v));
}

void ser_bool(cstring *s, bool v_)
{
	cstr_append_c(s, v_?1:0);
}

void ser_varlen(cstring *s, uint32_t vlen)
{
	unsigned char c;

	if (vlen < 253) {
		c = vlen;
		ser_bytes(s, &c, 1);
	}

	else if (vlen < 0x10000) {
		c = 253;
		ser_bytes(s, &c, 1);
		ser_u16(s, (uint16_t) vlen);
	}

	else {
		c = 254;
		ser_bytes(s, &c, 1);
		ser_u32(s, vlen);
	}

	/* u64 case intentionally not implemented */
}

void ser_str(cstring *s, const char *s_in, size_t maxlen)
{
	size_t slen = strnlen(s_in, maxlen);

	ser_varlen(s, slen);
	ser_bytes(s, s_in, slen);
}

void ser_varstr(cstring *s, cstring *s_in)
{
	if (!s_in || !s_in->len) {
		ser_varlen(s, 0);
		return;
	}

	ser_varlen(s, s_in->len);
	ser_bytes(s, s_in->str, s_in->len);
}

void ser_u256_array(cstring *s, parr *arr)
{
	unsigned int arr_len = arr ? arr->len : 0;

	ser_varlen(s, arr_len);

	unsigned int i;
	for (i = 0; i < arr_len; i++) {
		bu256_t *av;

		av = parr_idx(arr, i);
		ser_u256(s, av);
	}
}

bool deser_skip(struct const_buffer *buf, size_t len)
{
	if (buf->len < len)
		return false;

	buf->p += len;
	buf->len -= len;

	return true;
}

bool deser_bytes(void *po, struct const_buffer *buf, size_t len)
{
	if (buf->len < len)
		return false;

	memcpy(po, buf->p, len);
	buf->p += len;
	buf->len -= len;

	return true;
}

bool deser_u16(uint16_t *vo, struct const_buffer *buf)
{
	uint16_t v;

	if (!deser_bytes(&v, buf, sizeof(v)))
		return false;

	*vo = le16toh(v);
	return true;
}

bool deser_u32(uint32_t *vo, struct const_buffer *buf)
{
	uint32_t v;

	if (!deser_bytes(&v, buf, sizeof(v)))
		return false;

	*vo = le32toh(v);
	return true;
}

bool deser_u64(uint64_t *vo, struct const_buffer *buf)
{
	uint64_t v;

	if (!deser_bytes(&v, buf, sizeof(v)))
		return false;

	*vo = le64toh(v);
	return true;
}

bool deser_bool(bool *vo, struct const_buffer *buf)
{
	uint8_t v;

	if (!deser_bytes(&v, buf, sizeof(v)))
		return false;

	*vo = (0 != v);
	return true;
}

bool deser_varlen(uint32_t *lo, struct const_buffer *buf)
{
	uint32_t len;

	unsigned char c;
	if (!deser_bytes(&c, buf, 1)) return false;

	if (c == 253) {
		uint16_t v16;
		if (!deser_u16(&v16, buf)) return false;
		len = v16;
	}
	else if (c == 254) {
		uint32_t v32;
		if (!deser_u32(&v32, buf)) return false;
		len = v32;
	}
	else if (c == 255) {
		uint64_t v64;
		if (!deser_u64(&v64, buf)) return false;
		len = (uint32_t) v64;	/* WARNING: truncate */
	}
	else
		len = c;

	*lo = len;
	return true;
}

bool deser_str(char *so, struct const_buffer *buf, size_t maxlen)
{
	uint32_t len;
	if (!deser_varlen(&len, buf)) return false;

	/* if input larger than buffer, truncate copy, skip remainder */
	uint32_t skip_len = 0;
	if (len > maxlen) {
		skip_len = len - maxlen;
		len = maxlen;
	}

	if (!deser_bytes(so, buf, len)) return false;
	if (!deser_skip(buf, skip_len)) return false;

	/* add C string null */
	if (len < maxlen)
		so[len] = 0;
	else
		so[maxlen - 1] = 0;

	return true;
}

bool deser_varstr(cstring **so, struct const_buffer *buf)
{
	if (*so) {
		cstr_free(*so, true);
		*so = NULL;
	}

	uint32_t len;
	if (!deser_varlen(&len, buf)) return false;

	if (buf->len < len)
		return false;

	cstring *s = cstr_new_sz(len);
	cstr_append_buf(s, buf->p, len);

	buf->p += len;
	buf->len -= len;

	*so = s;

	return true;
}

bool deser_u256_array(parr **ao, struct const_buffer *buf)
{
	parr *arr = *ao;
	if (arr) {
		parr_free(arr, true);
		*ao = arr = NULL;
	}

	uint32_t vlen;
	if (!deser_varlen(&vlen, buf)) return false;

	if (!vlen)
		return true;

	arr = parr_new(vlen, bu256_free);
	if (!arr)
		return false;

	unsigned int i;
	for (i = 0; i < vlen; i++) {
		bu256_t *n;

		n = bu256_new(NULL);
		if (!deser_u256(n, buf)) {
			bu256_free(n);
			goto err_out;
		}

		parr_add(arr, n);
	}

	*ao = arr;
	return true;

err_out:
	parr_free(arr, true);
	return false;
}

void u256_from_compact(BIGNUM *vo, uint32_t c)
{
	uint32_t nbytes = (c >> 24) & 0xFF;
	uint32_t cv = c & 0xFFFFFF;

	BN_set_word(vo, cv);
	BN_lshift(vo, vo, (8 * (nbytes - 3)));
}

