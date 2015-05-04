/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <ctype.h>
#include <string.h>
#include <openssl/bn.h>
#include <ccoin/util.h>
#include <ccoin/cstr.h>

static const char base58_chars[] =
	"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

cstring *base58_encode(const void *data_, size_t data_len)
{
	const unsigned char *data = data_;
	BIGNUM bn58, bn0, bn, dv, rem;
	BN_CTX *ctx;

	ctx = BN_CTX_new();
	BN_init(&bn58);
	BN_init(&bn0);
	BN_init(&bn);
	BN_init(&dv);
	BN_init(&rem);

	BN_set_word(&bn58, 58);
	BN_set_word(&bn0, 0);

	unsigned char swapbuf[data_len + 1];
	bu_reverse_copy(swapbuf, data, data_len);
	swapbuf[data_len] = 0;

	bn_setvch(&bn, swapbuf, sizeof(swapbuf));

	cstring *rs = cstr_new_sz(data_len * 138 / 100 + 1);

	while (BN_cmp(&bn, &bn0) > 0) {
		if (!BN_div(&dv, &rem, &bn, &bn58, ctx))
			goto err_out;
		BN_copy(&bn, &dv);

		unsigned int c = BN_get_word(&rem);
		cstr_append_c(rs, base58_chars[c]);
	}

	unsigned int i;
	for (i = 0; i < data_len; i++) {
		if (data[i] == 0)
			cstr_append_c(rs, base58_chars[0]);
		else
			break;
	}

	cstring *rs_swap = cstr_new_sz(rs->len);
	cstr_resize(rs_swap, rs->len);
	bu_reverse_copy((unsigned char *) rs_swap->str,
		     (unsigned char *) rs->str, rs->len);

	cstr_free(rs, true);
	rs = rs_swap;

out:
	BN_clear_free(&bn58);
	BN_clear_free(&bn0);
	BN_clear_free(&bn);
	BN_clear_free(&dv);
	BN_clear_free(&rem);
	BN_CTX_free(ctx);

	return rs;

err_out:
	cstr_free(rs, true);
	rs = NULL;
	goto out;
}

cstring *base58_encode_check(unsigned char addrtype, bool have_addrtype,
			     const void *data, size_t data_len)
{
	cstring *s = cstr_new_sz(data_len + 1 + 4);

	if (have_addrtype)
		cstr_append_c(s, addrtype);
	cstr_append_buf(s, data, data_len);

	unsigned char md32[4];
	bu_Hash4(md32, s->str, s->len);

	cstr_append_buf(s, md32, 4);

	cstring *s_enc = base58_encode(s->str, s->len);

	cstr_free(s, true);

	return s_enc;
}

cstring *base58_decode(const char *s_in)
{
	BIGNUM bn58, bn, bnChar;
	BN_CTX *ctx;
	cstring *ret = NULL;

	ctx = BN_CTX_new();
	BN_init(&bn58);
	BN_init(&bn);
	BN_init(&bnChar);

	BN_set_word(&bn58, 58);
	BN_set_word(&bn, 0);

	while (isspace(*s_in))
		s_in++;

	const char *p;
	for (p = s_in; *p; p++) {
		const char *p1 = strchr(base58_chars, *p);
		if (!p1) {
			while (isspace(*p))
				p++;
			if (*p != '\0')
				goto out;
			break;
		}

		BN_set_word(&bnChar, p1 - base58_chars);

		if (!BN_mul(&bn, &bn, &bn58, ctx))
			goto out;

		if (!BN_add(&bn, &bn, &bnChar))
			goto out;
	}

	cstring *tmp = bn_getvch(&bn);

	if ((tmp->len >= 2) &&
	    (tmp->str[tmp->len - 1] == 0) &&
	    ((unsigned char)tmp->str[tmp->len - 2] >= 0x80))
		cstr_resize(tmp, tmp->len - 1);

	unsigned int leading_zero = 0;
	for (p = s_in; *p == base58_chars[0]; p++)
		leading_zero++;

	unsigned int be_sz = tmp->len + leading_zero;
	cstring *tmp_be = cstr_new_sz(be_sz);
	cstr_resize(tmp_be, be_sz);
	memset(tmp_be->str, 0, be_sz);

	bu_reverse_copy((unsigned char *)tmp_be->str + leading_zero,
			(unsigned char *)tmp->str, tmp->len);

	cstr_free(tmp, true);

	ret = tmp_be;

out:
	BN_clear_free(&bn58);
	BN_clear_free(&bn);
	BN_clear_free(&bnChar);
	BN_CTX_free(ctx);
	return ret;
}

cstring *base58_decode_check(unsigned char *addrtype, const char *s_in)
{
	/* decode base58 string */
	cstring *s = base58_decode(s_in);
	if (!s)
		return NULL;
	if (s->len < 4)
		goto err_out;

	/* validate with trailing hash, then remove hash */
	unsigned char md32[4];
	bu_Hash4(md32, s->str, s->len - 4);

	if (memcmp(md32, &s->str[s->len - 4], 4))
		goto err_out;

	cstr_resize(s, s->len - 4);

	/* if addrtype requested, remove from front of data string */
	if (addrtype) {
		*addrtype = (unsigned char) s->str[0];
		cstr_erase(s, 0, 1);
	}

	return s;

err_out:
	cstr_free(s, true);
	return NULL;
}

