/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <ctype.h>
#include <openssl/bn.h>
#include <glib.h>
#include <ccoin/util.h>

static const char base58_chars[] =
	"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

GString *base58_encode(const void *data_, size_t data_len)
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

	GString *rs = g_string_sized_new(data_len * 138 / 100 + 1);

	while (BN_cmp(&bn, &bn0) > 0) {
		if (!BN_div(&dv, &rem, &bn, &bn58, ctx))
			goto err_out;
		BN_copy(&bn, &dv);

		unsigned int c = BN_get_word(&rem);
		g_string_append_c(rs, base58_chars[c]);
	}

	unsigned int i;
	for (i = 0; i < data_len; i++) {
		if (data[i] == 0)
			g_string_append_c(rs, base58_chars[0]);
		else
			break;
	}

	GString *rs_swap = g_string_sized_new(rs->len);
	g_string_set_size(rs_swap, rs->len);
	bu_reverse_copy((unsigned char *) rs_swap->str,
		     (unsigned char *) rs->str, rs->len);

	g_string_free(rs, TRUE);
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
	g_string_free(rs, TRUE);
	rs = NULL;
	goto out;
}

GString *base58_address_encode(unsigned char addrtype, const void *data,
			       size_t data_len)
{
	GString *s = g_string_sized_new(data_len + 1 + 4);

	g_string_append_c(s, addrtype);
	g_string_append_len(s, data, data_len);

	unsigned char md32[4];
	bu_Hash4(md32, s->str, s->len);

	g_string_append_len(s, (gchar *) md32, 4);

	GString *s_enc = base58_encode(s->str, s->len);

	g_string_free(s, TRUE);

	return s_enc;
}

GString *base58_decode(const char *s_in)
{
	BIGNUM bn58, bn, bnChar;
	BN_CTX *ctx;
	GString *ret = NULL;

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

	GString *tmp = bn_getvch(&bn);

	if ((tmp->len >= 2) &&
	    (tmp->str[tmp->len - 1] == 0) &&
	    ((unsigned char)tmp->str[tmp->len - 2] >= 0x80))
		g_string_set_size(tmp, tmp->len - 1);

	unsigned int leading_zero = 0;
	for (p = s_in; *p == base58_chars[0]; p++)
		leading_zero++;

	unsigned int be_sz = tmp->len + leading_zero;
	GString *tmp_be = g_string_sized_new(be_sz);
	g_string_set_size(tmp_be, be_sz);
	memset(tmp_be->str, 0, be_sz);

	bu_reverse_copy((unsigned char *)tmp_be->str + leading_zero,
			(unsigned char *)tmp->str, tmp->len);

	g_string_free(tmp, TRUE);

	ret = tmp_be;

out:
	BN_clear_free(&bn58);
	BN_clear_free(&bn);
	BN_clear_free(&bnChar);
	BN_CTX_free(ctx);
	return ret;
}

