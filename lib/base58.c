/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <ctype.h>
#include <string.h>
#include <gmp.h>
#include <ccoin/util.h>
#include <ccoin/cstr.h>

static const char base58_chars[] =
	"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

cstring *base58_encode(const void *data_, size_t data_len)
{
	const unsigned char *data = data_;
	mpz_t bn;

	mpz_init(bn);

	mpz_import(bn, data_len, 1, 1, 1, 0, data);

	cstring *rs = cstr_new_sz(data_len * 138 / 100 + 1);

	while (mpz_sgn(bn) > 0) {
		unsigned int c = mpz_tdiv_q_ui(bn, bn, 58);

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

	mpz_clear(bn);

	return rs;
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
	mpz_t bn;
	cstring *ret = NULL;

	mpz_init(bn);

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
		mpz_mul_ui(bn, bn, 58);
		mpz_add_ui(bn, bn, p1 - base58_chars);
	}

	size_t buf_sz;
	char *buf = mpz_export(NULL, &buf_sz, 1, 1, 1, 0, bn);
	cstring *tmp = cstr_new_buf(buf,buf_sz);
	free(buf);

	if ((tmp->len >= 2) &&
	    (tmp->str[tmp->len - 1] == 0) &&
	    ((unsigned char)tmp->str[tmp->len - 2] >= 0x80))
		cstr_resize(tmp, tmp->len - 1);

	for (p = s_in; *p == base58_chars[0]; p++)
		cstr_prepend_c(tmp, '\0');

	ret = tmp;

out:
	mpz_clear(bn);
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

