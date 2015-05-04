/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <string.h>
#include <stdbool.h>
#include <ccoin/hexcode.h>
#include <ccoin/cstr.h>

static const unsigned char hexdigit_val[256] = {
	['0'] = 0,
	['1'] = 1,
	['2'] = 2,
	['3'] = 3,
	['4'] = 4,
	['5'] = 5,
	['6'] = 6,
	['7'] = 7,
	['8'] = 8,
	['9'] = 9,
	['a'] = 0xa,
	['b'] = 0xb,
	['c'] = 0xc,
	['d'] = 0xd,
	['e'] = 0xe,
	['f'] = 0xf,
	['A'] = 0xa,
	['B'] = 0xb,
	['C'] = 0xc,
	['D'] = 0xd,
	['E'] = 0xe,
	['F'] = 0xf,
};

bool decode_hex(void *p, size_t max_len, const char *hexstr, size_t *out_len_)
{
	if (!p || !hexstr)
		return false;
	if (!strncmp(hexstr, "0x", 2))
		hexstr += 2;
	if (strlen(hexstr) > (max_len * 2))
		return false;

	unsigned char *buf = p;
	size_t out_len = 0;

	while (*hexstr) {
		unsigned char c1 = (unsigned char) hexstr[0];
		unsigned char c2 = (unsigned char) hexstr[1];

		unsigned char v1 = hexdigit_val[c1];
		unsigned char v2 = hexdigit_val[c2];

		if (!v1 && (c1 != '0'))
			return false;
		if (!v2 && (c2 != '0'))
			return false;

		*buf = (v1 << 4) | v2;

		out_len++;
		buf++;
		hexstr += 2;
	}

	if (out_len_)
		*out_len_ = out_len;
	return true;
}

bool is_hexstr(const char *hexstr, bool require_prefix)
{
	if (!strncmp(hexstr, "0x", 2))
		hexstr += 2;
	else if (require_prefix)
		return false;

	while (*hexstr) {
		unsigned char c1 = (unsigned char) hexstr[0];
		unsigned char c2 = (unsigned char) hexstr[1];

		unsigned char v1 = hexdigit_val[c1];
		unsigned char v2 = hexdigit_val[c2];

		if (!v1 && (c1 != '0'))
			return false;
		if (!v2 && (c2 != '0'))
			return false;

		hexstr += 2;
	}

	return true;
}

cstring *hex2str(const char *hexstr)
{
	if (!hexstr || !*hexstr)
		return NULL;
	if (!strncmp(hexstr, "0x", 2))
		hexstr += 2;

	size_t slen = strlen(hexstr) / 2;
	cstring *s = cstr_new_sz(slen);
	cstr_resize(s, slen);
	memset(s->str, 0, slen);

	size_t outlen = 0;
	bool rc = decode_hex(s->str, slen, hexstr, &outlen);

	if (!rc || (slen != outlen)) {
		cstr_free(s, true);
		return NULL;
	}

	return s;
}

static const char hexdigit[] = "0123456789abcdef";

void encode_hex(char *hexstr, const void *p_, size_t len)
{
	const unsigned char *p = p_;
	unsigned int i;

	for (i = 0; i < len; i++) {
		unsigned char v, n1, n2;

		v = p[i];
		n1 = v >> 4;
		n2 = v & 0xf;

		*hexstr++ = hexdigit[n1];
		*hexstr++ = hexdigit[n2];
	}

	*hexstr = 0;
}

