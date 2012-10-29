
#include "picocoin-config.h"

#include <string.h>
#include <openssl/bn.h>
#include <glib.h>
#include "buint.h"

void bu256_bn(BIGNUM *vo, const bu256_t *vi)
{
	BN_zero(vo);

	BIGNUM tmp;
	BN_init(&tmp);

	unsigned int i;
	for (i = 0; i < 8; i++) {
		BN_set_word(&tmp, GUINT32_FROM_LE(vi->dword[i]));
		BN_lshift(&tmp, &tmp, (i * 32));

		BN_add(vo, vo, &tmp);
	}

	BN_free(&tmp);
}

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

static bool decode_hex(void *p, size_t max_len, const char *hexstr, size_t *out_len_)
{
	if (!strcmp(hexstr, "0x"))
		hexstr += 2;
	if (strlen(hexstr) > (max_len * 2))
		return false;
	
	unsigned char *buf = p;
	size_t out_len = 0;

	while (hexstr) {
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

bool hex_bu256(bu256_t *vo, const char *hexstr)
{
	size_t out_len = 0;

	if (!decode_hex(vo, sizeof(bu256_t), hexstr, &out_len))
		return false;
	
	if (out_len != sizeof(bu256_t))
		return false;
	
	return true;
}

void bu256_swap(bu256_t *v)
{
	unsigned int i;
	for (i = 0; i < 8; i++)
		v->dword[i] = GUINT32_SWAP_LE_BE(v->dword[i]);
}

void bu256_copy_swap(bu256_t *vo, const bu256_t *vi)
{
	unsigned int i;
	for (i = 0; i < 8; i++)
		vo->dword[i] = GUINT32_SWAP_LE_BE(vi->dword[i]);
}

