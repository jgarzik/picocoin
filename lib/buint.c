/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <string.h>
#include <openssl/bn.h>
#include <glib.h>
#include <ccoin/buint.h>
#include <ccoin/hexcode.h>

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

bool hex_bu256(bu256_t *vo, const char *hexstr)
{
	size_t out_len = 0;
	bu256_t tmpv, tmpv2;

	if (!decode_hex(&tmpv, sizeof(bu256_t), hexstr, &out_len))
		return false;
	
	if (out_len != sizeof(bu256_t))
		return false;

	bu256_copy_swap(&tmpv2, &tmpv);
	bu256_copy_swap_dwords(vo, &tmpv2);
	
	return true;
}

void bu256_hex(char *hexstr, const bu256_t *v)
{
	*hexstr = 0;

	int i;
	for (i = 7; i >= 0; i--) {		/* endian: high to low */
		char tmp[8 + 1];

		sprintf(tmp, "%08x", GUINT32_FROM_LE(v->dword[i]));
		strcat(hexstr, tmp);
	}
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

void bu256_copy_swap_dwords(bu256_t *vo, const bu256_t *vi)
{
	vo->dword[0] = vi->dword[7];
	vo->dword[1] = vi->dword[6];
	vo->dword[2] = vi->dword[5];
	vo->dword[3] = vi->dword[4];
	vo->dword[4] = vi->dword[3];
	vo->dword[5] = vi->dword[2];
	vo->dword[6] = vi->dword[1];
	vo->dword[7] = vi->dword[0];
}

void bu256_swap_dwords(bu256_t *v)
{
	bu256_t tmpv;

	bu256_copy_swap_dwords(&tmpv, v);
	memcpy(v, &tmpv, sizeof(*v));
}

guint g_bu256_hash(gconstpointer key_)
{
	const bu256_t *key = key_;

	return key->dword[4]; /* return random int in the middle of 32b hash */
}

gboolean g_bu256_equal(gconstpointer a_, gconstpointer b_)
{
	const bu256_t *a = a_;
	const bu256_t *b = b_;

	return bu256_equal(a, b) ? TRUE : FALSE;
}

guint g_bu160_hash(gconstpointer key_)
{
	const bu160_t *key = key_;

	return key->dword[BU160_WORDS / 2]; /* return rand int in the middle */
}

gboolean g_bu160_equal(gconstpointer a_, gconstpointer b_)
{
	const bu160_t *a = a_;
	const bu160_t *b = b_;

	return bu160_equal(a, b) ? TRUE : FALSE;
}

