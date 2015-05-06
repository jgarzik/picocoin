/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <string.h>
#include <openssl/bn.h>
#include <ccoin/buint.h>
#include <ccoin/hexcode.h>
#include <ccoin/endian.h>

void bu256_bn(BIGNUM *vo, const bu256_t *vi)
{
	BN_zero(vo);

	BIGNUM tmp;
	BN_init(&tmp);

	unsigned int i;
	for (i = 0; i < 8; i++) {
		BN_set_word(&tmp, le32toh(vi->dword[i]));
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

		sprintf(tmp, "%08x", le32toh(v->dword[i]));
		strcat(hexstr, tmp);
	}
}

void bu256_swap(bu256_t *v)
{
	unsigned int i;
	for (i = 0; i < 8; i++)
		v->dword[i] = bswap_32(v->dword[i]);
}

void bu256_copy_swap(bu256_t *vo, const bu256_t *vi)
{
	unsigned int i;
	for (i = 0; i < 8; i++)
		vo->dword[i] = bswap_32(vi->dword[i]);
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

unsigned long bu256_hash(const void *key_)
{
	const bu256_t *key = key_;
	unsigned long l = 0;

	memcpy(&l, &key->dword[4], sizeof(l));
	return l;
}

unsigned long bu160_hash(const void *key_)
{
	const bu160_t *key = key_;

	return key->dword[BU160_WORDS / 2]; /* return rand int in the middle */
}

void bu256_free(void *bu256_v)
{
	bu256_t *v = bu256_v;
	if (!v)
		return;

	memset(v, 0, sizeof(*v));
	free(v);
}

