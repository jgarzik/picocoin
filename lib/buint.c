
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

	if (!decode_hex(vo, sizeof(bu256_t), hexstr, &out_len))
		return false;
	
	if (out_len != sizeof(bu256_t))
		return false;
	
	return true;
}

void bu256_hex(char *hexstr, const bu256_t *v)
{
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

