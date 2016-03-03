/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <gmp.h>
#include <ccoin/util.h>

void bn_setvch(mpz_t vo, const void *data_, size_t data_len)
{
	const unsigned char *data = data_;

	mpz_import(vo, data_len, -1, 1, 1, 0, data);

	if (data[data_len - 1] & 0x80) {
		mpz_clrbit(vo, mpz_sizeinbase(vo, 2) - 1);
		mpz_neg(vo, vo);
	}
}

cstring *bn_getvch(const mpz_t v)
{
	/* get MPI format size */
	size_t sz;
	char *buf = mpz_export(NULL, &sz, -1, 1, 1, 0, v);

	if (sz == 0) {
		free(buf);
		return cstr_new(NULL);
	}

	cstring *s_le = cstr_new_buf(buf, sz);
	free(buf);

	/* check if sign bit is available */
	unsigned int msb = mpz_sizeinbase(v, 2);
	if ((!(msb & 0x07) && msb > 0)) {
		cstr_append_c(s_le, '\0');
		sz++;
	}
	cstr_resize(s_le, sz);

	/* set sign bit */
	if (mpz_sgn(v) == -1) {
		s_le->str[sz - 1] = (s_le->str[sz - 1] & 0xff) | 0x80;
	}

	return s_le;
}

