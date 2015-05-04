/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <openssl/bn.h>
#include <ccoin/util.h>

void bn_setvch(BIGNUM *vo, const void *data_, size_t data_len)
{
	const unsigned char *data = data_;
	unsigned int vch2_len = data_len + 4;
	unsigned char vch2[vch2_len];

	vch2[0] = (data_len >> 24) & 0xff;
	vch2[1] = (data_len >> 16) & 0xff;
	vch2[2] = (data_len >> 8) & 0xff;
	vch2[3] = (data_len >> 0) & 0xff;

	bu_reverse_copy(vch2 + 4, data, data_len);

	BN_mpi2bn(vch2, vch2_len, vo);
}

cstring *bn_getvch(const BIGNUM *v)
{
	/* get MPI format size */
	unsigned int sz = BN_bn2mpi(v, NULL);
	if (sz <= 4)
		return cstr_new(NULL);

	/* store bignum as MPI */
	cstring *s_be = cstr_new_sz(sz);
	cstr_resize(s_be, sz);
	BN_bn2mpi(v, (unsigned char *) s_be->str);

	/* copy-swap MPI to little endian, sans 32-bit size prefix */
	unsigned int le_sz = sz - 4;
	cstring *s_le = cstr_new_sz(le_sz);
	cstr_resize(s_le, le_sz);
	bu_reverse_copy((unsigned char *)s_le->str,
			(unsigned char *)s_be->str + 4, le_sz);

	cstr_free(s_be, true);

	return s_le;
}

