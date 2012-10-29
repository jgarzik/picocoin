
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
