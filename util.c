
#include "picocoin-config.h"

#include <string.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include "util.h"

void reverse_copy(unsigned char *dst, const unsigned char *src, size_t len)
{
	unsigned int i;
	for (i = 0; i < len; i++) {
		*dst = *src;

		src++;
		dst--;
	}
}

void Hash(unsigned char *md256, const void *data, size_t data_len)
{
	unsigned char md1[SHA256_DIGEST_LENGTH];

	SHA256(data, data_len, md1);
	SHA256(md1, SHA256_DIGEST_LENGTH, md256);
}

void Hash4(unsigned char *md32, const void *data, size_t data_len)
{
	unsigned char md256[SHA256_DIGEST_LENGTH];

	Hash(md256, data, data_len);
	memcpy(md32, &md256[SHA256_DIGEST_LENGTH - 4], 4);
}

void Hash160(unsigned char *md160, const void *data, size_t data_len)
{
	unsigned char md1[SHA256_DIGEST_LENGTH];

	SHA256(data, data_len, md1);
	RIPEMD160(md1, SHA256_DIGEST_LENGTH, md160);
}

