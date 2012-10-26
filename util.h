#ifndef __PICOCOIN_UTIL_H__
#define __PICOCOIN_UTIL_H__

#include <stdbool.h>
#include <openssl/bn.h>

extern void reverse_copy(unsigned char *dst, const unsigned char *src, size_t len);
extern void bn_setvch(BIGNUM *vo, const void *data_, size_t data_len);
extern void Hash(unsigned char *md256, const void *data, size_t data_len);
extern void Hash4(unsigned char *md32, const void *data, size_t data_len);
extern void Hash160(unsigned char *md160, const void *data, size_t data_len);
extern bool read_file(const char *filename, void **data_, size_t *data_len_,
	       size_t max_file_len);
extern bool write_file(const char *filename, const void *data, size_t data_len);

#endif /* __PICOCOIN_UTIL_H__ */
