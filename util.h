#ifndef __LIBCCOIN_UTIL_H__
#define __LIBCCOIN_UTIL_H__

#include <stdbool.h>
#include <glib.h>
#include <openssl/bn.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

extern void bn_setvch(BIGNUM *vo, const void *data_, size_t data_len);

extern void bu_reverse_copy(unsigned char *dst, const unsigned char *src, size_t len);
extern void bu_Hash(unsigned char *md256, const void *data, size_t data_len);
extern void bu_Hash4(unsigned char *md32, const void *data, size_t data_len);
extern void bu_Hash160(unsigned char *md160, const void *data, size_t data_len);
extern bool bu_read_file(const char *filename, void **data_, size_t *data_len_,
	       size_t max_file_len);
extern bool bu_write_file(const char *filename, const void *data, size_t data_len);
extern GList *bu_dns_seed_addrs(void);

#endif /* __LIBCCOIN_UTIL_H__ */
