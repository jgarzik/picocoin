#ifndef __LIBCCOIN_UTIL_H__
#define __LIBCCOIN_UTIL_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <ccoin/cstr.h>
#include <ccoin/clist.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif
#ifndef MIN
#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum {
	VALSTR_SZ	= 18,
#define VALSTR_SZ VALSTR_SZ
};

extern void btc_decimal(char *valstr, size_t valstr_sz, int64_t val);
extern cstring *bn_getvch(const BIGNUM *v);
extern void bn_setvch(BIGNUM *vo, const void *data_, size_t data_len);

extern void bu_reverse_copy(unsigned char *dst, const unsigned char *src, size_t len);
extern void bu_Hash(unsigned char *md256, const void *data, size_t data_len);
extern void bu_Hash_(unsigned char *md256,
		     const void *data1, size_t data_len1,
		     const void *data2, size_t data_len2);
extern void bu_Hash4(unsigned char *md32, const void *data, size_t data_len);
extern void bu_Hash160(unsigned char *md160, const void *data, size_t data_len);
extern bool bu_read_file(const char *filename, void **data_, size_t *data_len_,
	       size_t max_file_len);
extern bool bu_write_file(const char *filename, const void *data, size_t data_len);
extern int file_seq_open(const char *filename);

extern clist *bu_dns_lookup(clist *l, const char *seedname, unsigned int def_port);
extern clist *bu_dns_seed_addrs(void);

extern unsigned long djb2_hash(unsigned long hash, const void *_buf, size_t buflen);

extern unsigned long czstr_hash(const void *p);
extern bool czstr_equal(const void *a, const void *b);

extern void clist_shuffle(clist *l);

static inline void *memdup(const void *data, size_t sz)
{
	void *ret = malloc(sz);
	if (ret)
		memcpy(ret, data, sz);
	return ret;
}

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_UTIL_H__ */
