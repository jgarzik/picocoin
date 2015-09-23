#ifndef __LIBCCOIN_BUINT_H__
#define __LIBCCOIN_BUINT_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <ccoin/endian.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	BU160_WORDS	= (160 / 32),
#define BU160_WORDS BU160_WORDS

	BU256_WORDS	= (256 / 32),
#define BU256_WORDS BU256_WORDS

	BU256_STRSZ	= (32 * 2) + 1,
#define BU256_STRSZ BU256_STRSZ
};

/* unsigned 160 bit integer, with serialized bitcoin (little endian) ordering */
typedef struct bu160 {
	uint32_t dword[BU160_WORDS];
} bu160_t;

/* unsigned 256 bit integer, with serialized bitcoin (little endian) ordering */
typedef struct bu256 {
	uint32_t dword[BU256_WORDS];
} bu256_t;

extern unsigned long bu160_hash(const void *key_);

extern void bu256_bn(BIGNUM *vo, const bu256_t *vi);
extern bool hex_bu256(bu256_t *vo, const char *hexstr);
extern void bu256_hex(char *hexstr, const bu256_t *v);
extern void bu256_swap(bu256_t *v);
extern void bu256_swap_dwords(bu256_t *v);
extern void bu256_copy_swap(bu256_t *vo, const bu256_t *vi);
extern void bu256_copy_swap_dwords(bu256_t *vo, const bu256_t *vi);
extern void bu256_swap_dwords(bu256_t *v);
extern unsigned long bu256_hash(const void *key);
extern void bu256_free(void *bu256_v);

static inline bool bu256_is_zero(const bu256_t *v)
{
	return	v->dword[0] == 0 &&
		v->dword[1] == 0 &&
		v->dword[2] == 0 &&
		v->dword[3] == 0 &&
		v->dword[4] == 0 &&
		v->dword[5] == 0 &&
		v->dword[6] == 0 &&
		v->dword[7] == 0;
}

static inline void bu256_zero(bu256_t *v)
{
	memset(v, 0, sizeof(*v));
}

static inline void bu256_set_u64(bu256_t *vo, uint64_t vi)
{
	vo->dword[0] = htole32((uint32_t) vi);
	vo->dword[1] = htole32((uint32_t) (vi >> 32));
	vo->dword[2] = 0;
	vo->dword[3] = 0;
	vo->dword[4] = 0;
	vo->dword[5] = 0;
	vo->dword[6] = 0;
	vo->dword[7] = 0;
}

static inline bool bu256_equal(const bu256_t *a, const bu256_t *b)
{
	return memcmp(a, b, sizeof(bu256_t)) == 0;
}

static inline bool bu256_equal_(const void *a, const void *b)
{
	return bu256_equal((const bu256_t *)a, (const bu256_t *)b);
}

static inline void bu256_copy(bu256_t *vo, const bu256_t *vi)
{
	memcpy(vo, vi, sizeof(bu256_t));
}

static inline bu256_t *bu256_new(const bu256_t *init_val)
{
	bu256_t *v;

	if (init_val) {
		v = (bu256_t *)malloc(sizeof(bu256_t));
		bu256_copy(v, init_val);
	} else
		v = (bu256_t *)calloc(1, sizeof(bu256_t));

	return v;
}

static inline bool bu160_equal(const bu160_t *a, const bu160_t *b)
{
	return memcmp(a, b, sizeof(bu160_t)) == 0;
}

static inline bool bu160_equal_(const void *a, const void *b)
{
	return bu160_equal((bu160_t *)a, (bu160_t *)b);
}

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_BUINT_H__ */
