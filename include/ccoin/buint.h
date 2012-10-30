#ifndef __LIBCCOIN_BUINT_H__
#define __LIBCCOIN_BUINT_H__

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bn.h>

#define BU256_SZ	(256 / 32)

/* unsigned 256 bit integer, with serialized bitcoin (little endian) ordering */
typedef struct bu256 {
	uint32_t dword[256 / 32];
} bu256_t;

extern void bu256_bn(BIGNUM *vo, const bu256_t *vi);
extern bool hex_bu256(bu256_t *vo, const char *hexstr);
extern void bu256_hex(char *hexstr, const bu256_t *v);
extern void bu256_swap(bu256_t *v);
extern void bu256_copy_swap(bu256_t *vo, const bu256_t *vi);

static inline bool bu256_is_zero(const bu256_t *v)
{
	return memcmp(v,
	     "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
	     32);
}

static inline void bu256_zero(bu256_t *v)
{
	memset(v, 0, sizeof(*v));
}

static inline bool bu256_equal(const bu256_t *a, const bu256_t *b)
{
	return memcmp(a, b, sizeof(bu256_t)) == 0;
}

static inline void bu256_copy(bu256_t *vo, const bu256_t *vi)
{
	memcpy(vo, vi, sizeof(bu256_t));
}

static inline bu256_t *bu256_new(void)
{
	return calloc(1, sizeof(bu256_t));
}

static inline void bu256_free(bu256_t *v)
{
	if (v) {
		memset(v, 0, sizeof(*v));
		free(v);
	}
}

#endif /* __LIBCCOIN_BUINT_H__ */
