#ifndef __LIBCCOIN_SERIALIZE_H__
#define __LIBCCOIN_SERIALIZE_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdint.h>
#include <stdbool.h>
#include <openssl/bn.h>
#include <ccoin/buffer.h>
#include <ccoin/buint.h>
#include <ccoin/cstr.h>
#include <ccoin/parr.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void ser_bytes(cstring *s, const void *p, size_t len);
extern void ser_bool(cstring *s, bool v_);
extern void ser_u16(cstring *s, uint16_t v_);
extern void ser_u32(cstring *s, uint32_t v_);
extern void ser_u64(cstring *s, uint64_t v_);

static inline void ser_u256(cstring *s, const bu256_t *v_)
{
	ser_bytes(s, v_, sizeof(bu256_t));
}

extern void ser_varlen(cstring *s, uint32_t vlen);
extern void ser_str(cstring *s, const char *s_in, size_t maxlen);
extern void ser_varstr(cstring *s, cstring *s_in);

static inline void ser_s32(cstring *s, int32_t v_)
{
	ser_u32(s, (uint32_t) v_);
}

static inline void ser_s64(cstring *s, int64_t v_)
{
	ser_u64(s, (uint64_t) v_);
}

extern void ser_u256_array(cstring *s, parr *arr);

extern bool deser_skip(struct const_buffer *buf, size_t len);
extern bool deser_bytes(void *po, struct const_buffer *buf, size_t len);
extern bool deser_bool(bool *vo, struct const_buffer *buf);
extern bool deser_u16(uint16_t *vo, struct const_buffer *buf);
extern bool deser_u32(uint32_t *vo, struct const_buffer *buf);
extern bool deser_u64(uint64_t *vo, struct const_buffer *buf);

static inline bool deser_u256(bu256_t *vo, struct const_buffer *buf)
{
	return deser_bytes(vo, buf, sizeof(bu256_t));
}

extern bool deser_varlen(uint32_t *lo, struct const_buffer *buf);
extern bool deser_str(char *so, struct const_buffer *buf, size_t maxlen);
extern bool deser_varstr(cstring **so, struct const_buffer *buf);

static inline bool deser_s64(int64_t *vo, struct const_buffer *buf)
{
	return deser_u64((uint64_t *) vo, buf);
}

extern bool deser_u256_array(parr **ao, struct const_buffer *buf);

extern void u256_from_compact(BIGNUM *vo, uint32_t c);

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_SERIALIZE_H__ */
