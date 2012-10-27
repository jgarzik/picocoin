#ifndef __PICOCOIN_SERIALIZE_H__
#define __PICOCOIN_SERIALIZE_H__

#include <openssl/bn.h>
#include <stdint.h>
#include <stdbool.h>
#include <glib.h>
#include "buffer.h"

extern void ser_bytes(GString *s, const void *p, size_t len);
extern void ser_u16(GString *s, uint16_t v_);
extern void ser_u32(GString *s, uint32_t v_);
extern void ser_u64(GString *s, uint64_t v_);
extern void ser_u256(GString *s, const BIGNUM *v_);
extern void ser_varlen(GString *s, uint32_t vlen);
extern void ser_str(GString *s, const char *s_in, size_t maxlen);
extern void ser_varstr(GString *s, GString *s_in);

static inline void ser_s64(GString *s, int64_t v_)
{
	ser_u64(s, (uint64_t) v_);
}

extern bool deser_skip(struct buffer *buf, size_t len);
extern bool deser_bytes(void *po, struct buffer *buf, size_t len);
extern bool deser_u16(uint16_t *vo, struct buffer *buf);
extern bool deser_u32(uint32_t *vo, struct buffer *buf);
extern bool deser_u64(uint64_t *vo, struct buffer *buf);
extern bool deser_u256(BIGNUM *vo, struct buffer *buf);
extern bool deser_varlen(uint32_t *lo, struct buffer *buf);
extern bool deser_str(char *so, struct buffer *buf, size_t maxlen);
extern bool deser_varstr(GString **so, struct buffer *buf);

static inline bool deser_s64(int64_t *vo, struct buffer *buf)
{
	return deser_u64((uint64_t *) vo, buf);
}

extern void u256_from_compact(BIGNUM *vo, uint32_t c);
extern void bp_hash(BIGNUM *vo, void *data, size_t data_len);

#endif /* __PICOCOIN_SERIALIZE_H__ */
