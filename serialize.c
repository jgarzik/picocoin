
#include "picocoin-config.h"

#include <stdint.h>
#include <glib.h>
#include "picocoin.h"
#include "serialize.h"

void ser_bytes(GString *s, const void *p, size_t len)
{
	g_string_append_len(s, p, len);
}

void ser_u16(GString *s, uint16_t v_)
{
	uint16_t v = GUINT16_TO_LE(v_);
	g_string_append_len(s, (gchar *) &v, sizeof(v));
}

void ser_u32(GString *s, uint32_t v_)
{
	uint32_t v = GUINT32_TO_LE(v_);
	g_string_append_len(s, (gchar *) &v, sizeof(v));
}

void ser_u64(GString *s, uint64_t v_)
{
	uint64_t v = GUINT64_TO_LE(v_);
	g_string_append_len(s, (gchar *) &v, sizeof(v));
}

void ser_str(GString *s, const char *s_in, size_t maxlen)
{
	size_t slen = strnlen(s_in, maxlen);

	unsigned char c;

	if (slen < 253) {
		c = slen;
		ser_bytes(s, &c, 1);
	}

	else if (slen < 0x10000) {
		c = 253;
		ser_bytes(s, &c, 1);
		ser_u16(s, (uint16_t) slen);
	}

	else {
		c = 254;
		ser_bytes(s, &c, 1);
		ser_u32(s, (uint32_t) slen);
	}

	/* u64 case intentionally not implemented */

	ser_bytes(s, s_in, slen);
}

bool deser_skip(struct buffer *buf, size_t len)
{
	if (buf->len < len)
		return false;

	buf->p += len;
	buf->len -= len;

	return true;
}

bool deser_bytes(void *po, struct buffer *buf, size_t len)
{
	if (buf->len < len)
		return false;
	
	memcpy(po, buf->p, len);
	buf->p += len;
	buf->len -= len;

	return true;
}

bool deser_u16(uint16_t *vo, struct buffer *buf)
{
	uint16_t v;

	if (!deser_bytes(&v, buf, sizeof(v)))
		return false;

	*vo = GUINT16_FROM_LE(v);
	return true;
}

bool deser_u32(uint32_t *vo, struct buffer *buf)
{
	uint32_t v;

	if (!deser_bytes(&v, buf, sizeof(v)))
		return false;

	*vo = GUINT32_FROM_LE(v);
	return true;
}

bool deser_u64(uint64_t *vo, struct buffer *buf)
{
	uint64_t v;

	if (!deser_bytes(&v, buf, sizeof(v)))
		return false;

	*vo = GUINT64_FROM_LE(v);
	return true;
}

bool deser_str(char *so, struct buffer *buf, size_t maxlen)
{
	unsigned char c;
	uint32_t len, skip_len = 0;
	if (!deser_bytes(&c, buf, 1)) return false;

	if (c == 253) {
		uint16_t v16;
		if (!deser_u16(&v16, buf)) return false;
		len = v16;
	}
	else if (c == 254) {
		uint32_t v32;
		if (!deser_u32(&v32, buf)) return false;
		len = v32;
	}
	else if (c == 255) {
		uint64_t v64;
		if (!deser_u64(&v64, buf)) return false;
		len = (uint32_t) v64;	/* WARNING: truncate */
	}
	else
		len = c;

	/* if input larger than buffer, truncate copy, skip remainder */
	if (len > maxlen) {
		skip_len = len - maxlen;
		len = maxlen;
	}

	if (!deser_bytes(so, buf, len)) return false;
	if (!deser_skip(buf, skip_len)) return false;

	/* add C string null, if possible */
	if (len < maxlen)
		so[len] = 0;

	return true;
}

